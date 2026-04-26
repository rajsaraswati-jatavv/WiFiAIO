"""Google Geolocation API client for WiFiAIO.

Provides WiFi-based geolocation using the Google Geolocation API,
which can estimate position from nearby WiFi access point observations.
"""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from wifi_aio.exceptions import GeolocationError, WiFiTimeoutError

logger = logging.getLogger(__name__)


@dataclass
class WiFiAccessPoint:
    """A WiFi access point observation for geolocation."""
    mac_address: str
    signal_strength: int = 0
    age: int = 0  # Milliseconds since observation
    channel: int = 0
    signal_to_noise: int = 0


@dataclass
class GeolocationResult:
    """Result of a geolocation query."""
    latitude: float = 0.0
    longitude: float = 0.0
    accuracy: float = 0.0  # Accuracy in meters
    formatted_address: str = ""
    city: str = ""
    country: str = ""
    region: str = ""
    street: str = ""
    access_points_used: int = 0
    timestamp: float = 0.0


class GoogleLocate:
    """WiFi geolocation using the Google Geolocation API.

    Uses the Google Geolocation API to estimate geographic position
    from observed WiFi access point MAC addresses and signal strengths.

    Usage::

        locator = GoogleLocate(api_key="your-google-api-key")
        result = locator.locate(
            access_points=[
                {"mac": "AA:BB:CC:DD:EE:FF", "signal": -60},
                {"mac": "11:22:33:44:55:66", "signal": -70},
            ]
        )
        print(f"Location: ({result.latitude}, {result.longitude}) ±{result.accuracy}m")
    """

    # Google Geolocation API endpoint
    GEOLOCATION_URL = "https://www.googleapis.com/geolocation/v1/geolocate"
    # Google Geocoding API endpoint (for reverse geocoding)
    GEOCODING_URL = "https://maps.googleapis.com/maps/api/geocode/json"

    def __init__(
        self,
        api_key: str = "",
        timeout: int = 15,
        cache_duration: int = 86400,  # 24 hours
    ) -> None:
        """Initialize the Google geolocation client.

        Args:
            api_key: Google API key with Geolocation API enabled.
            timeout: Request timeout in seconds.
            cache_duration: Cache duration in seconds.
        """
        self.api_key = api_key
        self.timeout = timeout
        self.cache_duration = cache_duration
        self._cache: Dict[str, Tuple[float, GeolocationResult]] = {}
        logger.info("GoogleLocate initialized")

    def locate(
        self,
        access_points: Optional[List[Dict[str, Any]]] = None,
        mac_addresses: Optional[List[str]] = None,
        wifi_observations: Optional[List[WiFiAccessPoint]] = None,
        home_mobile_country_code: int = 0,
        home_mobile_network_code: int = 0,
        consider_ip: bool = True,
    ) -> GeolocationResult:
        """Estimate location from WiFi access point observations.

        Args:
            access_points: List of dicts with 'mac' and optional 'signal', 'channel'.
            mac_addresses: Simple list of MAC addresses.
            wifi_observations: List of WiFiAccessPoint objects.
            home_mobile_country_code: Mobile country code hint.
            home_mobile_network_code: Mobile network code hint.
            consider_ip: Whether to consider IP address as a fallback.

        Returns:
            GeolocationResult with estimated position.

        Raises:
            GeolocationError: If the API request fails.
        """
        # Build the request body
        wifi_ap_list: List[Dict[str, Any]] = []

        if access_points:
            for ap in access_points:
                entry: Dict[str, Any] = {
                    "macAddress": ap.get("mac", ap.get("macAddress", "")).upper().replace("-", ":"),
                }
                if "signal" in ap or "signalStrength" in ap:
                    entry["signalStrength"] = ap.get("signal", ap.get("signalStrength", 0))
                if "channel" in ap:
                    entry["channel"] = ap["channel"]
                if "age" in ap:
                    entry["age"] = ap["age"]
                if "signalToNoiseRatio" in ap:
                    entry["signalToNoiseRatio"] = ap["signalToNoiseRatio"]
                wifi_ap_list.append(entry)

        elif mac_addresses:
            for mac in mac_addresses:
                wifi_ap_list.append({"macAddress": mac.upper().replace("-", ":")})

        elif wifi_observations:
            for obs in wifi_observations:
                entry = {"macAddress": obs.mac_address.upper().replace("-", ":")}
                if obs.signal_strength:
                    entry["signalStrength"] = obs.signal_strength
                if obs.channel:
                    entry["channel"] = obs.channel
                if obs.age:
                    entry["age"] = obs.age
                if obs.signal_to_noise:
                    entry["signalToNoiseRatio"] = obs.signal_to_noise
                wifi_ap_list.append(entry)

        # Check cache
        cache_key = self._compute_cache_key(wifi_ap_list)
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        # Build request payload
        payload: Dict[str, Any] = {}
        if wifi_ap_list:
            payload["wifiAccessPoints"] = wifi_ap_list
        if home_mobile_country_code:
            payload["homeMobileCountryCode"] = home_mobile_country_code
        if home_mobile_network_code:
            payload["homeMobileNetworkCode"] = home_mobile_network_code
        payload["considerIp"] = consider_ip

        # Make API request
        response = self._make_geolocation_request(payload)

        if not response:
            return GeolocationResult(timestamp=time.time())

        # Parse response
        location = response.get("location", {})
        accuracy = response.get("accuracy", 0.0)

        result = GeolocationResult(
            latitude=location.get("lat", 0.0),
            longitude=location.get("lng", 0.0),
            accuracy=accuracy,
            access_points_used=len(wifi_ap_list),
            timestamp=time.time(),
        )

        # Reverse geocode for address information
        if result.latitude != 0.0 or result.longitude != 0.0:
            address_info = self._reverse_geocode(result.latitude, result.longitude)
            if address_info:
                result.formatted_address = address_info.get("formatted_address", "")
                result.city = address_info.get("city", "")
                result.country = address_info.get("country", "")
                result.region = address_info.get("region", "")
                result.street = address_info.get("street", "")

        self._set_cached(cache_key, result)
        return result

    def locate_from_scan(
        self,
        scan_results: List[Dict[str, Any]],
    ) -> GeolocationResult:
        """Locate from network scan results.

        Args:
            scan_results: List of scan result dictionaries with 'bssid'
                         and optional 'signal' fields.

        Returns:
            GeolocationResult with estimated position.
        """
        access_points = []
        for scan in scan_results:
            ap: Dict[str, Any] = {
                "mac": scan.get("bssid", scan.get("mac", "")),
            }
            if "signal" in scan or "rssi" in scan:
                ap["signal"] = scan.get("signal", scan.get("rssi", 0))
            if "channel" in scan:
                ap["channel"] = scan["channel"]
            access_points.append(ap)

        return self.locate(access_points=access_points)

    def _make_geolocation_request(
        self, payload: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Make a geolocation API request.

        Args:
            payload: Request payload.

        Returns:
            API response dictionary or None.
        """
        if not self.api_key:
            logger.warning("Google API key not configured")
            return None

        import urllib.request
        import urllib.parse

        url = f"{self.GEOLOCATION_URL}?key={self.api_key}"

        try:
            data = json.dumps(payload).encode("utf-8")
            request = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))

        except Exception as e:
            logger.error("Google Geolocation API request failed: %s", e)
            raise GeolocationError(f"Geolocation request failed: {e}")

    def _reverse_geocode(
        self, latitude: float, longitude: float
    ) -> Optional[Dict[str, str]]:
        """Reverse geocode coordinates to address.

        Args:
            latitude: Latitude coordinate.
            longitude: Longitude coordinate.

        Returns:
            Dictionary with address components or None.
        """
        if not self.api_key:
            return None

        import urllib.request
        import urllib.parse

        params = urllib.parse.urlencode({
            "latlng": f"{latitude},{longitude}",
            "key": self.api_key,
        })
        url = f"{self.GEOCODING_URL}?{params}"

        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))

                if data.get("status") != "OK":
                    return None

                results = data.get("results", [])
                if not results:
                    return None

                address_info: Dict[str, str] = {
                    "formatted_address": results[0].get("formatted_address", ""),
                }

                for component in results[0].get("address_components", []):
                    types = component.get("types", [])
                    if "locality" in types:
                        address_info["city"] = component.get("long_name", "")
                    elif "country" in types:
                        address_info["country"] = component.get("long_name", "")
                    elif "administrative_area_level_1" in types:
                        address_info["region"] = component.get("long_name", "")
                    elif "route" in types:
                        address_info["street"] = component.get("long_name", "")

                return address_info

        except Exception as e:
            logger.debug("Reverse geocoding failed: %s", e)
            return None

    def _compute_cache_key(self, access_points: List[Dict[str, Any]]) -> str:
        """Compute a cache key from access point list."""
        macs = sorted(ap.get("macAddress", "") for ap in access_points)
        key_str = ",".join(macs)
        import hashlib
        return hashlib.md5(key_str.encode()).hexdigest()

    def _get_cached(self, key: str) -> Optional[GeolocationResult]:
        """Get a cached result if valid."""
        if key in self._cache:
            timestamp, data = self._cache[key]
            if time.time() - timestamp < self.cache_duration:
                return data
            del self._cache[key]
        return None

    def _set_cached(self, key: str, data: GeolocationResult) -> None:
        """Cache a geolocation result."""
        self._cache[key] = (time.time(), data)

    def estimate_distance(
        self,
        signal_dbm: int,
        frequency_mhz: int = 2412,
    ) -> float:
        """Estimate distance to an access point from signal strength.

        Uses the free-space path loss model for a rough estimate.

        Args:
            signal_dbm: Observed signal strength in dBm.
            frequency_mhz: WiFi frequency in MHz.

        Returns:
            Estimated distance in meters.
        """
        # Free-space path loss model: FSPL = 20*log10(d) + 20*log10(f) + 32.44
        # Assume transmit power of ~20 dBm for typical home router
        tx_power = 20  # dBm
        path_loss = tx_power - signal_dbm  # Total loss in dB

        if path_loss <= 0:
            return 0.1  # Very close

        # FSPL = 20*log10(d) + 20*log10(f_MHz) - 27.55
        # Solve for d: d = 10^((FSPL - 20*log10(f_MHz) + 27.55) / 20)
        import math as m
        fspl = path_loss
        log_f = m.log10(frequency_mhz)
        distance = 10 ** ((fspl - 20 * log_f + 27.55) / 20)

        return max(distance, 0.1)

    def clear_cache(self) -> None:
        """Clear the geolocation cache."""
        self._cache.clear()
        logger.info("GoogleLocate cache cleared")
