"""WiGLE (Wireless Geographic Logging Engine) API client for WiFiAIO.

Provides access to the WiGLE WiFi database for looking up wireless
networks by BSSID, SSID, or geographic area.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from wifi_aio.exceptions import OSINTError, WiFiTimeoutError

logger = logging.getLogger(__name__)


@dataclass
class WiGLENetwork:
    """A Wi-Fi network entry from WiGLE."""
    bssid: str
    ssid: str = ""
    encryption: str = ""
    channel: int = 0
    frequency: int = 0
    latitude: float = 0.0
    longitude: float = 0.0
    signal_strength: int = 0
    first_seen: str = ""
    last_seen: str = ""
    country: str = ""
    region: str = ""
    city: str = ""
    road: str = ""
    type: str = ""  # "WIFI", "BT", etc.
    qos: int = 0  # Quality of signal
    transmissions: int = 0


@dataclass
class WiGLESearchResult:
    """Result of a WiGLE search operation."""
    query: str
    total_results: int = 0
    networks: List[WiGLENetwork] = field(default_factory=list)
    search_metadata: Dict[str, Any] = field(default_factory=dict)
    search_timestamp: float = 0.0


@dataclass
class WiGLEStats:
    """WiGLE user statistics."""
    username: str = ""
    total_networks: int = 0
    total_wifi: int = 0
    total_bt: int = 0
    total_gps: int = 0
    first_discovery: str = ""
    last_discovery: str = ""
    rank: int = 0
    month_rank: int = 0


class WiGLE:
    """Client for the WiGLE WiFi database API.

    Provides methods to search for wireless networks by BSSID, SSID,
    or geographic area. Requires a WiGLE API key for authentication.

    Usage::

        wigle = WiGLE(api_name="myapp", api_key="your-api-key")
        result = wigle.search_bssid("AA:BB:CC:DD:EE:FF")
        for network in result.networks:
            print(f"{network.ssid} at ({network.latitude}, {network.longitude})")
    """

    # WiGLE API endpoints
    BASE_URL = "https://api.wigle.net/api/v2"
    SEARCH_WIFI_URL = f"{BASE_URL}/wifi/search"
    BSSID_SEARCH_URL = f"{BASE_URL}/network/detail"
    STATS_URL = f"{BASE_URL}/stats"
    CELL_SEARCH_URL = f"{BASE_URL}/cell/search"

    # Rate limits
    REQUEST_DELAY = 1.0  # Seconds between API calls
    MAX_RESULTS_PER_PAGE = 100

    def __init__(
        self,
        api_name: str = "",
        api_key: str = "",
        timeout: int = 30,
        cache_duration: int = 3600,
    ) -> None:
        """Initialize the WiGLE client.

        Args:
            api_name: WiGLE API registered name.
            api_key: WiGLE API key.
            timeout: Request timeout in seconds.
            cache_duration: Cache duration in seconds.
        """
        self.api_name = api_name
        self.api_key = api_key
        self.timeout = timeout
        self.cache_duration = cache_duration
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._last_request_time: float = 0.0
        logger.info("WiGLE client initialized")

    def search_bssid(self, bssid: str) -> WiGLESearchResult:
        """Search for a specific BSSID in the WiGLE database.

        Args:
            bssid: BSSID/MAC address to search for.

        Returns:
            WiGLESearchResult with matching networks.

        Raises:
            OSINTError: If the API request fails.
        """
        bssid_normalized = bssid.upper().replace("-", ":")
        cache_key = f"bssid:{bssid_normalized}"

        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        params = {"netid": bssid_normalized}
        response = self._make_request(self.BSSID_SEARCH_URL, params)

        if not response:
            return WiGLESearchResult(
                query=bssid_normalized,
                search_timestamp=time.time(),
            )

        networks = self._parse_network_response(response)
        result = WiGLESearchResult(
            query=bssid_normalized,
            total_results=len(networks),
            networks=networks,
            search_timestamp=time.time(),
        )

        self._set_cached(cache_key, result)
        return result

    def search_ssid(
        self,
        ssid: str,
        latitude: float = 0.0,
        longitude: float = 0.0,
        radius_km: float = 0.0,
        encryption: str = "",
        limit: int = 100,
    ) -> WiGLESearchResult:
        """Search for networks by SSID in the WiGLE database.

        Args:
            ssid: SSID to search for.
            latitude: Center latitude for geographic search.
            longitude: Center longitude for geographic search.
            radius_km: Search radius in kilometers.
            encryption: Filter by encryption type.
            limit: Maximum number of results.

        Returns:
            WiGLESearchResult with matching networks.

        Raises:
            OSINTError: If the API request fails.
        """
        cache_key = f"ssid:{ssid}:{latitude}:{longitude}:{radius_km}:{encryption}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        params: Dict[str, Any] = {
            "ssid": ssid,
            "resultsPerPage": min(limit, self.MAX_RESULTS_PER_PAGE),
        }

        if latitude and longitude and radius_km:
            params["latrange1"] = latitude - (radius_km / 111.32)
            params["latrange2"] = latitude + (radius_km / 111.32)
            params["longrange1"] = longitude - (radius_km / (111.32 * math.cos(math.radians(latitude))))
            params["longrange2"] = longitude + (radius_km / (111.32 * math.cos(math.radians(latitude))))

        if encryption:
            params["encryption"] = encryption

        response = self._make_request(self.SEARCH_WIFI_URL, params)

        if not response:
            return WiGLESearchResult(query=ssid, search_timestamp=time.time())

        total = response.get("totalResults", 0)
        networks = self._parse_network_response(response)

        result = WiGLESearchResult(
            query=ssid,
            total_results=total,
            networks=networks[:limit],
            search_timestamp=time.time(),
            search_metadata={
                "latitude": latitude,
                "longitude": longitude,
                "radius_km": radius_km,
            },
        )

        self._set_cached(cache_key, result)
        return result

    def search_area(
        self,
        latitude: float,
        longitude: float,
        radius_km: float = 1.0,
        limit: int = 100,
    ) -> WiGLESearchResult:
        """Search for all networks in a geographic area.

        Args:
            latitude: Center latitude.
            longitude: Center longitude.
            radius_km: Search radius in kilometers.
            limit: Maximum number of results.

        Returns:
            WiGLESearchResult with networks in the area.

        Raises:
            OSINTError: If the API request fails.
        """
        cache_key = f"area:{latitude}:{longitude}:{radius_km}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        # Calculate bounding box
        lat_delta = radius_km / 111.32
        lon_delta = radius_km / (111.32 * math.cos(math.radians(latitude)))

        params: Dict[str, Any] = {
            "latrange1": latitude - lat_delta,
            "latrange2": latitude + lat_delta,
            "longrange1": longitude - lon_delta,
            "longrange2": longitude + lon_delta,
            "resultsPerPage": min(limit, self.MAX_RESULTS_PER_PAGE),
        }

        response = self._make_request(self.SEARCH_WIFI_URL, params)

        if not response:
            return WiGLESearchResult(
                query=f"area:{latitude},{longitude}",
                search_timestamp=time.time(),
            )

        total = response.get("totalResults", 0)
        networks = self._parse_network_response(response)

        result = WiGLESearchResult(
            query=f"area:{latitude},{longitude}",
            total_results=total,
            networks=networks[:limit],
            search_timestamp=time.time(),
            search_metadata={
                "center": (latitude, longitude),
                "radius_km": radius_km,
            },
        )

        self._set_cached(cache_key, result)
        return result

    def get_stats(self) -> WiGLEStats:
        """Get WiGLE user statistics.

        Returns:
            WiGLEStats with user account statistics.

        Raises:
            OSINTError: If the API request fails.
        """
        response = self._make_request(self.STATS_URL)

        if not response:
            return WiGLEStats()

        stats_data = response.get("statistics", {})
        rank_data = response.get("rank", {})

        return WiGLEStats(
            username=stats_data.get("userName", ""),
            total_networks=stats_data.get("discoveredWiFis", 0),
            total_wifi=stats_data.get("discoveredWiFis", 0),
            total_bt=stats_data.get("discoveredBT", 0),
            total_gps=stats_data.get("discoveredGPS", 0),
            first_discovery=stats_data.get("firstDiscovery", ""),
            last_discovery=stats_data.get("lastDiscovery", ""),
            rank=rank_data("rank", 0) if isinstance(rank_data, dict) else 0,
            month_rank=rank_data.get("monthRank", 0) if isinstance(rank_data, dict) else 0,
        )

    def geolocate(
        self,
        bssids: List[str],
        signal_strengths: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """Estimate location from observed BSSIDs using WiGLE data.

        Queries WiGLE for each BSSID and triangulates an approximate
        position based on known network locations.

        Args:
            bssids: List of observed BSSIDs.
            signal_strengths: Optional list of signal strengths.

        Returns:
            Dictionary with estimated location and accuracy.
        """
        locations: List[Tuple[float, float, int]] = []

        for bssid in bssids:
            result = self.search_bssid(bssid)
            for network in result.networks:
                if network.latitude != 0.0 and network.longitude != 0.0:
                    locations.append((network.latitude, network.longitude, network.signal_strength))

        if not locations:
            return {"latitude": 0.0, "longitude": 0.0, "accuracy": -1, "networks_used": 0}

        # Weighted average based on signal strength
        total_weight = 0.0
        weighted_lat = 0.0
        weighted_lon = 0.0

        for lat, lon, signal in locations:
            weight = max(abs(signal), 1)  # Use absolute signal as weight
            weighted_lat += lat * weight
            weighted_lon += lon * weight
            total_weight += weight

        if total_weight == 0:
            avg_lat = sum(l[0] for l in locations) / len(locations)
            avg_lon = sum(l[1] for l in locations) / len(locations)
        else:
            avg_lat = weighted_lat / total_weight
            avg_lon = weighted_lon / total_weight

        # Estimate accuracy from spread of locations
        if len(locations) > 1:
            lat_spread = max(l[0] for l in locations) - min(l[0] for l in locations)
            lon_spread = max(l[1] for l in locations) - min(l[1] for l in locations)
            accuracy_km = max(lat_spread, lon_spread) * 111.32
        else:
            accuracy_km = 0.05  # ~50m for single network

        return {
            "latitude": round(avg_lat, 6),
            "longitude": round(avg_lon, 6),
            "accuracy_km": round(accuracy_km, 3),
            "networks_used": len(locations),
        }

    def _make_request(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Make an API request to WiGLE.

        Args:
            url: API endpoint URL.
            params: Query parameters.

        Returns:
            Response JSON dictionary or None on failure.
        """
        if not self.api_name or not self.api_key:
            logger.warning("WiGLE API credentials not configured")
            return None

        # Rate limiting
        elapsed = time.time() - self._last_request_time
        if elapsed < self.REQUEST_DELAY:
            time.sleep(self.REQUEST_DELAY - elapsed)

        import urllib.request
        import urllib.parse
        import base64

        try:
            if params:
                query_string = urllib.parse.urlencode(params)
                full_url = f"{url}?{query_string}"
            else:
                full_url = url

            request = urllib.request.Request(full_url)
            credentials = base64.b64encode(
                f"{self.api_name}:{self.api_key}".encode()
            ).decode()
            request.add_header("Authorization", f"Basic {credentials}")

            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))

                if data.get("success", False) is False:
                    logger.error("WiGLE API error: %s", data.get("message", "Unknown"))
                    raise OSINTError(f"WiGLE API error: {data.get('message', 'Unknown')}")

                self._last_request_time = time.time()
                return data

        except Exception as e:
            if isinstance(e, OSINTError):
                raise
            logger.error("WiGLE request failed: %s", e)
            raise OSINTError(f"WiGLE request failed: {e}")

    def _parse_network_response(self, response: Dict[str, Any]) -> List[WiGLENetwork]:
        """Parse network data from WiGLE API response.

        Args:
            response: WiGLE API response dictionary.

        Returns:
            List of WiGLENetwork objects.
        """
        networks: List[WiGLENetwork] = []
        results = response.get("results", [])

        if not results and "networks" in response:
            results = response["networks"]

        for net in results:
            network = WiGLENetwork(
                bssid=net.get("netid", net.get("bssid", "")),
                ssid=net.get("ssid", ""),
                encryption=net.get("encryption", ""),
                channel=net.get("channel", 0),
                frequency=net.get("frequency", 0),
                latitude=net.get("trilat", net.get("latitude", 0.0)),
                longitude=net.get("trilong", net.get("longitude", 0.0)),
                signal_strength=net.get("signal", 0),
                first_seen=net.get("firsttime", net.get("firstSeen", "")),
                last_seen=net.get("lasttime", net.get("lastSeen", "")),
                country=net.get("country", ""),
                region=net.get("region", ""),
                city=net.get("city", ""),
                road=net.get("road", ""),
                type=net.get("type", "WIFI"),
                qos=net.get("qos", 0),
                transmissions=net.get("transid", 0),
            )
            networks.append(network)

        return networks

    def _get_cached(self, key: str) -> Any:
        """Get a cached result if still valid."""
        if key in self._cache:
            timestamp, data = self._cache[key]
            if time.time() - timestamp < self.cache_duration:
                return data
            del self._cache[key]
        return None

    def _set_cached(self, key: str, data: Any) -> None:
        """Cache a result."""
        self._cache[key] = (time.time(), data)

    def clear_cache(self) -> None:
        """Clear the result cache."""
        self._cache.clear()
        logger.info("WiGLE cache cleared")
