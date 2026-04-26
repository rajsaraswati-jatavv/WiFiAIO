"""Geolocation services using WiFi access point data.

Supports WiGLE API, Google Geolocation API, openWiFi, and KML export
for mapping discovered access points.
"""

import json
import logging
import os
import time
import xml.sax.saxutils
from typing import Dict, List, Optional, Tuple

import requests

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


class Geolocation:
    """Geolocate using WiFi access point data and export to KML.

    Supports:
    - WiGLE API for AP geolocation
    - Google Geolocation API
    - openWiFi database
    - KML export for mapping
    """

    def __init__(
        self,
        wigle_api_key: Optional[str] = None,
        google_api_key: Optional[str] = None,
    ):
        self.wigle_api_key = wigle_api_key
        self.google_api_key = google_api_key
        self._locations: List[Dict] = []

    # ------------------------------------------------------------------
    # WiGLE API
    # ------------------------------------------------------------------

    def wigle_search(
        self,
        ssid: Optional[str] = None,
        bssid: Optional[str] = None,
        lat_range: Optional[Tuple[float, float]] = None,
        lon_range: Optional[Tuple[float, float]] = None,
        api_key: Optional[str] = None,
    ) -> List[Dict]:
        """Search WiGLE database for WiFi networks.

        Args:
            ssid: SSID to search for.
            bssid: BSSID to search for.
            lat_range: Tuple of (min_lat, max_lat).
            lon_range: Tuple of (min_lon, max_lon).
            api_key: WiGLE API key (overrides init value).

        Returns:
            List of result dicts from WiGLE.
        """
        key = api_key or self.wigle_api_key
        if not key:
            raise WiFiConnectionError("WiGLE API key required. Set wigle_api_key.")

        params: Dict[str, str] = {}
        if ssid:
            params["ssid"] = ssid
        if bssid:
            params["netid"] = bssid.replace(":", "")
        if lat_range:
            params["latrange1"] = str(lat_range[0])
            params["latrange2"] = str(lat_range[1])
        if lon_range:
            params["lonrange1"] = str(lon_range[0])
            params["lonrange2"] = str(lon_range[1])

        headers = {"Authorization": f"Bearer {key}"}

        try:
            resp = requests.get(
                "https://api.wigle.net/api/v2/network/search",
                params=params,
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.Timeout:
            raise WiFiTimeoutError("WiGLE API request timed out")
        except requests.RequestException as exc:
            raise WiFiConnectionError(f"WiGLE API error: {exc}")

        results = data.get("results", [])
        for r in results:
            r["source"] = "wigle"
            self._locations.append(r)

        logger.info("WiGLE search returned %d results", len(results))
        return results

    def wigle_bssid_lookup(
        self,
        bssid: str,
        api_key: Optional[str] = None,
    ) -> Optional[Dict]:
        """Look up a specific BSSID in WiGLE.

        Args:
            bssid: MAC address of the AP.
            api_key: WiGLE API key.

        Returns:
            Dict with location data or None.
        """
        key = api_key or self.wigle_api_key
        if not key:
            raise WiFiConnectionError("WiGLE API key required")

        headers = {"Authorization": f"Bearer {key}"}
        netid = bssid.replace(":", "").upper()

        try:
            resp = requests.get(
                f"https://api.wigle.net/api/v2/network/detail",
                params={"netid": netid},
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.Timeout:
            raise WiFiTimeoutError("WiGLE BSSID lookup timed out")
        except requests.RequestException as exc:
            raise WiFiConnectionError(f"WiGLE lookup error: {exc}")

        results = data.get("results", [])
        if results:
            result = results[0]
            result["source"] = "wigle"
            self._locations.append(result)
            return result
        return None

    # ------------------------------------------------------------------
    # Google Geolocation API
    # ------------------------------------------------------------------

    def google_geolocate(
        self,
        access_points: List[Dict[str, str]],
        api_key: Optional[str] = None,
    ) -> Dict:
        """Use Google Geolocation API to estimate position from WiFi APs.

        Args:
            access_points: List of dicts with keys: macAddress, signalStrength,
                           age, channel.
            api_key: Google API key.

        Returns:
            Dict with: lat, lng, accuracy.
        """
        key = api_key or self.google_api_key
        if not key:
            raise WiFiConnectionError("Google API key required")

        wifi_access_points = []
        for ap in access_points[:35]:  # Google allows max 35 APs
            entry = {"macAddress": ap.get("macAddress", ap.get("bssid", ""))}
            if "signalStrength" in ap or "signal" in ap:
                entry["signalStrength"] = ap.get(
                    "signalStrength", ap.get("signal", 0)
                )
            if "channel" in ap:
                entry["channel"] = ap["channel"]
            if "age" in ap:
                entry["age"] = ap["age"]
            wifi_access_points.append(entry)

        payload = {
            "considerIp": "false",
            "wifiAccessPoints": wifi_access_points,
        }

        try:
            resp = requests.post(
                f"https://www.googleapis.com/geolocation/v1/geolocate?key={key}",
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.Timeout:
            raise WiFiTimeoutError("Google Geolocation API timed out")
        except requests.RequestException as exc:
            raise WiFiConnectionError(f"Google Geolocation error: {exc}")

        location = data.get("location", {})
        result = {
            "lat": location.get("lat", 0.0),
            "lng": location.get("lng", 0.0),
            "accuracy": data.get("accuracy", 0.0),
            "source": "google",
        }
        self._locations.append(result)
        return result

    # ------------------------------------------------------------------
    # openWiFi
    # ------------------------------------------------------------------

    def openwifi_lookup(
        self,
        bssid: str,
    ) -> Optional[Dict]:
        """Look up a BSSID in the openWiFi database.

        Args:
            bssid: MAC address of the AP.

        Returns:
            Dict with location data or None.
        """
        try:
            resp = requests.get(
                "https://api.openwifi.net/v1/ap",
                params={"bssid": bssid},
                timeout=15,
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
            data["source"] = "openwifi"
            self._locations.append(data)
            return data
        except requests.Timeout:
            raise WiFiTimeoutError("openWiFi lookup timed out")
        except requests.RequestException:
            return None

    def openwifi_search_area(
        self,
        lat: float,
        lon: float,
        radius: int = 1000,
    ) -> List[Dict]:
        """Search openWiFi for APs in a geographic area.

        Args:
            lat: Latitude.
            lon: Longitude.
            radius: Search radius in meters.

        Returns:
            List of AP location dicts.
        """
        try:
            resp = requests.get(
                "https://api.openwifi.net/v1/ap/area",
                params={"lat": lat, "lon": lon, "radius": radius},
                timeout=15,
            )
            resp.raise_for_status()
            results = resp.json()
            if isinstance(results, list):
                for r in results:
                    r["source"] = "openwifi"
                    self._locations.append(r)
                return results
        except requests.Timeout:
            raise WiFiTimeoutError("openWiFi area search timed out")
        except requests.RequestException:
            pass
        return []

    # ------------------------------------------------------------------
    # Multi-source geolocation
    # ------------------------------------------------------------------

    def geolocate_from_aps(
        self,
        access_points: List[Dict[str, str]],
    ) -> Dict:
        """Attempt geolocation using multiple sources.

        Tries Google Geolocation API first, then falls back to WiGLE.

        Args:
            access_points: List of AP dicts with bssid/macAddress, signal, etc.

        Returns:
            Best available location dict with lat, lng, accuracy, source.
        """
        # Try Google first
        if self.google_api_key:
            try:
                return self.google_geolocate(access_points)
            except (WiFiConnectionError, WiFiTimeoutError):
                pass

        # Fall back to WiGLE BSSID lookups
        if self.wigle_api_key:
            locations = []
            for ap in access_points[:10]:
                bssid = ap.get("bssid", ap.get("macAddress", ""))
                if bssid:
                    try:
                        result = self.wigle_bssid_lookup(bssid)
                        if result and "trilat" in result and "trilong" in result:
                            locations.append({
                                "lat": result["trilat"],
                                "lng": result["trilong"],
                            })
                    except (WiFiConnectionError, WiFiTimeoutError):
                        continue

            if locations:
                # Average the locations
                avg_lat = sum(l["lat"] for l in locations) / len(locations)
                avg_lng = sum(l["lng"] for l in locations) / len(locations)
                result = {
                    "lat": avg_lat,
                    "lng": avg_lng,
                    "accuracy": 50.0,  # Rough estimate
                    "source": "wigle_averaged",
                }
                self._locations.append(result)
                return result

        raise WiFiConnectionError("Could not geolocate: no API keys or no results")

    # ------------------------------------------------------------------
    # KML Export
    # ------------------------------------------------------------------

    def export_kml(
        self,
        locations: Optional[List[Dict]] = None,
        filepath: str = "wifiaio_locations.kml",
    ) -> str:
        """Export locations to KML format for Google Earth / Maps.

        Args:
            locations: List of location dicts. Uses cached locations if None.
            filepath: Output file path.

        Returns:
            Path to the written KML file.
        """
        data = locations or self._locations
        if not data:
            logger.warning("No locations to export")
            # Write empty KML
            kml = self._build_kml([])
            with open(filepath, "w", encoding="utf-8") as fh:
                fh.write(kml)
            return filepath

        # Build placemarks
        placemarks = []
        for loc in data:
            lat = loc.get("lat", loc.get("trilat", 0.0))
            lng = loc.get("lng", loc.get("trilong", loc.get("trilong", 0.0)))
            ssid = loc.get("ssid", loc.get("netid", "Unknown"))
            bssid = loc.get("bssid", loc.get("netid", ""))
            signal = loc.get("signal", loc.get("signal", "N/A"))
            encryption = loc.get("encryption", loc.get("auth", "Unknown"))
            source = loc.get("source", "unknown")
            accuracy = loc.get("accuracy", 0)

            description = (
                f"BSSID: {xml.sax.saxutils.escape(str(bssid))}&lt;br/&gt;"
                f"Signal: {xml.sax.saxutils.escape(str(signal))}&lt;br/&gt;"
                f"Encryption: {xml.sax.saxutils.escape(str(encryption))}&lt;br/&gt;"
                f"Source: {xml.sax.saxutils.escape(str(source))}&lt;br/&gt;"
                f"Accuracy: {xml.sax.saxutils.escape(str(accuracy))}m"
            )
            name = xml.sax.saxutils.escape(str(ssid))

            placemarks.append(
                f"""      <Placemark>
        <name>{name}</name>
        <description>{description}</description>
        <Point>
          <coordinates>{xml.sax.saxutils.escape(str(lng))},{xml.sax.saxutils.escape(str(lat))},0</coordinates>
        </Point>
      </Placemark>"""
            )

        kml = self._build_kml(placemarks)

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(kml)

        logger.info("KML exported to %s with %d placemarks", filepath, len(placemarks))
        return filepath

    @staticmethod
    def _build_kml(placemarks: List[str]) -> str:
        """Build a complete KML document from placemark strings."""
        placemarks_str = "\n".join(placemarks)
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>WiFiAIO Locations</name>
    <description>WiFi access point locations discovered by WiFiAIO</description>
    <Style id="wifiStyle">
      <IconStyle>
        <Icon>
          <href>http://maps.google.com/mapfiles/kml/pal2/icon56.png</href>
        </Icon>
      </IconStyle>
    </Style>
{placemarks_str}
  </Document>
</kml>"""

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def get_cached_locations(self) -> List[Dict]:
        """Return all cached location results."""
        return list(self._locations)

    def clear_cache(self) -> None:
        """Clear cached location data."""
        self._locations.clear()
