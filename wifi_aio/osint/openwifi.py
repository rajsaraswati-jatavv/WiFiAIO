"""OpenWiFi database client for WiFiAIO.

Provides access to open WiFi network databases and directories
for finding open/public WiFi networks by location.
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
class OpenWiFiNetwork:
    """An open/public WiFi network entry."""
    ssid: str
    bssid: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    venue_type: str = ""  # e.g., "cafe", "library", "airport"
    venue_name: str = ""
    address: str = ""
    city: str = ""
    country: str = ""
    is_free: bool = True
    requires_registration: bool = False
    has_captive_portal: bool = False
    speed_mbps: float = 0.0
    last_verified: str = ""
    source: str = ""


@dataclass
class OpenWiFiSearchResult:
    """Result of an OpenWiFi search."""
    query: str
    total_results: int = 0
    networks: List[OpenWiFiNetwork] = field(default_factory=list)
    search_timestamp: float = 0.0


# Known open WiFi network SSID patterns
OPEN_WIFI_SSID_PATTERNS: List[Dict[str, Any]] = [
    {"ssid": "xfinitywifi", "venue": "isp_hotspot", "free": False, "provider": "Comcast"},
    {"ssid": "CableWiFi", "venue": "isp_hotspot", "free": False, "provider": "Cable Providers"},
    {"ssid": "SpectrumWiFi", "venue": "isp_hotspot", "free": False, "provider": "Charter"},
    {"ssid": "attwifi", "venue": "isp_hotspot", "free": False, "provider": "AT&T"},
    {"ssid": "ATT-WIFI", "venue": "isp_hotspot", "free": False, "provider": "AT&T"},
    {"ssid": " optimumwifi", "venue": "isp_hotspot", "free": False, "provider": "Optimum"},
    {"ssid": "TMHS-CELEBRATE", "venue": "hotel", "free": True, "provider": ""},
    {"ssid": "McDonalds Free WiFi", "venue": "restaurant", "free": True, "provider": "McDonald's"},
    {"ssid": "Starbucks WiFi", "venue": "cafe", "free": True, "provider": "Starbucks"},
    {"ssid": "Panera", "venue": "restaurant", "free": True, "provider": "Panera Bread"},
    {"ssid": "Barnes & Noble WiFi", "venue": "bookstore", "free": True, "provider": "B&N"},
    {"ssid": "LibraryWiFi", "venue": "library", "free": True, "provider": ""},
    {"ssid": "AirportWiFi", "venue": "airport", "free": True, "provider": ""},
    {"ssid": "JetBlue_Free_WiFi", "venue": "airport", "free": True, "provider": "JetBlue"},
    {"ssid": "Google Starbucks", "venue": "cafe", "free": True, "provider": "Google"},
    {"ssid": "LinkNYC Free Wi-Fi", "venue": "municipal", "free": True, "provider": "NYC"},
    {"ssid": "_The Cloud", "venue": "public", "free": True, "provider": "The Cloud"},
    {"ssid": "BTWiFi", "venue": "isp_hotspot", "free": False, "provider": "BT"},
    {"ssid": "FON_WIFI", "venue": "community", "free": False, "provider": "Fon"},
    {"ssid": "WAYPORT", "venue": "hotel", "free": False, "provider": "AT&T"},
]


class OpenWiFi:
    """Open WiFi network database search.

    Identifies and catalogs open/public WiFi networks from known
    SSID patterns and external databases.

    Usage::

        openwifi = OpenWiFi()
        result = openwifi.search_area(latitude=40.7128, longitude=-74.0060, radius_km=1.0)
        for network in result.networks:
            if network.is_free:
                print(f"Free WiFi: {network.ssid} at {network.venue_name}")
    """

    # Open WiFi database URL (placeholder for actual API)
    OPENWIFI_API_URL = "https://api.openwifimap.net/v1"

    def __init__(
        self,
        api_key: str = "",
        timeout: int = 15,
        cache_duration: int = 7200,
    ) -> None:
        """Initialize the OpenWiFi client.

        Args:
            api_key: API key for external databases.
            timeout: Request timeout in seconds.
            cache_duration: Cache duration in seconds.
        """
        self.api_key = api_key
        self.timeout = timeout
        self.cache_duration = cache_duration
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._local_db: List[OpenWiFiNetwork] = self._build_local_db()
        logger.info("OpenWiFi initialized with %d local entries", len(self._local_db))

    def search_area(
        self,
        latitude: float,
        longitude: float,
        radius_km: float = 1.0,
        free_only: bool = False,
        venue_type: str = "",
    ) -> OpenWiFiSearchResult:
        """Search for open WiFi networks in a geographic area.

        Args:
            latitude: Center latitude.
            longitude: Center longitude.
            radius_km: Search radius in kilometers.
            free_only: Only return free networks.
            venue_type: Filter by venue type.

        Returns:
            OpenWiFiSearchResult with matching networks.
        """
        start_time = time.time()
        matching: List[OpenWiFiNetwork] = []

        for network in self._local_db:
            if network.latitude == 0.0 and network.longitude == 0.0:
                continue

            distance = self._haversine_distance(
                latitude, longitude,
                network.latitude, network.longitude,
            )

            if distance <= radius_km:
                if free_only and not network.is_free:
                    continue
                if venue_type and network.venue_type != venue_type:
                    continue
                matching.append(network)

        # Sort by distance
        matching.sort(
            key=lambda n: self._haversine_distance(
                latitude, longitude, n.latitude, n.longitude
            )
        )

        return OpenWiFiSearchResult(
            query=f"area:{latitude},{longitude}:{radius_km}km",
            total_results=len(matching),
            networks=matching,
            search_timestamp=start_time,
        )

    def search_ssid(self, ssid: str) -> OpenWiFiSearchResult:
        """Search for open WiFi networks by SSID pattern.

        Args:
            ssid: SSID or partial SSID to search for.

        Returns:
            OpenWiFiSearchResult with matching networks.
        """
        start_time = time.time()
        matching: List[OpenWiFiNetwork] = []
        ssid_lower = ssid.lower()

        # Check known patterns
        for pattern in OPEN_WIFI_SSID_PATTERNS:
            if ssid_lower in pattern["ssid"].lower() or pattern["ssid"].lower() in ssid_lower:
                matching.append(OpenWiFiNetwork(
                    ssid=pattern["ssid"],
                    venue_type=pattern["venue"],
                    is_free=pattern["free"],
                    source="known_pattern",
                ))

        # Check local database
        for network in self._local_db:
            if ssid_lower in network.ssid.lower():
                if not any(n.ssid == network.ssid for n in matching):
                    matching.append(network)

        return OpenWiFiSearchResult(
            query=ssid,
            total_results=len(matching),
            networks=matching,
            search_timestamp=start_time,
        )

    def identify_open_network(
        self,
        ssid: str,
        encryption: str = "",
    ) -> Dict[str, Any]:
        """Identify if a network is a known open WiFi network.

        Args:
            ssid: Network SSID.
            encryption: Encryption type string.

        Returns:
            Dictionary with identification results.
        """
        result: Dict[str, Any] = {
            "ssid": ssid,
            "is_open": encryption.lower() in ("open", "", "none") if encryption else False,
            "is_known_open_network": False,
            "provider": "",
            "venue_type": "",
            "is_free": False,
            "requires_captive_portal": False,
        }

        ssid_lower = ssid.lower().strip()

        for pattern in OPEN_WIFI_SSID_PATTERNS:
            if ssid_lower == pattern["ssid"].lower() or ssid_lower.startswith(pattern["ssid"].lower()):
                result["is_known_open_network"] = True
                result["provider"] = pattern.get("provider", "")
                result["venue_type"] = pattern.get("venue", "")
                result["is_free"] = pattern.get("free", False)
                result["requires_captive_portal"] = True
                break

        # Common open WiFi patterns
        open_indicators = [
            "free", "wifi", "wireless", "open", "guest", "public",
            "visitor", "lobby", "cafe", "hotel", "airport", "library",
        ]
        for indicator in open_indicators:
            if indicator in ssid_lower and not result["is_known_open_network"]:
                result["is_open"] = True
                result["is_known_open_network"] = False
                break

        return result

    def assess_safety(
        self,
        ssid: str,
        encryption: str = "",
        bssid: str = "",
    ) -> Dict[str, Any]:
        """Assess the safety of connecting to an open WiFi network.

        Args:
            ssid: Network SSID.
            encryption: Encryption type.
            bssid: Network BSSID.

        Returns:
            Dictionary with safety assessment.
        """
        assessment: Dict[str, Any] = {
            "ssid": ssid,
            "safe_to_connect": False,
            "risk_level": "high",
            "risks": [],
            "recommendations": [],
        }

        is_open = encryption.lower() in ("open", "", "none") if encryption else True
        id_result = self.identify_open_network(ssid, encryption)

        if is_open or id_result["is_open"]:
            assessment["risks"].append(
                "No encryption - all traffic is visible to anyone on the same network."
            )
            assessment["risks"].append(
                "Potential for evil twin attack - an attacker can clone this SSID."
            )

            if id_result["requires_captive_portal"]:
                assessment["risks"].append(
                    "Captive portal may collect personal information or serve malicious content."
                )

            if id_result["is_known_open_network"]:
                assessment["risk_level"] = "medium"
                assessment["recommendations"].append(
                    "Use a VPN to encrypt all traffic over this open network."
                )
                assessment["recommendations"].append(
                    "Avoid accessing sensitive accounts (banking, email) without VPN."
                )
                assessment["recommendations"].append(
                    "Verify the network is legitimate and not an evil twin."
                )
            else:
                assessment["risk_level"] = "high"
                assessment["risks"].append(
                    "Unknown open network - could be a rogue AP designed to capture traffic."
                )
                assessment["recommendations"].append(
                    "Do not connect to unknown open networks without a VPN."
                )
        else:
            assessment["safe_to_connect"] = True
            assessment["risk_level"] = "low"

        if assessment["risk_level"] in ("low", "medium") and id_result["is_known_open_network"]:
            assessment["safe_to_connect"] = True

        assessment["recommendations"].append(
            "Always use HTTPS websites and verify SSL certificates."
        )

        return assessment

    def _build_local_db(self) -> List[OpenWiFiNetwork]:
        """Build a local database of known open WiFi networks."""
        db: List[OpenWiFiNetwork] = []

        for pattern in OPEN_WIFI_SSID_PATTERNS:
            db.append(OpenWiFiNetwork(
                ssid=pattern["ssid"],
                venue_type=pattern.get("venue", ""),
                is_free=pattern.get("free", True),
                has_captive_portal=True,
                source="known_pattern",
            ))

        return db

    @staticmethod
    def _haversine_distance(
        lat1: float, lon1: float, lat2: float, lon2: float
    ) -> float:
        """Calculate haversine distance between two coordinates in km."""
        R = 6371.0  # Earth's radius in km
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = (
            math.sin(dlat / 2) ** 2
            + math.cos(math.radians(lat1))
            * math.cos(math.radians(lat2))
            * math.sin(dlon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c

    def quick_check(self, ssid: str) -> bool:
        """Quick check if an SSID is a known open WiFi network.

        Args:
            ssid: SSID to check.

        Returns:
            True if the SSID matches a known open network pattern.
        """
        result = self.identify_open_network(ssid)
        return result["is_known_open_network"] or result["is_open"]
