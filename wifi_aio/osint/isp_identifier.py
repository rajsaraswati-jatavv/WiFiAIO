"""ISP identification from BSSID/OUI prefix lookup.

Identifies the Internet Service Provider from a BSSID by matching
the OUI prefix against a database of known ISP MAC address ranges,
SSID naming conventions, and public IP allocation data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from wifi_aio.data.oui_database import OUIDatabase
from wifi_aio.exceptions import OSINTError


# ISP OUI prefix mapping: OUI prefix -> ISP info
_ISP_OUI_MAP: Dict[str, Dict] = {
    # Major US ISPs
    "00:01:5C": {"isp": "Comcast Xfinity", "country": "US", "type": "cable"},
    "00:05:CA": {"isp": "Comcast Xfinity", "country": "US", "type": "cable"},
    "00:0C:86": {"isp": "Comcast Xfinity", "country": "US", "type": "cable"},
    "00:11:70": {"isp": "Comcast Xfinity", "country": "US", "type": "cable"},
    "00:13:F7": {"isp": "Comcast Xfinity", "country": "US", "type": "cable"},
    "00:17:F2": {"isp": "AT&T", "country": "US", "type": "dsl/fiber"},
    "00:18:41": {"isp": "AT&T", "country": "US", "type": "dsl/fiber"},
    "00:1C:1E": {"isp": "AT&T", "country": "US", "type": "dsl/fiber"},
    "00:1E:BE": {"isp": "AT&T", "country": "US", "type": "dsl/fiber"},
    "00:21:5A": {"isp": "AT&T", "country": "US", "type": "dsl/fiber"},
    "00:24:B2": {"isp": "Verizon FiOS", "country": "US", "type": "fiber"},
    "00:1F:90": {"isp": "Verizon FiOS", "country": "US", "type": "fiber"},
    "00:22:41": {"isp": "Verizon FiOS", "country": "US", "type": "fiber"},
    "00:26:62": {"isp": "Verizon FiOS", "country": "US", "type": "fiber"},
    "20:4E:7F": {"isp": "Cox Communications", "country": "US", "type": "cable"},
    "00:0E:7F": {"isp": "Cox Communications", "country": "US", "type": "cable"},
    "00:14:A1": {"isp": "Cox Communications", "country": "US", "type": "cable"},
    "00:16:32": {"isp": "Charter Spectrum", "country": "US", "type": "cable"},
    "00:1A:1E": {"isp": "Charter Spectrum", "country": "US", "type": "cable"},
    "00:23:DF": {"isp": "Charter Spectrum", "country": "US", "type": "cable"},
    # Major European ISPs
    "00:1E:69": {"isp": "Deutsche Telekom", "country": "DE", "type": "dsl/fiber"},
    "00:24:FE": {"isp": "Deutsche Telekom", "country": "DE", "type": "dsl/fiber"},
    "58:98:35": {"isp": "Deutsche Telekom", "country": "DE", "type": "dsl/fiber"},
    "00:1D:68": {"isp": "BT Group", "country": "GB", "type": "dsl/fiber"},
    "00:14:7F": {"isp": "BT Group", "country": "GB", "type": "dsl/fiber"},
    "44:65:0D": {"isp": "BT Group", "country": "GB", "type": "dsl/fiber"},
    "00:19:70": {"isp": "Orange SA", "country": "FR", "type": "dsl/fiber"},
    "00:0D:54": {"isp": "Orange SA", "country": "FR", "type": "dsl/fiber"},
    "50:7E:5D": {"isp": "Orange SA", "country": "FR", "type": "dsl/fiber"},
    "00:18:82": {"isp": "Telefonica", "country": "ES", "type": "dsl/fiber"},
    "00:15:99": {"isp": "Telefonica", "country": "ES", "type": "dsl/fiber"},
    "00:1C:C1": {"isp": "Vodafone", "country": "GB", "type": "dsl/fiber"},
    "00:1D:29": {"isp": "Vodafone", "country": "DE", "type": "cable"},
    "00:24:7C": {"isp": "Vodafone", "country": "DE", "type": "cable"},
    # Asian ISPs
    "00:03:2D": {"isp": "NTT Communications", "country": "JP", "type": "fiber"},
    "00:0C:5E": {"isp": "NTT Communications", "country": "JP", "type": "fiber"},
    "00:1B:03": {"isp": "SoftBank", "country": "JP", "type": "dsl/fiber"},
    "00:07:4F": {"isp": "KDDI", "country": "JP", "type": "dsl/fiber"},
    "00:0E:50": {"isp": "China Telecom", "country": "CN", "type": "dsl/fiber"},
    "00:18:82": {"isp": "China Telecom", "country": "CN", "type": "dsl/fiber"},
    "00:25:11": {"isp": "China Unicom", "country": "CN", "type": "dsl/fiber"},
    "00:1E:73": {"isp": "China Mobile", "country": "CN", "type": "dsl/fiber"},
    "00:1C:62": {"isp": "KT Corporation", "country": "KR", "type": "dsl/fiber"},
    "00:1B:97": {"isp": "SK Broadband", "country": "KR", "type": "dsl/fiber"},
    "00:12:BF": {"isp": "Airtel", "country": "IN", "type": "dsl/fiber"},
    "00:1E:58": {"isp": "Airtel", "country": "IN", "type": "dsl/fiber"},
    "00:1C:39": {"isp": "Jio", "country": "IN", "type": "fiber"},
    "00:25:22": {"isp": "BSNL", "country": "IN", "type": "dsl"},
    # Australian / Oceania
    "00:0C:84": {"isp": "Telstra", "country": "AU", "type": "dsl/fiber"},
    "00:15:F7": {"isp": "Telstra", "country": "AU", "type": "dsl/fiber"},
    "00:24:43": {"isp": "Optus", "country": "AU", "type": "cable/fiber"},
    # ISP-provided router SSID patterns
    "xfinitywifi": {"isp": "Comcast Xfinity", "country": "US", "type": "cable"},
    "ATT-WIFI": {"isp": "AT&T", "country": "US", "type": "dsl/fiber"},
    "FIOS-": {"isp": "Verizon FiOS", "country": "US", "type": "fiber"},
    "CoxWiFi": {"isp": "Cox Communications", "country": "US", "type": "cable"},
    "SpectrumSetup": {"isp": "Charter Spectrum", "country": "US", "type": "cable"},
    "Telekom_FON": {"isp": "Deutsche Telekom", "country": "DE", "type": "dsl/fiber"},
    "BTWifi": {"isp": "BT Group", "country": "GB", "type": "dsl/fiber"},
    "ORANGE-": {"isp": "Orange SA", "country": "FR", "type": "dsl/fiber"},
    "Movistar_": {"isp": "Telefonica", "country": "ES", "type": "dsl/fiber"},
    "VodafoneHotspot": {"isp": "Vodafone", "country": "GB", "type": "dsl/fiber"},
    "NTT-EAP": {"isp": "NTT Communications", "country": "JP", "type": "fiber"},
    "ChinaNet": {"isp": "China Telecom", "country": "CN", "type": "dsl/fiber"},
    "Airtel_": {"isp": "Airtel", "country": "IN", "type": "dsl/fiber"},
    "JioFi": {"isp": "Jio", "country": "IN", "type": "fiber"},
    "Telstra-Air": {"isp": "Telstra", "country": "AU", "type": "dsl/fiber"},
}


@dataclass
class ISPInfo:
    """ISP identification result."""
    isp_name: str = ""
    country: str = ""
    connection_type: str = ""
    confidence: float = 0.0
    source: str = ""  # "oui", "ssid", "both"
    vendor: str = ""
    oui: str = ""


class ISPIdentifier:
    """Identifies the ISP from BSSID/OUI prefix and SSID patterns.

    Uses a combination of OUI prefix matching, SSID naming convention
    analysis, and vendor/manufacturer correlation to determine the
    likely Internet Service Provider for a given access point.
    """

    def __init__(self):
        self._oui_db = OUIDatabase()
        self._isp_map = dict(_ISP_OUI_MAP)

    def identify(self, bssid: str, ssid: str = "") -> ISPInfo:
        """Identify the ISP from a BSSID and optional SSID.

        Args:
            bssid: MAC address of the access point.
            ssid: SSID of the access point (used for pattern matching).

        Returns:
            ISPInfo with identification results.

        Raises:
            OSINTError: If the BSSID format is invalid.
        """
        if not bssid:
            raise OSINTError("BSSID is required for ISP identification")

        bssid_normalized = bssid.strip().upper().replace("-", ":")
        if len(bssid_normalized.split(":")) != 6:
            raise OSINTError(f"Invalid BSSID format: {bssid}")

        oui_prefix = ":".join(bssid_normalized.split(":")[:3])

        # Try OUI-based lookup
        oui_result = self._lookup_by_oui(oui_prefix)

        # Try SSID-based lookup
        ssid_result = self._lookup_by_ssid(ssid) if ssid else None

        # Combine results
        if oui_result and ssid_result:
            # Both match - high confidence
            if oui_result.isp_name == ssid_result.isp_name:
                return ISPInfo(
                    isp_name=oui_result.isp_name,
                    country=oui_result.country or ssid_result.country,
                    connection_type=oui_result.connection_type or ssid_result.connection_type,
                    confidence=0.95,
                    source="both",
                    vendor=self._oui_db.lookup(bssid) or "",
                    oui=oui_prefix,
                )
            else:
                # Conflicting results - prefer OUI with lower confidence
                return ISPInfo(
                    isp_name=oui_result.isp_name,
                    country=oui_result.country,
                    connection_type=oui_result.connection_type,
                    confidence=0.6,
                    source="oui",
                    vendor=self._oui_db.lookup(bssid) or "",
                    oui=oui_prefix,
                )
        elif oui_result:
            return ISPInfo(
                isp_name=oui_result.isp_name,
                country=oui_result.country,
                connection_type=oui_result.connection_type,
                confidence=0.7,
                source="oui",
                vendor=self._oui_db.lookup(bssid) or "",
                oui=oui_prefix,
            )
        elif ssid_result:
            return ISPInfo(
                isp_name=ssid_result.isp_name,
                country=ssid_result.country,
                connection_type=ssid_result.connection_type,
                confidence=0.8,
                source="ssid",
                vendor=self._oui_db.lookup(bssid) or "",
                oui=oui_prefix,
            )
        else:
            # No ISP match - try vendor-based inference
            vendor = self._oui_db.lookup(bssid) or ""
            inferred_isp = self._infer_isp_from_vendor(vendor)
            return ISPInfo(
                isp_name=inferred_isp,
                country="",
                connection_type="",
                confidence=0.3 if inferred_isp else 0.0,
                source="vendor_inference" if inferred_isp else "unknown",
                vendor=vendor,
                oui=oui_prefix,
            )

    def identify_batch(self, access_points: List[Dict]) -> List[ISPInfo]:
        """Identify ISPs for a batch of access points.

        Args:
            access_points: List of dicts with 'bssid' and optional 'ssid' keys.

        Returns:
            List of ISPInfo results corresponding to each access point.
        """
        results = []
        for ap in access_points:
            bssid = ap.get("bssid", "")
            ssid = ap.get("ssid", "")
            try:
                results.append(self.identify(bssid, ssid))
            except OSINTError:
                results.append(ISPInfo(oui=":".join(bssid.split(":")[:3]) if bssid else ""))
        return results

    def get_known_isps(self, country: Optional[str] = None) -> List[Dict]:
        """Get a list of known ISPs, optionally filtered by country.

        Args:
            country: ISO country code filter (e.g., "US", "DE").

        Returns:
            List of ISP info dicts with name, country, and connection types.
        """
        isps = {}
        for key, info in self._isp_map.items():
            name = info.get("isp", "")
            if not name:
                continue
            if country and info.get("country") != country:
                continue
            if name not in isps:
                isps[name] = {
                    "name": name,
                    "country": info.get("country", ""),
                    "connection_types": set(),
                }
            if info.get("type"):
                isps[name]["connection_types"].add(info["type"])

        return [
            {**v, "connection_types": sorted(v["connection_types"])}
            for v in sorted(isps.values(), key=lambda x: x["name"])
        ]

    def _lookup_by_oui(self, oui_prefix: str) -> Optional[ISPInfo]:
        """Look up ISP by OUI prefix.

        Args:
            oui_prefix: OUI in XX:XX:XX format.

        Returns:
            ISPInfo if found, None otherwise.
        """
        info = self._isp_map.get(oui_prefix)
        if info:
            return ISPInfo(
                isp_name=info.get("isp", ""),
                country=info.get("country", ""),
                connection_type=info.get("type", ""),
                confidence=0.7,
                source="oui",
                oui=oui_prefix,
            )
        return None

    def _lookup_by_ssid(self, ssid: str) -> Optional[ISPInfo]:
        """Look up ISP by SSID naming pattern.

        Args:
            ssid: SSID string to match against known patterns.

        Returns:
            ISPInfo if a pattern matches, None otherwise.
        """
        ssid_upper = ssid.upper().strip()
        for pattern, info in self._isp_map.items():
            if not info.get("isp"):
                continue
            # Check if the pattern is a SSID pattern (contains letters, not just hex)
            if any(c.isalpha() for c in pattern):
                if ssid_upper.startswith(pattern.upper()) or pattern.upper() in ssid_upper:
                    return ISPInfo(
                        isp_name=info.get("isp", ""),
                        country=info.get("country", ""),
                        connection_type=info.get("type", ""),
                        confidence=0.8,
                        source="ssid",
                    )
        return None

    @staticmethod
    def _infer_isp_from_vendor(vendor: str) -> str:
        """Infer possible ISP from router vendor name.

        Some ISPs use vendor-specific router models exclusively.

        Args:
            vendor: Router vendor/manufacturer name.

        Returns:
            Inferred ISP name or empty string.
        """
        vendor_lower = vendor.lower()
        isp_vendor_map = {
            "arris": "Comcast Xfinity / Spectrum",
            "pace": "AT&T",
            "motorola": "Comcast Xfinity / Cox",
            "technicolor": "Various ISP",
            "sagemcom": "Various ISP",
            "hitron": "Comcast Xfinity / Cox",
            "ubee": "Comcast Xfinity / Spectrum",
            "cisco": "Various ISP (Enterprise)",
        }
        for vendor_keyword, isp_name in isp_vendor_map.items():
            if vendor_keyword in vendor_lower:
                return isp_name
        return ""
