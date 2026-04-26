"""Router fingerprint identification from signal characteristics, SSID patterns, and OUI.

Analyzes access point metadata to determine the likely router model,
manufacturer, firmware version, and known vulnerabilities based on
signal characteristics, SSID naming conventions, OUI vendor lookup,
and beacon frame information elements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from wifi_aio.data.oui_database import OUIDatabase
from wifi_aio.data.router_defaults import ROUTER_DEFAULTS
from wifi_aio.exceptions import OSINTError


# SSID pattern -> router model / manufacturer mapping
_SSID_PATTERNS: Dict[str, Dict] = {
    "TP-LINK_": {"vendor": "TP-Link", "model_family": "Archer/WR Series", "default_security": "WPA2-PSK"},
    "TP-LINK ": {"vendor": "TP-Link", "model_family": "Archer/WR Series", "default_security": "WPA2-PSK"},
    "Deco_": {"vendor": "TP-Link", "model_family": "Deco Mesh", "default_security": "WPA2-PSK"},
    "NETGEAR": {"vendor": "Netgear", "model_family": "Nighthawk/R Series", "default_security": "WPA2-PSK"},
    "NETGEAR-": {"vendor": "Netgear", "model_family": "Nighthawk/R Series", "default_security": "WPA2-PSK"},
    "ORBI": {"vendor": "Netgear", "model_family": "Orbi Mesh", "default_security": "WPA2-PSK"},
    "dlink-": {"vendor": "D-Link", "model_family": "DIR Series", "default_security": "WPA2-PSK"},
    "D-Link": {"vendor": "D-Link", "model_family": "DIR Series", "default_security": "WPA2-PSK"},
    "COVR-": {"vendor": "D-Link", "model_family": "COVR Mesh", "default_security": "WPA2-PSK"},
    "linksys": {"vendor": "Linksys", "model_family": "WRT/EA Series", "default_security": "WPA2-PSK"},
    "Linksys": {"vendor": "Linksys", "model_family": "WRT/EA Series", "default_security": "WPA2-PSK"},
    "ASUS_": {"vendor": "ASUS", "model_family": "RT Series", "default_security": "WPA2-PSK"},
    "ZenWiFi": {"vendor": "ASUS", "model_family": "ZenWiFi Mesh", "default_security": "WPA2-PSK"},
    "HUAWEI-": {"vendor": "Huawei", "model_family": "HG/WS Series", "default_security": "WPA2-PSK"},
    "HUAWEI ": {"vendor": "Huawei", "model_family": "HG/WS Series", "default_security": "WPA2-PSK"},
    "Xiaomi_": {"vendor": "Xiaomi", "model_family": "Mi Router Series", "default_security": "WPA2-PSK"},
    "MikroTik": {"vendor": "MikroTik", "model_family": "hAP/RB Series", "default_security": "Open/WPA2"},
    "Ubiquiti": {"vendor": "Ubiquiti", "model_family": "UniFi Series", "default_security": "WPA2-PSK"},
    "AmpliFi": {"vendor": "Ubiquiti", "model_family": "AmpliFi Mesh", "default_security": "WPA2-PSK"},
    "ZTE_": {"vendor": "ZTE", "model_family": "F Series", "default_security": "WPA2-PSK"},
    "Tenda_": {"vendor": "Tenda", "model_family": "AC/F Series", "default_security": "WPA2-PSK"},
    "Ruckus": {"vendor": "Ruckus", "model_family": "R Series (Enterprise)", "default_security": "WPA2-Enterprise"},
    "Aruba": {"vendor": "Aruba/HPE", "model_family": "AP Series (Enterprise)", "default_security": "WPA2-Enterprise"},
    "Fortinet": {"vendor": "Fortinet", "model_family": "FortiAP Series", "default_security": "WPA2-Enterprise"},
    "DIRECT-": {"vendor": "Various", "model_family": "WiFi Direct", "default_security": "WPA2-PSK"},
    "AndroidAP": {"vendor": "Various", "model_family": "Mobile Hotspot", "default_security": "WPA2-PSK"},
    "iPhone": {"vendor": "Apple", "model_family": "iOS Hotspot", "default_security": "WPA2-PSK"},
    "FRITZ!Box": {"vendor": "AVM", "model_family": "FRITZ!Box Series", "default_security": "WPA2-PSK"},
    "SFR_": {"vendor": "SFR/Altice", "model_family": "ISP Router", "default_security": "WPA2-PSK"},
    "Livebox-": {"vendor": "Orange SA", "model_family": "Livebox Series", "default_security": "WPA2-PSK"},
    "Bbox-": {"vendor": "Bouygues Telecom", "model_family": "Bbox Series", "default_security": "WPA2-PSK"},
    "Freebox-": {"vendor": "Free SAS", "model_family": "Freebox Series", "default_security": "WPA2-PSK"},
    "VM": {"vendor": "Virgin Media", "model_family": "Hub Series", "default_security": "WPA2-PSK"},
    "SKY": {"vendor": "Sky Broadband", "model_family": "Sky Hub", "default_security": "WPA2-PSK"},
    "PlusnetHub": {"vendor": "Plusnet", "model_family": "Hub Series", "default_security": "WPA2-PSK"},
    "BTHub": {"vendor": "BT Group", "model_family": "Smart Hub Series", "default_security": "WPA2-PSK"},
    "EE-Smart-Hub": {"vendor": "EE", "model_family": "Smart Hub", "default_security": "WPA2-PSK"},
    "Vodafone-": {"vendor": "Vodafone", "model_family": "Broadband Router", "default_security": "WPA2-PSK"},
    "SuperHub": {"vendor": "Virgin Media", "model_family": "Super Hub Series", "default_security": "WPA2-PSK"},
    "HomeHub": {"vendor": "BT Group", "model_family": "Home Hub Series", "default_security": "WPA2-PSK"},
}

# OUI -> router model family mapping for common ISP-issued routers
_OUI_ROUTOR_MAP: Dict[str, Dict] = {
    "00:27:19": {"vendor": "TP-Link", "common_models": ["WR841N", "WR940N", "Archer C20"]},
    "50:C7:BF": {"vendor": "TP-Link", "common_models": ["Archer C7", "Archer C9", "Archer A7"]},
    "60:32:B1": {"vendor": "TP-Link", "common_models": ["Archer C1200", "Archer C50"]},
    "00:09:5B": {"vendor": "Netgear", "common_models": ["WNR2000", "WNDR3700"]},
    "60:38:E0": {"vendor": "Netgear", "common_models": ["R7000", "R8000", "R6700"]},
    "9C:3D:CF": {"vendor": "Netgear", "common_models": ["R7000P", "Orbi RBK50"]},
    "00:05:5D": {"vendor": "D-Link", "common_models": ["DIR-615", "DIR-825"]},
    "84:C9:B2": {"vendor": "D-Link", "common_models": ["DIR-868L", "DIR-882"]},
    "00:14:BF": {"vendor": "Linksys", "common_models": ["WRT54G", "E1200"]},
    "30:5A:3A": {"vendor": "Linksys", "common_models": ["WRT1900AC", "EA7500"]},
    "04:D4:C4": {"vendor": "ASUS", "common_models": ["RT-AC68U", "RT-AC88U"]},
    "60:45:CB": {"vendor": "ASUS", "common_models": ["RT-AX88U", "RT-AX92U"]},
    "00:1A:2B": {"vendor": "Huawei", "common_models": ["HG532e", "WS5200"]},
    "3C:FA:43": {"vendor": "Huawei", "common_models": ["AX3 Pro", "B525"]},
    "28:E3:1F": {"vendor": "Xiaomi", "common_models": ["Mi Router 4A", "AX3600"]},
    "00:0C:42": {"vendor": "MikroTik", "common_models": ["hAP ac2", "RB4011"]},
    "00:15:6D": {"vendor": "Ubiquiti", "common_models": ["UniFi AP AC Pro", "EdgeRouter X"]},
    "00:26:5E": {"vendor": "ZTE", "common_models": ["F660", "F670L"]},
    "00:0E:E8": {"vendor": "Tenda", "common_models": ["AC10U", "AC15"]},
}

# Beacon interval signatures (unusual beacon intervals can indicate specific router models)
_BEACON_SIGNATURES: Dict[int, Dict] = {
    25: {"vendor": "MikroTik", "note": "MikroTik default beacon interval"},
    50: {"vendor": "Ubiquiti", "note": "Ubiquiti UniFi default beacon interval"},
    100: {"vendor": "Generic", "note": "Standard 802.11 beacon interval (most routers)"},
    1000: {"vendor": "Enterprise", "note": "Long beacon interval (power saving / enterprise)"},
}

# WPS manufacturer and model name heuristics
_WPS_DEVICE_TYPE_MAP: Dict[str, Dict] = {
    "TP-LINK": {"vendor": "TP-Link", "models": ["Archer C7", "WR841N"]},
    "NETGEAR": {"vendor": "Netgear", "models": ["R7000", "WNDR4300"]},
    "D-Link": {"vendor": "D-Link", "models": ["DIR-825", "DIR-615"]},
    "Cisco": {"vendor": "Cisco", "models": ["Linksys E1000", "RV340W"]},
    "ASUS": {"vendor": "ASUS", "models": ["RT-AC68U", "RT-N66U"]},
    "Huawei": {"vendor": "Huawei", "models": ["HG532e", "WS5200"]},
    "Xiaomi": {"vendor": "Xiaomi", "models": ["Mi Router 4A", "AX3600"]},
    "Ruckus": {"vendor": "Ruckus", "models": ["R510", "R710"]},
    "Aruba": {"vendor": "Aruba/HPE", "models": ["AP-315", "AP-515"]},
    "Shenzhen": {"vendor": "OEM (Shenzhen)", "models": ["Generic Chinese Router"]},
}


@dataclass
class RouterFingerprintResult:
    """Result of router fingerprinting analysis."""
    vendor: str = ""
    model_family: str = ""
    likely_models: List[str] = field(default_factory=list)
    oui: str = ""
    confidence: float = 0.0
    ssid_pattern_match: str = ""
    beacon_interval_note: str = ""
    default_credentials: Dict[str, str] = field(default_factory=dict)
    default_security: str = ""
    is_isp_issued: bool = False
    is_enterprise: bool = False
    known_vulnerabilities: List[str] = field(default_factory=list)
    firmware_hints: List[str] = field(default_factory=list)


class RouterFingerprint:
    """Fingerprints router models from AP signal characteristics and metadata.

    Uses a combination of OUI vendor lookup, SSID naming pattern analysis,
    beacon interval signatures, WPS information, and encryption suite
    detection to identify the likely router model and its characteristics.
    """

    def __init__(self):
        self._oui_db = OUIDatabase()

    def fingerprint(
        self,
        bssid: str,
        ssid: str = "",
        channel: int = 0,
        signal_dbm: int = 0,
        encryption: str = "",
        wps: bool = False,
        wps_device_name: str = "",
        beacon_interval: int = 100,
        pmf: str = "disabled",
    ) -> RouterFingerprintResult:
        """Fingerprint a router from access point characteristics.

        Args:
            bssid: MAC address of the access point.
            ssid: SSID of the network.
            channel: Channel number.
            signal_dbm: Signal strength in dBm.
            encryption: Encryption type string.
            wps: Whether WPS is enabled.
            wps_device_name: WPS manufacturer/model name from probe response.
            beacon_interval: Beacon interval in TUs.
            pmf: PMF status ("disabled", "capable", "required").

        Returns:
            RouterFingerprintResult with identification details.

        Raises:
            OSINTError: If the BSSID format is invalid.
        """
        if not bssid:
            raise OSINTError("BSSID is required for router fingerprinting")

        bssid_normalized = bssid.strip().upper().replace("-", ":")
        if len(bssid_normalized.split(":")) != 6:
            raise OSINTError(f"Invalid BSSID format: {bssid}")

        oui_prefix = ":".join(bssid_normalized.split(":")[:3])
        vendor = self._oui_db.lookup(bssid) or ""

        result = RouterFingerprintResult(oui=oui_prefix)

        # Step 1: OUI-based identification
        oui_info = _OUI_ROUTOR_MAP.get(oui_prefix)
        if oui_info:
            result.vendor = oui_info.get("vendor", vendor)
            result.likely_models = oui_info.get("common_models", [])
            result.confidence = 0.7
        elif vendor:
            result.vendor = vendor
            result.confidence = 0.4
            # Try to match vendor against router defaults
            for model_name in ROUTER_DEFAULTS:
                if vendor.lower() in model_name.lower():
                    result.likely_models.append(model_name)
            if result.likely_models:
                result.confidence = 0.5

        # Step 2: SSID pattern matching
        ssid_match = self._match_ssid_pattern(ssid)
        if ssid_match:
            result.ssid_pattern_match = ssid_match.get("model_family", "")
            result.default_security = ssid_match.get("default_security", "")
            if not result.vendor:
                result.vendor = ssid_match.get("vendor", "")
                result.confidence = 0.6
            elif result.vendor == ssid_match.get("vendor", ""):
                result.confidence = min(1.0, result.confidence + 0.15)
            else:
                result.confidence = max(0.3, result.confidence - 0.1)

            # Check if it's ISP-issued
            isp_indicators = [
                "ISP Router", "Hub Series", "Livebox", "Super Hub",
                "Smart Hub", "Home Hub", "Bbox", "Freebox",
            ]
            for indicator in isp_indicators:
                if indicator in result.ssid_pattern_match:
                    result.is_isp_issued = True
                    break

        # Step 3: WPS device name matching
        if wps and wps_device_name:
            wps_match = self._match_wps_device(wps_device_name)
            if wps_match:
                if not result.vendor:
                    result.vendor = wps_match.get("vendor", "")
                    result.confidence = 0.75
                if wps_match.get("models"):
                    for model in wps_match["models"]:
                        if model not in result.likely_models:
                            result.likely_models.append(model)

        # Step 4: Beacon interval signature
        beacon_info = _BEACON_SIGNATURES.get(beacon_interval)
        if beacon_info:
            result.beacon_interval_note = beacon_info.get("note", "")
            if beacon_info.get("vendor") == result.vendor:
                result.confidence = min(1.0, result.confidence + 0.05)

        # Step 5: Enterprise detection
        enterprise_vendors = ["Cisco", "Aruba", "Ruckus", "Fortinet", "Juniper", "Mist"]
        if any(ev in result.vendor for ev in enterprise_vendors):
            result.is_enterprise = True
        if pmf == "required" or "Enterprise" in encryption:
            result.is_enterprise = True

        # Step 6: Default credentials lookup
        for model in result.likely_models[:3]:
            defaults = ROUTER_DEFAULTS.get(model)
            if defaults:
                result.default_credentials = {
                    "username": defaults.get("username", ""),
                    "password": defaults.get("password", ""),
                }
                break

        # Step 7: Firmware hints based on characteristics
        result.firmware_hints = self._get_firmware_hints(
            result.vendor, encryption, wps, pmf, beacon_interval
        )

        # Step 8: Known vulnerability indicators
        result.known_vulnerabilities = self._get_known_vulns(
            result.vendor, encryption, wps, pmf
        )

        return result

    def fingerprint_batch(self, access_points: List[Dict]) -> List[RouterFingerprintResult]:
        """Fingerprint a batch of access points.

        Args:
            access_points: List of AP info dicts.

        Returns:
            List of RouterFingerprintResult instances.
        """
        results = []
        for ap in access_points:
            try:
                results.append(self.fingerprint(
                    bssid=ap.get("bssid", ""),
                    ssid=ap.get("ssid", ""),
                    channel=ap.get("channel", 0),
                    signal_dbm=ap.get("signal_dbm", 0),
                    encryption=ap.get("encryption", ""),
                    wps=ap.get("wps", False),
                    wps_device_name=ap.get("wps_device_name", ""),
                    beacon_interval=ap.get("beacon_interval", 100),
                    pmf=ap.get("pmf", "disabled"),
                ))
            except OSINTError:
                results.append(RouterFingerprintResult())
        return results

    @staticmethod
    def _match_ssid_pattern(ssid: str) -> Optional[Dict]:
        """Match SSID against known patterns.

        Args:
            ssid: SSID string to match.

        Returns:
            Pattern info dict if matched, None otherwise.
        """
        if not ssid:
            return None
        ssid_upper = ssid.upper()
        for pattern, info in _SSID_PATTERNS.items():
            if ssid_upper.startswith(pattern.upper()) or pattern.upper() in ssid_upper:
                return info
        return None

    @staticmethod
    def _match_wps_device(device_name: str) -> Optional[Dict]:
        """Match WPS device name against known manufacturers.

        Args:
            device_name: WPS manufacturer/model name.

        Returns:
            Device info dict if matched, None otherwise.
        """
        if not device_name:
            return None
        name_upper = device_name.upper()
        for key, info in _WPS_DEVICE_TYPE_MAP.items():
            if key.upper() in name_upper:
                return info
        return None

    @staticmethod
    def _get_firmware_hints(
        vendor: str,
        encryption: str,
        wps: bool,
        pmf: str,
        beacon_interval: int,
    ) -> List[str]:
        """Generate firmware version hints based on observed characteristics.

        Args:
            vendor: Router vendor name.
            encryption: Encryption type.
            wps: Whether WPS is enabled.
            pmf: PMF status.
            beacon_interval: Beacon interval.

        Returns:
            List of firmware hint strings.
        """
        hints = []
        vendor_lower = vendor.lower()

        # WPA3 / PMF hints
        if "SAE" in encryption or "WPA3" in encryption:
            hints.append("Firmware supports WPA3 (relatively recent)")
        if pmf == "required":
            hints.append("PMF required - WPA3-capable firmware")

        # WPS hints
        if wps:
            if "tp-link" in vendor_lower:
                hints.append("WPS active - may be vulnerable to Pixie Dust (older firmware)")
            elif "d-link" in vendor_lower:
                hints.append("WPS active - known PIN vulnerabilities in older DIR models")
            elif "netgear" in vendor_lower:
                hints.append("WPS active - check for PIN brute-force vulnerability")

        # Encryption hints
        if "WEP" in encryption:
            hints.append("WEP in use - extremely outdated firmware")
        elif "TKIP" in encryption:
            hints.append("TKIP cipher - firmware likely pre-2014")
        elif "GCMP" in encryption:
            hints.append("GCMP cipher - WPA3-capable firmware (2019+)")

        # Beacon interval hints
        if beacon_interval != 100:
            hints.append(f"Non-standard beacon interval ({beacon_interval} TU) - may indicate custom firmware")

        return hints

    @staticmethod
    def _get_known_vulns(
        vendor: str,
        encryption: str,
        wps: bool,
        pmf: str,
    ) -> List[str]:
        """Check for known vulnerabilities based on router characteristics.

        Args:
            vendor: Router vendor name.
            encryption: Encryption type.
            wps: Whether WPS is enabled.
            pmf: PMF status.

        Returns:
            List of known vulnerability strings.
        """
        vulns = []
        vendor_lower = vendor.lower()

        # Encryption-based vulnerabilities
        if "WEP" in encryption:
            vulns.append("WEP encryption - trivially broken (FMS/PTW attack)")
        if "TKIP" in encryption:
            vulns.append("TKIP cipher - vulnerable to Michael attack and Beck-Tews attack")

        # WPS vulnerabilities
        if wps:
            vulns.append("WPS enabled - potential Pixie Dust / PIN brute-force attack")
            if "tp-link" in vendor_lower:
                vulns.append("TP-Link WPS - known vulnerable implementations in older models")
            elif "d-link" in vendor_lower:
                vulns.append("D-Link WPS - multiple models vulnerable to online PIN attacks")

        # PMF vulnerabilities
        if pmf != "required":
            if "WPA2" in encryption or "WPA3" in encryption:
                vulns.append("PMF not required - vulnerable to deauthentication attacks")

        # KRACK
        if "WPA2" in encryption and "SAE" not in encryption:
            vulns.append("WPA2-PSK without WPA3 - potentially vulnerable to KRACK if unpatched")

        # Vendor-specific vulnerabilities
        if "huawei" in vendor_lower:
            vulns.append("Huawei routers - known for default credential issues and command injection")
        elif "d-link" in vendor_lower:
            vulns.append("D-Link routers - multiple CVEs for command injection and authentication bypass")
        elif "tp-link" in vendor_lower:
            vulns.append("TP-Link routers - some models have known command injection and path traversal CVEs")
        elif "cisco" in vendor_lower:
            vulns.append("Cisco devices - check for CVE-2017-13080 (KRACK) and firmware-specific issues")

        return vulns
