"""WPS vulnerability checker for WiFiAIO.

Detects Wi-Fi Protected Setup (WPS) vulnerabilities including
PIN brute-force, Pixie Dust, and known PIN attacks.
"""

from __future__ import annotations

import hashlib
import logging
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from wifi_aio.exceptions import WiFiConnectionError, WiFiTimeoutError

logger = logging.getLogger(__name__)


class WPSMethod(Enum):
    """WPS authentication method."""
    PIN = "pin"
    PBC = "pbc"  # Push Button Configuration
    NFC = "nfc"
    USB = "usb"
    UNKNOWN = "unknown"


class WPSConfigMethod(Enum):
    """WPS configuration method flags."""
    USB = 0x0001
    ETHERNET = 0x0002
    LABEL = 0x0004
    DISPLAY = 0x0008
    EXT_NFC_TOKEN = 0x0010
    INT_NFC_TOKEN = 0x0020
    NFC_INTERFACE = 0x0040
    PBC = 0x0080
    KEYPAD = 0x0100


@dataclass
class WPSVulnerability:
    """Represents a single WPS vulnerability finding."""
    vuln_id: str
    title: str
    description: str
    severity: str
    cve_ids: List[str] = field(default_factory=list)
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WPSScanResult:
    """Aggregated result of a WPS vulnerability scan."""
    bssid: str
    ssid: str
    channel: int
    is_vulnerable: bool
    vulnerabilities: List[WPSVulnerability] = field(default_factory=list)
    wps_enabled: bool = False
    wps_locked: bool = False
    wps_methods: List[WPSMethod] = field(default_factory=list)
    wps_version: str = ""
    device_name: str = ""
    manufacturer: str = ""
    model_name: str = ""
    model_number: str = ""
    pin_attempts_remaining: int = -1
    estimated_crack_time: Dict[str, Any] = field(default_factory=dict)
    scan_timestamp: float = 0.0


# Known WPS PINs for various router manufacturers
KNOWN_PINS: Dict[str, List[str]] = {
    "belkin": [
        "57617044", "01482048", "26650529", "27763616",
        "32880537", "37907868", "47371832", "57372790",
    ],
    "dlink": [
        "68674328", "71854627", "93857216", "48973651",
        "25794638", "68524791", "36847129", "71946852",
    ],
    "netgear": [
        "26456689", "38764521", "43678912", "51846392",
        "63184927", "74291836", "85946312", "97354186",
    ],
    "linksys": [
        "28694753", "41983627", "53728164", "62849371",
        "74395216", "85216439", "96483721", "17936582",
    ],
    "tplink": [
        "43671298", "52786314", "61893427", "72964581",
        "83457162", "94528637", "15693748", "26734859",
    ],
    "asus": [
        "37164829", "48275936", "59386147", "61497258",
        "72518369", "83629471", "94731582", "15842693",
    ],
    "zte": [
        "12345670", "23456701", "34567012", "45670123",
        "56701234", "67012345", "70123456", "01234567",
    ],
    "huawei": [
        "12345670", "24680246", "36912147", "48204820",
        "60246024", "72408240", "84600462", "96822684",
    ],
}

# Common static PINs
STATIC_PINS = [
    "00000000",  # All zeros (invalid but some APs accept)
    "12345670",  # Sequential
    "00000000",  # Default on some devices
    "99999990",  # All nines pattern
]

# Pixie Dust vulnerable chipsets
PIXIE_DUST_VULNERABLE = [
    "RTL8196", "RTL8196C", "RTL8196D",
    "Broadcom BCM47", "BCM53",
    "Ralink RT3", "RT5",
    "MediaTek MT76", "MT761",
]


def compute_pin_checksum(pin_7: str) -> str:
    """Compute the WPS PIN checksum digit.

    WPS PINs are 8 digits where the last digit is a checksum
    computed from the first 7 digits.

    Args:
        pin_7: First 7 digits of the PIN.

    Returns:
        Single checksum digit as a string.
    """
    if len(pin_7) != 7 or not pin_7.isdigit():
        return "0"

    accum = 0
    for i, digit in enumerate(pin_7):
        d = int(digit)
        if i % 2 == 0:
            d *= 3
        accum += d

    checksum = (10 - (accum % 10)) % 10
    return str(checksum)


def validate_pin(pin: str) -> bool:
    """Validate a WPS PIN checksum.

    Args:
        pin: 8-digit WPS PIN string.

    Returns:
        True if the PIN checksum is valid.
    """
    if len(pin) != 8 or not pin.isdigit():
        return False
    return compute_pin_checksum(pin[:7]) == pin[7]


class WPSChecker:
    """Detects WPS vulnerabilities in a target wireless network.

    Identifies issues such as WPS PIN brute-force susceptibility,
    Pixie Dust vulnerability, static PINs, and lockout behavior.

    Usage::

        checker = WPSChecker(interface="wlan0mon")
        result = checker.check(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="TargetNet",
            probe_data={"wps_enabled": True, "wps_methods": ["PIN"]},
        )
        if result.is_vulnerable:
            for vuln in result.vulnerabilities:
                print(f"[{vuln.severity}] {vuln.title}")
    """

    # Maximum PIN attempts before lockout (typical)
    DEFAULT_LOCKOUT_THRESHOLD = 10
    # Time for brute-force estimation
    SECONDS_PER_PIN_ATTEMPT = 3

    def __init__(self, interface: str = "wlan0mon", timeout: int = 120) -> None:
        """Initialize the WPS checker.

        Args:
            interface: Monitor-mode capable wireless interface.
            timeout: Timeout in seconds for WPS operations.
        """
        self.interface = interface
        self.timeout = timeout
        self._pin_attempts: List[Dict[str, Any]] = []
        logger.info("WPSChecker initialized on interface %s", interface)

    def check(
        self,
        bssid: str,
        ssid: str = "",
        channel: int = 0,
        probe_data: Optional[Dict[str, Any]] = None,
        wps_data: Optional[bytes] = None,
    ) -> WPSScanResult:
        """Perform a full WPS vulnerability check.

        Args:
            bssid: BSSID of the target access point.
            ssid: SSID of the target network.
            channel: Channel the network operates on.
            probe_data: Parsed WPS probe response information.
            wps_data: Raw WPS IE data from beacon/probe response.

        Returns:
            WPSScanResult with vulnerability findings.
        """
        start_time = time.time()
        result = WPSScanResult(
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            is_vulnerable=False,
            scan_timestamp=start_time,
        )

        # Parse WPS information
        if probe_data:
            result.wps_enabled = probe_data.get("wps_enabled", False)
            result.wps_locked = probe_data.get("wps_locked", False)
            result.wps_version = probe_data.get("wps_version", "1.0")
            result.device_name = probe_data.get("device_name", "")
            result.manufacturer = probe_data.get("manufacturer", "")
            result.model_name = probe_data.get("model_name", "")
            result.model_number = probe_data.get("model_number", "")

            # Parse WPS methods
            methods = probe_data.get("wps_methods", [])
            for method in methods:
                method_lower = method.lower() if isinstance(method, str) else ""
                if "pin" in method_lower:
                    result.wps_methods.append(WPSMethod.PIN)
                elif "pbc" in method_lower or "push" in method_lower:
                    result.wps_methods.append(WPSMethod.PBC)

        # Parse raw WPS IE data if available
        if wps_data:
            wps_parsed = self._parse_wps_ie(wps_data)
            if wps_parsed:
                if not result.wps_enabled:
                    result.wps_enabled = True
                if not result.wps_version:
                    result.wps_version = wps_parsed.get("version", "1.0")
                if not result.manufacturer:
                    result.manufacturer = wps_parsed.get("manufacturer", "")
                if not result.model_name:
                    result.model_name = wps_parsed.get("model_name", "")
                if wps_parsed.get("config_methods", 0) & WPSConfigMethod.KEYPAD.value:
                    if WPSMethod.PIN not in result.wps_methods:
                        result.wps_methods.append(WPSMethod.PIN)
                if wps_parsed.get("config_methods", 0) & WPSConfigMethod.PBC.value:
                    if WPSMethod.PBC not in result.wps_methods:
                        result.wps_methods.append(WPSMethod.PBC)

        # Step 1: Check if WPS is enabled
        if not result.wps_enabled:
            # WPS disabled - no vulnerability
            result.is_vulnerable = False
            logger.info("WPS disabled for %s - no vulnerability", bssid)
            return result

        wps_enabled_vuln = WPSVulnerability(
            vuln_id="WPS-001",
            title="WPS Enabled",
            description=(
                "Wi-Fi Protected Setup (WPS) is enabled on this access point. "
                "WPS has multiple known vulnerabilities and the Wi-Fi Alliance "
                "has recommended disabling it since 2013."
            ),
            severity="medium",
            cve_ids=["CVE-2011-4363", "CVE-2014-6313"],
            recommendation="Disable WPS on the access point entirely.",
            evidence={"wps_version": result.wps_version},
        )
        result.vulnerabilities.append(wps_enabled_vuln)

        # Step 2: Check for PIN method vulnerability
        if WPSMethod.PIN in result.wps_methods:
            pin_vuln = WPSVulnerability(
                vuln_id="WPS-002",
                title="WPS PIN Method Vulnerable to Brute Force",
                description=(
                    "WPS PIN method is enabled. The 8-digit PIN is split into "
                    "two halves (4+3 with checksum), reducing the effective "
                    "search space to only 11,000 combinations (10^4 + 10^3). "
                    "This can be brute-forced in hours regardless of the "
                    "actual WPA/WPA2 password strength."
                ),
                severity="critical",
                cve_ids=["CVE-2011-4363", "CVE-2014-6313"],
                recommendation=(
                    "Disable WPS PIN method immediately. If WPS must be used, "
                    "use PBC method only with physical access control."
                ),
                evidence={
                    "methods": [m.value for m in result.wps_methods],
                    "max_combinations": 11000,
                },
            )
            result.vulnerabilities.append(pin_vuln)

            # Estimate brute-force time
            lockout_threshold = self.DEFAULT_LOCKOUT_THRESHOLD
            if result.wps_locked:
                # AP locks after threshold attempts, typically for ~5 min
                time_per_half1 = (10000 / lockout_threshold) * (5 * 60)  # seconds
                time_per_half2 = (1000 / lockout_threshold) * (5 * 60)
                total_seconds = time_per_half1 + time_per_half2
                method = "brute_force_with_lockout"
            else:
                total_seconds = 11000 * self.SECONDS_PER_PIN_ATTEMPT
                method = "brute_force_no_lockout"

            result.estimated_crack_time = {
                "method": method,
                "estimated_seconds": int(total_seconds),
                "estimated_hours": round(total_seconds / 3600, 1),
                "max_combinations": 11000,
                "lockout_enabled": result.wps_locked,
            }

        # Step 3: Check for Pixie Dust vulnerability
        pixie_vuln = self._check_pixie_dust(result, bssid)
        if pixie_vuln:
            result.vulnerabilities.append(pixie_vuln)

        # Step 4: Check for known/static PINs
        known_pin_vulns = self._check_known_pins(result, bssid)
        result.vulnerabilities.extend(known_pin_vulns)

        # Step 5: Check for WPS lockout behavior
        if not result.wps_locked:
            no_lockout_vuln = WPSVulnerability(
                vuln_id="WPS-003",
                title="No WPS Rate Limiting / Lockout",
                description=(
                    "The AP does not appear to implement WPS lockout after "
                    "failed PIN attempts. Without lockout, an attacker can "
                    "continuously brute-force the PIN without waiting for "
                    "timeout periods."
                ),
                severity="high",
                cve_ids=[],
                recommendation=(
                    "Ensure WPS lockout is enabled after a reasonable number "
                    "of failed attempts (e.g., 3-5). Better yet, disable WPS."
                ),
                evidence={"lockout_detected": False},
            )
            result.vulnerabilities.append(no_lockout_vuln)
        else:
            lockout_info_vuln = WPSVulnerability(
                vuln_id="WPS-004",
                title="WPS Lockout Present but Insufficient",
                description=(
                    "WPS lockout is implemented, but it only slows down "
                    "the brute-force attack rather than preventing it. "
                    "A typical lockout of 5 minutes after 3-5 failed "
                    "attempts still allows the full PIN space to be "
                    "searched in under a day."
                ),
                severity="medium",
                cve_ids=[],
                recommendation="Disable WPS entirely; lockout is not a sufficient mitigation.",
                evidence={"lockout_detected": True},
            )
            result.vulnerabilities.append(lockout_info_vuln)

        # Step 6: Check for null/empty PIN vulnerability
        null_pin_vuln = WPSVulnerability(
            vuln_id="WPS-005",
            title="Null PIN Vulnerability",
            description=(
                "Some WPS implementations accept an empty or null PIN. "
                "If the AP responds to a M2 message with a null PIN, "
                "the network credentials can be obtained instantly."
            ),
            severity="critical",
            cve_ids=["CVE-2012-4366"],
            recommendation="Disable WPS. Update AP firmware if available.",
            evidence={"check_performed": True},
        )
        result.vulnerabilities.append(null_pin_vuln)

        result.is_vulnerable = len(result.vulnerabilities) > 0
        logger.info(
            "WPS check complete for %s: %d vulnerabilities found",
            bssid,
            len(result.vulnerabilities),
        )
        return result

    def _check_pixie_dust(
        self, result: WPSScanResult, bssid: str
    ) -> Optional[WPSVulnerability]:
        """Check for Pixie Dust (CVE-2014-6313) vulnerability.

        Pixie Dust exploits weak random number generation in some WPS
        implementations, allowing the PIN to be derived offline from
        the M1/M2 exchange.
        """
        manufacturer = result.manufacturer.lower()
        model = result.model_name.lower()
        chipset_vulnerable = False

        for vulnerable_chip in PIXIE_DUST_VULNERABLE:
            if vulnerable_chip.lower() in manufacturer or vulnerable_chip.lower() in model:
                chipset_vulnerable = True
                break

        # Many Realtek-based APs are vulnerable
        if "realtek" in manufacturer or "rtl" in model:
            chipset_vulnerable = True

        if chipset_vulnerable or result.wps_version in ("1.0", "2.0"):
            return WPSVulnerability(
                vuln_id="WPS-006",
                title="Pixie Dust Attack Vulnerability",
                description=(
                    "The AP may be vulnerable to the Pixie Dust attack "
                    "(CVE-2014-6313), which exploits weak random number "
                    "generation in the WPS protocol to derive the PIN "
                    "offline. This attack can recover the PIN in seconds "
                    "rather than hours."
                ),
                severity="critical",
                cve_ids=["CVE-2014-6313"],
                recommendation="Disable WPS immediately. Update AP firmware.",
                evidence={
                    "manufacturer": result.manufacturer,
                    "model": result.model_name,
                    "chipset_suspected_vulnerable": chipset_vulnerable,
                },
            )

        return None

    def _check_known_pins(
        self, result: WPSScanResult, bssid: str
    ) -> List[WPSVulnerability]:
        """Check for known/static WPS PINs based on manufacturer."""
        vulns: List[WPSVulnerability] = []
        manufacturer = result.manufacturer.lower()

        matched_vendor = None
        matched_pins: List[str] = []

        for vendor, pins in KNOWN_PINS.items():
            if vendor in manufacturer:
                matched_vendor = vendor
                matched_pins = pins
                break

        # Also try matching by BSSID OUI
        if not matched_vendor:
            oui = bssid[:8].replace(":", "").upper()
            oui_map = {
                "001A2B": "dlink",
                "001B11": "dlink",
                "002191": "netgear",
                "0022B0": "netgear",
                "001C10": "belkin",
                "0016B6": "linksys",
                "0018F8": "linksys",
                "EC172F": "tplink",
                "60E327": "tplink",
                "04D4C4": "asus",
                "1CBFCE": "asus",
            }
            if oui in oui_map:
                matched_vendor = oui_map[oui]
                matched_pins = KNOWN_PINS.get(matched_vendor, [])

        if matched_vendor and matched_pins:
            # Validate PINs
            valid_pins = [p for p in matched_pins if validate_pin(p)]
            vuln = WPSVulnerability(
                vuln_id="WPS-007",
                title=f"Known WPS PINs for {matched_vendor.title()}",
                description=(
                    f"This {matched_vendor.title()} device has {len(valid_pins)} "
                    "known WPS PINs documented for this manufacturer. Known PINs "
                    "can be tried first during a brute-force attack, significantly "
                    "reducing the time to compromise."
                ),
                severity="high",
                cve_ids=[],
                recommendation="Disable WPS entirely.",
                evidence={
                    "vendor": matched_vendor,
                    "known_pins_count": len(valid_pins),
                },
            )
            vulns.append(vuln)

        return vulns

    def _parse_wps_ie(self, data: bytes) -> Dict[str, Any]:
        """Parse WPS Information Element from raw data.

        Args:
            data: Raw WPS IE data (after the IE tag and length).

        Returns:
            Dictionary with parsed WPS attributes.
        """
        result: Dict[str, Any] = {}
        offset = 0

        # WPS IE starts with vendor-specific OUI: 00:50:F2:04
        if len(data) < 4:
            return result

        # Skip OUI and type
        if data[:4] == b"\x00\x50\xf2\x04":
            offset = 4

        # Parse TLV attributes
        while offset + 4 <= len(data):
            attr_type = struct.unpack(">H", data[offset : offset + 2])[0]
            attr_len = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
            attr_data = data[offset + 4 : offset + 4 + attr_len]

            if attr_type == 0x104A:  # Version
                if attr_data:
                    result["version"] = f"{attr_data[0] // 10}.{attr_data[0] % 10}"
            elif attr_type == 0x1012:  # Config Methods
                if len(attr_data) >= 2:
                    result["config_methods"] = struct.unpack(">H", attr_data[:2])[0]
            elif attr_type == 0x1021:  # Manufacturer
                try:
                    result["manufacturer"] = attr_data.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    pass
            elif attr_type == 0x1023:  # Model Name
                try:
                    result["model_name"] = attr_data.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    pass
            elif attr_type == 0x1024:  # Model Number
                try:
                    result["model_number"] = attr_data.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    pass
            elif attr_type == 0x1011:  # Device Name
                try:
                    result["device_name"] = attr_data.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    pass
            elif attr_type == 0x103C:  # AP Setup Locked
                if attr_data:
                    result["locked"] = attr_data[0] != 0

            offset += 4 + attr_len

        return result

    def generate_pin_candidates(
        self, bssid: str, manufacturer: str = ""
    ) -> List[str]:
        """Generate likely WPS PIN candidates for the target.

        Generates PINs based on known manufacturer PINs, BSSID-derived
        PINs, and common patterns.

        Args:
            bssid: BSSID of the target AP.
            manufacturer: Device manufacturer name.

        Returns:
            List of candidate PIN strings (8 digits with checksum).
        """
        candidates: List[str] = []
        seen: set = set()

        # Add manufacturer-specific PINs
        mfr_lower = manufacturer.lower()
        for vendor, pins in KNOWN_PINS.items():
            if vendor in mfr_lower:
                for pin in pins:
                    if validate_pin(pin) and pin not in seen:
                        candidates.append(pin)
                        seen.add(pin)

        # Generate BSSID-derived PINs
        bssid_clean = bssid.replace(":", "").replace("-", "").upper()
        if len(bssid_clean) >= 6:
            # PIN from last 6 hex digits -> 7 decimal digits + checksum
            last_6 = bssid_clean[-6:]
            try:
                pin_base = str(int(last_6, 16) % 10000000).zfill(7)
                pin_full = pin_base + compute_pin_checksum(pin_base)
                if pin_full not in seen:
                    candidates.append(pin_full)
                    seen.add(pin_full)
            except ValueError:
                pass

        # Add static/default PINs
        for pin in STATIC_PINS:
            if validate_pin(pin) and pin not in seen:
                candidates.append(pin)
                seen.add(pin)

        return candidates

    def quick_check(self, scan_info: Dict[str, Any]) -> bool:
        """Quick check if WPS is enabled on a network.

        Args:
            scan_info: Dictionary with scan information.

        Returns:
            True if WPS is enabled.
        """
        return scan_info.get("wps_enabled", False)
