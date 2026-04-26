"""Default credential checker for WiFiAIO.

Detects networks that may be using factory-default credentials including
default SSIDs, passwords, WPS PINs, and admin panel credentials.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from wifi_aio.exceptions import WiFiConnectionError, WiFiTimeoutError

logger = logging.getLogger(__name__)


@dataclass
class DefaultCredVulnerability:
    """Represents a single default credential vulnerability finding."""
    vuln_id: str
    title: str
    description: str
    severity: str
    cve_ids: List[str] = field(default_factory=list)
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DefaultCredScanResult:
    """Aggregated result of a default credential scan."""
    bssid: str
    ssid: str
    is_vulnerable: bool
    vulnerabilities: List[DefaultCredVulnerability] = field(default_factory=list)
    matched_manufacturer: str = ""
    matched_model: str = ""
    default_passwords_found: List[str] = field(default_factory=list)
    default_ssids_matched: List[str] = field(default_factory=list)
    default_admin_creds_found: List[Dict[str, str]] = field(default_factory=list)
    confidence: str = "low"
    scan_timestamp: float = 0.0


# Default SSID patterns by manufacturer
DEFAULT_SSID_PATTERNS: Dict[str, List[Dict[str, Any]]] = {
    "netgear": [
        {"pattern": r"^NETGEAR\d*$", "models": ["Generic Netgear"]},
        {"pattern": r"^NETGEAR-\w+$", "models": ["Netgear N-Series"]},
        {"pattern": r"^NG-\w+$", "models": ["Netgear NightHawk"]},
    ],
    "linksys": [
        {"pattern": r"^Linksys\d*$", "models": ["Linksys E-Series"]},
        {"pattern": r"^LINKYS-\w+$", "models": ["Linksys WRT"]},
        {"pattern": r"^linksys\w+$", "models": ["Linksys Smart Wi-Fi"]},
    ],
    "dlink": [
        {"pattern": r"^dlink$", "models": ["D-Link Generic"]},
        {"pattern": r"^DIR-\w+$", "models": ["D-Link DIR Series"]},
        {"pattern": r"^DAP-\w+$", "models": ["D-Link DAP Series"]},
        {"pattern": r"^dlink_\w+$", "models": ["D-Link Default"]},
    ],
    "belkin": [
        {"pattern": r"^Belkin\.\w+$", "models": ["Belkin N+"]},
        {"pattern": r"^belkin\d*$", "models": ["Belkin Generic"]},
    ],
    "tplink": [
        {"pattern": r"^TP-LINK_\w+$", "models": ["TP-Link Generic"]},
        {"pattern": r"^TP-Link_\w+$", "models": ["TP-Link Archer"]},
    ],
    "asus": [
        {"pattern": r"^ASUS_\w+$", "models": ["ASUS RT-Series"]},
        {"pattern": r"^RT-\w+$", "models": ["ASUS RT Router"]},
    ],
    "xfinity": [
        {"pattern": r"^xfinitywifi$", "models": ["Xfinity Hotspot"]},
        {"pattern": r"^XFINITY-\w+$", "models": ["Xfinity Home"]},
        {"pattern": r"^HOME-\w+$", "models": ["Xfinity Home Gateway"]},
    ],
    "att": [
        {"pattern": r"^ATT\w+$", "models": ["AT&T Gateway"]},
        {"pattern": r"^2WIRE\d*$", "models": ["2Wire Gateway"]},
        {"pattern": r"^Pace-\w+$", "models": ["Pace/AT&T"]},
    ],
    "verizon": [
        {"pattern": r"^FIOS-\w+$", "models": ["Verizon FiOS"]},
        {"pattern": r"^Verizon_\w+$", "models": ["Verizon Gateway"]},
    ],
    "spectrum": [
        {"pattern": r"^SpectrumSetup-\w+$", "models": ["Spectrum Gateway"]},
        {"pattern": r"^MySpectrum\w+$", "models": ["Spectrum Router"]},
    ],
    "cox": [
        {"pattern": r"^Cox-\w+$", "models": ["Cox Gateway"]},
    ],
    "huawei": [
        {"pattern": r"^HUAWEI-\w+$", "models": ["Huawei Generic"]},
        {"pattern": r"^Honor-\w+$", "models": ["Huawei Honor"]},
    ],
    "zte": [
        {"pattern": r"^ZTE-\w+$", "models": ["ZTE Generic"]},
        {"pattern": r"^ZXHN-\w+$", "models": ["ZTE ZXHN"]},
    ],
}

# Default passwords by manufacturer/model
DEFAULT_PASSWORDS: Dict[str, Dict[str, List[str]]] = {
    "netgear": {
        "admin_passwords": ["password", "admin", "1234", "netgear1", "NETGEAR"],
        "wifi_passwords": ["password", "12345678", "netgear123"],
        "models": {
            "R7000": {"admin": "admin/password", "wifi": "on_label"},
            "R8000": {"admin": "admin/password", "wifi": "on_label"},
            "C7000": {"admin": "admin/password", "wifi": "on_label"},
        },
    },
    "linksys": {
        "admin_passwords": ["admin", "password", ""],
        "wifi_passwords": ["password", "12345678", "linksys123"],
        "models": {
            "EA7500": {"admin": "admin/admin", "wifi": "on_label"},
            "WRT54G": {"admin": "admin/admin", "wifi": "admin"},
        },
    },
    "dlink": {
        "admin_passwords": ["admin", "password", ""],
        "wifi_passwords": ["password", "12345678", "dlink123"],
        "models": {
            "DIR-615": {"admin": "admin/", "wifi": "on_label"},
            "DIR-825": {"admin": "admin/", "wifi": "on_label"},
        },
    },
    "belkin": {
        "admin_passwords": ["admin", "password", ""],
        "wifi_passwords": ["password", "12345678", "belkin123"],
        "models": {},
    },
    "tplink": {
        "admin_passwords": ["admin", "admin/admin", "password"],
        "wifi_passwords": ["password", "12345678", "tplink123"],
        "models": {
            "Archer C7": {"admin": "admin/admin", "wifi": "on_label"},
            "Archer A7": {"admin": "admin/admin", "wifi": "on_label"},
        },
    },
    "asus": {
        "admin_passwords": ["admin", "admin/admin", "password"],
        "wifi_passwords": ["password", "12345678"],
        "models": {
            "RT-AC68U": {"admin": "admin/admin", "wifi": "on_label"},
            "RT-AC66U": {"admin": "admin/admin", "wifi": "on_label"},
        },
    },
    "verizon": {
        "admin_passwords": ["admin", "password", "verizon"],
        "wifi_passwords": ["password", "verizon123"],
        "models": {
            "G3100": {"admin": "admin/password", "wifi": "on_label"},
        },
    },
    "xfinity": {
        "admin_passwords": ["admin", "password", "1234"],
        "wifi_passwords": ["password", "12345678"],
        "models": {
            "xFi Gateway": {"admin": "admin/password", "wifi": "on_label"},
        },
    },
}

# Default admin panel credentials
DEFAULT_ADMIN_CREDENTIALS: List[Dict[str, str]] = [
    {"username": "admin", "password": "admin", "vendor": "generic"},
    {"username": "admin", "password": "password", "vendor": "generic"},
    {"username": "admin", "password": "", "vendor": "dlink"},
    {"username": "admin", "password": "admin", "vendor": "dlink"},
    {"username": "admin", "password": "password", "vendor": "netgear"},
    {"username": "admin", "password": "1234", "vendor": "netgear"},
    {"username": "", "password": "admin", "vendor": "linksys"},
    {"username": "admin", "password": "admin", "vendor": "linksys"},
    {"username": "admin", "password": "", "vendor": "belkin"},
    {"username": "admin", "password": "admin", "vendor": "tplink"},
    {"username": "admin", "password": "password", "vendor": "tplink"},
    {"username": "admin", "password": "admin", "vendor": "asus"},
    {"username": "superadmin", "password": "admin", "vendor": "zte"},
    {"username": "admin", "password": "admin", "vendor": "huawei"},
    {"username": "admin", "password": "Huawei@123", "vendor": "huawei"},
    {"username": "cusadmin", "password": "highspeed", "vendor": "xfinity"},
    {"username": "admin", "password": "password", "vendor": "verizon"},
    {"username": "admin", "password": "motorola", "vendor": "motorola"},
    {"username": "admin", "password": "broadband", "vendor": "spectrum"},
    {"username": "admin", "password": "C0nf1gur3M3!", "vendor": "ubiquiti"},
]

# BSSID OUI to manufacturer mapping
OUI_DATABASE: Dict[str, str] = {
    "001A2B": "dlink",
    "001B11": "dlink",
    "001CF0": "dlink",
    "002191": "netgear",
    "0022B0": "netgear",
    "0023EB": "netgear",
    "0016B6": "linksys",
    "0018F8": "linksys",
    "001C10": "belkin",
    "0017F2": "belkin",
    "EC172F": "tplink",
    "60E327": "tplink",
    "50C7BF": "tplink",
    "04D4C4": "asus",
    "1CBFCE": "asus",
    "60456B": "asus",
    "C43DC7": "huawei",
    "48DB50": "huawei",
    "E0191D": "huawei",
    "F83A5E": "zte",
    "C89E43": "zte",
    "3C46D8": "xfinity",
    "7CB3D6": "xfinity",
    "A4B197": "verizon",
    "88F7C7": "verizon",
    "0024C4": "spectrum",
    "7C1E52": "spectrum",
}


class DefaultCredChecker:
    """Detects default credential vulnerabilities in Wi-Fi networks.

    Identifies networks that may be using factory-default SSIDs,
    passwords, admin panel credentials, or WPS PINs.

    Usage::

        checker = DefaultCredChecker()
        result = checker.check(bssid="AA:BB:CC:DD:EE:FF", ssid="NETGEAR-5G")
        if result.is_vulnerable:
            print(f"Default credentials likely: {result.default_passwords_found}")
    """

    def __init__(self, timeout: int = 10) -> None:
        """Initialize the default credential checker.

        Args:
            timeout: Timeout for network checks.
        """
        self.timeout = timeout
        self._checked_networks: Dict[str, DefaultCredScanResult] = {}
        logger.info("DefaultCredChecker initialized")

    def check(
        self,
        bssid: str,
        ssid: str = "",
        manufacturer: str = "",
        model: str = "",
        encryption: str = "",
        additional_info: Optional[Dict[str, Any]] = None,
    ) -> DefaultCredScanResult:
        """Perform a default credential check.

        Args:
            bssid: BSSID of the target access point.
            ssid: SSID of the target network.
            manufacturer: Known manufacturer name.
            model: Known device model.
            encryption: Encryption type string.
            additional_info: Additional information about the device.

        Returns:
            DefaultCredScanResult with findings.
        """
        start_time = time.time()
        result = DefaultCredScanResult(
            bssid=bssid,
            ssid=ssid,
            is_vulnerable=False,
            scan_timestamp=start_time,
        )

        # Step 1: Identify manufacturer from BSSID OUI
        oui_manufacturer = self._lookup_oui(bssid)
        if oui_manufacturer and not manufacturer:
            manufacturer = oui_manufacturer
        result.matched_manufacturer = manufacturer

        # Step 2: Check for default SSID patterns
        ssid_matches = self._check_ssid_patterns(ssid)
        if ssid_matches:
            result.default_ssids_matched = [m["ssid"] for m in ssid_matches]
            for match in ssid_matches:
                if not manufacturer:
                    manufacturer = match.get("manufacturer", "")
                    result.matched_manufacturer = manufacturer

            ssid_vuln = DefaultCredVulnerability(
                vuln_id="DEFCRED-001",
                title="Default SSID Detected",
                description=(
                    f"The SSID '{ssid}' matches a known default pattern for "
                    f"{manufacturer or 'unknown'} devices. Default SSIDs "
                    "indicate that the router may not have been properly "
                    "configured and could be using default credentials."
                ),
                severity="medium",
                cve_ids=[],
                recommendation="Change the SSID to a custom, non-identifying name.",
                evidence={
                    "ssid": ssid,
                    "matched_patterns": result.default_ssids_matched,
                    "manufacturer": manufacturer,
                },
            )
            result.vulnerabilities.append(ssid_vuln)

        # Step 3: Check for default passwords
        if manufacturer:
            mfr_lower = manufacturer.lower()
            for vendor, creds in DEFAULT_PASSWORDS.items():
                if vendor in mfr_lower or mfr_lower in vendor:
                    result.default_passwords_found = creds.get("wifi_passwords", [])

                    if result.default_passwords_found:
                        pwd_vuln = DefaultCredVulnerability(
                            vuln_id="DEFCRED-002",
                            title="Potential Default WiFi Password",
                            description=(
                                f"This {manufacturer} device may use a "
                                "factory-default WiFi password. Default "
                                "passwords are widely documented online and "
                                "can be found in device manuals and support "
                                "forums."
                            ),
                            severity="high",
                            cve_ids=[],
                            recommendation=(
                                "Change the WiFi password immediately to a "
                                "strong, unique passphrase of at least 16 "
                                "characters."
                            ),
                            evidence={
                                "manufacturer": manufacturer,
                                "default_passwords_count": len(result.default_passwords_found),
                            },
                        )
                        result.vulnerabilities.append(pwd_vuln)

                    # Check model-specific defaults
                    if model:
                        model_creds = creds.get("models", {}).get(model, {})
                        if model_creds:
                            model_vuln = DefaultCredVulnerability(
                                vuln_id="DEFCRED-003",
                                title=f"Model-Specific Default Credentials ({model})",
                                description=(
                                    f"Default credentials for {manufacturer} {model} "
                                    f"are documented: {model_creds}"
                                ),
                                severity="high",
                                cve_ids=[],
                                recommendation="Change all default credentials immediately.",
                                evidence={"model": model, "defaults": model_creds},
                            )
                            result.vulnerabilities.append(model_vuln)
                    break

        # Step 4: Check for default admin panel credentials
        admin_creds = self._check_admin_credentials(manufacturer)
        if admin_creds:
            result.default_admin_creds_found = admin_creds
            admin_vuln = DefaultCredVulnerability(
                vuln_id="DEFCRED-004",
                title="Default Admin Panel Credentials",
                description=(
                    f"Found {len(admin_creds)} sets of default admin credentials "
                    f"for {manufacturer or 'this'} device. Default admin "
                    "credentials allow full control over the router, including "
                    "changing DNS settings, viewing connected devices, and "
                    "modifying security settings."
                ),
                severity="critical",
                cve_ids=[],
                recommendation=(
                    "Change the admin panel password immediately. Disable "
                    "remote admin access if not needed."
                ),
                evidence={
                    "manufacturer": manufacturer,
                    "default_creds_count": len(admin_creds),
                },
            )
            result.vulnerabilities.append(admin_vuln)

        # Step 5: Check for weak encryption with default credentials
        if encryption and encryption.lower() in ("wep", "open"):
            weak_enc_vuln = DefaultCredVulnerability(
                vuln_id="DEFCRED-005",
                title="Weak Encryption with Possible Default Credentials",
                description=(
                    f"The network uses {encryption} encryption, which is "
                    "commonly found on misconfigured or default-configured "
                    "routers. This combination significantly increases risk."
                ),
                severity="critical",
                cve_ids=[],
                recommendation=(
                    "Upgrade to WPA2-AES or WPA3 and change all default passwords."
                ),
                evidence={"encryption": encryption},
            )
            result.vulnerabilities.append(weak_enc_vuln)

        # Step 6: Determine confidence level
        evidence_count = len(result.vulnerabilities)
        if evidence_count >= 3:
            result.confidence = "high"
        elif evidence_count >= 2:
            result.confidence = "medium"
        elif evidence_count >= 1:
            result.confidence = "low"

        result.is_vulnerable = len(result.vulnerabilities) > 0
        logger.info(
            "Default credential check for %s: %d findings, confidence=%s",
            bssid,
            len(result.vulnerabilities),
            result.confidence,
        )
        return result

    def _lookup_oui(self, bssid: str) -> str:
        """Look up the manufacturer from BSSID OUI.

        Args:
            bssid: BSSID/MAC address.

        Returns:
            Manufacturer name or empty string.
        """
        if not bssid:
            return ""

        oui = bssid.replace(":", "").replace("-", "").upper()[:6]
        return OUI_DATABASE.get(oui, "")

    def _check_ssid_patterns(self, ssid: str) -> List[Dict[str, Any]]:
        """Check if SSID matches known default patterns.

        Args:
            ssid: SSID to check.

        Returns:
            List of matching patterns with manufacturer info.
        """
        matches: List[Dict[str, Any]] = []

        if not ssid:
            return matches

        for manufacturer, patterns in DEFAULT_SSID_PATTERNS.items():
            for pattern_info in patterns:
                pattern = pattern_info["pattern"]
                if re.match(pattern, ssid, re.IGNORECASE):
                    matches.append({
                        "ssid": ssid,
                        "pattern": pattern,
                        "manufacturer": manufacturer,
                        "models": pattern_info.get("models", []),
                    })

        return matches

    def _check_admin_credentials(self, manufacturer: str) -> List[Dict[str, str]]:
        """Check for default admin credentials for a manufacturer.

        Args:
            manufacturer: Device manufacturer name.

        Returns:
            List of default credential dictionaries.
        """
        if not manufacturer:
            return []

        mfr_lower = manufacturer.lower()
        matching_creds: List[Dict[str, str]] = []

        for cred in DEFAULT_ADMIN_CREDENTIALS:
            if cred["vendor"] == "generic" or cred["vendor"] in mfr_lower or mfr_lower in cred["vendor"]:
                matching_creds.append({
                    "username": cred["username"],
                    "password": cred["password"],
                })

        return matching_creds

    def check_password_strength(self, password: str) -> Dict[str, Any]:
        """Check the strength of a WiFi password.

        Args:
            password: Password to evaluate.

        Returns:
            Dictionary with strength assessment.
        """
        result: Dict[str, Any] = {
            "strength": "weak",
            "score": 0,
            "issues": [],
            "is_default": False,
        }

        if not password:
            result["issues"].append("Password is empty")
            return result

        score = 0
        issues: List[str] = []

        # Length check
        if len(password) < 8:
            issues.append("Password is shorter than 8 characters")
        elif len(password) < 12:
            score += 1
            issues.append("Password should be at least 12 characters")
        elif len(password) < 16:
            score += 2
        else:
            score += 3

        # Character variety
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        variety = sum([has_lower, has_upper, has_digit, has_special])
        score += variety

        if variety < 3:
            issues.append("Password should use a mix of character types")

        # Check if it's a common default
        for vendor_creds in DEFAULT_PASSWORDS.values():
            if password in vendor_creds.get("wifi_passwords", []):
                result["is_default"] = True
                issues.append("Password is a known default")
                score = 0
                break

        for cred in DEFAULT_ADMIN_CREDENTIALS:
            if password == cred["password"]:
                result["is_default"] = True
                issues.append("Password is a known default admin password")
                score = 0
                break

        # Sequential/pattern check
        if len(set(password)) <= 3:
            issues.append("Password has very low character diversity")
            score = max(score - 2, 0)

        if password.isdigit():
            issues.append("Password is all digits")
            score = max(score - 1, 0)

        # Common patterns
        common_patterns = ["1234", "4321", "abcd", "password", "qwerty", "admin"]
        for pattern in common_patterns:
            if pattern in password.lower():
                issues.append(f"Password contains common pattern: {pattern}")
                score = max(score - 1, 0)

        result["score"] = score
        result["issues"] = issues

        if result["is_default"] or score <= 1:
            result["strength"] = "weak"
        elif score <= 3:
            result["strength"] = "fair"
        elif score <= 5:
            result["strength"] = "good"
        else:
            result["strength"] = "strong"

        return result

    def generate_credential_report(self, bssid: str, ssid: str) -> Dict[str, Any]:
        """Generate a comprehensive credential assessment report.

        Args:
            bssid: BSSID of the target.
            ssid: SSID of the target.

        Returns:
            Dictionary with complete credential assessment.
        """
        scan_result = self.check(bssid=bssid, ssid=ssid)

        report: Dict[str, Any] = {
            "target": {"bssid": bssid, "ssid": ssid},
            "vulnerable": scan_result.is_vulnerable,
            "confidence": scan_result.confidence,
            "manufacturer": scan_result.matched_manufacturer,
            "findings_count": len(scan_result.vulnerabilities),
            "findings": [],
            "recommendations": [],
        }

        for vuln in scan_result.vulnerabilities:
            report["findings"].append({
                "id": vuln.vuln_id,
                "title": vuln.title,
                "severity": vuln.severity,
                "description": vuln.description,
            })
            if vuln.recommendation and vuln.recommendation not in report["recommendations"]:
                report["recommendations"].append(vuln.recommendation)

        return report

    def quick_check(self, ssid: str, bssid: str = "") -> bool:
        """Quick check if a network may use default credentials.

        Args:
            ssid: SSID to check.
            bssid: Optional BSSID for OUI lookup.

        Returns:
            True if default credentials are suspected.
        """
        if ssid and self._check_ssid_patterns(ssid):
            return True
        if bssid and self._lookup_oui(bssid):
            return True
        return False
