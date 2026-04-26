"""
WiFiAIO Vulnerability Scanner Module

Comprehensive WiFi vulnerability assessment: WEP/WPA/WPA2/WPA3/WPS checks,
default credentials, DNS hijack detection, KRACK, PMF, rogue DHCP.

FIX: Normalizes CVE severity strings with _normalize_severity() mapping.
"""

import os
import re
import time
import json
import logging
import subprocess
import socket
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    VulnScanError,
)

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnCategory(Enum):
    """Vulnerability categories."""
    ENCRYPTION = "encryption"
    AUTHENTICATION = "authentication"
    CONFIGURATION = "configuration"
    PROTOCOL = "protocol"
    WPS = "wps"
    ROGUE = "rogue"
    DNS = "dns"
    DEFAULT_CREDENTIALS = "default_credentials"
    PMF = "pmf"
    KRACK = "krack"


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    id: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    category: VulnCategory = VulnCategory.CONFIGURATION
    cve: str = ""
    cvss_score: float = 0.0
    recommendation: str = ""
    affected_component: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "cve": self.cve,
            "cvss_score": self.cvss_score,
            "recommendation": self.recommendation,
            "affected_component": self.affected_component,
            "details": self.details,
        }


@dataclass
class AuditResult:
    """Complete audit result."""
    target_bssid: str = ""
    target_ssid: str = ""
    timestamp: float = 0.0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    info_items: List[Vulnerability] = field(default_factory=list)
    scan_duration: float = 0.0
    score: int = 100  # Security score (100 = perfect)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_bssid": self.target_bssid,
            "target_ssid": self.target_ssid,
            "timestamp": self.timestamp,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "info_items": [i.to_dict() for i in self.info_items],
            "scan_duration": self.scan_duration,
            "score": self.score,
        }

    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)

    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)


def _normalize_severity(severity_str: str) -> Severity:
    """
    Normalize various CVE severity string representations to Severity enum.

    FIX: Maps various severity strings to standardized values.

    Args:
        severity_str: Severity string from various sources (NVD, CVE, etc.)

    Returns:
        Normalized Severity enum value.
    """
    severity_map = {
        # NVD standard
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        # CVSS score-based strings
        "9.0": Severity.CRITICAL,
        "8.0": Severity.HIGH,
        "7.0": Severity.HIGH,
        "6.0": Severity.MEDIUM,
        "5.0": Severity.MEDIUM,
        "4.0": Severity.MEDIUM,
        "3.0": Severity.LOW,
        "2.0": Severity.LOW,
        "1.0": Severity.LOW,
        "0.0": Severity.INFO,
        # Common variations
        "crit": Severity.CRITICAL,
        "important": Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "minor": Severity.LOW,
        "informational": Severity.INFO,
        "note": Severity.INFO,
        "warning": Severity.MEDIUM,
        "urgent": Severity.CRITICAL,
        # Capitalized versions
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
        # Mixed case
        "Critical": Severity.CRITICAL,
        "High": Severity.HIGH,
        "Medium": Severity.MEDIUM,
        "Low": Severity.LOW,
        # Numeric strings
        "3": Severity.CRITICAL,
        "2": Severity.HIGH,
        "1": Severity.MEDIUM,
        "0": Severity.LOW,
    }

    # Direct lookup
    normalized = severity_str.strip()
    if normalized in severity_map:
        return severity_map[normalized]

    # Try lowercase
    lower = normalized.lower()
    if lower in severity_map:
        return severity_map[lower]

    # Try to parse as float score
    try:
        score = float(normalized)
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0.0:
            return Severity.LOW
        else:
            return Severity.INFO
    except ValueError:
        pass

    # Partial match
    lower = normalized.lower()
    if "crit" in lower:
        return Severity.CRITICAL
    elif "high" in lower or "import" in lower or "urgent" in lower:
        return Severity.HIGH
    elif "med" in lower or "moder" in lower or "warn" in lower:
        return Severity.MEDIUM
    elif "low" in lower or "minor" in lower:
        return Severity.LOW
    elif "info" in lower or "note" in lower:
        return Severity.INFO

    # Default to medium for unknown strings
    logger.warning("Unknown severity string '%s', defaulting to MEDIUM", severity_str)
    return Severity.MEDIUM


# Default credentials database (common router defaults)
DEFAULT_CREDENTIALS_DB: Dict[str, List[Dict[str, str]]] = {
    "linksys": [
        {"username": "admin", "password": "admin"},
        {"username": "", "password": "admin"},
        {"username": "admin", "password": ""},
        {"username": "admin", "password": "password"},
    ],
    "netgear": [
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": "1234"},
        {"username": "admin", "password": ""},
    ],
    "d-link": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": ""},
        {"username": "admin", "password": "password"},
    ],
    "tp-link": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "", "password": "admin"},
    ],
    "asus": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
    ],
    "cisco": [
        {"username": "admin", "password": "admin"},
        {"username": "cisco", "password": "cisco"},
        {"username": "", "password": ""},
    ],
    "belkin": [
        {"username": "admin", "password": "admin"},
        {"username": "", "password": ""},
    ],
    "technicolor": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
    ],
    "huawei": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "Huawei@123"},
    ],
    "xiaomi": [
        {"username": "admin", "password": "admin"},
        {"username": "", "password": ""},
    ],
}


class VulnScanner:
    """
    WiFi vulnerability scanner.

    Performs comprehensive security assessment including:
    - Encryption protocol analysis (WEP/WPA/WPA2/WPA3)
    - WPS vulnerability detection
    - Default credential testing
    - DNS hijack detection
    - KRACK vulnerability check
    - PMF (Protected Management Frames) check
    - Rogue DHCP detection
    """

    def __init__(self, interface: str = "wlan0"):
        """
        Initialize VulnScanner.

        Args:
            interface: Wireless interface name.
        """
        self.interface = interface
        self._running = False

    def _check_root(self) -> None:
        """Verify running as root for operations requiring it."""
        if os.geteuid() != 0:
            raise WiFiPermissionError("Vulnerability scanning requires root privileges")

    def _run_command(self, cmd: List[str], timeout: int = 30) -> Tuple[str, int]:
        """Run a command and return (output, returncode)."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"Command timed out: {' '.join(cmd)}")
        except FileNotFoundError:
            return "", -1

    def full_audit(self, bssid: str, ssid: str = "", channel: int = 0,
                   check_credentials: bool = True,
                   check_dns: bool = True,
                   check_rogue: bool = True) -> AuditResult:
        """
        Perform a full vulnerability audit on a target network.

        Args:
            bssid: Target AP BSSID.
            ssid: Target SSID.
            channel: Target channel.
            check_credentials: Test default credentials.
            check_dns: Check for DNS hijacking.
            check_rogue: Check for rogue DHCP.

        Returns:
            AuditResult with all findings.
        """
        self._running = True
        start_time = time.time()

        result = AuditResult(
            target_bssid=bssid,
            target_ssid=ssid,
            timestamp=time.time(),
        )

        # Run all vulnerability checks
        result.vulnerabilities.extend(self.check_encryption(bssid, ssid, channel))
        result.vulnerabilities.extend(self.check_wps(bssid, channel))
        result.vulnerabilities.extend(self.check_krack(bssid, channel))
        result.vulnerabilities.extend(self.check_pmf(bssid, ssid, channel))

        if check_credentials:
            result.vulnerabilities.extend(self.check_default_credentials(bssid, ssid))

        if check_dns:
            result.vulnerabilities.extend(self.check_dns_hijack())

        if check_rogue:
            result.vulnerabilities.extend(self.check_rogue_dhcp())

        # Calculate security score
        result.score = self._calculate_score(result.vulnerabilities)

        result.scan_duration = time.time() - start_time
        self._running = False
        return result

    def _calculate_score(self, vulns: List[Vulnerability]) -> int:
        """Calculate security score from vulnerabilities found."""
        score = 100
        deductions = {
            Severity.CRITICAL: 30,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 5,
            Severity.INFO: 0,
        }
        for vuln in vulns:
            score -= deductions.get(vuln.severity, 0)
        return max(0, score)

    def check_encryption(self, bssid: str, ssid: str = "",
                          channel: int = 0) -> List[Vulnerability]:
        """
        Check encryption protocol vulnerabilities (WEP/WPA/WPA2/WPA3).

        Args:
            bssid: Target AP BSSID.
            ssid: Target SSID.
            channel: Target channel.

        Returns:
            List of discovered vulnerabilities.
        """
        vulns: List[Vulnerability] = []

        # Scan for network details
        output, rc = self._run_command(
            ["iw", "dev", self.interface, "scan"]
        )

        security_info = self._parse_security_from_iw(output, bssid)
        sec_type = security_info.get("type", "OPEN")
        cipher = security_info.get("cipher", "")
        key_mgmt = security_info.get("key_mgmt", "")

        # WEP check
        if "WEP" in sec_type.upper():
            vulns.append(Vulnerability(
                id="WIFIAIO-001",
                title="WEP Encryption Detected",
                description="WEP encryption is broken and can be cracked within minutes. "
                           "It provides no meaningful security.",
                severity=Severity.CRITICAL,
                category=VulnCategory.ENCRYPTION,
                cve="CVE-2001-0466",
                cvss_score=9.8,
                recommendation="Upgrade to WPA2 or WPA3 encryption immediately.",
                affected_component="Encryption Protocol",
                details={"protocol": "WEP"},
            ))

        # WPA check
        if sec_type.upper() == "WPA" and "WPA2" not in sec_type.upper():
            vulns.append(Vulnerability(
                id="WIFIAIO-002",
                title="WPA (TKIP) Encryption Detected",
                description="WPA with TKIP is deprecated and vulnerable to multiple attacks "
                           "including Beck-Tews and ohili cuts.",
                severity=Severity.HIGH,
                category=VulnCategory.ENCRYPTION,
                cve="CVE-2009-4664",
                cvss_score=7.5,
                recommendation="Upgrade to WPA2 with CCMP/AES encryption.",
                affected_component="Encryption Protocol",
                details={"protocol": "WPA-TKIP"},
            ))

        # WPA2 with weak cipher
        if "WPA2" in sec_type.upper() and "TKIP" in cipher.upper():
            vulns.append(Vulnerability(
                id="WIFIAIO-003",
                title="WPA2 with TKIP Cipher",
                description="WPA2 using TKIP cipher is weaker than CCMP/AES. "
                           "TKIP is deprecated and has known vulnerabilities.",
                severity=Severity.MEDIUM,
                category=VulnCategory.ENCRYPTION,
                recommendation="Configure WPA2 with CCMP/AES cipher only.",
                affected_component="Cipher Suite",
                details={"cipher": "TKIP"},
            ))

        # Open network
        if sec_type.upper() == "OPEN":
            vulns.append(Vulnerability(
                id="WIFIAIO-004",
                title="Open (Unencrypted) Network",
                description="Network has no encryption. All traffic can be sniffed and modified.",
                severity=Severity.CRITICAL,
                category=VulnCategory.ENCRYPTION,
                recommendation="Enable WPA2 or WPA3 encryption.",
                affected_component="Encryption Protocol",
                details={"protocol": "OPEN"},
            ))

        # WPA3 transition mode
        if "WPA3" not in sec_type.upper() and "WPA2" in sec_type.upper():
            vulns.append(Vulnerability(
                id="WIFIAIO-005",
                title="WPA3 Not Supported",
                description="Network does not support WPA3, which provides enhanced "
                           "security with SAE authentication.",
                severity=Severity.LOW,
                category=VulnCategory.ENCRYPTION,
                recommendation="Consider upgrading to WPA3-capable hardware.",
                affected_component="Authentication Protocol",
                details={"current_protocol": sec_type},
            ))

        # Check for Dragonblood (WPA3 SAE vulnerabilities)
        if "WPA3" in sec_type.upper() or "SAE" in key_mgmt.upper():
            vulns.append(Vulnerability(
                id="WIFIAIO-006",
                title="Potential Dragonblood Vulnerability",
                description="WPA3 SAE implementation may be vulnerable to Dragonblood "
                           "attacks (side-channel, timing, downgrade).",
                severity=Severity.MEDIUM,
                category=VulnCategory.PROTOCOL,
                cve="CVE-2019-9494",
                cvss_score=5.3,
                recommendation="Ensure WPA3 firmware is up to date. "
                              "Verify SAE anti-clogging is enabled.",
                affected_component="WPA3 SAE",
                details={"cve": "CVE-2019-9494"},
            ))

        return vulns

    def _parse_security_from_iw(self, iw_output: str, bssid: str) -> Dict[str, str]:
        """Parse security information from iw scan output."""
        info: Dict[str, str] = {"type": "OPEN", "cipher": "", "key_mgmt": ""}
        in_target = False

        for line in iw_output.splitlines():
            stripped = line.strip()
            if bssid.lower() in stripped.lower():
                in_target = True
                continue
            if stripped.startswith("BSSID") and in_target:
                in_target = False
                continue

            if in_target:
                if "RSN:" in stripped:
                    info["type"] = "WPA2"
                elif "WPA:" in stripped:
                    if info["type"] != "WPA2":
                        info["type"] = "WPA"
                if "cipher" in stripped.lower():
                    if "CCMP" in stripped:
                        info["cipher"] = "CCMP"
                    elif "TKIP" in stripped:
                        info["cipher"] = "TKIP"
                if "authentication" in stripped.lower() or "key_mgmt" in stripped.lower():
                    if "SAE" in stripped:
                        info["key_mgmt"] = "SAE"
                    elif "PSK" in stripped:
                        info["key_mgmt"] = "PSK"
                    elif "802.1X" in stripped or "EAP" in stripped:
                        info["key_mgmt"] = "802.1X"

        return info

    def check_wps(self, bssid: str, channel: int = 0) -> List[Vulnerability]:
        """
        Check WPS vulnerabilities.

        Args:
            bssid: Target AP BSSID.
            channel: Target channel.

        Returns:
            List of WPS-related vulnerabilities.
        """
        vulns: List[Vulnerability] = []

        # Check if WPS is enabled using wash
        output, rc = self._run_command(["wash", "-i", self.interface, "-c", str(channel)])

        if rc == 0 and bssid.lower() in output.lower():
            # WPS is enabled
            vulns.append(Vulnerability(
                id="WIFIAIO-010",
                title="WPS Enabled",
                description="WPS is enabled on this access point. WPS is vulnerable to "
                           "brute-force attacks and Pixie Dust attacks.",
                severity=Severity.HIGH,
                category=VulnCategory.WPS,
                cve="CVE-2014-6313",
                cvss_score=7.8,
                recommendation="Disable WPS on the access point.",
                affected_component="WPS",
            ))

            # Check for WPS lock
            if "Locked" in output or "Lckd" in output:
                vulns.append(Vulnerability(
                    id="WIFIAIO-011",
                    title="WPS Lock Detected",
                    description="WPS is locked, indicating previous brute-force attempts. "
                               "This may indicate the AP is vulnerable.",
                    severity=Severity.MEDIUM,
                    category=VulnCategory.WPS,
                    recommendation="Disable WPS entirely rather than relying on lockout.",
                    affected_component="WPS Lock",
                ))

        return vulns

    def check_default_credentials(self, bssid: str, ssid: str = "",
                                   vendor: str = "") -> List[Vulnerability]:
        """
        Check for default credentials based on vendor/SSID.

        Args:
            bssid: Target AP BSSID.
            ssid: Target SSID.
            vendor: Known vendor name.

        Returns:
            List of default credential vulnerabilities.
        """
        vulns: List[Vulnerability] = []

        # Try to determine vendor from SSID patterns
        detected_vendor = vendor.lower()
        ssid_lower = ssid.lower()

        if not detected_vendor:
            vendor_patterns = {
                "linksys": ["linksys"],
                "netgear": ["netgear", "ng-"],
                "d-link": ["dlink", "dir-"],
                "tp-link": ["tp-link", "tplink"],
                "asus": ["asus"],
                "cisco": ["cisco"],
                "belkin": ["belkin"],
                "technicolor": ["technicolor"],
                "huawei": ["huawei"],
                "xiaomi": ["xiaomi", "mi-"],
            }
            for vendor_name, patterns in vendor_patterns.items():
                for pattern in patterns:
                    if pattern in ssid_lower:
                        detected_vendor = vendor_name
                        break
                if detected_vendor:
                    break

        if detected_vendor and detected_vendor in DEFAULT_CREDENTIALS_DB:
            creds = DEFAULT_CREDENTIALS_DB[detected_vendor]
            cred_list = [
                f"{c['username']}:{c['password']}" if c['username'] else f":{c['password']}"
                for c in creds
            ]
            vulns.append(Vulnerability(
                id="WIFIAIO-020",
                title="Default Credentials Likely",
                description=f"Based on vendor ({detected_vendor}), this device likely uses "
                           f"default credentials: {', '.join(cred_list)}",
                severity=Severity.HIGH,
                category=VulnCategory.DEFAULT_CREDENTIALS,
                recommendation="Change all default passwords immediately.",
                affected_component="Web Administration",
                details={
                    "vendor": detected_vendor,
                    "possible_credentials": creds,
                },
            ))

        return vulns

    def check_dns_hijack(self) -> List[Vulnerability]:
        """
        Check for DNS hijacking on the current network.

        Returns:
            List of DNS hijack vulnerabilities.
        """
        vulns: List[Vulnerability] = []

        # Test DNS resolution
        dns_servers = self._get_dns_servers()
        for dns_server in dns_servers:
            # Check if DNS server is on local network (router)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(3)
                    # Send a DNS query for a known domain
                    import struct
                    # Build DNS query for example.com
                    txid = os.urandom(2)
                    flags = struct.pack(">H", 0x0100)  # Standard query
                    qdcount = struct.pack(">H", 1)
                    ancount = struct.pack(">H", 0)
                    nscount = struct.pack(">H", 0)
                    arcount = struct.pack(">H", 0)
                    query = txid + flags + qdcount + ancount + nscount + arcount
                    # QNAME for example.com
                    query += b"\x07example\x03com\x00"
                    query += struct.pack(">HH", 1, 1)  # Type A, Class IN

                    s.sendto(query, (dns_server, 53))
                    data, addr = s.recvfrom(512)

                    # Check if response came from expected server
                    if addr[0] != dns_server:
                        vulns.append(Vulnerability(
                            id="WIFIAIO-030",
                            title="DNS Hijacking Detected",
                            description=f"DNS response came from {addr[0]} instead of "
                                       f"expected server {dns_server}",
                            severity=Severity.HIGH,
                            category=VulnCategory.DNS,
                            recommendation="Verify DNS configuration and check for rogue "
                                          "DNS servers on the network.",
                            affected_component="DNS Resolution",
                            details={"expected": dns_server, "actual": addr[0]},
                        ))
            except (socket.timeout, OSError):
                pass

        # Check if common domains resolve to internal IPs
        test_domains = ["google.com", "cloudflare.com"]
        for domain in test_domains:
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                for ip in ips:
                    if ip.startswith(("10.", "172.16.", "192.168.")):
                        vulns.append(Vulnerability(
                            id="WIFIAIO-031",
                            title="DNS Hijacking - Internal IP Resolution",
                            description=f"{domain} resolves to internal IP {ip}, "
                                       f"indicating possible DNS hijacking.",
                            severity=Severity.HIGH,
                            category=VulnCategory.DNS,
                            recommendation="Check DNS server configuration for tampering.",
                            affected_component="DNS Resolution",
                            details={"domain": domain, "resolved_ip": ip},
                        ))
            except socket.gaierror:
                pass

        return vulns

    def _get_dns_servers(self) -> List[str]:
        """Get current DNS server addresses."""
        servers = []
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
        except OSError:
            pass
        return servers

    def check_krack(self, bssid: str, channel: int = 0) -> List[Vulnerability]:
        """
        Check for KRACK (Key Reinstallation Attacks) vulnerability.

        KRACK affects WPA2 by exploiting the 4-way handshake to reinstall
        an already-in-use encryption key.

        Args:
            bssid: Target AP BSSID.
            channel: Target channel.

        Returns:
            List of KRACK vulnerabilities.
        """
        vulns: List[Vulnerability] = []

        # Check if the AP supports WPA2 (which is vulnerable to KRACK)
        output, rc = self._run_command(["iw", "dev", self.interface, "scan"])

        if rc == 0:
            in_target = False
            has_wpa2 = False

            for line in output.splitlines():
                stripped = line.strip()
                if bssid.lower() in stripped.lower():
                    in_target = True
                    continue
                if stripped.startswith("BSSID") and in_target:
                    in_target = False
                    continue

                if in_target:
                    if "RSN:" in stripped or "WPA2" in stripped:
                        has_wpa2 = True

            if has_wpa2:
                # All WPA2 implementations are potentially vulnerable unless patched
                vulns.append(Vulnerability(
                    id="WIFIAIO-040",
                    title="WPA2 KRACK Vulnerability",
                    description="WPA2 is potentially vulnerable to Key Reinstallation "
                               "Attacks (KRACK). This allows attackers to decrypt packets, "
                               "inject packets, and hijack connections.",
                    severity=Severity.HIGH,
                    category=VulnCategory.KRACK,
                    cve="CVE-2017-13080",
                    cvss_score=6.5,
                    recommendation="Ensure all devices have KRACK patches applied. "
                                  "Upgrade to WPA3 where possible.",
                    affected_component="WPA2 4-Way Handshake",
                    details={
                        "cve": "CVE-2017-13080",
                        "related_cves": [
                            "CVE-2017-13077", "CVE-2017-13078",
                            "CVE-2017-13079", "CVE-2017-13081",
                            "CVE-2017-13082", "CVE-2017-13084",
                            "CVE-2017-13086", "CVE-2017-13087",
                            "CVE-2017-13088",
                        ],
                    },
                ))

        return vulns

    def check_pmf(self, bssid: str, ssid: str = "",
                   channel: int = 0) -> List[Vulnerability]:
        """
        Check Protected Management Frames (PMF) status.

        PMF prevents deauthentication and disassociation frame spoofing.

        Args:
            bssid: Target AP BSSID.
            ssid: Target SSID.
            channel: Target channel.

        Returns:
            List of PMF-related vulnerabilities.
        """
        vulns: List[Vulnerability] = []

        output, rc = self._run_command(["iw", "dev", self.interface, "scan"])

        if rc == 0:
            in_target = False
            pmf_required = False
            pmf_capable = False

            for line in output.splitlines():
                stripped = line.strip()
                if bssid.lower() in stripped.lower():
                    in_target = True
                    continue
                if stripped.startswith("BSSID") and in_target:
                    in_target = False
                    continue

                if in_target:
                    if "MFP required" in stripped or "PMF required" in stripped:
                        pmf_required = True
                    elif "MFP capable" in stripped or "PMF capable" in stripped:
                        pmf_capable = True

            if not pmf_capable and not pmf_required:
                vulns.append(Vulnerability(
                    id="WIFIAIO-050",
                    title="Protected Management Frames Not Supported",
                    description="PMF is not supported on this AP. This allows "
                               "easy deauthentication and disassociation attacks.",
                    severity=Severity.MEDIUM,
                    category=VulnCategory.PMF,
                    cve="CVE-2019-16646",
                    cvss_score=5.3,
                    recommendation="Enable PMF (802.11w) on the access point.",
                    affected_component="Management Frame Protection",
                ))
            elif pmf_capable and not pmf_required:
                vulns.append(Vulnerability(
                    id="WIFIAIO-051",
                    title="PMF Capable But Not Required",
                    description="PMF is supported but not mandatory. Clients that "
                               "don't negotiate PMF remain vulnerable to deauth attacks.",
                    severity=Severity.LOW,
                    category=VulnCategory.PMF,
                    recommendation="Set PMF to 'required' instead of 'optional'.",
                    affected_component="Management Frame Protection",
                ))

        return vulns

    def check_rogue_dhcp(self) -> List[Vulnerability]:
        """
        Check for rogue DHCP servers on the network.

        Returns:
            List of rogue DHCP vulnerabilities.
        """
        vulns: List[Vulnerability] = []

        try:
            # Send DHCP discover and check for multiple responses
            # Use nmap for DHCP discovery
            output, rc = self._run_command(
                ["nmap", "--script", "broadcast-dhcp-discover", "-e", self.interface],
                timeout=15
            )

            if rc == 0:
                # Count DHCP offers
                offer_count = output.count("DHCPOFFER")
                if offer_count > 1:
                    # Extract offered IPs and servers
                    servers = re.findall(r"Server Identifier:\s*(\S+)", output)
                    vulns.append(Vulnerability(
                        id="WIFIAIO-060",
                        title="Rogue DHCP Server Detected",
                        description=f"Multiple DHCP servers detected ({offer_count} offers). "
                                   f"Servers: {', '.join(servers)}",
                        severity=Severity.HIGH,
                        category=VulnCategory.ROGUE,
                        recommendation="Identify and disable unauthorized DHCP servers. "
                                      "Enable DHCP snooping on managed switches.",
                        affected_component="DHCP Service",
                        details={"servers": servers},
                    ))
        except WiFiTimeoutError:
            pass

        return vulns

    def check_cve(self, cve_id: str) -> Vulnerability:
        """
        Check a specific CVE and return normalized severity.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2017-13080").

        Returns:
            Vulnerability with normalized severity.
        """
        # Try to look up CVE from local database
        cve_db = self._get_local_cve_db()

        if cve_id in cve_db:
            entry = cve_db[cve_id]
            return Vulnerability(
                id=f"WIFIAIO-CVE-{cve_id}",
                title=entry.get("title", cve_id),
                description=entry.get("description", ""),
                severity=_normalize_severity(entry.get("severity", "medium")),
                category=VulnCategory.PROTOCOL,
                cve=cve_id,
                cvss_score=entry.get("cvss", 0.0),
                recommendation=entry.get("recommendation", "Apply vendor patches."),
                affected_component=entry.get("component", ""),
            )

        # Unknown CVE
        return Vulnerability(
            id=f"WIFIAIO-CVE-{cve_id}",
            title=f"Unknown CVE: {cve_id}",
            description="CVE not found in local database.",
            severity=Severity.MEDIUM,
            category=VulnCategory.PROTOCOL,
            cve=cve_id,
        )

    def _get_local_cve_db(self) -> Dict[str, Dict[str, Any]]:
        """Get local CVE database with WiFi-related CVEs."""
        return {
            "CVE-2017-13080": {
                "title": "KRACK - WPA2 Key Reinstallation",
                "description": "Vulnerability in WPA2 4-way handshake",
                "severity": "high",
                "cvss": 6.5,
                "recommendation": "Apply vendor patches, upgrade to WPA3",
                "component": "WPA2 4-Way Handshake",
            },
            "CVE-2019-9494": {
                "title": "Dragonblood - WPA3 SAE",
                "description": "Side-channel attack on WPA3 SAE",
                "severity": "medium",
                "cvss": 5.3,
                "recommendation": "Update WPA3 firmware",
                "component": "WPA3 SAE",
            },
            "CVE-2014-6313": {
                "title": "WPS Brute Force",
                "description": "WPS PIN brute-force vulnerability",
                "severity": "high",
                "cvss": 7.8,
                "recommendation": "Disable WPS",
                "component": "WPS",
            },
            "CVE-2001-0466": {
                "title": "WEP Encryption Weakness",
                "description": "Fundamental weaknesses in WEP encryption",
                "severity": "critical",
                "cvss": 9.8,
                "recommendation": "Migrate to WPA2/WPA3",
                "component": "WEP",
            },
            "CVE-2009-4664": {
                "title": "WPA-TKIP Beck-Tews Attack",
                "description": "TKIP key recovery attack",
                "severity": "medium",
                "cvss": 5.8,
                "recommendation": "Use CCMP/AES instead of TKIP",
                "component": "WPA-TKIP",
            },
            "CVE-2019-16646": {
                "title": "Unprotected Management Frames",
                "description": "Lack of PMF allows deauth attacks",
                "severity": "medium",
                "cvss": 5.3,
                "recommendation": "Enable PMF/802.11w",
                "component": "Management Frames",
            },
        }

    def export_report(self, result: AuditResult, filepath: str,
                      format: str = "json") -> None:
        """
        Export audit report to file.

        Args:
            result: Audit result to export.
            filepath: Output file path.
            format: Output format ('json' or 'html').
        """
        if format == "json":
            try:
                with open(filepath, "w") as f:
                    json.dump(result.to_dict(), f, indent=2, default=str)
                logger.info("Exported report to %s", filepath)
            except OSError as e:
                raise VulnScanError(f"Failed to export report: {e}")

        elif format == "html":
            try:
                with open(filepath, "w") as f:
                    f.write(self._generate_html_report(result))
                logger.info("Exported HTML report to %s", filepath)
            except OSError as e:
                raise VulnScanError(f"Failed to export HTML report: {e}")

    def _generate_html_report(self, result: AuditResult) -> str:
        """Generate HTML audit report."""
        severity_colors = {
            Severity.CRITICAL: "#dc3545",
            Severity.HIGH: "#fd7e14",
            Severity.MEDIUM: "#ffc107",
            Severity.LOW: "#28a745",
            Severity.INFO: "#17a2b8",
        }

        html = f"""<!DOCTYPE html>
<html><head><title>WiFiAIO Vulnerability Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }}
.header {{ background: #343a40; color: white; padding: 20px; border-radius: 5px; }}
.score {{ font-size: 48px; font-weight: bold; }}
.vuln {{ background: white; padding: 15px; margin: 10px 0; border-radius: 5px;
         border-left: 5px solid; }}
.severity-tag {{ color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
</style></head><body>
<div class="header">
<h1>WiFiAIO Vulnerability Report</h1>
<p>Target: {result.target_ssid} ({result.target_bssid})</p>
<p>Score: <span class="score" style="color: {
            '#dc3545' if result.score < 50 else '#fd7e14' if result.score < 75 else '#28a745'
        }">{result.score}/100</span></p>
<p>Scan Duration: {result.scan_duration:.1f}s</p>
</div>
<h2>Vulnerabilities ({len(result.vulnerabilities)} found)</h2>
"""
        for vuln in result.vulnerabilities:
            color = severity_colors.get(vuln.severity, "#6c757d")
            html += f"""
<div class="vuln" style="border-left-color: {color}">
<h3>{vuln.title} <span class="severity-tag" style="background: {color}">{
                vuln.severity.value.upper()
            }</span></h3>
<p>{vuln.description}</p>
<p><strong>Recommendation:</strong> {vuln.recommendation}</p>
{'<p><strong>CVE:</strong> ' + vuln.cve + '</p>' if vuln.cve else ''}
{'<p><strong>CVSS:</strong> ' + str(vuln.cvss_score) + '</p>' if vuln.cvss_score else ''}
</div>"""

        html += "</body></html>"
        return html

    def stop(self) -> None:
        """Stop the vulnerability scan."""
        self._running = False
        logger.info("Vulnerability scanner stopped")
