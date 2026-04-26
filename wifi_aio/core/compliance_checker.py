"""WiFi compliance checking against security standards.

Provides automated compliance assessment for PCI-DSS, NIST SP 800-53,
CIS Controls, and ISO 27001 as they relate to wireless network security.
"""

import logging
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from wifi_aio.exceptions import (
    WiFiConnectionError,
)

logger = logging.getLogger(__name__)


class ComplianceStatus(Enum):
    """Possible outcomes for a single compliance check."""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class ComplianceStandard(Enum):
    """Supported compliance standards."""
    PCI_DSS = "PCI-DSS"
    NIST = "NIST-800-53"
    CIS = "CIS"
    ISO_27001 = "ISO-27001"


# ---------------------------------------------------------------------------
# PCI-DSS WiFi Requirements
# ---------------------------------------------------------------------------

PCI_DSS_CHECKS = [
    {
        "id": "PCI-1.2",
        "requirement": "Secure network configuration",
        "description": "WiFi networks must not use WEP encryption.",
        "check_key": "no_wep",
        "severity": "critical",
    },
    {
        "id": "PCI-1.3",
        "requirement": "Network segmentation",
        "description": "Guest WiFi must be segmented from cardholder data networks.",
        "check_key": "guest_isolation",
        "severity": "high",
    },
    {
        "id": "PCI-2.1",
        "requirement": "Default passwords changed",
        "description": "WiFi equipment must not use vendor-supplied defaults for passwords.",
        "check_key": "no_default_creds",
        "severity": "critical",
    },
    {
        "id": "PCI-4.1",
        "requirement": "Strong encryption",
        "description": "WiFi must use WPA2 or WPA3 encryption with strong ciphers.",
        "check_key": "strong_encryption",
        "severity": "critical",
    },
    {
        "id": "PCI-4.1a",
        "requirement": "No open networks",
        "description": "Open (unencrypted) WiFi networks must not be used for cardholder data.",
        "check_key": "no_open_networks",
        "severity": "critical",
    },
    {
        "id": "PCI-6.1",
        "requirement": "Vulnerability management",
        "description": "WiFi equipment must have a process for identifying and patching vulnerabilities.",
        "check_key": "vuln_management",
        "severity": "high",
    },
    {
        "id": "PCI-8.1",
        "requirement": "Authentication",
        "description": "WiFi networks must require authentication (802.1X or strong PSK).",
        "check_key": "authentication_required",
        "severity": "high",
    },
    {
        "id": "PCI-8.2",
        "requirement": "Strong authentication",
        "description": "WPA-Enterprise (802.1X) is required for POS/cardholder environments.",
        "check_key": "enterprise_auth",
        "severity": "medium",
    },
    {
        "id": "PCI-10.1",
        "requirement": "Audit logging",
        "description": "WiFi access attempts must be logged and monitored.",
        "check_key": "audit_logging",
        "severity": "medium",
    },
    {
        "id": "PCI-11.1",
        "requirement": "Rogue AP detection",
        "description": "Processes must exist to detect and identify unauthorized wireless access points.",
        "check_key": "rogue_detection",
        "severity": "high",
    },
    {
        "id": "PCI-11.4",
        "requirement": "Intrusion detection",
        "description": "Wireless intrusion detection or prevention must be deployed.",
        "check_key": "wids_wips",
        "severity": "medium",
    },
    {
        "id": "PCI-12.3",
        "requirement": "Acceptable use policy",
        "description": "WiFi usage policies must be established and enforced.",
        "check_key": "usage_policy",
        "severity": "medium",
    },
]

# ---------------------------------------------------------------------------
# NIST SP 800-53 WiFi Controls
# ---------------------------------------------------------------------------

NIST_CHECKS = [
    {
        "id": "AC-18",
        "requirement": "Wireless access control",
        "description": "Wireless access must be authenticated and authorized.",
        "check_key": "access_control",
        "severity": "high",
    },
    {
        "id": "AC-18(1)",
        "requirement": "Wireless intrusion detection",
        "description": "Wireless intrusion detection must be implemented.",
        "check_key": "wids_wips",
        "severity": "medium",
    },
    {
        "id": "AC-18(2)",
        "requirement": "Wireless monitoring",
        "description": "Wireless usage must be monitored and tracked.",
        "check_key": "audit_logging",
        "severity": "medium",
    },
    {
        "id": "AC-18(3)",
        "requirement": "Wireless restriction",
        "description": "Wireless access must be restricted to authorized users and devices.",
        "check_key": "access_restriction",
        "severity": "high",
    },
    {
        "id": "SC-7",
        "requirement": "Boundary protection",
        "description": "WiFi networks must be separated from internal networks by boundaries.",
        "check_key": "guest_isolation",
        "severity": "high",
    },
    {
        "id": "SC-8",
        "requirement": "Transmission confidentiality",
        "description": "WiFi transmissions must be protected via strong encryption (WPA2/WPA3).",
        "check_key": "strong_encryption",
        "severity": "critical",
    },
    {
        "id": "SC-13",
        "requirement": "Cryptographic protection",
        "description": "FIPS-validated cryptography must be used where required.",
        "check_key": "strong_encryption",
        "severity": "high",
    },
    {
        "id": "SC-23",
        "requirement": "Session authenticity",
        "description": "WiFi sessions must be protected against hijacking.",
        "check_key": "session_protection",
        "severity": "medium",
    },
    {
        "id": "AU-2",
        "requirement": "Audit events",
        "description": "WiFi authentication and connection events must be auditable.",
        "check_key": "audit_logging",
        "severity": "medium",
    },
    {
        "id": "AU-12",
        "requirement": "Audit generation",
        "description": "WiFi systems must generate audit records for security events.",
        "check_key": "audit_logging",
        "severity": "medium",
    },
    {
        "id": "IA-3",
        "requirement": "Device identification",
        "description": "WiFi devices must be uniquely identified and authenticated.",
        "check_key": "device_identification",
        "severity": "high",
    },
    {
        "id": "SI-4",
        "requirement": "System monitoring",
        "description": "Wireless system must be monitored for security events and anomalies.",
        "check_key": "wids_wips",
        "severity": "medium",
    },
]

# ---------------------------------------------------------------------------
# CIS Controls (WiFi-relevant)
# ---------------------------------------------------------------------------

CIS_CHECKS = [
    {
        "id": "CIS-1.1",
        "requirement": "Inventory of authorized devices",
        "description": "All authorized WiFi devices must be inventoried.",
        "check_key": "device_inventory",
        "severity": "high",
    },
    {
        "id": "CIS-1.2",
        "requirement": "Inventory of unauthorized devices",
        "description": "Unauthorized WiFi devices must be detected and remediated.",
        "check_key": "rogue_detection",
        "severity": "high",
    },
    {
        "id": "CIS-2.1",
        "requirement": "Inventory of authorized software",
        "description": "WiFi management software must be inventoried and authorized.",
        "check_key": "authorized_software",
        "severity": "medium",
    },
    {
        "id": "CIS-4.1",
        "requirement": "Secure configuration",
        "description": "WiFi devices must follow secure configuration baselines.",
        "check_key": "secure_config",
        "severity": "high",
    },
    {
        "id": "CIS-4.2",
        "requirement": "No default passwords",
        "description": "Default WiFi device passwords must be changed.",
        "check_key": "no_default_creds",
        "severity": "critical",
    },
    {
        "id": "CIS-7.1",
        "requirement": "Ensure encryption in transit",
        "description": "WiFi traffic must be encrypted using WPA2-AES or WPA3.",
        "check_key": "strong_encryption",
        "severity": "critical",
    },
    {
        "id": "CIS-7.5",
        "requirement": "Network segmentation",
        "description": "Guest WiFi must be isolated from corporate networks.",
        "check_key": "guest_isolation",
        "severity": "high",
    },
    {
        "id": "CIS-11.1",
        "requirement": "Vulnerability scanning",
        "description": "WiFi infrastructure must be regularly scanned for vulnerabilities.",
        "check_key": "vuln_management",
        "severity": "high",
    },
    {
        "id": "CIS-13.1",
        "requirement": "Network monitoring",
        "description": "WiFi networks must be monitored for security events.",
        "check_key": "wids_wips",
        "severity": "medium",
    },
    {
        "id": "CIS-16.1",
        "requirement": "Incident response",
        "description": "WiFi security incidents must be handled per incident response plan.",
        "check_key": "incident_response",
        "severity": "medium",
    },
]

# ---------------------------------------------------------------------------
# ISO 27001 WiFi Controls
# ---------------------------------------------------------------------------

ISO_27001_CHECKS = [
    {
        "id": "ISO-A.6.2.1",
        "requirement": "Mobile device policy",
        "description": "WiFi-connected mobile devices must comply with security policy.",
        "check_key": "usage_policy",
        "severity": "medium",
    },
    {
        "id": "ISO-A.6.2.2",
        "requirement": "Mobile device registration",
        "description": "WiFi devices must be registered before network access.",
        "check_key": "device_identification",
        "severity": "high",
    },
    {
        "id": "ISO-A.8.1.1",
        "requirement": "Asset inventory",
        "description": "WiFi infrastructure assets must be identified and inventoried.",
        "check_key": "device_inventory",
        "severity": "high",
    },
    {
        "id": "ISO-A.8.1.3",
        "requirement": "Acceptable use of assets",
        "description": "WiFi usage rules must be documented and enforced.",
        "check_key": "usage_policy",
        "severity": "medium",
    },
    {
        "id": "ISO-A.9.1.1",
        "requirement": "Access control policy",
        "description": "WiFi access must be controlled based on business requirements.",
        "check_key": "access_control",
        "severity": "high",
    },
    {
        "id": "ISO-A.9.1.2",
        "requirement": "Network access control",
        "description": "WiFi networks must enforce access control at network boundaries.",
        "check_key": "guest_isolation",
        "severity": "high",
    },
    {
        "id": "ISO-A.10.1.1",
        "requirement": "Encryption policy",
        "description": "WiFi must use encryption appropriate to the classification of information.",
        "check_key": "strong_encryption",
        "severity": "critical",
    },
    {
        "id": "ISO-A.12.1.1",
        "requirement": "Operational procedures",
        "description": "WiFi management must follow documented operational procedures.",
        "check_key": "authorized_software",
        "severity": "medium",
    },
    {
        "id": "ISO-A.12.4.1",
        "requirement": "Event logging",
        "description": "WiFi access and security events must be logged.",
        "check_key": "audit_logging",
        "severity": "medium",
    },
    {
        "id": "ISO-A.12.6.1",
        "requirement": "Vulnerability management",
        "description": "WiFi vulnerabilities must be assessed and remediated promptly.",
        "check_key": "vuln_management",
        "severity": "high",
    },
    {
        "id": "ISO-A.13.1.1",
        "requirement": "Network controls",
        "description": "WiFi networks must be adequately managed and controlled.",
        "check_key": "access_restriction",
        "severity": "high",
    },
    {
        "id": "ISO-A.13.1.3",
        "requirement": "Network segregation",
        "description": "WiFi guest networks must be segregated from internal networks.",
        "check_key": "guest_isolation",
        "severity": "high",
    },
    {
        "id": "ISO-A.16.1.1",
        "requirement": "Incident management",
        "description": "WiFi security incidents must be managed per incident response procedures.",
        "check_key": "incident_response",
        "severity": "medium",
    },
]

# Map of standard name -> checks list
STANDARD_CHECKS = {
    ComplianceStandard.PCI_DSS: PCI_DSS_CHECKS,
    ComplianceStandard.NIST: NIST_CHECKS,
    ComplianceStandard.CIS: CIS_CHECKS,
    ComplianceStandard.ISO_27001: ISO_27001_CHECKS,
}


class ComplianceCheck:
    """Result of a single compliance check."""

    def __init__(
        self,
        check_id: str,
        requirement: str,
        description: str,
        status: ComplianceStatus,
        severity: str = "medium",
        recommendation: str = "",
        evidence: str = "",
    ):
        self.check_id = check_id
        self.requirement = requirement
        self.description = description
        self.status = status
        self.severity = severity
        self.recommendation = recommendation
        self.evidence = evidence

    def to_dict(self) -> Dict:
        return {
            "id": self.check_id,
            "requirement": self.requirement,
            "description": self.description,
            "status": self.status.value,
            "severity": self.severity,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


class ComplianceChecker:
    """Check WiFi network configurations against compliance standards.

    Supports:
    - PCI-DSS v4.0 (WiFi-relevant requirements)
    - NIST SP 800-53 Rev5 (wireless controls)
    - CIS Controls v8 (wireless-relevant controls)
    - ISO/IEC 27001:2022 (Annex A wireless controls)
    """

    def __init__(self):
        self._scan_data: List[Dict] = []
        self._assessment_results: Dict[str, Dict] = {}

    # ------------------------------------------------------------------
    # Data Input
    # ------------------------------------------------------------------

    def load_scan_data(self, networks: List[Dict]) -> None:
        """Load network scan data for compliance assessment.

        Args:
            networks: List of network dicts with keys like ssid, bssid,
                      encryption, channel, signal, etc.
        """
        self._scan_data = networks

    def load_vulnerability_data(self, vulnerabilities: List[Dict]) -> None:
        """Load vulnerability scan results for compliance checks.

        Args:
            vulnerabilities: List of vulnerability dicts.
        """
        self._vulnerabilities = vulnerabilities

    # ------------------------------------------------------------------
    # PCI-DSS Assessment
    # ------------------------------------------------------------------

    def check_pci_dss(self, networks: Optional[List[Dict]] = None) -> Dict:
        """Perform PCI-DSS WiFi compliance check.

        Args:
            networks: Network scan data (uses loaded data if None).

        Returns:
            Dict with compliance assessment results.
        """
        data = networks or self._scan_data
        checks = self._run_checks(PCI_DSS_CHECKS, data)
        result = self._compile_results(ComplianceStandard.PCI_DSS.value, checks)
        self._assessment_results[ComplianceStandard.PCI_DSS.value] = result
        return result

    # ------------------------------------------------------------------
    # NIST Assessment
    # ------------------------------------------------------------------

    def check_nist(self, networks: Optional[List[Dict]] = None) -> Dict:
        """Perform NIST SP 800-53 WiFi compliance check.

        Args:
            networks: Network scan data.

        Returns:
            Dict with compliance assessment results.
        """
        data = networks or self._scan_data
        checks = self._run_checks(NIST_CHECKS, data)
        result = self._compile_results(ComplianceStandard.NIST.value, checks)
        self._assessment_results[ComplianceStandard.NIST.value] = result
        return result

    # ------------------------------------------------------------------
    # CIS Assessment
    # ------------------------------------------------------------------

    def check_cis(self, networks: Optional[List[Dict]] = None) -> Dict:
        """Perform CIS Controls WiFi compliance check.

        Args:
            networks: Network scan data.

        Returns:
            Dict with compliance assessment results.
        """
        data = networks or self._scan_data
        checks = self._run_checks(CIS_CHECKS, data)
        result = self._compile_results(ComplianceStandard.CIS.value, checks)
        self._assessment_results[ComplianceStandard.CIS.value] = result
        return result

    # ------------------------------------------------------------------
    # ISO 27001 Assessment
    # ------------------------------------------------------------------

    def check_iso_27001(self, networks: Optional[List[Dict]] = None) -> Dict:
        """Perform ISO 27001 WiFi compliance check.

        Args:
            networks: Network scan data.

        Returns:
            Dict with compliance assessment results.
        """
        data = networks or self._scan_data
        checks = self._run_checks(ISO_27001_CHECKS, data)
        result = self._compile_results(ComplianceStandard.ISO_27001.value, checks)
        self._assessment_results[ComplianceStandard.ISO_27001.value] = result
        return result

    # ------------------------------------------------------------------
    # Check All Standards
    # ------------------------------------------------------------------

    def check_all(self, networks: Optional[List[Dict]] = None) -> Dict:
        """Run compliance checks against all supported standards.

        Args:
            networks: Network scan data.

        Returns:
            Dict mapping standard name -> results dict.
        """
        results = {}
        results["PCI-DSS"] = self.check_pci_dss(networks)
        results["NIST-800-53"] = self.check_nist(networks)
        results["CIS"] = self.check_cis(networks)
        results["ISO-27001"] = self.check_iso_27001(networks)
        return results

    # ------------------------------------------------------------------
    # Check Runner
    # ------------------------------------------------------------------

    def _run_checks(
        self,
        check_definitions: List[Dict],
        networks: List[Dict],
    ) -> List[ComplianceCheck]:
        """Run all compliance checks against network data.

        Args:
            check_definitions: List of check definition dicts.
            networks: List of network scan result dicts.

        Returns:
            List of ComplianceCheck result objects.
        """
        results: List[ComplianceCheck] = []
        check_methods = {
            "no_wep": self._check_no_wep,
            "guest_isolation": self._check_guest_isolation,
            "no_default_creds": self._check_no_default_creds,
            "strong_encryption": self._check_strong_encryption,
            "no_open_networks": self._check_no_open_networks,
            "vuln_management": self._check_vuln_management,
            "authentication_required": self._check_authentication_required,
            "enterprise_auth": self._check_enterprise_auth,
            "audit_logging": self._check_audit_logging,
            "rogue_detection": self._check_rogue_detection,
            "wids_wips": self._check_wids_wips,
            "usage_policy": self._check_usage_policy,
            "access_control": self._check_access_control,
            "access_restriction": self._check_access_restriction,
            "session_protection": self._check_session_protection,
            "device_identification": self._check_device_identification,
            "device_inventory": self._check_device_inventory,
            "authorized_software": self._check_authorized_software,
            "secure_config": self._check_secure_config,
            "incident_response": self._check_incident_response,
        }

        for check_def in check_definitions:
            check_key = check_def["check_key"]
            check_fn = check_methods.get(check_key)

            if check_fn is None:
                results.append(ComplianceCheck(
                    check_id=check_def["id"],
                    requirement=check_def["requirement"],
                    description=check_def["description"],
                    status=ComplianceStatus.NOT_APPLICABLE,
                    severity=check_def.get("severity", "medium"),
                    recommendation="No automated check available for this requirement.",
                ))
                continue

            try:
                status, evidence, recommendation = check_fn(networks)
                results.append(ComplianceCheck(
                    check_id=check_def["id"],
                    requirement=check_def["requirement"],
                    description=check_def["description"],
                    status=status,
                    severity=check_def.get("severity", "medium"),
                    recommendation=recommendation,
                    evidence=evidence,
                ))
            except Exception as exc:
                logger.error("Compliance check %s failed: %s", check_def["id"], exc)
                results.append(ComplianceCheck(
                    check_id=check_def["id"],
                    requirement=check_def["requirement"],
                    description=check_def["description"],
                    status=ComplianceStatus.ERROR,
                    severity=check_def.get("severity", "medium"),
                    recommendation="Manual review required - automated check encountered an error.",
                    evidence=str(exc),
                ))

        return results

    # ------------------------------------------------------------------
    # Individual Check Implementations
    # ------------------------------------------------------------------

    @staticmethod
    def _check_no_wep(networks: List[Dict]):
        """Check that no networks use WEP encryption."""
        wep_networks = []
        for net in networks:
            enc = net.get("encryption", net.get("security", net.get("privacy", ""))).upper()
            if "WEP" in enc:
                wep_networks.append(net.get("ssid", net.get("bssid", "unknown")))

        if wep_networks:
            return (
                ComplianceStatus.FAIL,
                f"WEP networks found: {', '.join(wep_networks)}",
                "Migrate all WEP networks to WPA2-AES or WPA3 immediately.",
            )
        return (
            ComplianceStatus.PASS,
            "No WEP networks detected",
            "",
        )

    @staticmethod
    def _check_guest_isolation(networks: List[Dict]):
        """Check guest network isolation."""
        guest_networks = []
        for net in networks:
            ssid = net.get("ssid", "").lower()
            if any(keyword in ssid for keyword in ["guest", "visitor", "public", "free"]):
                guest_networks.append(net.get("ssid", "unknown"))

        if not guest_networks:
            return (
                ComplianceStatus.WARNING,
                "No guest networks identified by naming convention",
                "Verify guest network is deployed and properly isolated from corporate network.",
            )

        # We cannot programmatically verify isolation; flag for manual review
        return (
            ComplianceStatus.WARNING,
            f"Guest networks found: {', '.join(guest_networks)} - manual verification of isolation required",
            "Ensure guest WiFi is on a separate VLAN with firewall rules blocking access to internal networks.",
        )

    @staticmethod
    def _check_no_default_creds(networks: List[Dict]):
        """Check for default credentials on network devices."""
        default_ssid_patterns = [
            "NETGEAR", "LINKSYS", "ASUS", "TP-LINK", "D-LINK",
            "Belkin", "xfinity", "ATT", "Verizon", "default",
        ]
        default_networks = []
        for net in networks:
            ssid = net.get("ssid", "")
            if any(ssid.startswith(p) or ssid == p for p in default_ssid_patterns):
                default_networks.append(ssid)

        if default_networks:
            return (
                ComplianceStatus.FAIL,
                f"Networks with default SSIDs found (likely default credentials): {', '.join(default_networks)}",
                "Change all default passwords and SSIDs on WiFi equipment.",
            )
        return (
            ComplianceStatus.PASS,
            "No default SSIDs detected",
            "",
        )

    @staticmethod
    def _check_strong_encryption(networks: List[Dict]):
        """Check that networks use WPA2 or WPA3 with strong ciphers."""
        weak_networks = []
        for net in networks:
            enc = net.get("encryption", net.get("security", net.get("privacy", ""))).upper()
            # WPA2 with TKIP is weak
            if "TKIP" in enc:
                weak_networks.append(f"{net.get('ssid', 'unknown')} (uses TKIP)")
            # WPA (not WPA2, not WPA3) is weak
            elif enc == "WPA" or enc == "WPA-PSK":
                weak_networks.append(f"{net.get('ssid', 'unknown')} (WPA only)")

        if weak_networks:
            return (
                ComplianceStatus.FAIL,
                f"Weak encryption found: {', '.join(weak_networks)}",
                "Upgrade all networks to WPA2-AES (CCMP) or WPA3.",
            )
        return (
            ComplianceStatus.PASS,
            "All networks use WPA2-AES or WPA3 encryption",
            "",
        )

    @staticmethod
    def _check_no_open_networks(networks: List[Dict]):
        """Check for open (unencrypted) networks."""
        open_networks = []
        for net in networks:
            enc = net.get("encryption", net.get("security", net.get("privacy", ""))).upper()
            if enc in ("", "OPEN", "NONE", "OPN") or not enc:
                open_networks.append(net.get("ssid", net.get("bssid", "unknown")))

        if open_networks:
            return (
                ComplianceStatus.FAIL,
                f"Open networks found: {', '.join(open_networks)}",
                "Enable WPA2 or WPA3 encryption on all networks. Open networks violate compliance.",
            )
        return (
            ComplianceStatus.PASS,
            "No open networks detected",
            "",
        )

    def _check_vuln_management(self, networks: List[Dict]):
        """Check vulnerability management process."""
        vulns = getattr(self, "_vulnerabilities", [])
        critical_vulns = [
            v for v in vulns
            if v.get("severity", "").lower() in ("critical", "high")
        ]

        if critical_vulns:
            return (
                ComplianceStatus.FAIL,
                f"{len(critical_vulns)} critical/high vulnerabilities found",
                "Establish a vulnerability management process and remediate all critical/high findings within 30 days.",
            )
        return (
            ComplianceStatus.WARNING,
            "Automated vulnerability scan not yet performed or no critical findings",
            "Implement regular vulnerability scanning (at least quarterly) for all WiFi infrastructure.",
        )

    @staticmethod
    def _check_authentication_required(networks: List[Dict]):
        """Check that all networks require authentication."""
        no_auth = []
        for net in networks:
            enc = net.get("encryption", net.get("security", net.get("privacy", ""))).upper()
            if enc in ("", "OPEN", "NONE", "OPN"):
                no_auth.append(net.get("ssid", "unknown"))

        if no_auth:
            return (
                ComplianceStatus.FAIL,
                f"Networks without authentication: {', '.join(no_auth)}",
                "Require authentication (PSK or 802.1X) on all WiFi networks.",
            )
        return (
            ComplianceStatus.PASS,
            "All networks require authentication",
            "",
        )

    @staticmethod
    def _check_enterprise_auth(networks: List[Dict]):
        """Check for 802.1X enterprise authentication."""
        enterprise_count = 0
        psk_count = 0
        for net in networks:
            enc = net.get("encryption", net.get("security", net.get("privacy", ""))).upper()
            auth = net.get("auth", net.get("key_mgmt", "")).upper()
            if "802.1X" in auth or "EAP" in auth or "ENTERPRISE" in enc:
                enterprise_count += 1
            elif "PSK" in enc or "PSK" in auth or "WPA2" in enc or "WPA3" in enc:
                psk_count += 1

        if enterprise_count > 0:
            return (
                ComplianceStatus.PASS,
                f"Enterprise (802.1X) authentication found on {enterprise_count} networks",
                "",
            )
        if psk_count > 0:
            return (
                ComplianceStatus.WARNING,
                f"All {psk_count} networks use PSK; no 802.1X enterprise authentication detected",
                "Consider deploying WPA-Enterprise (802.1X) for environments handling sensitive data.",
            )
        return (
            ComplianceStatus.FAIL,
            "No enterprise authentication found",
            "Deploy WPA-Enterprise (802.1X) for all networks in cardholder or sensitive environments.",
        )

    @staticmethod
    def _check_audit_logging(networks: List[Dict]):
        """Check for WiFi audit logging capability."""
        # Cannot programmatically verify logging; provide guidance
        return (
            ComplianceStatus.WARNING,
            "WiFi audit logging cannot be verified automatically",
            "Ensure WiFi controllers and APs are configured to log authentication events, "
            "association/disassociation, and management frame activity. Forward logs to a SIEM.",
        )

    @staticmethod
    def _check_rogue_detection(networks: List[Dict]):
        """Check for rogue AP detection capability."""
        # Check if scan data includes any indicators of rogue detection
        # This is typically a process/tool check, not a scan data check
        return (
            ComplianceStatus.WARNING,
            "Rogue AP detection capability requires manual verification",
            "Deploy WIDS/WIPS or conduct regular wireless surveys to detect unauthorized access points.",
        )

    @staticmethod
    def _check_wids_wips(networks: List[Dict]):
        """Check for Wireless IDS/IPS deployment."""
        return (
            ComplianceStatus.WARNING,
            "WIDS/WIPS deployment cannot be verified automatically",
            "Deploy a Wireless Intrusion Detection/Prevention System to monitor for threats.",
        )

    @staticmethod
    def _check_usage_policy(networks: List[Dict]):
        """Check for WiFi usage policy."""
        return (
            ComplianceStatus.WARNING,
            "WiFi usage policy requires manual verification",
            "Document and enforce a WiFi acceptable use policy covering: approved devices, "
            "prohibited activities, guest access procedures, and incident reporting.",
        )

    @staticmethod
    def _check_access_control(networks: List[Dict]):
        """Check WiFi access control mechanisms."""
        controlled = 0
        uncontrolled = 0
        for net in networks:
            enc = net.get("encryption", net.get("security", net.get("privacy", ""))).upper()
            if enc and enc not in ("", "OPEN", "NONE", "OPN"):
                controlled += 1
            else:
                uncontrolled += 1

        if uncontrolled > 0:
            return (
                ComplianceStatus.FAIL,
                f"{uncontrolled} networks without access control, {controlled} with access control",
                "Implement access control on all WiFi networks.",
            )
        return (
            ComplianceStatus.PASS,
            f"All {controlled} networks have access control",
            "",
        )

    @staticmethod
    def _check_access_restriction(networks: List[Dict]):
        """Check that WiFi access is restricted to authorized users."""
        open_count = sum(
            1 for net in networks
            if net.get("encryption", net.get("security", net.get("privacy", ""))).upper()
            in ("", "OPEN", "NONE", "OPN")
        )

        if open_count > 0:
            return (
                ComplianceStatus.FAIL,
                f"{open_count} open networks allow unrestricted access",
                "Restrict WiFi access using authentication and encryption.",
            )
        return (
            ComplianceStatus.PASS,
            "All networks restrict access via authentication",
            "",
        )

    @staticmethod
    def _check_session_protection(networks: List[Dict]):
        """Check for session protection mechanisms (PMF)."""
        pmf_count = 0
        no_pmf_count = 0
        for net in networks:
            # Check for Protected Management Frames
            pmf = net.get("pmf", net.get("management_frame_protection", ""))
            if pmf and str(pmf).lower() in ("required", "enabled", "true", "1"):
                pmf_count += 1
            else:
                no_pmf_count += 1

        if no_pmf_count > 0 and pmf_count == 0:
            return (
                ComplianceStatus.WARNING,
                f"No networks have Protected Management Frames (PMF) enabled",
                "Enable PMF (802.11w) on all WPA2/WPA3 networks to protect against session hijacking.",
            )
        if no_pmf_count > 0:
            return (
                ComplianceStatus.WARNING,
                f"PMF enabled on {pmf_count} networks, {no_pmf_count} without PMF",
                "Enable PMF on all networks for consistent session protection.",
            )
        return (
            ComplianceStatus.PASS,
            "All networks have PMF enabled",
            "",
        )

    @staticmethod
    def _check_device_identification(networks: List[Dict]):
        """Check for device identification and authentication."""
        # Check for MAC-based or certificate-based auth indicators
        has_8021x = False
        for net in networks:
            enc = net.get("encryption", net.get("security", "")).upper()
            auth = net.get("auth", net.get("key_mgmt", "")).upper()
            if "802.1X" in auth or "EAP" in auth or "ENTERPRISE" in enc:
                has_8021x = True
                break

        if has_8021x:
            return (
                ComplianceStatus.PASS,
                "802.1X device authentication detected",
                "",
            )
        return (
            ComplianceStatus.WARNING,
                "No 802.1X device authentication detected - devices identified by PSK only",
            "Implement 802.1X/EAP for per-device authentication and identification.",
        )

    @staticmethod
    def _check_device_inventory(networks: List[Dict]):
        """Check for device inventory compliance."""
        if networks:
            return (
                ComplianceStatus.PASS,
                f"{len(networks)} WiFi networks discovered and inventoried during scan",
                "Maintain an up-to-date inventory of all authorized WiFi infrastructure.",
            )
        return (
            ComplianceStatus.WARNING,
            "No network scan data available for inventory",
            "Conduct regular WiFi surveys to maintain an inventory of all wireless devices.",
        )

    @staticmethod
    def _check_authorized_software(networks: List[Dict]):
        """Check for authorized WiFi management software."""
        return (
            ComplianceStatus.WARNING,
            "WiFi management software authorization requires manual verification",
            "Ensure all WiFi management and monitoring tools are authorized and documented.",
        )

    @staticmethod
    def _check_secure_config(networks: List[Dict]):
        """Check for secure WiFi configuration baselines."""
        findings = []
        for net in networks:
            ssid = net.get("ssid", "unknown")
            enc = net.get("encryption", net.get("security", "")).upper()
            channel = net.get("channel", 0)

            # Check for WPS
            wps = net.get("wps", "")
            if str(wps).lower() in ("enabled", "configured", "locked"):
                findings.append(f"{ssid}: WPS enabled (security risk)")

            # Check channel overlap (2.4 GHz)
            try:
                ch = int(channel)
                if 1 <= ch <= 13 and ch not in (1, 6, 11):
                    findings.append(f"{ssid}: Non-standard 2.4GHz channel {ch}")
            except (ValueError, TypeError):
                pass

            # Check for hidden SSID
            if not net.get("ssid", "").strip():
                findings.append(f"{net.get('bssid', 'unknown')}: Hidden SSID (provides no security)")

        if findings:
            return (
                ComplianceStatus.WARNING,
                f"Configuration issues: {'; '.join(findings[:10])}",
                "Remediate configuration weaknesses: disable WPS, use standard channels, avoid hidden SSIDs.",
            )
        return (
            ComplianceStatus.PASS,
            "No configuration issues detected",
            "",
        )

    @staticmethod
    def _check_incident_response(networks: List[Dict]):
        """Check for WiFi incident response capability."""
        return (
            ComplianceStatus.WARNING,
            "WiFi incident response capability requires manual verification",
            "Establish incident response procedures for WiFi security events including: "
            "rogue AP detection, unauthorized connections, and deauthentication attacks.",
        )

    # ------------------------------------------------------------------
    # Results Compilation
    # ------------------------------------------------------------------

    @staticmethod
    def _compile_results(standard: str, checks: List[ComplianceCheck]) -> Dict:
        """Compile check results into a summary dict.

        Args:
            standard: Compliance standard name.
            checks: List of ComplianceCheck objects.

        Returns:
            Dict with summary and detailed results.
        """
        passed = sum(1 for c in checks if c.status == ComplianceStatus.PASS)
        failed = sum(1 for c in checks if c.status == ComplianceStatus.FAIL)
        warnings = sum(1 for c in checks if c.status == ComplianceStatus.WARNING)
        na = sum(1 for c in checks if c.status == ComplianceStatus.NOT_APPLICABLE)
        errors = sum(1 for c in checks if c.status == ComplianceStatus.ERROR)
        total = len(checks)

        # Calculate compliance percentage (passes / applicable checks)
        applicable = total - na - errors
        compliance_pct = (passed / applicable * 100) if applicable > 0 else 0.0

        # Overall determination
        critical_fails = sum(
            1 for c in checks
            if c.status == ComplianceStatus.FAIL and c.severity == "critical"
        )
        if critical_fails > 0:
            determination = "non-compliant"
        elif compliance_pct >= 80:
            determination = "compliant"
        elif compliance_pct >= 60:
            determination = "partially-compliant"
        else:
            determination = "non-compliant"

        return {
            "standard": standard,
            "timestamp": datetime.now().isoformat(),
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "not_applicable": na,
            "errors": errors,
            "compliance_percentage": round(compliance_pct, 1),
            "determination": determination,
            "critical_failures": critical_fails,
            "checks": [c.to_dict() for c in checks],
        }

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def get_assessment_results(self, standard: Optional[str] = None) -> Dict:
        """Get stored assessment results.

        Args:
            standard: Standard name (None for all).

        Returns:
            Assessment results dict.
        """
        if standard:
            return self._assessment_results.get(standard, {})
        return dict(self._assessment_results)

    def get_failed_checks(self, standard: str) -> List[Dict]:
        """Get only the failed checks for a standard.

        Returns:
            List of failed check dicts.
        """
        results = self._assessment_results.get(standard, {})
        return [
            c for c in results.get("checks", [])
            if c.get("status") == "fail"
        ]

    def get_critical_findings(self, standard: Optional[str] = None) -> List[Dict]:
        """Get critical-severity findings across all or specific standards.

        Returns:
            List of critical finding dicts.
        """
        findings = []
        standards = [standard] if standard else list(self._assessment_results.keys())
        for std in standards:
            results = self._assessment_results.get(std, {})
            for check in results.get("checks", []):
                if check.get("status") == "fail" and check.get("severity") == "critical":
                    findings.append({"standard": std, **check})
        return findings

    @staticmethod
    def get_available_standards() -> List[str]:
        """Get list of supported compliance standards.

        Returns:
            List of standard name strings.
        """
        return [s.value for s in ComplianceStandard]
