"""WPA/TKIP vulnerability checker for WiFiAIO.

Detects vulnerabilities in WPA and WPA/TKIP configurations including
TKIP MIC attacks, session key recovery, and downgrade vulnerabilities.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from wifi_aio.exceptions import WiFiConnectionError, WiFiTimeoutError

logger = logging.getLogger(__name__)


class WPAVersion(Enum):
    """WPA version."""
    WPA = "WPA"
    WPA2 = "WPA2"
    UNKNOWN = "unknown"


class CipherSuite(Enum):
    """Encryption cipher suite."""
    TKIP = "TKIP"
    CCMP = "CCMP"
    GCMP = "GCMP"
    UNKNOWN = "unknown"


class KeyManagement(Enum):
    """Key management method."""
    PSK = "PSK"
    ENTERPRISE = "802.1X/EAP"
    FT_PSK = "FT-PSK"
    FT_ENTERPRISE = "FT-802.1X"
    UNKNOWN = "unknown"


@dataclass
class WPAVulnerability:
    """Represents a single WPA/TKIP vulnerability finding."""
    vuln_id: str
    title: str
    description: str
    severity: str  # "critical", "high", "medium", "low", "info"
    cve_ids: List[str] = field(default_factory=list)
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WPAScanResult:
    """Aggregated result of a WPA/TKIP vulnerability scan."""
    bssid: str
    ssid: str
    channel: int
    is_vulnerable: bool
    vulnerabilities: List[WPAVulnerability] = field(default_factory=list)
    wpa_version: WPAVersion = WPAVersion.UNKNOWN
    cipher_pairwise: CipherSuite = CipherSuite.UNKNOWN
    cipher_group: CipherSuite = CipherSuite.UNKNOWN
    key_mgmt: KeyManagement = KeyManagement.UNKNOWN
    tkip_countermeasures_enabled: bool = False
    scan_timestamp: float = 0.0


# TKIP MIC key recovery attack parameters
TKIP_MIC_BECK_Tews_PARAMS = {
    "min_packets_for_mic_error": 1,
    "channel_switch_interval_seconds": 60,
    "max_retries_per_channel": 3,
}


class WPAChecker:
    """Detects WPA/TKIP vulnerabilities in a target wireless network.

    Identifies issues such as TKIP cipher usage, WPA1-only configurations,
    downgrade attacks, and Michael MIC attack susceptibility.

    Usage::

        checker = WPAChecker(interface="wlan0mon")
        result = checker.check(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="TargetNet",
            beacon_data={"wpa_version": "WPA", "cipher": "TKIP"},
        )
        if result.is_vulnerable:
            for vuln in result.vulnerabilities:
                print(f"[{vuln.severity}] {vuln.title}")
    """

    # Timeout for capture operations
    CAPTURE_TIMEOUT = 30
    # Number of MIC errors that trigger TKIP countermeasures
    MIC_ERROR_THRESHOLD = 2

    def __init__(self, interface: str = "wlan0mon", timeout: int = 30) -> None:
        """Initialize the WPA/TKIP checker.

        Args:
            interface: Monitor-mode capable wireless interface.
            timeout: Timeout in seconds for capture operations.
        """
        self.interface = interface
        self.timeout = timeout
        self._mic_error_count = 0
        self._packet_buffer: List[bytes] = []
        logger.info("WPAChecker initialized on interface %s", interface)

    def check(
        self,
        bssid: str,
        ssid: str = "",
        channel: int = 0,
        beacon_data: Optional[Dict[str, Any]] = None,
        handshake_data: Optional[bytes] = None,
    ) -> WPAScanResult:
        """Perform a full WPA/TKIP vulnerability check.

        Args:
            bssid: BSSID of the target access point.
            ssid: SSID of the target network.
            channel: Channel the network operates on.
            beacon_data: Parsed beacon frame information.
            handshake_data: Captured EAPOL handshake data.

        Returns:
            WPAScanResult with vulnerability findings.
        """
        start_time = time.time()
        result = WPAScanResult(
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            is_vulnerable=False,
            scan_timestamp=start_time,
        )

        # Parse beacon data for WPA info
        if beacon_data:
            result.wpa_version = self._parse_wpa_version(beacon_data)
            result.cipher_pairwise = self._parse_cipher_pairwise(beacon_data)
            result.cipher_group = self._parse_cipher_group(beacon_data)
            result.key_mgmt = self._parse_key_mgmt(beacon_data)

        # Step 1: Check for TKIP cipher usage
        if result.cipher_pairwise == CipherSuite.TKIP:
            tkip_vuln = WPAVulnerability(
                vuln_id="WPA-001",
                title="TKIP Cipher Suite in Use",
                description=(
                    "The network uses TKIP as the pairwise cipher suite. "
                    "TKIP is vulnerable to Beck-Tews partial plaintext "
                    "recovery attacks and Michael MIC key recovery. TKIP was "
                    "deprecated by the Wi-Fi Alliance in 2012."
                ),
                severity="high",
                cve_ids=["CVE-2009-4274", "CVE-2012-4320"],
                recommendation="Configure the AP to use AES-CCMP exclusively.",
                evidence={
                    "pairwise_cipher": "TKIP",
                    "wpa_version": result.wpa_version.value,
                },
            )
            result.vulnerabilities.append(tkip_vuln)

        # Step 2: Check for TKIP group cipher
        if result.cipher_group == CipherSuite.TKIP:
            group_tkip_vuln = WPAVulnerability(
                vuln_id="WPA-002",
                title="TKIP Group Cipher",
                description=(
                    "The group cipher is TKIP, which allows an attacker to "
                    "inject frames into the network by exploiting TKIP's "
                    "weaknesses in broadcast/multicast traffic. Even if "
                    "pairwise cipher is CCMP, TKIP group cipher is a risk."
                ),
                severity="medium",
                cve_ids=["CVE-2009-4274"],
                recommendation="Set both pairwise and group cipher to CCMP.",
                evidence={"group_cipher": "TKIP"},
            )
            result.vulnerabilities.append(group_tkip_vuln)

        # Step 3: Check for WPA1-only (no WPA2)
        if result.wpa_version == WPAVersion.WPA:
            wpa1_vuln = WPAVulnerability(
                vuln_id="WPA-003",
                title="WPA1-Only Configuration",
                description=(
                    "The network only supports WPA1 (IEEE 802.11i draft), "
                    "not WPA2 (IEEE 802.11i ratified). WPA1 lacks the "
                    "security improvements of WPA2 including mandatory CCMP "
                    "and is susceptible to downgrade attacks."
                ),
                severity="high",
                cve_ids=["CVE-2018-14526"],
                recommendation="Enable WPA2 on the access point and disable WPA1.",
                evidence={"wpa_version": "WPA1-only"},
            )
            result.vulnerabilities.append(wpa1_vuln)

        # Step 4: Check for Michael MIC attack vulnerability
        if result.cipher_pairwise == CipherSuite.TKIP or result.cipher_group == CipherSuite.TKIP:
            mic_vuln = WPAVulnerability(
                vuln_id="WPA-004",
                title="Michael MIC Attack Vulnerability",
                description=(
                    "TKIP uses the Michael MIC algorithm for message integrity, "
                    "which is cryptographically weak. The Beck-Tews attack (2008) "
                    "can recover the MIC key and inject arbitrary packets within "
                    "about 12-15 minutes. While TKIP countermeasures attempt to "
                    "mitigate this, the 60-second countermeasure window still "
                    "allows practical exploitation."
                ),
                severity="high",
                cve_ids=["CVE-2009-4274", "CVE-2009-4492"],
                recommendation="Disable TKIP entirely and use CCMP/AES only.",
                evidence={"cipher": "TKIP"},
            )
            result.vulnerabilities.append(mic_vuln)

        # Step 5: Check for downgrade attack vulnerability
        if result.wpa_version == WPAVersion.WPA or result.cipher_pairwise == CipherSuite.TKIP:
            downgrade_vuln = WPAVulnerability(
                vuln_id="WPA-005",
                title="Protocol Downgrade Vulnerability",
                description=(
                    "The network allows downgrade to WPA1 and/or TKIP, which "
                    "enables an attacker to force a client to use weaker "
                    "encryption by spoofing RSN IE elements in beacon frames. "
                    "This is possible because the protocol negotiation is not "
                    "authenticated in the initial association."
                ),
                severity="medium",
                cve_ids=["CVE-2018-14526"],
                recommendation="Disable WPA1 and TKIP on the access point.",
                evidence={
                    "supports_wpa1": result.wpa_version in (WPAVersion.WPA, WPAVersion.UNKNOWN),
                    "supports_tkip": result.cipher_pairwise == CipherSuite.TKIP,
                },
            )
            result.vulnerabilities.append(downgrade_vuln)

        # Step 6: Check for short PTK derivation (WPA1)
        if result.wpa_version == WPAVersion.WPA:
            ptk_vuln = WPAVulnerability(
                vuln_id="WPA-006",
                title="Short PTK Derivation (WPA1)",
                description=(
                    "WPA1 uses a 512-bit Pairwise Transient Key (PTK) derived "
                    "from SHA-1, while WPA2 uses a 576-bit PTK. The shorter "
                    "key derivation in WPA1 reduces the effective security "
                    "margin, particularly for the encryption key material."
                ),
                severity="medium",
                cve_ids=[],
                recommendation="Upgrade to WPA2 or WPA3 for stronger key derivation.",
                evidence={"ptk_length": "512 bits"},
            )
            result.vulnerabilities.append(ptk_vuln)

        # Step 7: Check for lack of PMF with WPA
        if beacon_data:
            pmf_capable = beacon_data.get("pmf_capable", False)
            pmf_required = beacon_data.get("pmf_required", False)
            if not pmf_required and result.wpa_version in (WPAVersion.WPA, WPAVersion.WPA2):
                pmf_vuln = WPAVulnerability(
                    vuln_id="WPA-007",
                    title="Protected Management Frames Not Required",
                    description=(
                        "PMF is not required, allowing deauthentication and "
                        "disassociation frame spoofing attacks. An attacker "
                        "can disconnect clients by forging management frames."
                    ),
                    severity="medium",
                    cve_ids=["CVE-2019-11233"],
                    recommendation="Enable PMF (802.11w) in required mode on the AP.",
                    evidence={
                        "pmf_capable": pmf_capable,
                        "pmf_required": pmf_required,
                    },
                )
                result.vulnerabilities.append(pmf_vuln)

        # Step 8: Check handshake for weak ANCE/SNonce
        if handshake_data:
            handshake_vulns = self._analyze_handshake(handshake_data, bssid)
            result.vulnerabilities.extend(handshake_vulns)

        result.is_vulnerable = len(result.vulnerabilities) > 0
        logger.info(
            "WPA check complete for %s: %d vulnerabilities found",
            bssid,
            len(result.vulnerabilities),
        )
        return result

    def _parse_wpa_version(self, beacon_data: Dict[str, Any]) -> WPAVersion:
        """Parse WPA version from beacon data."""
        wpa_type = beacon_data.get("wpa_version", "")
        if isinstance(wpa_type, str):
            wpa_lower = wpa_type.lower()
            if "wpa2" in wpa_lower:
                return WPAVersion.WPA2
            if "wpa" in wpa_lower and "wpa2" not in wpa_lower:
                return WPAVersion.WPA
        # Check RSN IE presence (indicates WPA2)
        if beacon_data.get("rsn_ie_present", False):
            return WPAVersion.WPA2
        if beacon_data.get("wpa_ie_present", False):
            return WPAVersion.WPA
        return WPAVersion.UNKNOWN

    def _parse_cipher_pairwise(self, beacon_data: Dict[str, Any]) -> CipherSuite:
        """Parse pairwise cipher from beacon data."""
        cipher = beacon_data.get("pairwise_cipher", "").upper()
        if "CCMP" in cipher:
            return CipherSuite.CCMP
        if "GCMP" in cipher:
            return CipherSuite.GCMP
        if "TKIP" in cipher:
            return CipherSuite.TKIP
        # Check RSN IE cipher suite OUI
        rsn_cipher = beacon_data.get("rsn_pairwise_cipher_oui", b"")
        if rsn_cipher:
            if rsn_cipher.endswith(b"\x04"):
                return CipherSuite.CCMP
            if rsn_cipher.endswith(b"\x02"):
                return CipherSuite.TKIP
        return CipherSuite.UNKNOWN

    def _parse_cipher_group(self, beacon_data: Dict[str, Any]) -> CipherSuite:
        """Parse group cipher from beacon data."""
        cipher = beacon_data.get("group_cipher", "").upper()
        if "CCMP" in cipher:
            return CipherSuite.CCMP
        if "GCMP" in cipher:
            return CipherSuite.GCMP
        if "TKIP" in cipher:
            return CipherSuite.TKIP
        rsn_cipher = beacon_data.get("rsn_group_cipher_oui", b"")
        if rsn_cipher:
            if rsn_cipher.endswith(b"\x04"):
                return CipherSuite.CCMP
            if rsn_cipher.endswith(b"\x02"):
                return CipherSuite.TKIP
        return CipherSuite.UNKNOWN

    def _parse_key_mgmt(self, beacon_data: Dict[str, Any]) -> KeyManagement:
        """Parse key management from beacon data."""
        akm = beacon_data.get("key_mgmt", "").lower()
        if "ft-psk" in akm:
            return KeyManagement.FT_PSK
        if "ft-802.1x" in akm or "ft-enterprise" in akm:
            return KeyManagement.FT_ENTERPRISE
        if "802.1x" in akm or "enterprise" in akm:
            return KeyManagement.ENTERPRISE
        if "psk" in akm:
            return KeyManagement.PSK
        # Check RSN IE AKM suite OUI
        rsn_akm = beacon_data.get("rsn_akm_suite_oui", b"")
        if rsn_akm:
            suite_type = rsn_akm[-1] if rsn_akm else 0
            if suite_type == 1:
                return KeyManagement.PSK
            if suite_type == 2:
                return KeyManagement.ENTERPRISE
            if suite_type == 3:
                return KeyManagement.FT_PSK
            if suite_type == 4:
                return KeyManagement.FT_ENTERPRISE
        return KeyManagement.UNKNOWN

    def _analyze_handshake(self, handshake_data: bytes, bssid: str) -> List[WPAVulnerability]:
        """Analyze captured EAPOL handshake for vulnerabilities."""
        vulns: List[WPAVulnerability] = []

        # Parse EAPOL frames from handshake data
        eapol_frames = self._parse_eapol_frames(handshake_data)
        if len(eapol_frames) < 4:
            incomplete_vuln = WPAVulnerability(
                vuln_id="WPA-008",
                title="Incomplete Handshake Capture",
                description=(
                    f"Only {len(eapol_frames)} of 4 EAPOL frames captured. "
                    "While this doesn't represent a vulnerability per se, "
                    "an incomplete handshake may indicate network instability "
                    "or active countermeasures."
                ),
                severity="info",
                cve_ids=[],
                recommendation="Ensure all 4 EAPOL frames are captured for full analysis.",
                evidence={"frames_captured": len(eapol_frames)},
            )
            vulns.append(incomplete_vuln)

        # Check for nonce reuse in M1/M3 (ANonce)
        if len(eapol_frames) >= 2:
            anonce_1 = self._extract_nonce(eapol_frames[0], is_anonce=True)
            anonce_3 = self._extract_nonce(eapol_frames[2] if len(eapol_frames) > 2 else b"", is_anonce=True)
            if anonce_1 and anonce_3 and anonce_1 == anonce_3:
                nonce_reuse_vuln = WPAVulnerability(
                    vuln_id="WPA-009",
                    title="ANonce Reuse in Handshake",
                    description=(
                        "The same ANonce was used in both M1 and M3, which "
                        "may indicate a non-conformant implementation that "
                        "could weaken the PTK derivation."
                    ),
                    severity="medium",
                    cve_ids=[],
                    recommendation="Update AP firmware to ensure proper nonce generation.",
                    evidence={"anonce": anonce_1.hex() if anonce_1 else ""},
                )
                vulns.append(nonce_reuse_vuln)

        return vulns

    def _parse_eapol_frames(self, data: bytes) -> List[bytes]:
        """Parse EAPOL frames from captured data."""
        frames: List[bytes] = []
        offset = 0
        eapol_marker = b"\x88\x8e"  # EAPOL EtherType

        while offset < len(data):
            idx = data.find(eapol_marker, offset)
            if idx == -1:
                break
            # Extract frame (approximate length from EAPOL body)
            if idx + 4 <= len(data):
                body_len = struct.unpack("!H", data[idx + 2 : idx + 4])[0]
                frame_end = min(idx + 4 + body_len, len(data))
                frames.append(data[idx:frame_end])
                offset = frame_end
            else:
                offset = idx + 2

        return frames

    def _extract_nonce(self, frame: bytes, is_anonce: bool = True) -> Optional[bytes]:
        """Extract nonce from an EAPOL frame."""
        if not frame or len(frame) < 100:
            return None
        # Nonce is typically at offset 17 in EAPOL-Key frame (after header)
        # ANonce: offset 17 in M1, SNonce: offset 17 in M2
        nonce_offset = 17
        if nonce_offset + 32 <= len(frame):
            return frame[nonce_offset : nonce_offset + 32]
        return None

    def check_tkip_mic_vulnerability(
        self,
        bssid: str,
        capture_data: bytes,
        timeout: int = 300,
    ) -> Dict[str, Any]:
        """Specifically test for TKIP Michael MIC vulnerability.

        Args:
            bssid: BSSID of the target.
            capture_data: Captured TKIP-encrypted data.
            timeout: Maximum time for analysis in seconds.

        Returns:
            Dictionary with MIC vulnerability analysis results.
        """
        result: Dict[str, Any] = {
            "vulnerable": False,
            "mic_errors_detected": 0,
            "estimated_mic_recovery_time": 0,
            "countermeasures_triggered": False,
        }

        mic_errors = 0
        frames = self._parse_eapol_frames(capture_data) if capture_data else []

        # Look for Michael MIC failure reports in captured frames
        for frame in frames:
            if len(frame) >= 8:
                key_info = struct.unpack("!H", frame[5:7])[0] if len(frame) >= 7 else 0
                # Check for MIC error bit (bit 6 in key info for EAPOL-Key)
                if key_info & 0x0040:
                    mic_errors += 1

        result["mic_errors_detected"] = mic_errors

        if mic_errors >= self.MIC_ERROR_THRESHOLD:
            result["countermeasures_triggered"] = True
            result["estimated_mic_recovery_time"] = 60  # 60 second cooldown
        elif mic_errors > 0:
            result["vulnerable"] = True
            result["estimated_mic_recovery_time"] = 12 * 60  # ~12 minutes

        return result

    def quick_check(self, encryption_info: str) -> bool:
        """Quick check if a network uses WPA/TKIP.

        Args:
            encryption_info: Encryption info string from scan results.

        Returns:
            True if TKIP is detected.
        """
        if not encryption_info:
            return False
        return "tkip" in encryption_info.lower()
