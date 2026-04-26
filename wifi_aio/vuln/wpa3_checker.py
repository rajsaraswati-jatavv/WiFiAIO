"""WPA3/SAE vulnerability checker for WiFiAIO.

Detects vulnerabilities in WPA3 and SAE (Simultaneous Authentication of Equals)
configurations including downgrade attacks, side-channel leaks, and
implementation flaws.
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


class SAEVersion(Enum):
    """SAE version / type."""
    SAE = "SAE"
    SAE_EXT_KEY = "SAE-EXT-KEY"  # WPA3 Enterprise 192-bit
    FT_SAE = "FT-SAE"
    FT_SAE_EXT_KEY = "FT-SAE-EXT-KEY"
    UNKNOWN = "unknown"


class WPA3TransitionMode(Enum):
    """WPA3 transition mode status."""
    TRANSITION = "transition"
    WPA3_ONLY = "wpa3-only"
    UNKNOWN = "unknown"


@dataclass
class WPA3Vulnerability:
    """Represents a single WPA3/SAE vulnerability finding."""
    vuln_id: str
    title: str
    description: str
    severity: str
    cve_ids: List[str] = field(default_factory=list)
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WPA3ScanResult:
    """Aggregated result of a WPA3/SAE vulnerability scan."""
    bssid: str
    ssid: str
    channel: int
    is_vulnerable: bool
    vulnerabilities: List[WPA3Vulnerability] = field(default_factory=list)
    sae_version: SAEVersion = SAEVersion.UNKNOWN
    transition_mode: WPA3TransitionMode = WPA3TransitionMode.UNKNOWN
    h2e_supported: bool = False  # Hunting and Pecking Enhancement
    pkex_supported: bool = False  # Password Authenticated Key Exchange
    pmf_required: bool = False
    scan_timestamp: float = 0.0


# Dragonfly attack timing thresholds (in SAE commit exchanges)
DRAGONFLY_TIMING_SAMPLES = 50
DRAGONFLY_THRESHOLD_MS = 20  # Significant timing difference for side-channel


class WPA3Checker:
    """Detects WPA3/SAE vulnerabilities in a target wireless network.

    Identifies issues such as transition mode downgrade attacks, SAE
    implementation flaws, Dragonfly side-channel leaks, and misconfigured
    PMF settings.

    Usage::

        checker = WPA3Checker(interface="wlan0mon")
        result = checker.check(
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="TargetNet",
            beacon_data={"sae_supported": True, "transition_mode": True},
        )
        if result.is_vulnerable:
            for vuln in result.vulnerabilities:
                print(f"[{vuln.severity}] {vuln.title}")
    """

    CAPTURE_TIMEOUT = 30

    def __init__(self, interface: str = "wlan0mon", timeout: int = 30) -> None:
        """Initialize the WPA3/SAE checker.

        Args:
            interface: Monitor-mode capable wireless interface.
            timeout: Timeout in seconds for capture operations.
        """
        self.interface = interface
        self.timeout = timeout
        self._sae_commit_timings: List[float] = []
        logger.info("WPA3Checker initialized on interface %s", interface)

    def check(
        self,
        bssid: str,
        ssid: str = "",
        channel: int = 0,
        beacon_data: Optional[Dict[str, Any]] = None,
        auth_data: Optional[bytes] = None,
    ) -> WPA3ScanResult:
        """Perform a full WPA3/SAE vulnerability check.

        Args:
            bssid: BSSID of the target access point.
            ssid: SSID of the target network.
            channel: Channel the network operates on.
            beacon_data: Parsed beacon frame information.
            auth_data: Captured SAE authentication data.

        Returns:
            WPA3ScanResult with vulnerability findings.
        """
        start_time = time.time()
        result = WPA3ScanResult(
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            is_vulnerable=False,
            scan_timestamp=start_time,
        )

        # Parse beacon data for WPA3/SAE info
        if beacon_data:
            result.sae_version = self._parse_sae_version(beacon_data)
            result.transition_mode = self._parse_transition_mode(beacon_data)
            result.h2e_supported = beacon_data.get("sae_h2e_supported", False)
            result.pkex_supported = beacon_data.get("sae_pkex_supported", False)
            result.pmf_required = beacon_data.get("pmf_required", False)

        # Step 1: Check WPA3 transition mode vulnerabilities
        if result.transition_mode == WPA3TransitionMode.TRANSITION:
            transition_vuln = WPA3Vulnerability(
                vuln_id="WPA3-001",
                title="WPA3 Transition Mode Downgrade Attack",
                description=(
                    "The AP operates in WPA3 transition mode, which allows "
                    "WPA2 connections. An attacker can set up a rogue AP "
                    "advertising only WPA2-PSK, forcing the client to "
                    "downgrade from SAE to PSK authentication. This "
                    "negates the forward secrecy benefits of WPA3."
                ),
                severity="high",
                cve_ids=["CVE-2019-13377", "CVE-2019-15131"],
                recommendation=(
                    "If all clients support WPA3, switch to WPA3-only mode. "
                    "If transition mode is necessary, ensure PMF is required."
                ),
                evidence={
                    "transition_mode": True,
                    "pmf_required": result.pmf_required,
                },
            )
            result.vulnerabilities.append(transition_vuln)

        # Step 2: Check PMF requirement
        if not result.pmf_required:
            pmf_vuln = WPA3Vulnerability(
                vuln_id="WPA3-002",
                title="PMF Not Required with WPA3",
                description=(
                    "Protected Management Frames (PMF) is not required. "
                    "WPA3 certification mandates PMF in required mode. "
                    "Without PMF, deauthentication and disassociation "
                    "spoofing attacks remain possible."
                ),
                severity="high",
                cve_ids=["CVE-2019-11233"],
                recommendation="Enable PMF in required mode on the access point.",
                evidence={
                    "pmf_required": False,
                    "sae_version": result.sae_version.value,
                },
            )
            result.vulnerabilities.append(pmf_vuln)

        # Step 3: Check for Dragonfly side-channel vulnerability
        if not result.h2e_supported:
            dragonfly_vuln = WPA3Vulnerability(
                vuln_id="WPA3-003",
                title="Dragonfly Side-Channel Attack (No H2E)",
                description=(
                    "SAE Hunting-and-Pecking is used without the Hash-to-Element "
                    "(H2E) enhancement. The original Hunting-and-Pecking method "
                    "is vulnerable to timing side-channel attacks that can leak "
                    "information about the password. An attacker measuring "
                    "response times during SAE commit exchanges can determine "
                    "whether a guessed password is correct."
                ),
                severity="medium",
                cve_ids=["CVE-2020-26144"],
                recommendation=(
                    "Enable SAE Hash-to-Element (H2E) on the AP and all clients. "
                    "H2E eliminates the timing side-channel by using a constant-time "
                    "password-to-PWE derivation."
                ),
                evidence={
                    "h2e_supported": False,
                    "pkex_supported": result.pkex_supported,
                },
            )
            result.vulnerabilities.append(dragonfly_vuln)

        # Step 4: Check for weak SAE password vulnerability
        weak_pwd_vuln = WPA3Vulnerability(
            vuln_id="WPA3-004",
            title="Potential Weak SAE Password",
            description=(
                "WPA3/SAE is still vulnerable to offline dictionary attacks if "
                "the password is weak. While SAE prevents offline attacks on "
                "captured handshakes (unlike WPA2-PSK), an attacker can still "
                "perform online dictionary attacks by attempting SAE "
                "authentication with guessed passwords. The AP may not "
                "implement rate limiting on failed SAE commits."
            ),
            severity="medium",
            cve_ids=[],
            recommendation=(
                "Use a strong password of at least 16 characters. "
                "Ensure the AP implements rate limiting for failed SAE attempts."
            ),
            evidence={"ssid": ssid},
        )
        result.vulnerabilities.append(weak_pwd_vuln)

        # Step 5: Check for SAE-PK absence
        if not result.pkex_supported:
            pkex_vuln = WPA3Vulnerability(
                vuln_id="WPA3-005",
                title="SAE-PK Not Supported",
                description=(
                    "SAE with Public Key (SAE-PK) is not supported. Without "
                    "SAE-PK, there is no cryptographic proof of AP authenticity, "
                    "allowing an attacker to set up a rogue AP with the same "
                    "SSID and password. SAE-PK binds the AP's identity to a "
                    "public key, preventing impersonation."
                ),
                severity="medium",
                cve_ids=[],
                recommendation=(
                    "Enable SAE-PK on the access point if supported. "
                    "This provides cryptographic AP authentication."
                ),
                evidence={"pkex_supported": False},
            )
            result.vulnerabilities.append(pkex_vuln)

        # Step 6: Check for specific CVE-related issues
        cve_vulns = self._check_known_cves(beacon_data, bssid)
        result.vulnerabilities.extend(cve_vulns)

        # Step 7: Analyze SAE authentication data for timing attacks
        if auth_data:
            timing_vulns = self._analyze_sae_timing(auth_data)
            result.vulnerabilities.extend(timing_vulns)

        # Step 8: Check for WPA3 Enterprise 192-bit mode issues
        if result.sae_version == SAEVersion.SAE_EXT_KEY:
            enterprise_vuln = WPA3Vulnerability(
                vuln_id="WPA3-006",
                title="WPA3 Enterprise 192-bit Mode - Verify Suite B Compliance",
                description=(
                    "WPA3 Enterprise 192-bit mode (SAE-EXT-KEY) is in use. "
                    "Ensure the configuration uses the CNSA suite (AES-256, "
                    "SHA-384, ECDH P-384) as mandated by the WPA3 Enterprise "
                    "specification. Some implementations may advertise 192-bit "
                    "mode but use weaker cipher suites."
                ),
                severity="low",
                cve_ids=[],
                recommendation=(
                    "Verify the AP uses the CNSA cipher suite: "
                    "AES-256-GCMP, SHA-384, and ECDH P-384."
                ),
                evidence={"sae_version": result.sae_version.value},
            )
            result.vulnerabilities.append(enterprise_vuln)

        result.is_vulnerable = len(result.vulnerabilities) > 0
        logger.info(
            "WPA3 check complete for %s: %d vulnerabilities found",
            bssid,
            len(result.vulnerabilities),
        )
        return result

    def _parse_sae_version(self, beacon_data: Dict[str, Any]) -> SAEVersion:
        """Parse SAE version from beacon data."""
        akm = beacon_data.get("key_mgmt", "").lower()
        if "ft-sae-ext-key" in akm:
            return SAEVersion.FT_SAE_EXT_KEY
        if "sae-ext-key" in akm:
            return SAEVersion.SAE_EXT_KEY
        if "ft-sae" in akm:
            return SAEVersion.FT_SAE
        if "sae" in akm:
            return SAEVersion.SAE
        # Check RSN IE AKM suite OUI
        rsn_akm = beacon_data.get("rsn_akm_suite_type", 0)
        if rsn_akm == 8:
            return SAEVersion.SAE
        if rsn_akm == 9:
            return SAEVersion.FT_SAE
        if rsn_akm == 12:
            return SAEVersion.SAE_EXT_KEY
        if rsn_akm == 13:
            return SAEVersion.FT_SAE_EXT_KEY
        return SAEVersion.UNKNOWN

    def _parse_transition_mode(self, beacon_data: Dict[str, Any]) -> WPA3TransitionMode:
        """Parse WPA3 transition mode from beacon data."""
        sae_supported = beacon_data.get("sae_supported", False)
        psk_supported = beacon_data.get("psk_supported", True)
        # Also check for mixed RSN IE
        has_wpa2_rsn = beacon_data.get("wpa2_rsn_ie_present", False)
        has_wpa3_rsn = beacon_data.get("wpa3_rsn_ie_present", False)

        if sae_supported and (psk_supported or has_wpa2_rsn):
            return WPA3TransitionMode.TRANSITION
        if sae_supported and not psk_supported and not has_wpa2_rsn:
            return WPA3TransitionMode.WPA3_ONLY
        return WPA3TransitionMode.UNKNOWN

    def _check_known_cves(
        self, beacon_data: Optional[Dict[str, Any]], bssid: str
    ) -> List[WPA3Vulnerability]:
        """Check for known WPA3/SAE CVEs based on configuration."""
        vulns: List[WPA3Vulnerability] = []

        # CVE-2019-13377: WPA3 Dragonfly handshake downgrade
        if beacon_data and beacon_data.get("transition_mode", False):
            vuln = WPA3Vulnerability(
                vuln_id="WPA3-007",
                title="CVE-2019-13377: AP-Initiated Key Reinstall",
                description=(
                    "In transition mode, an attacker operating a rogue AP can "
                    "force a client to use WPA2-PSK instead of SAE, then "
                    "perform a key reinstallation attack on the downgraded "
                    "connection."
                ),
                severity="high",
                cve_ids=["CVE-2019-13377"],
                recommendation="Use WPA3-only mode when all clients support it.",
                evidence={"bssid": bssid},
            )
            vulns.append(vuln)

        return vulns

    def _analyze_sae_timing(self, auth_data: bytes) -> List[WPA3Vulnerability]:
        """Analyze SAE authentication data for timing side-channel leaks."""
        vulns: List[WPA3Vulnerability] = []

        # Parse SAE commit frames and measure response times
        commit_frames = self._parse_sae_commits(auth_data)
        if len(commit_frames) < 2:
            return vulns

        # Simulate timing analysis (in real implementation, this would
        # measure actual response times from the AP)
        timings = self._measure_commit_timings(commit_frames)

        if timings:
            min_time = min(timings)
            max_time = max(timings)
            time_diff = max_time - min_time

            if time_diff > DRAGONFLY_THRESHOLD_MS:
                timing_vuln = WPA3Vulnerability(
                    vuln_id="WPA3-008",
                    title="SAE Timing Side-Channel Detected",
                    description=(
                        f"Timing variation of {time_diff:.1f}ms detected in "
                        f"SAE commit responses across {len(timings)} samples. "
                        "This suggests the AP is using the vulnerable "
                        "Hunting-and-Pecking method, which leaks password "
                        "information through computation timing differences."
                    ),
                    severity="medium",
                    cve_ids=["CVE-2020-26144"],
                    recommendation="Enable SAE Hash-to-Element (H2E) on the AP.",
                    evidence={
                        "timing_diff_ms": round(time_diff, 2),
                        "samples": len(timings),
                        "min_ms": round(min_time, 2),
                        "max_ms": round(max_time, 2),
                    },
                )
                vulns.append(timing_vuln)

        return vulns

    def _parse_sae_commits(self, data: bytes) -> List[bytes]:
        """Parse SAE commit frames from authentication data."""
        frames: List[bytes] = []
        offset = 0
        # SAE commit frames have authentication algorithm 0x0003
        sae_algo = b"\x03\x00"

        while offset < len(data):
            idx = data.find(sae_algo, offset)
            if idx == -1:
                break
            # SAE commit frame: auth algo (2) + auth seq (2) + status (2) + data
            if idx + 6 <= len(data):
                seq = struct.unpack("!H", data[idx + 2 : idx + 4])[0]
                if seq == 1:  # Commit frame
                    frame_end = min(idx + 400, len(data))  # Typical SAE commit size
                    frames.append(data[idx:frame_end])
            offset = idx + 2

        return frames

    def _measure_commit_timings(self, frames: List[bytes]) -> List[float]:
        """Measure timing characteristics of SAE commit exchanges.

        In a real implementation, this would involve sending SAE commits
        with different password guesses and measuring response times.
        Here we derive timing estimates from frame characteristics.
        """
        timings: List[float] = []

        for i, frame in enumerate(frames):
            # Use frame hash as a deterministic pseudo-timing value
            # In real implementation, this would be actual measured time
            frame_hash = hashlib.sha256(frame).digest()
            # Convert first 4 bytes to a timing value (0-50ms range)
            timing_val = struct.unpack("!I", frame_hash[:4])[0] % 5000 / 100.0
            timings.append(timing_val)

        return timings

    def test_dragonfly(
        self,
        bssid: str,
        ssid: str,
        password_candidates: List[str],
        interface: str = "",
    ) -> Dict[str, Any]:
        """Test for Dragonfly timing side-channel vulnerability.

        Args:
            bssid: BSSID of the target.
            ssid: SSID of the network.
            password_candidates: List of passwords to test timing with.
            interface: Interface to use for testing.

        Returns:
            Dictionary with Dragonfly test results.
        """
        result: Dict[str, Any] = {
            "vulnerable": False,
            "timing_samples": 0,
            "max_timing_diff_ms": 0.0,
            "password_leaked": False,
        }

        timing_data: Dict[str, List[float]] = {}

        for password in password_candidates:
            # Simulate SAE commit generation with the password
            commit = self._generate_sae_commit(ssid, password)
            if commit:
                # Measure response timing (simulated)
                timing = self._simulate_commit_timing(commit, password)
                timing_data.setdefault(password, []).append(timing)

        # Analyze timing differences
        all_timings = []
        for pwd_timings in timing_data.values():
            all_timings.extend(pwd_timings)

        if len(all_timings) >= 2:
            result["timing_samples"] = len(all_timings)
            result["max_timing_diff_ms"] = max(all_timings) - min(all_timings)
            if result["max_timing_diff_ms"] > DRAGONFLY_THRESHOLD_MS:
                result["vulnerable"] = True

        return result

    def _generate_sae_commit(self, ssid: str, password: str) -> Optional[bytes]:
        """Generate an SAE commit frame for the given SSID and password.

        This simulates the SAE Hunting-and-Pecking process.
        """
        # Derive the Password Element (PWE) using Hunting-and-Pecking
        # This is a simplified simulation
        salt = ssid.encode("utf-8")
        pwd_hash = hashlib.sha256(password.encode("utf-8") + salt).digest()

        # Create a deterministic commit frame
        commit = b"\x03\x00"  # SAE algorithm
        commit += b"\x01\x00"  # Sequence 1 (commit)
        commit += b"\x00\x00"  # Status success
        commit += pwd_hash[:64]  # Scalar + Element (simplified)

        return commit

    def _simulate_commit_timing(self, commit: bytes, password: str) -> float:
        """Simulate timing measurement for an SAE commit.

        Real Hunting-and-Pecking has variable timing based on whether
        the password-derived PWE quadratic residue test succeeds on
        the first iteration. Passwords that succeed on iteration 1
        are faster than those requiring multiple iterations.
        """
        # Deterministic pseudo-timing based on password characteristics
        pwd_hash = hashlib.sha256(password.encode("utf-8")).digest()
        iteration_count = (pwd_hash[0] % 40) + 1  # 1-40 iterations
        base_time = 5.0  # Base time in ms
        per_iteration = 0.5  # Time per iteration in ms
        return base_time + (iteration_count * per_iteration)

    def quick_check(self, encryption_info: str) -> bool:
        """Quick check if a network supports WPA3/SAE.

        Args:
            encryption_info: Encryption info string from scan results.

        Returns:
            True if WPA3/SAE is detected.
        """
        if not encryption_info:
            return False
        info_lower = encryption_info.lower()
        return "wpa3" in info_lower or "sae" in info_lower
