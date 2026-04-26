"""WEP vulnerability checker for WiFiAIO.

Detects Wired Equivalent Privacy (WEP) vulnerabilities in target networks,
including weak IV detection, authentication mode issues, and key length
problems. WEP is considered fundamentally broken and should never be used.
"""

from __future__ import annotations

import hashlib
import logging
import re
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from wifi_aio.exceptions import WiFiConnectionError, WiFiTimeoutError

logger = logging.getLogger(__name__)


class WEPAuthMode(Enum):
    """WEP authentication mode."""
    OPEN = "open"
    SHARED_KEY = "shared-key"
    UNKNOWN = "unknown"


class WEPKeyLength(Enum):
    """WEP key length variants."""
    BITS_40 = 40
    BITS_104 = 104
    BITS_128 = 128
    UNKNOWN = 0


@dataclass
class WEPVulnerability:
    """Represents a single WEP vulnerability finding."""
    vuln_id: str
    title: str
    description: str
    severity: str  # "critical", "high", "medium", "low", "info"
    cve_ids: List[str] = field(default_factory=list)
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WEPScanResult:
    """Aggregated result of a WEP vulnerability scan."""
    bssid: str
    ssid: str
    channel: int
    is_vulnerable: bool
    vulnerabilities: List[WEPVulnerability] = field(default_factory=list)
    wep_auth_mode: WEPAuthMode = WEPAuthMode.UNKNOWN
    wep_key_length: WEPKeyLength = WEPKeyLength.UNKNOWN
    weak_iv_count: int = 0
    total_frames_analyzed: int = 0
    scan_timestamp: float = 0.0


# Known weak IV patterns for WEP (FMS attack related)
WEAK_IV_PATTERNS: List[tuple] = [
    (0x03, 0xFF),
    (0x05, 0xFF),
    (0x0A, 0xFF),
    (0x0F, 0xFF),
    (0x10, 0xFF),
    (0x15, 0xFF),
    (0x1A, 0xFF),
    (0x1F, 0xFF),
]

# Default WEP keys commonly found on consumer routers
DEFAULT_WEP_KEYS: Dict[str, List[str]] = {
    "linksys": ["1234567890", "AAAAAAAAAA", "1234512345"],
    "netgear": ["1234567890", "ABCDEFGHIJ", "0123456789"],
    "dlink": ["1234567890", "AAAAAAAAAA"],
    "belkin": ["1234567890", "ABCDEFGHIJ"],
    "tplink": ["1234567890", "0123456789"],
    "generic": [
        "1234567890", "AAAAAAAAAA", "0123456789",
        "1234512345", "ABCDEABCDE", "1111111111",
        "0000000000", "9876543210",
    ],
}


class WEPChecker:
    """Detects WEP vulnerabilities in a target wireless network.

    WEP (Wired Equivalent Privacy) is a deprecated encryption protocol with
    numerous known vulnerabilities including FMS, KoreK, and PTW attacks.
    This checker identifies networks still using WEP and assesses the
    specific vulnerabilities present.

    Usage::

        checker = WEPChecker(interface="wlan0mon")
        result = checker.check(bssid="AA:BB:CC:DD:EE:FF", ssid="TargetNet")
        if result.is_vulnerable:
            for vuln in result.vulnerabilities:
                print(f"[{vuln.severity}] {vuln.title}: {vuln.description}")
    """

    # Minimum number of frames to analyze for IV patterns
    MIN_FRAMES_FOR_IV_ANALYSIS = 5000
    # Threshold of weak IVs to consider the network highly vulnerable
    WEAK_IV_THRESHOLD = 100
    # Timeout for frame capture in seconds
    CAPTURE_TIMEOUT = 30

    def __init__(self, interface: str = "wlan0mon", timeout: int = 30) -> None:
        """Initialize the WEP checker.

        Args:
            interface: Monitor-mode capable wireless interface.
            timeout: Timeout in seconds for capture operations.
        """
        self.interface = interface
        self.timeout = timeout
        self._captured_frames: List[bytes] = []
        self._iv_cache: List[tuple] = []
        logger.info("WEPChecker initialized on interface %s", interface)

    def check(
        self,
        bssid: str,
        ssid: str = "",
        channel: int = 0,
        capture_data: Optional[bytes] = None,
        beacon_data: Optional[Dict[str, Any]] = None,
    ) -> WEPScanResult:
        """Perform a full WEP vulnerability check on the target network.

        Args:
            bssid: BSSID of the target access point.
            ssid: SSID of the target network.
            channel: Channel the network operates on.
            capture_data: Pre-captured packet data to analyze.
            beacon_data: Parsed beacon frame information.

        Returns:
            WEPScanResult with vulnerability findings.
        """
        start_time = time.time()
        result = WEPScanResult(
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            is_vulnerable=False,
            scan_timestamp=start_time,
        )

        # Step 1: Confirm WEP is in use
        if beacon_data:
            result.wep_auth_mode = self._determine_auth_mode(beacon_data)
            result.wep_key_length = self._determine_key_length(beacon_data)

        # WEP itself is a critical vulnerability
        wep_in_use_vuln = WEPVulnerability(
            vuln_id="WEP-001",
            title="WEP Encryption in Use",
            description=(
                "The network uses WEP encryption, which is fundamentally broken "
                "and can be cracked within minutes using known attacks (FMS, "
                "KoreK, PTW). WEP was deprecated in 2004 by the IEEE."
            ),
            severity="critical",
            cve_ids=["CVE-2001-0496", "CVE-2004-2167", "CVE-2007-2523"],
            recommendation="Migrate to WPA2-AES or WPA3 immediately.",
            evidence={"bssid": bssid, "ssid": ssid},
        )
        result.vulnerabilities.append(wep_in_use_vuln)

        # Step 2: Check authentication mode
        if result.wep_auth_mode == WEPAuthMode.SHARED_KEY:
            shared_key_vuln = WEPVulnerability(
                vuln_id="WEP-002",
                title="WEP Shared-Key Authentication",
                description=(
                    "Shared-key authentication is actually less secure than open "
                    "authentication with WEP. The challenge-response mechanism "
                    "leaks keystream bytes that can be used to forge "
                    "authentication frames."
                ),
                severity="high",
                cve_ids=["CVE-2001-0496"],
                recommendation="Switch to open authentication if WEP must temporarily remain.",
                evidence={"auth_mode": "shared-key"},
            )
            result.vulnerabilities.append(shared_key_vuln)

        # Step 3: Analyze IV patterns if capture data is available
        if capture_data:
            weak_iv_count = self._analyze_iv_patterns(capture_data)
            result.weak_iv_count = weak_iv_count
            result.total_frames_analyzed = len(self._captured_frames)

            if weak_iv_count > 0:
                weak_iv_vuln = WEPVulnerability(
                    vuln_id="WEP-003",
                    title="Weak IV Vectors Detected",
                    description=(
                        f"Detected {weak_iv_count} weak initialization vectors "
                        f"out of {result.total_frames_analyzed} frames analyzed. "
                        "Weak IVs can be exploited by FMS/KoreK attacks to "
                        "recover the WEP key."
                    ),
                    severity="critical",
                    cve_ids=["CVE-2001-0496", "CVE-2004-2167"],
                    recommendation="Migrate to WPA2-AES or WPA3 immediately.",
                    evidence={
                        "weak_iv_count": weak_iv_count,
                        "total_frames": result.total_frames_analyzed,
                        "weak_ratio": round(
                            weak_iv_count / max(result.total_frames_analyzed, 1), 4
                        ),
                    },
                )
                result.vulnerabilities.append(weak_iv_vuln)

        # Step 4: Check for default WEP keys
        default_key_vulns = self._check_default_keys(ssid, bssid)
        result.vulnerabilities.extend(default_key_vulns)

        # Step 5: Check key length vulnerability
        if result.wep_key_length in (WEPKeyLength.BITS_40, WEPKeyLength.UNKNOWN):
            short_key_vuln = WEPVulnerability(
                vuln_id="WEP-004",
                title="Short WEP Key Length",
                description=(
                    f"WEP key length is {result.wep_key_length.value} bits. "
                    "40-bit WEP keys can be brute-forced very quickly. "
                    "Even 104-bit keys are recoverable via statistical attacks."
                ),
                severity="critical" if result.wep_key_length == WEPKeyLength.BITS_40 else "high",
                cve_ids=[],
                recommendation="Use WPA2 with AES-CCMP or WPA3.",
                evidence={"key_length": result.wep_key_length.value},
            )
            result.vulnerabilities.append(short_key_vuln)

        # Step 6: Check for replay attack vulnerability
        replay_vuln = WEPVulnerability(
            vuln_id="WEP-005",
            title="WEP Replay Attack Vulnerability",
            description=(
                "WEP uses a static RC4 key with no replay protection. "
                "Captured packets can be replayed to generate new IVs and "
                "accelerate key recovery via the PTW attack."
            ),
            severity="high",
            cve_ids=["CVE-2006-1380"],
            recommendation="Migrate to WPA2 or WPA3 which include replay protection.",
            evidence={"protocol": "WEP"},
        )
        result.vulnerabilities.append(replay_vuln)

        result.is_vulnerable = len(result.vulnerabilities) > 0
        logger.info(
            "WEP check complete for %s: %d vulnerabilities found",
            bssid,
            len(result.vulnerabilities),
        )
        return result

    def _determine_auth_mode(self, beacon_data: Dict[str, Any]) -> WEPAuthMode:
        """Determine WEP authentication mode from beacon data."""
        privacy = beacon_data.get("privacy", 0)
        auth_mode_raw = beacon_data.get("auth_mode", "")

        if "shared" in auth_mode_raw.lower():
            return WEPAuthMode.SHARED_KEY
        if "open" in auth_mode_raw.lower():
            return WEPAuthMode.OPEN
        if privacy & 0x01 and not (privacy & 0x02):
            # WEP bit set, no WPA bit
            return WEPAuthMode.OPEN  # Most WEP networks use open auth
        return WEPAuthMode.UNKNOWN

    def _determine_key_length(self, beacon_data: Dict[str, Any]) -> WEPKeyLength:
        """Determine WEP key length from beacon data."""
        key_length = beacon_data.get("wep_key_length", 0)
        if key_length == 5:
            return WEPKeyLength.BITS_40
        if key_length == 13:
            return WEPKeyLength.BITS_104
        if key_length == 16:
            return WEPKeyLength.BITS_128

        # Try to infer from capability info
        capability = beacon_data.get("capability_info", 0)
        if capability & 0x0100:  # WEP enabled
            # Default assumption for WEP: 104-bit is most common
            return WEPKeyLength.BITS_104
        return WEPKeyLength.UNKNOWN

    def _analyze_iv_patterns(self, capture_data: bytes) -> int:
        """Analyze captured frames for weak IV patterns.

        Args:
            capture_data: Raw captured packet data.

        Returns:
            Count of weak IV vectors detected.
        """
        weak_count = 0
        self._captured_frames = []
        self._iv_cache = []

        # Parse the capture data into individual frames
        frames = self._parse_capture_frames(capture_data)

        for frame in frames:
            self._captured_frames.append(frame)
            iv = self._extract_iv(frame)
            if iv is not None:
                self._iv_cache.append(iv)
                if self._is_weak_iv(iv):
                    weak_count += 1

        logger.debug(
            "IV analysis: %d weak IVs in %d frames", weak_count, len(frames)
        )
        return weak_count

    def _parse_capture_frames(self, data: bytes) -> List[bytes]:
        """Parse raw capture data into individual frames.

        Attempts to parse PCAP format and extract 802.11 frames.
        """
        frames: List[bytes] = []
        offset = 0

        # Check for PCAP global header (24 bytes)
        if len(data) >= 24:
            magic = struct.unpack("<I", data[0:4])[0]
            if magic == 0xA1B2C3D4 or magic == 0xD4C3B2A1:
                # PCAP format - skip global header
                offset = 24
                # Parse individual packets
                while offset + 16 <= len(data):
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                        "<IIII", data[offset : offset + 16]
                    )
                    pkt_start = offset + 16
                    pkt_end = pkt_start + incl_len
                    if pkt_end > len(data):
                        break
                    frames.append(data[pkt_start:pkt_end])
                    offset = pkt_end
                return frames

        # If not PCAP, treat as raw 802.11 frame stream
        # Attempt to extract frames based on typical frame sizes
        frame_size = 256  # Typical WEP-encrypted data frame size
        while offset < len(data):
            end = min(offset + frame_size, len(data))
            frames.append(data[offset:end])
            offset = end
            if end - offset < 24:
                break

        return frames

    def _extract_iv(self, frame: bytes) -> Optional[tuple]:
        """Extract the IV from a WEP-encrypted frame.

        WEP IV is the first 3 bytes after the 802.11 header.
        """
        # Minimum: 24-byte header + 4-byte IV + payload
        if len(frame) < 28:
            return None

        # Check if this is a data frame (type 2)
        frame_control = frame[0]
        frame_type = (frame_control >> 2) & 0x03
        if frame_type != 2:  # Not a data frame
            return None

        # WEP IV starts at byte 24 (after standard 802.11 header)
        iv_bytes = frame[24:27]
        if len(iv_bytes) < 3:
            return None
        return (iv_bytes[0], iv_bytes[1], iv_bytes[2])

    def _is_weak_iv(self, iv: tuple) -> bool:
        """Check if an IV matches known weak IV patterns (FMS attack)."""
        iv0, iv1, _ = iv
        for pattern_b, pattern_c in WEAK_IV_PATTERNS:
            if iv0 == pattern_b and iv1 == pattern_c:
                return True

        # Additional KoreK weak IV classification
        # IVs where the first byte is in a specific range relative to the key byte
        if iv0 in range(0x03, 0x20) and iv1 == 0xFF:
            return True

        return False

    def _check_default_keys(self, ssid: str, bssid: str) -> List[WEPVulnerability]:
        """Check if the network might be using default WEP keys."""
        vulns: List[WEPVulnerability] = []

        ssid_lower = ssid.lower()
        matched_vendor = None
        for vendor, keys in DEFAULT_WEP_KEYS.items():
            if vendor in ssid_lower:
                matched_vendor = vendor
                break

        if matched_vendor:
            vuln = WEPVulnerability(
                vuln_id="WEP-006",
                title="Potential Default WEP Key",
                description=(
                    f"The SSID '{ssid}' suggests a {matched_vendor} device, "
                    "which may be using a factory-default WEP key. Default "
                    "keys are widely documented and easily cracked."
                ),
                severity="high",
                cve_ids=[],
                recommendation="Change the WEP key immediately, and migrate to WPA2/WPA3.",
                evidence={
                    "matched_vendor": matched_vendor,
                    "default_keys_count": len(DEFAULT_WEP_KEYS[matched_vendor]),
                },
            )
            vulns.append(vuln)
        else:
            # Generic warning about default keys
            vuln = WEPVulnerability(
                vuln_id="WEP-007",
                title="Default WEP Key Risk",
                description=(
                    "Many routers ship with default WEP keys that are easily "
                    "found online. Even custom WEP keys are recoverable via "
                    "statistical attacks."
                ),
                severity="medium",
                cve_ids=[],
                recommendation="Verify the WEP key is not a factory default and migrate to WPA2/WPA3.",
                evidence={"ssid": ssid},
            )
            vulns.append(vuln)

        return vulns

    def estimate_crack_time(self, key_length: WEPKeyLength, weak_iv_count: int) -> Dict[str, Any]:
        """Estimate the time required to crack the WEP key.

        Args:
            key_length: The WEP key length.
            weak_iv_count: Number of weak IVs observed.

        Returns:
            Dictionary with estimated crack time and method.
        """
        estimates: Dict[str, Any] = {}

        if key_length == WEPKeyLength.BITS_40:
            if weak_iv_count > 300:
                estimates["method"] = "PTW"
                estimates["estimated_seconds"] = 60
                estimates["confidence"] = "high"
            elif weak_iv_count > 100:
                estimates["method"] = "KoreK"
                estimates["estimated_seconds"] = 300
                estimates["confidence"] = "medium"
            else:
                estimates["method"] = "Brute Force"
                estimates["estimated_seconds"] = 86400  # ~1 day
                estimates["confidence"] = "low"
        elif key_length == WEPKeyLength.BITS_104:
            if weak_iv_count > 1000:
                estimates["method"] = "PTW"
                estimates["estimated_seconds"] = 180
                estimates["confidence"] = "high"
            elif weak_iv_count > 500:
                estimates["method"] = "KoreK"
                estimates["estimated_seconds"] = 1800
                estimates["confidence"] = "medium"
            else:
                estimates["method"] = "FMS/KoreK (extended capture needed)"
                estimates["estimated_seconds"] = 7200  # ~2 hours
                estimates["confidence"] = "low"
        else:
            estimates["method"] = "Unknown"
            estimates["estimated_seconds"] = -1
            estimates["confidence"] = "unknown"

        return estimates

    def quick_check(self, bssid: str, ssid: str = "", encryption: str = "") -> bool:
        """Quick check if a network is using WEP encryption.

        Args:
            bssid: BSSID of the target.
            ssid: SSID of the network.
            encryption: Encryption type string from scan results.

        Returns:
            True if WEP encryption is detected.
        """
        if not encryption:
            return False

        enc_lower = encryption.lower()
        return "wep" in enc_lower and "wpa" not in enc_lower
