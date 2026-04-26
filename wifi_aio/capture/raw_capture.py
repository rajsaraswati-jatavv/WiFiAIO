"""Raw socket packet capture on a monitor-mode interface.

Uses Linux AF_PACKET raw sockets to capture 802.11 frames directly
from a wireless interface operating in monitor mode, without any
external dependency beyond the Python standard library.
"""

import errno
import os
import select
import socket
import struct
import threading
import time
from typing import Callable, List, Optional

from wifi_aio.exceptions import (
    CaptureError,
    MonitorModeError,
    WiFiPermissionError,
    WiFiTimeoutError,
)


# Linux socket constants not always available via the socket module
AF_PACKET = getattr(socket, "AF_PACKET", 17)
PACKET_MR_PROMISC = 1
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1

# Radiotap header link-layer type
LINKTYPE_IEEE802_11_RADIOTAP = 127
LINKTYPE_IEEE802_11 = 105

# Buffer size per recv call
RECV_BUFFER = 65535


class RawCapture:
    """Capture 802.11 frames using a raw Linux packet socket.

    Parameters
    ----------
    interface:
        Name of the wireless interface (must already be in monitor mode).
    linktype:
        PCAP link-layer type to tag captured packets with.
    buffer_size:
        Kernel socket receive-buffer size in bytes (0 = system default).
    snaplen:
        Maximum bytes to capture per packet.
    """

    def __init__(
        self,
        interface: str = "wlan0mon",
        linktype: int = LINKTYPE_IEEE802_11_RADIOTAP,
        buffer_size: int = 2 * 1024 * 1024,
        snaplen: int = 65535,
    ) -> None:
        self.interface = interface
        self.linktype = linktype
        self.buffer_size = buffer_size
        self.snaplen = snaplen

        self._sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._callback: Optional[Callable[[bytes, float], None]] = None
        self._packets: List[tuple] = []
        self._packet_count = 0
        self._start_time: Optional[float] = None

    # ── Context manager ────────────────────────────────────────────────

    def __enter__(self) -> "RawCapture":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    # ── Public API ─────────────────────────────────────────────────────

    def start(
        self,
        callback: Optional[Callable[[bytes, float], None]] = None,
    ) -> None:
        """Open the raw socket and begin capturing.

        Parameters
        ----------
        callback:
            If provided, each packet ``(raw_bytes, timestamp)`` is
            delivered here in real time.  If ``None``, packets are
            buffered internally and retrieved via :meth:`read`.
        """
        if self._running:
            raise CaptureError("Capture is already running")

        self._check_permissions()
        self._sock = self._create_socket()

        self._callback = callback
        self._packets.clear()
        self._packet_count = 0
        self._running = True
        self._start_time = time.time()

        self._thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="raw-capture"
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop capturing and close the socket."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def read(self, count: int = 1, timeout: Optional[float] = None) -> List[tuple]:
        """Return up to *count* buffered packets as ``[(data, ts), ...]``.

        Blocks until *count* packets are available or *timeout* expires.
        If *timeout* is ``None`` and no packets are available, returns
        an empty list immediately.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._lock:
                if len(self._packets) >= count:
                    result = self._packets[:count]
                    self._packets = self._packets[count:]
                    return result
            if deadline is not None and time.monotonic() >= deadline:
                with self._lock:
                    result = list(self._packets)
                    self._packets.clear()
                    return result
            if not self._running:
                with self._lock:
                    result = list(self._packets)
                    self._packets.clear()
                    return result
            time.sleep(0.01)

    def read_all(self) -> List[tuple]:
        """Return all buffered packets and clear the internal buffer."""
        with self._lock:
            result = list(self._packets)
            self._packets.clear()
            return result

    @property
    def packet_count(self) -> int:
        """Total number of packets captured since :meth:`start`."""
        return self._packet_count

    @property
    def elapsed(self) -> float:
        """Seconds elapsed since capture started."""
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time

    @property
    def pps(self) -> float:
        """Packets per second."""
        e = self.elapsed
        return self._packet_count / e if e > 0 else 0.0

    @property
    def is_running(self) -> bool:
        """Whether the capture loop is active."""
        return self._running

    # ── Internals ──────────────────────────────────────────────────────

    def _check_permissions(self) -> None:
        """Raise if we lack the privileges needed for raw sockets."""
        if os.geteuid() != 0:
            raise WiFiPermissionError(
                "Root privileges are required for raw socket capture. "
                "Run with sudo or as root."
            )

    def _create_socket(self) -> socket.socket:
        """Create and bind an AF_PACKET raw socket with promiscuous mode."""
        try:
            sock = socket.socket(AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        except OSError as exc:
            if exc.errno == errno.EACCES:
                raise WiFiPermissionError(
                    f"Permission denied creating raw socket on {self.interface}"
                ) from exc
            raise CaptureError(
                f"Failed to create raw socket: {exc}"
            ) from exc

        # Increase receive buffer
        if self.buffer_size > 0:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_size)
            except OSError:
                pass  # non-fatal

        # Bind to the interface
        try:
            sock.bind((self.interface, 0x0003))
        except OSError as exc:
            sock.close()
            raise MonitorModeError(
                f"Cannot bind to {self.interface} – is it in monitor mode? ({exc})"
            ) from exc

        # Enable promiscuous mode
        try:
            ifr = struct.pack("16sH", self.interface.encode(), socket.PACKET_MR_PROMISC)
            sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, ifr)
        except OSError:
            pass  # best-effort

        sock.settimeout(0.5)
        return sock

    def _capture_loop(self) -> None:
        """Main capture loop running in a background thread."""
        while self._running and self._sock is not None:
            try:
                ready, _, _ = select.select([self._sock], [], [], 0.5)
                if not ready:
                    continue
                data = self._sock.recv(RECV_BUFFER)
            except (socket.timeout, InterruptedError):
                continue
            except OSError as exc:
                if self._running:
                    # Socket may have been closed by stop()
                    pass
                continue

            ts = time.time()
            self._packet_count += 1

            # Truncate to snaplen
            if len(data) > self.snaplen:
                data = data[: self.snaplen]

            if self._callback is not None:
                try:
                    self._callback(data, ts)
                except Exception:
                    pass  # swallow callback errors
            else:
                with self._lock:
                    self._packets.append((data, ts))

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def is_monitor_mode(interface: str) -> bool:
        """Check whether *interface* is in monitor mode via /sys/net."""
        mode_path = f"/sys/class/net/{interface}/type"
        try:
            with open(mode_path, "r") as fh:
                # 803 for monitor, 1 for managed
                return fh.read().strip() == "803"
        except FileNotFoundError:
            return False

    @staticmethod
    def set_monitor_mode(interface: str) -> None:
        """Put *interface* into monitor mode using iw.

        Requires root privileges.
        """
        if os.geteuid() != 0:
            raise WiFiPermissionError("Root privileges required to set monitor mode")

        from wifi_aio.utils import run_command

        # Bring interface down
        run_command(["ip", "link", "set", interface, "down"], sudo=True)
        # Set monitor mode
        rc, _, err = run_command(
            ["iw", "dev", interface, "set", "type", "monitor"], sudo=True
        )
        if rc != 0:
            raise MonitorModeError(
                f"Failed to set {interface} to monitor mode: {err}"
            )
        # Bring interface up
        run_command(["ip", "link", "set", interface, "up"], sudo=True)

    @staticmethod
    def set_channel(interface: str, channel: int) -> None:
        """Set the channel on *interface* (monitor mode)."""
        if os.geteuid() != 0:
            raise WiFiPermissionError("Root privileges required to set channel")

        from wifi_aio.utils import run_command

        rc, _, err = run_command(
            ["iw", "dev", interface, "set", "channel", str(channel)], sudo=True
        )
        if rc != 0:
            raise CaptureError(f"Failed to set channel {channel} on {interface}: {err}")
