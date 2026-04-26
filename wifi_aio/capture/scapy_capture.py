"""Scapy-based WiFi packet capture with BPF and display filters.

Wraps Scapy's sniff() function to provide a higher-level, asyncio-friendly
capture interface with filter support and packet callbacks.
"""

import threading
import time
from typing import Callable, Dict, List, Optional, Any

from wifi_aio.exceptions import (
    CaptureError,
    WiFiPermissionError,
    WiFiTimeoutError,
)


class ScapyCapture:
    """Capture 802.11 frames using Scapy's sniff engine.

    Parameters
    ----------
    interface:
        Wireless interface name (monitor mode).
    bpf_filter:
        Berkeley Packet Filter string (e.g. ``"type mgt subtype beacon"``).
    display_filter:
        Post-capture display filter applied to each packet before callback.
    snaplen:
        Maximum capture length per packet in bytes.
    channel:
        If set, the interface channel is switched before capture starts.
    """

    def __init__(
        self,
        interface: str = "wlan0mon",
        bpf_filter: Optional[str] = None,
        display_filter: Optional[str] = None,
        snaplen: int = 65535,
        channel: Optional[int] = None,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.display_filter = display_filter
        self.snaplen = snaplen
        self.channel = channel

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable[[Any], None]] = None
        self._packets: List[Any] = []
        self._packet_count = 0
        self._start_time: Optional[float] = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    # ── Context manager ────────────────────────────────────────────────

    def __enter__(self) -> "ScapyCapture":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    # ── Public API ─────────────────────────────────────────────────────

    def start(
        self,
        callback: Optional[Callable[[Any], None]] = None,
        timeout: Optional[float] = None,
        count: Optional[int] = None,
    ) -> None:
        """Begin capturing packets.

        Parameters
        ----------
        callback:
            Called for every matching packet.  If ``None``, packets are
            buffered internally.
        timeout:
            Stop automatically after this many seconds.
        count:
            Stop automatically after this many matching packets.
        """
        if self._running:
            raise CaptureError("Capture is already running")

        self._ensure_scapy()
        self._callback = callback
        self._packets.clear()
        self._packet_count = 0
        self._running = True
        self._stop_event.clear()
        self._start_time = time.time()

        # Set channel if requested
        if self.channel is not None:
            from wifi_aio.capture.raw_capture import RawCapture
            RawCapture.set_channel(self.interface, self.channel)

        self._thread = threading.Thread(
            target=self._capture_loop,
            kwargs={"timeout": timeout, "count": count},
            daemon=True,
            name="scapy-capture",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the capture."""
        self._stop_event.set()
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def read(self, count: int = 1, timeout: Optional[float] = None) -> List[Any]:
        """Return up to *count* buffered packets.

        Blocks until *count* packets are available or *timeout* expires.
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

    def read_all(self) -> List[Any]:
        """Return all buffered packets and clear the internal buffer."""
        with self._lock:
            result = list(self._packets)
            self._packets.clear()
            return result

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def elapsed(self) -> float:
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time

    @property
    def pps(self) -> float:
        e = self.elapsed
        return self._packet_count / e if e > 0 else 0.0

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Internals ──────────────────────────────────────────────────────

    @staticmethod
    def _ensure_scapy() -> None:
        """Verify that scapy is importable."""
        try:
            from scapy.all import sniff  # noqa: F401
        except ImportError as exc:
            raise CaptureError(
                "Scapy is required for ScapyCapture. "
                "Install it with: pip install scapy"
            ) from exc

    def _matches_display_filter(self, packet: Any) -> bool:
        """Apply a simple display filter expression to a packet.

        Supports basic attribute checks like ``"type=0 mgt"``,
        ``"subtype=beacon"``, ``"addr1=ff:ff:ff:ff:ff:ff"``.
        """
        if not self.display_filter:
            return True

        from scapy.all import Dot11

        if not packet.haslayer(Dot11):
            return False

        dot11 = packet[Dot11]
        filters = self.display_filter.split()
        for filt in filters:
            if "=" not in filt:
                continue
            key, value = filt.split("=", 1)
            key = key.strip().lower()
            value = value.strip().lower()
            if key == "type":
                type_map = {"mgt": 0, "ctl": 1, "data": 2}
                if dot11.type != type_map.get(value, int(value, 0)):
                    return False
            elif key == "subtype":
                subtype_map = {
                    "beacon": 8, "probe_req": 4, "probe_resp": 5,
                    "auth": 11, "deauth": 12, "assoc_req": 0,
                    "assoc_resp": 1, "reassoc_req": 2, "reassoc_resp": 3,
                    "disassoc": 10, "action": 13,
                }
                if dot11.subtype != subtype_map.get(value, int(value, 0)):
                    return False
            elif key == "addr1":
                if dot11.addr1 and dot11.addr1.lower() != value:
                    return False
            elif key == "addr2":
                if dot11.addr2 and dot11.addr2.lower() != value:
                    return False
            elif key == "addr3":
                if dot11.addr3 and dot11.addr3.lower() != value:
                    return False
        return True

    def _capture_loop(
        self,
        timeout: Optional[float] = None,
        count: Optional[int] = None,
    ) -> None:
        """Run scapy.sniff in a background thread."""
        from scapy.all import sniff

        def _prn(pkt: Any) -> None:
            if not self._matches_display_filter(pkt):
                return
            self._packet_count += 1
            if self._callback is not None:
                try:
                    self._callback(pkt)
                except Exception:
                    pass
            else:
                with self._lock:
                    self._packets.append(pkt)

        kwargs: Dict[str, Any] = {
            "iface": self.interface,
            "prn": _prn,
            "store": False,
            "stop_filter": lambda p: self._stop_event.is_set(),
        }
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter
        if timeout is not None:
            kwargs["timeout"] = int(timeout)
        if count is not None:
            kwargs["count"] = count

        try:
            sniff(**kwargs)
        except PermissionError as exc:
            raise WiFiPermissionError(
                f"Permission denied capturing on {self.interface}"
            ) from exc
        except Exception as exc:
            if not self._stop_event.is_set():
                raise CaptureError(f"Scapy capture error: {exc}") from exc
        finally:
            self._running = False
