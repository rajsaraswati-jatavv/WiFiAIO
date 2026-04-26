"""PCAP and PCAPNG file writer.

Provides a pure-Python writer for both legacy PCAP and next-generation
PCAPNG capture file formats, with proper link-layer and per-packet
header construction.
"""

import os
import struct
import time
from typing import BinaryIO, List, Optional, Union

from wifi_aio.exceptions import PCAPError


# ── PCAP format constants ──────────────────────────────────────────────

PCAP_MAGIC = 0xA1B2C3D4
PCAP_SWAPPED_MAGIC = 0xD4C3B2A1
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

# Link-layer types
LINKTYPE_ETHERNET = 1
LINKTYPE_IEEE802_11 = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127
LINKTYPE_PRISM_HEADER = 119

# PCAPNG block types
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_EPB = 0x00000006
PCAPNG_SPB = 0x00000003

PCAPNG_VERSION_MAJOR = 1
PCAPNG_VERSION_MINOR = 0


def _pad4(data: bytes) -> bytes:
    """Pad *data* to a 4-byte boundary."""
    remainder = len(data) % 4
    if remainder:
        data += b"\x00" * (4 - remainder)
    return data


class PCAPWriter:
    """Write captured packets to a PCAP or PCAPNG file.

    Parameters
    ----------
    path:
        Output file path.
    linktype:
        PCAP link-layer type (default: IEEE 802.11 Radiotap).
    format:
        ``"pcap"`` or ``"pcapng"``.
    snaplen:
        Maximum packet length declared in the file header.
    overwrite:
        If ``True``, overwrite an existing file.
    """

    def __init__(
        self,
        path: str,
        linktype: int = LINKTYPE_IEEE802_11_RADIOTAP,
        format: str = "pcap",
        snaplen: int = 65535,
        overwrite: bool = True,
    ) -> None:
        if format not in ("pcap", "pcapng"):
            raise PCAPError(f"Unsupported format: {format!r} – use 'pcap' or 'pcapng'")

        self.path = path
        self.linktype = linktype
        self.format = format
        self.snaplen = snaplen
        self.overwrite = overwrite

        self._fh: Optional[BinaryIO] = None
        self._packet_count = 0
        self._closed = False
        self._byte_order = "="  # native

    # ── Context manager ────────────────────────────────────────────────

    def __enter__(self) -> "PCAPWriter":
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # ── Public API ─────────────────────────────────────────────────────

    def open(self) -> None:
        """Open the file and write the global header."""
        if self._fh is not None:
            raise PCAPError("File is already open")

        if os.path.exists(self.path) and not self.overwrite:
            raise PCAPError(f"File already exists: {self.path}")

        # Ensure parent directory exists
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        self._fh = open(self.path, "wb")

        if self.format == "pcap":
            self._write_pcap_global_header()
        else:
            self._write_pcapng_shb()
            self._write_pcapng_idb()

    def close(self) -> None:
        """Flush and close the file."""
        if self._fh is not None and not self._closed:
            self._fh.flush()
            self._fh.close()
        self._fh = None
        self._closed = True

    def write_packet(
        self,
        data: bytes,
        timestamp: Optional[float] = None,
        original_length: Optional[int] = None,
    ) -> None:
        """Write a single packet.

        Parameters
        ----------
        data:
            Raw packet bytes.
        timestamp:
            Unix timestamp (seconds).  ``None`` means *now*.
        original_length:
            Original length on the wire if *data* was truncated.
            ``None`` means ``len(data)``.
        """
        if self._fh is None:
            raise PCAPError("File is not open – call open() first")
        if self._closed:
            raise PCAPError("File is already closed")

        if timestamp is None:
            timestamp = time.time()
        if original_length is None:
            original_length = len(data)

        # Truncate if exceeding snaplen
        captured_length = min(len(data), self.snaplen)
        packet_data = data[:captured_length]

        if self.format == "pcap":
            self._write_pcap_packet(packet_data, timestamp, captured_length, original_length)
        else:
            self._write_pcapng_epb(packet_data, timestamp, captured_length, original_length)

        self._packet_count += 1

    def write_packets(
        self,
        packets: List[tuple],
    ) -> int:
        """Write multiple packets at once.

        Parameters
        ----------
        packets:
            List of ``(data, timestamp)`` or
            ``(data, timestamp, original_length)`` tuples.

        Returns
        -------
        int
            Number of packets written.
        """
        for pkt in packets:
            if len(pkt) == 2:
                self.write_packet(pkt[0], pkt[1])
            elif len(pkt) >= 3:
                self.write_packet(pkt[0], pkt[1], pkt[2])
            else:
                self.write_packet(pkt[0])
        return len(packets)

    def flush(self) -> None:
        """Flush the underlying file handle."""
        if self._fh is not None:
            self._fh.flush()

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def file_size(self) -> int:
        """Current file size in bytes."""
        if self._fh is not None:
            self._fh.flush()
            return self._fh.tell()
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    # ── PCAP format ────────────────────────────────────────────────────

    def _write_pcap_global_header(self) -> None:
        """Write the 24-byte PCAP global header."""
        # Magic, version major, version minor, thiszone, sigfigs, snaplen, network
        header = struct.pack(
            "=IHHiIII",
            PCAP_MAGIC,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,  # thiszone (GMT)
            0,  # sigfigs
            self.snaplen,
            self.linktype,
        )
        self._fh.write(header)

    def _write_pcap_packet(
        self,
        data: bytes,
        ts: float,
        captured_length: int,
        original_length: int,
    ) -> None:
        """Write a single PCAP packet record."""
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        pkt_header = struct.pack(
            "=IIII",
            ts_sec,
            ts_usec,
            captured_length,
            original_length,
        )
        self._fh.write(pkt_header)
        self._fh.write(data)

    # ── PCAPNG format ──────────────────────────────────────────────────

    def _write_pcapng_shb(self) -> None:
        """Write the Section Header Block."""
        # SHB: block type, block total length, byte-order magic,
        #       version, section length, options, block total length
        body = struct.pack(
            "=IHHq",
            PCAP_MAGIC,  # byte-order magic
            PCAPNG_VERSION_MAJOR,
            PCAPNG_VERSION_MINOR,
            -1,  # section length (unspecified)
        )
        # Add comment option (opt_end_of_opts = 0)
        comment = b"Created by WiFiAIO"
        opt = struct.pack("=HH", 1, len(comment)) + comment  # opt_comment = 1
        opt += _pad4(opt)
        opt += struct.pack("=HH", 0, 0)  # opt_end_of_opts

        body += opt
        total_length = 8 + len(body) + 4  # type(4) + length(4) + body + length(4)
        header = struct.pack("=II", PCAPNG_SHB, total_length)
        footer = struct.pack("=I", total_length)
        self._fh.write(header + body + footer)

    def _write_pcapng_idb(self) -> None:
        """Write an Interface Description Block."""
        # IDB body: linktype(2) + reserved(2) + snaplen(4)
        body = struct.pack("=HHI", self.linktype, 0, self.snaplen)
        # Options: if_name
        if_name = self._encode_str(self.path)
        opt = struct.pack("=HH", 2, len(if_name)) + if_name  # if_name = 2
        opt = _pad4(opt)
        opt += struct.pack("=HH", 0, 0)  # opt_end_of_opts
        body += opt

        total_length = 8 + len(body) + 4
        header = struct.pack("=II", PCAPNG_IDB, total_length)
        footer = struct.pack("=I", total_length)
        self._fh.write(header + body + footer)

    def _write_pcapng_epb(
        self,
        data: bytes,
        ts: float,
        captured_length: int,
        original_length: int,
    ) -> None:
        """Write an Enhanced Packet Block."""
        # EPB body: interface_id(4) + ts_high(4) + ts_low(4) +
        #            captured_len(4) + original_len(4) + packet_data + padding
        ts_resolution = 1_000_000  # microseconds
        ts_int = int(ts * ts_resolution)
        ts_high = (ts_int >> 32) & 0xFFFFFFFF
        ts_low = ts_int & 0xFFFFFFFF

        padded_data = _pad4(data)
        body = struct.pack(
            "=IIIII",
            0,  # interface id
            ts_high,
            ts_low,
            captured_length,
            original_length,
        )
        body += padded_data
        # No options, just end-of-options
        body += struct.pack("=HH", 0, 0)

        total_length = 8 + len(body) + 4
        header = struct.pack("=II", PCAPNG_EPB, total_length)
        footer = struct.pack("=I", total_length)
        self._fh.write(header + body + footer)

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _encode_str(s: str) -> bytes:
        """Encode a string as UTF-8 bytes."""
        return s.encode("utf-8")

    @staticmethod
    def linktype_name(linktype: int) -> str:
        """Return a human-readable name for a PCAP link-layer type."""
        names = {
            LINKTYPE_ETHERNET: "Ethernet",
            LINKTYPE_IEEE802_11: "IEEE 802.11",
            LINKTYPE_IEEE802_11_RADIOTAP: "IEEE 802.11 Radiotap",
            LINKTYPE_PRISM_HEADER: "Prism Header",
        }
        return names.get(linktype, f"Unknown ({linktype})")
