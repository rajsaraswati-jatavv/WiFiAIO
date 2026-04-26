"""PCAP file reader and parser.

Reads legacy PCAP and PCAPNG files, yielding individual packets with
their timestamps and metadata.  Supports both little-endian and
big-endian byte orders.
"""

import os
import struct
from typing import BinaryIO, Dict, Iterator, List, Optional, Tuple

from wifi_aio.exceptions import PCAPError, WiFiTimeoutError


# ── PCAP format constants ──────────────────────────────────────────────

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAPNG_SHB_MAGIC = 0x0A0D0D0A

LINKTYPE_NAMES: Dict[int, str] = {
    0: "NULL",
    1: "Ethernet",
    105: "IEEE 802.11",
    119: "Prism Header",
    127: "IEEE 802.11 Radiotap",
}

# PCAPNG block types
PCAPNG_IDB = 0x00000001
PCAPNG_EPB = 0x00000006
PCAPNG_SPB = 0x00000003
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_NRB = 0x00000004


class PCAPHeader:
    """Parsed PCAP global header metadata."""

    def __init__(
        self,
        magic: int,
        version_major: int,
        version_minor: int,
        thiszone: int,
        sigfigs: int,
        snaplen: int,
        linktype: int,
        byte_order: str,
    ) -> None:
        self.magic = magic
        self.version_major = version_major
        self.version_minor = version_minor
        self.thiszone = thiszone
        self.sigfigs = sigfigs
        self.snaplen = snaplen
        self.linktype = linktype
        self.byte_order = byte_order

    @property
    def linktype_name(self) -> str:
        return LINKTYPE_NAMES.get(self.linktype, f"Unknown ({self.linktype})")

    def __repr__(self) -> str:
        return (
            f"PCAPHeader(magic=0x{self.magic:08X}, version={self.version_major}."
            f"{self.version_minor}, snaplen={self.snaplen}, "
            f"linktype={self.linktype_name})"
        )


class PCAPPacket:
    """A single parsed PCAP packet record."""

    __slots__ = ("timestamp", "captured_length", "original_length", "data")

    def __init__(
        self,
        timestamp: float,
        captured_length: int,
        original_length: int,
        data: bytes,
    ) -> None:
        self.timestamp = timestamp
        self.captured_length = captured_length
        self.original_length = original_length
        self.data = data

    @property
    def is_truncated(self) -> bool:
        return self.captured_length < self.original_length

    def __repr__(self) -> str:
        return (
            f"PCAPPacket(ts={self.timestamp:.6f}, len={self.captured_length}"
            f"/{self.original_length})"
        )

    def __len__(self) -> int:
        return self.captured_length


class PCAPReader:
    """Read and iterate over packets in a PCAP or PCAPNG file.

    Parameters
    ----------
    path:
        Path to the PCAP/PCAPNG file.
    """

    def __init__(self, path: str) -> None:
        if not os.path.isfile(path):
            raise PCAPError(f"File not found: {path}")

        self.path = path
        self._fh: Optional[BinaryIO] = None
        self._header: Optional[PCAPHeader] = None
        self._packet_count = 0
        self._is_pcapng = False
        self._byte_order_prefix = "<"  # little-endian default
        self._pcapng_interfaces: List[Dict] = []
        self._ts_resolution = 1_000_000  # microseconds default

    # ── Context manager ────────────────────────────────────────────────

    def __enter__(self) -> "PCAPReader":
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # ── Iterator ───────────────────────────────────────────────────────

    def __iter__(self) -> Iterator[PCAPPacket]:
        return self.iter_packets()

    # ── Public API ─────────────────────────────────────────────────────

    def open(self) -> None:
        """Open the file, detect format and read the global header."""
        if self._fh is not None:
            raise PCAPError("File is already open")

        self._fh = open(self.path, "rb")

        # Detect format by reading first 4 bytes
        magic_bytes = self._fh.read(4)
        if len(magic_bytes) < 4:
            raise PCAPError("File is too short to contain a valid header")

        magic = struct.unpack("<I", magic_bytes)[0]

        if magic == PCAPNG_SHB_MAGIC:
            self._is_pcapng = True
            self._read_pcapng_shb()
        elif magic == PCAP_MAGIC_LE:
            self._byte_order_prefix = "<"
            self._fh.seek(0)
            self._read_pcap_global_header()
        elif magic == PCAP_MAGIC_BE:
            self._byte_order_prefix = ">"
            self._fh.seek(0)
            self._read_pcap_global_header()
        else:
            raise PCAPError(
                f"Not a valid PCAP/PCAPNG file (magic: 0x{magic:08X})"
            )

    def close(self) -> None:
        """Close the file handle."""
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def iter_packets(self) -> Iterator[PCAPPacket]:
        """Yield :class:`PCAPPacket` objects from the file."""
        if self._fh is None:
            raise PCAPError("File is not open – call open() first")

        if self._is_pcapng:
            yield from self._iter_pcapng_packets()
        else:
            yield from self._iter_pcap_packets()

    def read_all(self, max_packets: Optional[int] = None) -> List[PCAPPacket]:
        """Read all packets into a list.

        Parameters
        ----------
        max_packets:
            If set, stop after this many packets.
        """
        packets: List[PCAPPacket] = []
        for i, pkt in enumerate(self.iter_packets()):
            packets.append(pkt)
            if max_packets is not None and i + 1 >= max_packets:
                break
        return packets

    @property
    def header(self) -> Optional[PCAPHeader]:
        return self._header

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def is_pcapng(self) -> bool:
        return self._is_pcapng

    @property
    def file_size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def stats(self) -> Dict:
        """Return a summary of the PCAP file."""
        return {
            "path": self.path,
            "format": "pcapng" if self._is_pcapng else "pcap",
            "linktype": self._header.linktype if self._header else None,
            "linktype_name": (
                self._header.linktype_name if self._header else None
            ),
            "snaplen": self._header.snaplen if self._header else None,
            "packets_read": self._packet_count,
            "file_size": self.file_size,
        }

    # ── PCAP reading ───────────────────────────────────────────────────

    def _read_pcap_global_header(self) -> None:
        """Parse the 24-byte PCAP global header."""
        header_data = self._fh.read(24)
        if len(header_data) < 24:
            raise PCAPError("Truncated PCAP global header")

        fields = struct.unpack(f"{self._byte_order_prefix}IHHiIII", header_data)
        self._header = PCAPHeader(
            magic=fields[0],
            version_major=fields[1],
            version_minor=fields[2],
            thiszone=fields[3],
            sigfigs=fields[4],
            snaplen=fields[5],
            linktype=fields[6],
            byte_order=self._byte_order_prefix,
        )

    def _iter_pcap_packets(self) -> Iterator[PCAPPacket]:
        """Yield packets from a legacy PCAP file."""
        bo = self._byte_order_prefix
        while True:
            pkt_header = self._fh.read(16)
            if len(pkt_header) < 16:
                break  # EOF

            ts_sec, ts_usec, captured_len, original_len = struct.unpack(
                f"{bo}IIII", pkt_header
            )

            if captured_len > 0x100000:  # sanity check: 1 MB
                raise PCAPError(
                    f"Unreasonable captured length ({captured_len}) – "
                    "file may be corrupted"
                )

            data = self._fh.read(captured_len)
            if len(data) < captured_len:
                raise PCAPError("Truncated packet data")

            timestamp = ts_sec + ts_usec / 1_000_000.0
            self._packet_count += 1
            yield PCAPPacket(timestamp, captured_len, original_len, data)

    # ── PCAPNG reading ─────────────────────────────────────────────────

    def _read_pcapng_shb(self) -> None:
        """Parse the PCAPNG Section Header Block."""
        bo = self._byte_order_prefix
        # Already read 4 bytes of magic; read the rest of the block length
        length_data = self._fh.read(4)
        if len(length_data) < 4:
            raise PCAPError("Truncated SHB")
        block_length = struct.unpack(f"{bo}I", length_data)[0]

        # Read the rest of the SHB (skip body, verify trailing length)
        remaining = block_length - 12  # magic(4) + length(4) + trailing_length(4)
        if remaining > 0:
            self._fh.read(remaining)

        # Create a synthetic PCAP header for API compatibility
        self._header = PCAPHeader(
            magic=PCAPNG_SHB_MAGIC,
            version_major=1,
            version_minor=0,
            thiszone=0,
            sigfigs=0,
            snaplen=65535,
            linktype=127,
            byte_order=bo,
        )

    def _iter_pcapng_packets(self) -> Iterator[PCAPPacket]:
        """Yield packets from a PCAPNG file."""
        bo = self._byte_order_prefix

        while True:
            block_type_data = self._fh.read(4)
            if len(block_type_data) < 4:
                break  # EOF

            block_type = struct.unpack(f"{bo}I", block_type_data)[0]
            block_length_data = self._fh.read(4)
            if len(block_length_data) < 4:
                break
            block_length = struct.unpack(f"{bo}I", block_length_data)[0]

            # Body size = total - 8 (type+length) - 4 (trailing length)
            body_size = block_length - 12
            if body_size < 0 or body_size > 0x10000000:
                # Skip to trailing length
                self._fh.read(max(body_size, 0))
                self._fh.read(4)
                continue

            body = self._fh.read(body_size) if body_size > 0 else b""
            # Read trailing length (should match block_length)
            self._fh.read(4)

            if block_type == PCAPNG_IDB:
                self._parse_idb(body)
            elif block_type == PCAPNG_EPB:
                pkt = self._parse_epb(body)
                if pkt is not None:
                    self._packet_count += 1
                    yield pkt
            elif block_type == PCAPNG_SPB:
                pkt = self._parse_spb(body)
                if pkt is not None:
                    self._packet_count += 1
                    yield pkt
            # SHB, NRB and other blocks are skipped

    def _parse_idb(self, body: bytes) -> None:
        """Parse an Interface Description Block."""
        if len(body) < 8:
            return
        bo = self._byte_order_prefix
        linktype, reserved, snaplen = struct.unpack(f"{bo}HHI", body[:8])
        self._pcapng_interfaces.append({
            "linktype": linktype,
            "snaplen": snaplen,
            "ts_resolution": 6,  # default: microseconds
        })
        # Update the synthetic header
        if self._header is not None:
            self._header.linktype = linktype
            self._header.snaplen = snaplen

    def _parse_epb(self, body: bytes) -> Optional[PCAPPacket]:
        """Parse an Enhanced Packet Block."""
        if len(body) < 20:
            return None
        bo = self._byte_order_prefix
        iface_id, ts_high, ts_low, captured_len, original_len = struct.unpack(
            f"{bo}IIIII", body[:20]
        )

        # Compute timestamp
        ts_res = self._ts_resolution
        if iface_id < len(self._pcapng_interfaces):
            ts_res = 10 ** (-self._pcapng_interfaces[iface_id].get("ts_resolution", -6))

        ts_raw = (ts_high << 32) | ts_low
        timestamp = ts_raw * ts_res if ts_res else ts_raw / 1_000_000.0

        # Extract packet data (padded to 4 bytes)
        padded_len = captured_len + (4 - captured_len % 4) % 4
        if 20 + padded_len > len(body):
            return None
        data = body[20: 20 + captured_len]

        return PCAPPacket(timestamp, captured_len, original_len, data)

    def _parse_spb(self, body: bytes) -> Optional[PCAPPacket]:
        """Parse a Simple Packet Block."""
        if len(body) < 4:
            return None
        bo = self._byte_order_prefix
        original_len = struct.unpack(f"{bo}I", body[:4])[0]
        # SPB doesn't have a timestamp; use 0.0
        data = body[4:]
        captured_len = len(data)
        return PCAPPacket(0.0, captured_len, original_len, data)
