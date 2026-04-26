"""Memory-efficient chunked PCAP reader with overlapping boundaries.

Reads large PCAP files in fixed-size chunks, ensuring that packets
spanning chunk boundaries are correctly reassembled via an overlap
region.  This allows processing files that are too large to fit in
memory.
"""

import os
import struct
from typing import Dict, Iterator, List, Optional, Tuple

from wifi_aio.exceptions import PCAPError, WiFiTimeoutError


class ChunkedPCAPReader:
    """Read a PCAP file in memory-efficient chunks.

    Parameters
    ----------
    path:
        Path to the PCAP file.
    chunk_size:
        Size of each chunk in bytes (default 10 MB).
    overlap:
        Number of bytes to overlap between chunks to avoid splitting
        packets across boundaries (default 4096).
    """

    def __init__(
        self,
        path: str,
        chunk_size: int = 10 * 1024 * 1024,
        overlap: int = 4096,
    ) -> None:
        if not os.path.isfile(path):
            raise PCAPError(f"File not found: {path}")

        self.path = path
        self.chunk_size = chunk_size
        self.overlap = overlap

        self._file_size = os.path.getsize(path)
        self._header: Optional[Dict] = None
        self._byte_order_prefix = "<"
        self._total_packets = 0
        self._current_chunk = 0
        self._position = 0

    # ── Public API ─────────────────────────────────────────────────────

    def read_header(self) -> Dict:
        """Read and return the PCAP global header information."""
        with open(self.path, "rb") as fh:
            magic_data = fh.read(4)
            if len(magic_data) < 4:
                raise PCAPError("File too short to read magic number")

            magic = struct.unpack("<I", magic_data)[0]
            if magic == 0xA1B2C3D4:
                self._byte_order_prefix = "<"
            elif magic == 0xD4C3B2A1:
                self._byte_order_prefix = ">"
            else:
                raise PCAPError(f"Invalid PCAP magic: 0x{magic:08X}")

            fh.seek(0)
            header_data = fh.read(24)
            if len(header_data) < 24:
                raise PCAPError("Truncated PCAP global header")

            bo = self._byte_order_prefix
            fields = struct.unpack(f"{bo}IHHiIII", header_data)
            self._header = {
                "magic": fields[0],
                "version_major": fields[1],
                "version_minor": fields[2],
                "thiszone": fields[3],
                "sigfigs": fields[4],
                "snaplen": fields[5],
                "linktype": fields[6],
                "byte_order": bo,
            }
            return self._header

    def iter_chunks(self) -> Iterator[List[Tuple[float, int, int, bytes]]]:
        """Yield lists of packets, one chunk at a time.

        Each yielded chunk is a list of
        ``(timestamp, captured_length, original_length, data)`` tuples.
        """
        if self._header is None:
            self.read_header()

        bo = self._byte_order_prefix
        header_size = 24  # global header size

        with open(self.path, "rb") as fh:
            # Skip the global header
            fh.seek(header_size)

            # We process packets sequentially, reading in large chunks
            # to avoid per-packet system calls, but track the file offset
            file_offset = header_size
            leftover = b""
            chunk_packets: List[Tuple[float, int, int, bytes]] = []
            chunk_start = header_size

            while True:
                # Read a block of data
                read_size = self.chunk_size
                raw = fh.read(read_size)
                if not raw and not leftover:
                    # Yield any remaining packets in the current chunk
                    if chunk_packets:
                        yield chunk_packets
                    break

                data = leftover + raw
                offset = 0

                while offset + 16 <= len(data):
                    # Parse packet header
                    ts_sec, ts_usec, captured_len, original_len = struct.unpack(
                        f"{bo}IIII", data[offset: offset + 16]
                    )

                    # Sanity check
                    if captured_len > 0x100000 or captured_len == 0:
                        # Bad record – skip 1 byte and try to resync
                        offset += 1
                        continue

                    total_record = 16 + captured_len
                    if offset + total_record > len(data):
                        # Packet spans read boundary – save for next iteration
                        break

                    pkt_data = data[offset + 16: offset + 16 + captured_len]
                    timestamp = ts_sec + ts_usec / 1_000_000.0

                    self._total_packets += 1
                    chunk_packets.append(
                        (timestamp, captured_len, original_len, pkt_data)
                    )

                    offset += total_record

                    # If we've crossed the chunk boundary, yield the chunk
                    current_file_pos = file_offset + offset - len(leftover)
                    if current_file_pos - chunk_start >= self.chunk_size:
                        yield chunk_packets
                        chunk_packets = []
                        chunk_start = current_file_pos

                # Save any partial data for the next read
                leftover = data[offset:]
                file_offset += len(raw)

            # Yield any remaining packets
            if chunk_packets:
                yield chunk_packets

    def iter_packets(self) -> Iterator[Tuple[float, int, int, bytes]]:
        """Yield individual packets from the PCAP file.

        Each packet is a ``(timestamp, captured_length, original_length, data)``
        tuple.  Internally reads in chunks for memory efficiency.
        """
        for chunk in self.iter_chunks():
            yield from chunk

    def count_packets(self) -> int:
        """Count total packets in the file without storing them."""
        for _ in self.iter_packets():
            pass
        return self._total_packets

    @property
    def total_packets(self) -> int:
        return self._total_packets

    @property
    def file_size(self) -> int:
        return self._file_size

    @property
    def num_chunks(self) -> int:
        """Estimated number of chunks."""
        if self._file_size <= 24:
            return 0
        data_size = self._file_size - 24  # subtract global header
        return max(1, (data_size + self.chunk_size - 1) // self.chunk_size)

    @property
    def progress(self) -> float:
        """Read progress as a fraction (0.0–1.0)."""
        if self._file_size == 0:
            return 1.0
        return self._position / self._file_size

    def stats(self) -> Dict:
        """Return summary statistics."""
        return {
            "path": self.path,
            "file_size": self._file_size,
            "chunk_size": self.chunk_size,
            "overlap": self.overlap,
            "estimated_chunks": self.num_chunks,
            "total_packets_read": self._total_packets,
            "header": self._header,
        }
