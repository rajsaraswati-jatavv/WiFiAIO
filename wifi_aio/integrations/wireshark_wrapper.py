"""Wireshark/tshark wrapper for packet capture and analysis.

Provides a Python API for tshark (the command-line Wireshark tool)
for packet capture, filtering, protocol analysis, and statistics.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from wifi_aio.exceptions import (
    CaptureError,
    PCAPError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


@dataclass
class TsharkPacket:
    """A single packet parsed from tshark output.

    Attributes:
        frame_number: Frame number in the capture.
        timestamp: Epoch timestamp.
        source: Source address.
        destination: Destination address.
        protocol: Highest-layer protocol.
        length: Frame length in bytes.
        info: Packet summary line.
        fields: Key-value field data from -T fields.
    """

    frame_number: int = 0
    timestamp: float = 0.0
    source: str = ""
    destination: str = ""
    protocol: str = ""
    length: int = 0
    info: str = ""
    fields: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "frame_number": self.frame_number,
            "timestamp": self.timestamp,
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "length": self.length,
            "info": self.info,
            "fields": self.fields,
        }


@dataclass
class TsharkResult:
    """Result of a tshark capture or analysis session."""

    packets: list[TsharkPacket] = field(default_factory=list)
    total_packets: int = 0
    capture_file: str = ""
    elapsed: float = 0.0
    output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_packets": self.total_packets,
            "capture_file": self.capture_file,
            "elapsed": self.elapsed,
            "packets": [p.to_dict() for p in self.packets[:100]],  # Limit
        }


class WiresharkWrapper:
    """tshark/wireshark integration for packet analysis.

    Provides methods for live capture, reading PCAP files,
    filtering, protocol statistics, and field extraction.

    Example::

        ws = WiresharkWrapper(interface="wlan0mon")
        result = ws.capture(duration=30, display_filter="eapol")
        for pkt in result.packets:
            print(pkt.source, pkt.destination, pkt.protocol)
    """

    def __init__(
        self,
        tshark_path: str = "tshark",
        wireshark_path: str = "wireshark",
        timeout: int = 60,
    ) -> None:
        self.tshark_path = tshark_path
        self.wireshark_path = wireshark_path
        self.timeout = timeout
        self._capture_proc: Optional[subprocess.Popen] = None

    # ── Live capture ───────────────────────────────────────────────────

    def capture(
        self,
        interface: str = "",
        duration: int = 30,
        capture_filter: Optional[str] = None,
        display_filter: Optional[str] = None,
        output_file: Optional[str] = None,
        max_packets: int = 0,
    ) -> TsharkResult:
        """Perform a live packet capture using tshark.

        Args:
            interface: Capture interface.
            duration: Capture duration in seconds.
            capture_filter: BPF capture filter.
            display_filter: Wireshark display filter.
            output_file: Save captured packets to this file.
            max_packets: Stop after this many packets (0 = unlimited).

        Returns:
            TsharkResult with captured packets.
        """
        cmd = [
            self.tshark_path,
            "-i", interface or "eth0",
            "-T", "fields",
            "-E", "separator=|",
            "-E", "header=y",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "frame.protocols",
            "-e", "frame.len",
        ]

        if capture_filter:
            cmd.extend(["-f", capture_filter])
        if display_filter:
            cmd.extend(["-Y", display_filter])
        if output_file:
            cmd.extend(["-w", output_file])
        if max_packets > 0:
            cmd.extend(["-c", str(max_packets)])

        # Auto-stop after duration
        cmd.extend(["-a", f"duration:{duration}"])

        start = time.time()
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=duration + 30,
            )
            output = result.stdout
        except FileNotFoundError:
            raise CaptureError("tshark not found. Install wireshark/tshark.")
        except subprocess.TimeoutExpired:
            output = ""
            logger.warning("tshark capture timed out")

        elapsed = time.time() - start

        packets = self._parse_field_output(output)

        tshark_result = TsharkResult(
            packets=packets,
            total_packets=len(packets),
            capture_file=output_file or "",
            elapsed=elapsed,
            output=output,
        )

        logger.info("tshark captured %d packets in %.1fs", len(packets), elapsed)
        return tshark_result

    # ── PCAP analysis ──────────────────────────────────────────────────

    def read_pcap(
        self,
        pcap_file: str,
        display_filter: Optional[str] = None,
        fields: Optional[list[str]] = None,
        max_packets: int = 0,
    ) -> TsharkResult:
        """Read and parse a PCAP file.

        Args:
            pcap_file: Path to the .pcap/.pcapng file.
            display_filter: Wireshark display filter.
            fields: List of tshark field names to extract.
            max_packets: Maximum packets to read (0 = all).

        Returns:
            TsharkResult with parsed packets.
        """
        if not os.path.isfile(pcap_file):
            raise PCAPError(f"PCAP file not found: {pcap_file}")

        cmd = [self.tshark_path, "-r", pcap_file]

        if display_filter:
            cmd.extend(["-Y", display_filter])

        if fields:
            cmd.extend(["-T", "fields", "-E", "separator=|", "-E", "header=y"])
            for f in fields:
                cmd.extend(["-e", f])
        else:
            cmd.extend(["-T", "fields", "-E", "separator=|", "-E", "header=y"])
            cmd.extend([
                "-e", "frame.number",
                "-e", "frame.time_epoch",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "frame.protocols",
                "-e", "frame.len",
            ])

        if max_packets > 0:
            cmd.extend(["-c", str(max_packets)])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout,
            )
            output = result.stdout
        except FileNotFoundError:
            raise CaptureError("tshark not found")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("tshark read timed out")

        packets = self._parse_field_output(output)
        return TsharkResult(
            packets=packets,
            total_packets=len(packets),
            capture_file=pcap_file,
            output=output,
        )

    # ── Statistics ──────────────────────────────────────────────────────

    def protocol_stats(self, pcap_file: str) -> dict[str, Any]:
        """Get protocol hierarchy statistics from a PCAP file."""
        if not os.path.isfile(pcap_file):
            raise PCAPError(f"PCAP file not found: {pcap_file}")

        cmd = [self.tshark_path, "-r", pcap_file, "-q", "-z", "io,phs"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout,
            )
            return {"output": result.stdout}
        except FileNotFoundError:
            raise CaptureError("tshark not found")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("tshark stats timed out")

    def conversations(self, pcap_file: str, protocol: str = "eth") -> dict[str, Any]:
        """Get conversation statistics from a PCAP file.

        Args:
            pcap_file: Path to PCAP file.
            protocol: Protocol type (``"eth"``, ``"ip"``, ``"tcp"``, ``"udp"``).

        Returns:
            Dict with conversation statistics.
        """
        if not os.path.isfile(pcap_file):
            raise PCAPError(f"PCAP file not found: {pcap_file}")

        cmd = [self.tshark_path, "-r", pcap_file, "-q", "-z", f"conv,{protocol}"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout,
            )
            return {"output": result.stdout}
        except FileNotFoundError:
            raise CaptureError("tshark not found")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("tshark conversations timed out")

    def extract_fields(
        self,
        pcap_file: str,
        field_names: list[str],
        display_filter: Optional[str] = None,
    ) -> list[dict[str, str]]:
        """Extract specific fields from a PCAP file.

        Args:
            pcap_file: Path to PCAP file.
            field_names: List of tshark field names.
            display_filter: Optional display filter.

        Returns:
            List of dicts with field values.
        """
        if not os.path.isfile(pcap_file):
            raise PCAPError(f"PCAP file not found: {pcap_file}")

        cmd = [
            self.tshark_path, "-r", pcap_file,
            "-T", "fields",
            "-E", "separator=|",
            "-E", "header=y",
        ]
        for f in field_names:
            cmd.extend(["-e", f])
        if display_filter:
            cmd.extend(["-Y", display_filter])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout,
            )
        except FileNotFoundError:
            raise CaptureError("tshark not found")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("tshark field extraction timed out")

        rows: list[dict[str, str]] = []
        lines = result.stdout.strip().splitlines()
        if not lines:
            return rows

        headers = [h.strip() for h in lines[0].split("|")]
        for line in lines[1:]:
            values = [v.strip() for v in line.split("|")]
            row = dict(zip(headers, values))
            rows.append(row)

        return rows

    # ── Conversion ─────────────────────────────────────────────────────

    def convert_format(
        self, input_file: str, output_file: str, output_type: str = "pcapng",
    ) -> str:
        """Convert PCAP between formats.

        Args:
            input_file: Input file path.
            output_file: Output file path.
            output_type: Output format (``"pcapng"``, ``"pcap"``, ``"json"``).

        Returns:
            Path to the output file.
        """
        if not os.path.isfile(input_file):
            raise PCAPError(f"Input file not found: {input_file}")

        cmd = [
            self.tshark_path, "-r", input_file,
            "-F", output_type,
            "-w", output_file,
        ]

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            return output_file
        except FileNotFoundError:
            raise CaptureError("tshark not found")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("tshark conversion timed out")

    # ── Parsing ────────────────────────────────────────────────────────

    @staticmethod
    def _parse_field_output(output: str) -> list[TsharkPacket]:
        """Parse tshark -T fields output into TsharkPacket objects."""
        packets: list[TsharkPacket] = []
        lines = output.strip().splitlines()
        if not lines:
            return packets

        # First line should be headers
        headers = [h.strip() for h in lines[0].split("|")]

        for line in lines[1:]:
            values = [v.strip() for v in line.split("|")]
            if len(values) < len(headers):
                continue

            field_map = dict(zip(headers, values))

            pkt = TsharkPacket(
                frame_number=int(field_map.get("frame.number", 0) or 0),
                timestamp=float(field_map.get("frame.time_epoch", 0) or 0),
                source=field_map.get("ip.src", ""),
                destination=field_map.get("ip.dst", ""),
                protocol=field_map.get("frame.protocols", ""),
                length=int(field_map.get("frame.len", 0) or 0),
                fields=field_map,
            )
            packets.append(pkt)

        return packets

    # ── Wireshark GUI ──────────────────────────────────────────────────

    def open_in_wireshark(self, pcap_file: str) -> None:
        """Open a PCAP file in the Wireshark GUI."""
        if not os.path.isfile(pcap_file):
            raise PCAPError(f"PCAP file not found: {pcap_file}")

        try:
            subprocess.Popen(
                [self.wireshark_path, pcap_file],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            raise CaptureError("wireshark not found")

    # ── Lifecycle ──────────────────────────────────────────────────────

    def stop_capture(self) -> None:
        """Stop a running tshark capture."""
        if self._capture_proc and self._capture_proc.poll() is None:
            self._capture_proc.terminate()
            try:
                self._capture_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._capture_proc.kill()
                self._capture_proc.wait()
        self._capture_proc = None

    def __repr__(self) -> str:
        return f"WiresharkWrapper(tshark={self.tshark_path!r})"
