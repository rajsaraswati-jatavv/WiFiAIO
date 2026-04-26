"""
WiFiAIO Packet Sniffer Module

Real-time WiFi packet capture using tshark or scapy as backends.

FIX: Combines multiple -Y display filters with && operator.
"""

import os
import re
import time
import logging
import subprocess
import threading
import queue
from typing import List, Dict, Optional, Any, Callable, Generator, Tuple
from dataclasses import dataclass, field
from enum import Enum

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    WiFiScanError,
)

logger = logging.getLogger(__name__)


class CaptureBackend(Enum):
    """Packet capture backend."""
    TSHARK = "tshark"
    SCAPY = "scapy"


@dataclass
class PacketInfo:
    """Parsed packet information."""
    timestamp: float = 0.0
    frame_number: int = 0
    src_mac: str = ""
    dst_mac: str = ""
    bssid: str = ""
    frame_type: str = ""
    frame_subtype: str = ""
    ssid: str = ""
    channel: int = 0
    signal_dbm: int = 0
    protocol: str = ""
    length: int = 0
    info: str = ""
    raw_data: bytes = b""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "frame_number": self.frame_number,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "bssid": self.bssid,
            "frame_type": self.frame_type,
            "frame_subtype": self.frame_subtype,
            "ssid": self.ssid,
            "channel": self.channel,
            "signal_dbm": self.signal_dbm,
            "protocol": self.protocol,
            "length": self.length,
            "info": self.info,
        }


@dataclass
class CaptureStats:
    """Packet capture statistics."""
    packets_captured: int = 0
    packets_dropped: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    bytes_captured: int = 0
    rate_per_second: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packets_captured": self.packets_captured,
            "packets_dropped": self.packets_dropped,
            "bytes_captured": self.bytes_captured,
            "duration": self.end_time - self.start_time if self.end_time else 0,
            "rate_per_second": self.rate_per_second,
        }


class PacketSniffer:
    """
    Real-time WiFi packet sniffer using tshark or scapy.

    Supports filtering, real-time callbacks, and pcap output.
    """

    def __init__(self, interface: str = "wlan0mon",
                 backend: CaptureBackend = CaptureBackend.TSHARK):
        """
        Initialize PacketSniffer.

        Args:
            interface: Monitor mode interface.
            backend: Capture backend (tshark or scapy).
        """
        self.interface = interface
        self.backend = backend
        self._running = False
        self._process: Optional[subprocess.Popen] = None
        self._stats = CaptureStats()
        self._packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._callbacks: List[Callable] = []
        self._capture_thread: Optional[threading.Thread] = None
        self._output_file: Optional[str] = None

    def _check_root(self) -> None:
        """Verify running as root."""
        if os.geteuid() != 0:
            raise WiFiPermissionError("Packet capture requires root privileges")

    def _build_tshark_filter(self, filters: Optional[List[str]] = None) -> List[str]:
        """
        Build tshark display filter arguments.

        FIX: Combines multiple -Y filters with && operator.

        Args:
            filters: List of display filter strings.

        Returns:
            List of tshark command arguments for filtering.
        """
        if not filters:
            return []

        # FIX: Combine all filters with && instead of multiple -Y flags
        combined_filter = " && ".join(f"({f})" for f in filters)
        return ["-Y", combined_filter]

    def start_capture(self, filters: Optional[List[str]] = None,
                      output_file: Optional[str] = None,
                      channel: Optional[int] = None,
                      max_packets: int = 0,
                      timeout: int = 0) -> CaptureStats:
        """
        Start packet capture.

        Args:
            filters: List of tshark display filters (combined with &&).
            output_file: Save captured packets to pcap file.
            channel: Set interface to specific channel.
            max_packets: Stop after capturing this many packets (0 = unlimited).
            timeout: Stop after this many seconds (0 = unlimited).

        Returns:
            CaptureStats with capture statistics.
        """
        self._check_root()

        if self._running:
            raise WiFiScanError("Capture is already running")

        self._running = True
        self._stats = CaptureStats(start_time=time.time())
        self._output_file = output_file

        # Set channel if specified
        if channel is not None:
            try:
                subprocess.run(
                    ["iw", "dev", self.interface, "set", "channel", str(channel)],
                    check=True, capture_output=True, timeout=10
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                logger.warning("Failed to set channel %d: %s", channel, e)

        if self.backend == CaptureBackend.TSHARK:
            return self._capture_tshark(filters, output_file, max_packets, timeout)
        else:
            return self._capture_scapy(filters, output_file, max_packets, timeout)

    def _capture_tshark(self, filters: Optional[List[str]],
                         output_file: Optional[str],
                         max_packets: int, timeout: int) -> CaptureStats:
        """Capture packets using tshark."""
        cmd = [
            "tshark",
            "-i", self.interface,
            "-l",  # Line-buffered output
            "-T", "fields",
            "-E", "separator=|",
            "-E", "header=n",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "wlan.bssid",
            "-e", "wlan.fc.type",
            "-e", "wlan.fc.subtype",
            "-e", "wlan_mgt.ssid",
            "-e", "radiotap.dbm_antsignal",
            "-e", "frame.len",
            "-e", "wlan.fc.type_subtype",
        ]

        # Add display filter
        # FIX: Combine multiple filters with &&
        filter_args = self._build_tshark_filter(filters)
        cmd.extend(filter_args)

        # Add capture filter for output
        if output_file:
            cmd.extend(["-w", output_file])

        # Add packet count limit
        if max_packets > 0:
            cmd.extend(["-c", str(max_packets)])

        try:
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            logger.info("Started tshark capture on %s", self.interface)
        except FileNotFoundError:
            raise WiFiScanError("tshark not found. Install Wireshark/tshark.")

        # Read packets
        try:
            while self._running:
                line = self._process.stdout.readline()
                if not line:
                    break

                packet = self._parse_tshark_line(line.strip())
                if packet is not None:
                    self._stats.packets_captured += 1
                    self._stats.bytes_captured += packet.length

                    # Notify callbacks
                    for callback in self._callbacks:
                        try:
                            callback(packet)
                        except Exception as e:
                            logger.error("Callback error: %s", e)

                    # Put in queue for consumers
                    try:
                        self._packet_queue.put_nowait(packet)
                    except queue.Full:
                        self._stats.packets_dropped += 1

                # Check max packets
                if max_packets > 0 and self._stats.packets_captured >= max_packets:
                    break

                # Check timeout
                if timeout > 0 and time.time() - self._stats.start_time >= timeout:
                    break

        finally:
            self._stop_process()

        self._stats.end_time = time.time()
        duration = self._stats.end_time - self._stats.start_time
        self._stats.rate_per_second = (
            self._stats.packets_captured / duration if duration > 0 else 0
        )
        self._running = False
        return self._stats

    def _parse_tshark_line(self, line: str) -> Optional[PacketInfo]:
        """Parse a tshark fields output line into PacketInfo."""
        if not line:
            return None

        parts = line.split("|")
        if len(parts) < 11:
            return None

        try:
            # Frame type/subtype mapping
            type_val = parts[5].strip()
            subtype_val = parts[6].strip()
            type_subtype = parts[10].strip()

            frame_type = self._decode_frame_type(type_val)
            frame_subtype = self._decode_frame_subtype(type_subtype)

            signal = 0
            signal_str = parts[8].strip()
            if signal_str:
                # tshark may return multiple signal values
                try:
                    signal = int(signal_str.split(",")[0])
                except ValueError:
                    signal = 0

            return PacketInfo(
                frame_number=int(parts[0].strip()) if parts[0].strip() else 0,
                timestamp=float(parts[1].strip()) if parts[1].strip() else 0.0,
                src_mac=parts[2].strip(),
                dst_mac=parts[3].strip(),
                bssid=parts[4].strip(),
                frame_type=frame_type,
                frame_subtype=frame_subtype,
                ssid=parts[7].strip(),
                signal_dbm=signal,
                length=int(parts[9].strip()) if parts[9].strip() else 0,
            )
        except (ValueError, IndexError) as e:
            logger.debug("Failed to parse tshark line: %s", e)
            return None

    def _decode_frame_type(self, type_val: str) -> str:
        """Decode 802.11 frame type number to name."""
        types = {"0": "Management", "1": "Control", "2": "Data"}
        return types.get(type_val.strip(), f"Unknown({type_val})")

    def _decode_frame_subtype(self, type_subtype: str) -> str:
        """Decode 802.11 frame type/subtype hex to name."""
        subtypes = {
            "0x0000": "Association Request",
            "0x0001": "Association Response",
            "0x0004": "Probe Request",
            "0x0005": "Probe Response",
            "0x0008": "Beacon",
            "0x000a": "Disassociation",
            "0x000b": "Authentication",
            "0x000c": "Deauthentication",
            "0x000d": "Action",
            "0x001b": "RTS",
            "0x001c": "CTS",
            "0x001d": "ACK",
            "0x0020": "Data",
            "0x0028": "QoS Data",
        }
        return subtypes.get(type_subtype.strip().lower(), f"Unknown({type_subtype})")

    def _capture_scapy(self, filters: Optional[List[str]],
                        output_file: Optional[str],
                        max_packets: int, timeout: int) -> CaptureStats:
        """Capture packets using scapy."""
        try:
            from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeReq, RadioTap, wrpcap
        except ImportError:
            raise WiFiScanError("scapy not found. Install scapy: pip install scapy")

        captured_packets = []
        packet_count = 0

        def packet_handler(pkt):
            nonlocal packet_count
            if not self._running:
                return

            packet_count += 1
            info = self._scapy_to_packet_info(pkt)
            if info is not None:
                self._stats.packets_captured += 1
                self._stats.bytes_captured += info.length

                for callback in self._callbacks:
                    try:
                        callback(info)
                    except Exception as e:
                        logger.error("Callback error: %s", e)

                try:
                    self._packet_queue.put_nowait(info)
                except queue.Full:
                    self._stats.packets_dropped += 1

            if output_file:
                captured_packets.append(pkt)

            if max_packets > 0 and packet_count >= max_packets:
                return True  # Stop sniffing

        # Build BPF filter from display filters
        bpf_filter = None
        if filters:
            # Convert tshark-style filters to BPF (approximate)
            bpf_filter = " and ".join(filters)

        try:
            sniff_kwargs = {
                "iface": self.interface,
                "prn": packet_handler,
                "store": 0,
                "stop_filter": lambda p: not self._running,
            }
            if bpf_filter:
                sniff_kwargs["filter"] = bpf_filter
            if timeout > 0:
                sniff_kwargs["timeout"] = timeout

            sniff(**sniff_kwargs)

        except Exception as e:
            logger.error("Scapy capture error: %s", e)

        # Save to pcap if requested
        if output_file and captured_packets:
            try:
                from scapy.all import wrpcap
                wrpcap(output_file, captured_packets)
            except Exception as e:
                logger.error("Failed to save pcap: %s", e)

        self._stats.end_time = time.time()
        duration = self._stats.end_time - self._stats.start_time
        self._stats.rate_per_second = (
            self._stats.packets_captured / duration if duration > 0 else 0
        )
        self._running = False
        return self._stats

    def _scapy_to_packet_info(self, pkt) -> Optional[PacketInfo]:
        """Convert a scapy packet to PacketInfo."""
        try:
            from scapy.all import Dot11, RadioTap

            info = PacketInfo(timestamp=time.time())

            if pkt.haslayer(RadioTap):
                if hasattr(pkt[RadioTap], "dBm_AntSignal"):
                    info.signal_dbm = pkt[RadioTap].dBm_AntSignal or 0

            if pkt.haslayer(Dot11):
                dot11 = pkt[Dot11]
                info.src_mac = str(dot11.addr2) if dot11.addr2 else ""
                info.dst_mac = str(dot11.addr1) if dot11.addr1 else ""
                info.bssid = str(dot11.addr3) if dot11.addr3 else ""
                info.length = len(pkt)

                # Determine frame type
                fc = dot11.FC
                if hasattr(fc, "type"):
                    info.frame_type = self._decode_frame_type(str(fc.type))
                if hasattr(fc, "subtype"):
                    info.frame_subtype = str(fc.subtype)

            return info
        except Exception as e:
            logger.debug("Failed to convert scapy packet: %s", e)
            return None

    def start_background_capture(self, filters: Optional[List[str]] = None,
                                  output_file: Optional[str] = None,
                                  channel: Optional[int] = None) -> None:
        """
        Start packet capture in a background thread.

        Args:
            filters: List of display filters.
            output_file: Save packets to pcap file.
            channel: Set interface channel.
        """
        if self._running:
            raise WiFiScanError("Capture is already running")

        def _capture_thread():
            self.start_capture(
                filters=filters,
                output_file=output_file,
                channel=channel,
            )

        self._capture_thread = threading.Thread(target=_capture_thread, daemon=True)
        self._capture_thread.start()
        logger.info("Background capture started")

    def get_packet(self, timeout: float = 1.0) -> Optional[PacketInfo]:
        """
        Get the next captured packet from the queue.

        Args:
            timeout: Wait timeout in seconds.

        Returns:
            PacketInfo or None if no packet available.
        """
        try:
            return self._packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_packets(self, max_count: int = 100) -> List[PacketInfo]:
        """
        Get all available packets from the queue.

        Args:
            max_count: Maximum number of packets to return.

        Returns:
            List of PacketInfo objects.
        """
        packets = []
        while len(packets) < max_count:
            try:
                packet = self._packet_queue.get_nowait()
                packets.append(packet)
            except queue.Empty:
                break
        return packets

    def add_callback(self, callback: Callable) -> None:
        """
        Add a callback for real-time packet processing.

        Args:
            callback: Function that takes a PacketInfo argument.
        """
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable) -> None:
        """Remove a previously added callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def _stop_process(self) -> None:
        """Stop the capture process."""
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
        self._process = None

    def stop(self) -> None:
        """Stop packet capture."""
        self._running = False
        self._stop_process()

        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5)

        self._capture_thread = None
        logger.info("Packet sniffer stopped")

    def get_stats(self) -> CaptureStats:
        """Get current capture statistics."""
        return self._stats

    def is_running(self) -> bool:
        """Check if capture is running."""
        return self._running

    def extract_ssid_list(self, pcap_file: str) -> List[Dict[str, str]]:
        """
        Extract unique SSIDs from a pcap file.

        Args:
            pcap_file: Path to pcap file.

        Returns:
            List of dicts with SSID and BSSID.
        """
        ssids = []
        seen = set()

        try:
            result = subprocess.run(
                ["tshark", "-r", pcap_file,
                 "-Y", "wlan.fc.type_subtype == 0x0008 || wlan.fc.type_subtype == 0x0005",
                 "-T", "fields",
                 "-e", "wlan.bssid",
                 "-e", "wlan_mgt.ssid"],
                capture_output=True, text=True, timeout=30
            )

            for line in result.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    bssid = parts[0].strip()
                    ssid = parts[1].strip()
                    if ssid and bssid and (bssid, ssid) not in seen:
                        seen.add((bssid, ssid))
                        ssids.append({"bssid": bssid, "ssid": ssid})

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return ssids

    def extract_eapol_packets(self, pcap_file: str) -> List[Dict[str, Any]]:
        """
        Extract EAPOL packets from a pcap file.

        Args:
            pcap_file: Path to pcap file.

        Returns:
            List of EAPOL packet info dicts.
        """
        eapol_packets = []

        try:
            result = subprocess.run(
                ["tshark", "-r", pcap_file,
                 "-Y", "eapol",
                 "-T", "fields",
                 "-e", "frame.number",
                 "-e", "frame.time_epoch",
                 "-e", "wlan.sa",
                 "-e", "wlan.da",
                 "-e", "eapol.keydes.keyinfo",
                 "-e", "eapol.keydes.nonce"],
                capture_output=True, text=True, timeout=30
            )

            for line in result.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 4:
                    eapol_packets.append({
                        "frame_number": parts[0].strip(),
                        "timestamp": parts[1].strip(),
                        "src_mac": parts[2].strip(),
                        "dst_mac": parts[3].strip(),
                        "key_info": parts[4].strip() if len(parts) > 4 else "",
                        "nonce": parts[5].strip() if len(parts) > 5 else "",
                    })

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return eapol_packets
