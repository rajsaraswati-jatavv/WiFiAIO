"""
WiFiAIO Frame Injector Module

Crafts and injects custom 802.11 frames including management, control,
and data frames. Provides IE builders and fuzzing support.

FIX: Uses tcpreplay instead of aireplay-ng --inject for frame injection.
"""

import os
import struct
import time
import random
import logging
import subprocess
import tempfile
from typing import List, Dict, Optional, Any, Tuple, Callable, Generator
from dataclasses import dataclass, field
from enum import IntEnum

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    WiFiInjectionError,
)

logger = logging.getLogger(__name__)


class FrameCategory(IntEnum):
    """802.11 frame categories."""
    MANAGEMENT = 0
    CONTROL = 1
    DATA = 2


class ManagementSubtype(IntEnum):
    """802.11 management frame subtypes."""
    ASSOCIATION_REQUEST = 0
    ASSOCIATION_RESPONSE = 1
    REASSOCIATION_REQUEST = 2
    REASSOCIATION_RESPONSE = 3
    PROBE_REQUEST = 4
    PROBE_RESPONSE = 5
    BEACON = 8
    ATIM = 9
    DISASSOCIATION = 10
    AUTHENTICATION = 11
    DEAUTHENTICATION = 12
    ACTION = 13


class ControlSubtype(IntEnum):
    """802.11 control frame subtypes."""
    RTS = 11
    CTS = 12
    ACK = 13
    BLOCK_ACK = 14
    BLOCK_ACK_REQ = 15


class DataSubtype(IntEnum):
    """802.11 data frame subtypes."""
    DATA = 0
    DATA_CF_ACK = 1
    DATA_CF_POLL = 2
    DATA_CF_ACK_POLL = 3
    NULL = 4
    CF_ACK = 5
    CF_POLL = 6
    CF_ACK_POLL = 7
    QOS_DATA = 8


@dataclass
class InjectionResult:
    """Result of a frame injection operation."""
    success: bool = False
    frames_sent: int = 0
    frames_failed: int = 0
    bytes_sent: int = 0
    time_elapsed: float = 0.0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "frames_sent": self.frames_sent,
            "frames_failed": self.frames_failed,
            "bytes_sent": self.bytes_sent,
            "time_elapsed": self.time_elapsed,
            "error": self.error,
        }


@dataclass
class FuzzConfig:
    """Configuration for frame fuzzing."""
    category: FrameCategory = FrameCategory.MANAGEMENT
    subtype: int = 0
    target_bssid: str = ""
    fuzz_fields: List[str] = field(default_factory=list)
    mutation_strategy: str = "random"  # random, bitflip, boundary, exhaustive
    max_mutations: int = 1000
    delay: float = 0.01
    stop_on_response: bool = True


class IEBuilder:
    """
    Builder for 802.11 Information Elements (IEs).

    Provides methods to construct various IE types found in
    management frames like beacons and probe responses.
    """

    # IE type IDs
    IE_SSID = 0
    IE_SUPPORTED_RATES = 1
    IE_DSSS_PARAMETER_SET = 3
    IE_TIM = 5
    IE_COUNTRY = 7
    IE_RSN = 48
    IE_EXTENDED_RATES = 50
    IE_HT_CAPABILITIES = 45
    IE_HT_OPERATION = 61
    IE_VHT_CAPABILITIES = 191
    IE_VHT_OPERATION = 192
    IE_VENDOR_SPECIFIC = 221

    @staticmethod
    def build_ssid(ssid: str) -> bytes:
        """Build SSID IE (type 0)."""
        ssid_bytes = ssid.encode("utf-8")
        return struct.pack("BB", 0, len(ssid_bytes)) + ssid_bytes

    @staticmethod
    def build_supported_rates(rates: Optional[List[float]] = None) -> bytes:
        """Build Supported Rates IE (type 1)."""
        if rates is None:
            rates = [1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0]
        rate_bytes = bytearray()
        for rate in rates:
            # Rate is in units of 500 kbps, with MSB set for basic rates
            rate_val = int(rate * 2)
            rate_bytes.append(rate_val)
        return struct.pack("BB", 1, len(rate_bytes)) + bytes(rate_bytes)

    @staticmethod
    def build_extended_rates(rates: Optional[List[float]] = None) -> bytes:
        """Build Extended Supported Rates IE (type 50)."""
        if rates is None:
            rates = [24.0, 36.0, 48.0, 54.0]
        rate_bytes = bytearray()
        for rate in rates:
            rate_val = int(rate * 2)
            rate_bytes.append(rate_val)
        return struct.pack("BB", 50, len(rate_bytes)) + bytes(rate_bytes)

    @staticmethod
    def build_dsss_param_set(channel: int) -> bytes:
        """Build DSSS Parameter Set IE (type 3)."""
        return struct.pack("BBB", 3, 1, channel)

    @staticmethod
    def build_tim(dtim_count: int = 0, dtim_period: int = 1,
                  bitmap_control: int = 0, partial_bitmap: bytes = b"") -> bytes:
        """Build Traffic Indication Map IE (type 5)."""
        body = struct.pack("BBB", dtim_count, dtim_period, bitmap_control)
        body += partial_bitmap
        return struct.pack("BB", 5, len(body)) + body

    @staticmethod
    def build_rsn(akm_suites: Optional[List[int]] = None,
                  pairwise_ciphers: Optional[List[int]] = None) -> bytes:
        """
        Build RSN (Robust Security Network) IE (type 48).

        Args:
            akm_suites: List of AKM suite OUI+type values.
            pairwise_ciphers: List of pairwise cipher OUI+type values.

        Returns:
            RSN IE bytes.
        """
        # RSN IE format
        version = struct.pack("<H", 1)  # RSN version 1

        # Group cipher: CCMP
        group_cipher = bytes([0x00, 0x0F, 0xAC, 0x04])

        # Pairwise ciphers
        if pairwise_ciphers is None:
            pairwise_ciphers = [0x04]  # CCMP
        pairwise_count = struct.pack("<H", len(pairwise_ciphers))
        pairwise_data = b""
        for cipher in pairwise_ciphers:
            pairwise_data += bytes([0x00, 0x0F, 0xAC, cipher])

        # AKM suites
        if akm_suites is None:
            akm_suites = [0x02]  # PSK
        akm_count = struct.pack("<H", len(akm_suites))
        akm_data = b""
        for akm in akm_suites:
            akm_data += bytes([0x00, 0x0F, 0xAC, akm])

        # RSN capabilities
        rsn_cap = struct.pack("<H", 0x000C)  # MFPR=0, MFPC=1, SPP=1

        body = version + group_cipher + pairwise_count + pairwise_data + \
               akm_count + akm_data + rsn_cap

        return struct.pack("BB", 48, len(body)) + body

    @staticmethod
    def build_vendor_specific(oui: bytes, data: bytes) -> bytes:
        """Build Vendor Specific IE (type 221)."""
        body = oui + data
        return struct.pack("BB", 221, len(body)) + body

    @staticmethod
    def build_ht_capabilities(ampdu_factor: int = 3, ampdu_density: int = 4,
                              rx_stbc: int = 1, tx_stbc: int = 1,
                              short_gi_20: int = 1, short_gi_40: int = 1,
                              supported_channel_width: int = 1) -> bytes:
        """Build HT Capabilities IE (type 45)."""
        # HT Capabilities Info (2 bytes)
        ht_info = (supported_channel_width & 0x01) | \
                  ((short_gi_20 & 0x01) << 5) | \
                  ((short_gi_40 & 0x01) << 6)

        ht_cap_info = struct.pack("<H", ht_info)

        # A-MPDU Parameters (1 byte)
        ampdu_params = (ampdu_factor & 0x03) | ((ampdu_density & 0x07) << 2)

        # Supported MCS set (16 bytes) - default all 1-stream MCS
        mcs_set = bytes([0xFF] + [0x00] * 15)

        # HT Extended Capabilities (2 bytes)
        ht_ext_cap = struct.pack("<H", 0x0000)

        # TX Beamforming Capabilities (4 bytes)
        txbf_cap = struct.pack("<I", 0x00000000)

        # ASEL Capabilities (1 byte)
        asel_cap = bytes([0x00])

        body = ht_cap_info + bytes([ampdu_params]) + mcs_set + \
               ht_ext_cap + txbf_cap + asel_cap

        return struct.pack("BB", 45, len(body)) + body

    @staticmethod
    def build_country(country_str: str = "US ",
                      channel_triplets: Optional[List[Tuple[int, int, int]]] = None) -> bytes:
        """Build Country IE (type 7)."""
        body = country_str.encode("ascii")[:3].ljust(3, b" ")
        body += b" "  # Environment: " " = all environments

        if channel_triplets:
            for first, count, max_power in channel_triplets:
                body += struct.pack("BBB", first, count, max_power)

        body += b"\x00"  # Pad

        return struct.pack("BB", 7, len(body)) + body


class FrameInjector:
    """
    802.11 frame injection engine.

    Crafts and injects management, control, and data frames.
    Uses tcpreplay for injection (not aireplay-ng --inject).
    """

    # Frame control type values
    TYPE_MANAGEMENT = 0x00
    TYPE_CONTROL = 0x01
    TYPE_DATA = 0x02

    def __init__(self, interface: str = "wlan0mon"):
        """
        Initialize FrameInjector.

        Args:
            interface: Monitor mode interface for injection.
        """
        self.interface = interface
        self._running = False
        self._stats = InjectionResult()
        self._sequence = 0

    def _check_root(self) -> None:
        """Verify running as root."""
        if os.geteuid() != 0:
            raise WiFiPermissionError("Frame injection requires root privileges")

    def _mac_to_bytes(self, mac: str) -> bytes:
        """Convert MAC address string to bytes."""
        return bytes(int(b, 16) for b in mac.split(":"))

    def _next_sequence(self) -> int:
        """Get next frame sequence number."""
        seq = self._sequence & 0xFFF
        self._sequence += 1
        return seq

    def _build_frame_control(self, frame_type: int, subtype: int,
                              to_ds: int = 0, from_ds: int = 0,
                              more_frag: int = 0, retry: int = 0,
                              power_mgmt: int = 0, more_data: int = 0,
                              protected: int = 0, order: int = 0) -> int:
        """Build 802.11 Frame Control field."""
        fc = (subtype & 0x0F) << 4
        fc |= (frame_type & 0x03) << 2
        fc |= (to_ds & 0x01) << 8
        fc |= (from_ds & 0x01) << 9
        fc |= (more_frag & 0x01) << 10
        fc |= (retry & 0x01) << 11
        fc |= (power_mgmt & 0x01) << 12
        fc |= (more_data & 0x01) << 13
        fc |= (protected & 0x01) << 14
        fc |= (order & 0x01) << 15
        return fc

    def _build_radiotap_header(self, rate: int = 2, tx_power: int = 0,
                                flags: int = 0x08) -> bytes:
        """Build radiotap header for injection."""
        # Version 0, pad 0, length 13
        # Present flags: TX_FLAGS (0x8) + RATE (0x4)
        header = struct.pack(
            "<BBHI BB x",
            0x00,  # version
            0x00,  # pad
            13,    # header length
            0x00000804,  # present flags
            rate,  # TX rate (in 0.5 Mbps units)
            flags,  # TX flags (0x08 = no ACK)
        )
        return header

    def craft_management_frame(self, subtype: int, bssid: str,
                                dest: str, source: str,
                                ie_list: Optional[List[bytes]] = None,
                                body: bytes = b"") -> bytes:
        """
        Craft an 802.11 management frame.

        Args:
            subtype: Management frame subtype.
            bssid: BSSID address.
            dest: Destination address.
            source: Source address.
            ie_list: List of Information Element bytes to include.
            body: Additional frame body bytes.

        Returns:
            Complete 802.11 management frame bytes.
        """
        fc = self._build_frame_control(self.TYPE_MANAGEMENT, subtype)
        fc_bytes = struct.pack("<H", fc)
        duration = struct.pack("<H", 0x0000)
        seq_ctrl = struct.pack("<H", self._next_sequence() << 4)

        addr1 = self._mac_to_bytes(dest)
        addr2 = self._mac_to_bytes(source)
        addr3 = self._mac_to_bytes(bssid)

        frame_body = body
        if ie_list:
            for ie in ie_list:
                frame_body += ie

        frame = fc_bytes + duration + addr1 + addr2 + addr3 + seq_ctrl + frame_body
        return frame

    def craft_beacon(self, bssid: str, ssid: str, channel: int,
                     rates: Optional[List[float]] = None) -> bytes:
        """
        Craft an 802.11 Beacon frame.

        Args:
            bssid: BSSID address.
            ssid: Network SSID.
            channel: Channel number.
            rates: Supported rates list.

        Returns:
            Complete beacon frame bytes.
        """
        # Beacon body: timestamp + interval + capability
        timestamp = struct.pack("<Q", int(time.time() * 1000000))
        beacon_interval = struct.pack("<H", 100)  # 100 TUs
        capability = struct.pack("<H", 0x0431)  # ESS + short slot + RSN

        body = timestamp + beacon_interval + capability

        # Add IEs
        ie_list = [
            IEBuilder.build_ssid(ssid),
            IEBuilder.build_supported_rates(rates),
            IEBuilder.build_dsss_param_set(channel),
            IEBuilder.build_extended_rates(),
            IEBuilder.build_rsn(),
        ]

        return self.craft_management_frame(
            ManagementSubtype.BEACON, bssid,
            dest="FF:FF:FF:FF:FF:FF", source=bssid,
            ie_list=ie_list, body=body
        )

    def craft_probe_request(self, ssid: str = "",
                             source: str = "00:11:22:33:44:55") -> bytes:
        """Craft an 802.11 Probe Request frame."""
        body = b""
        ie_list = []
        if ssid:
            ie_list.append(IEBuilder.build_ssid(ssid))
        ie_list.append(IEBuilder.build_supported_rates())
        ie_list.append(IEBuilder.build_extended_rates())

        return self.craft_management_frame(
            ManagementSubtype.PROBE_REQUEST, bssid="FF:FF:FF:FF:FF:FF",
            dest="FF:FF:FF:FF:FF:FF", source=source,
            ie_list=ie_list
        )

    def craft_probe_response(self, bssid: str, ssid: str, channel: int,
                              dest: str) -> bytes:
        """Craft an 802.11 Probe Response frame."""
        timestamp = struct.pack("<Q", int(time.time() * 1000000))
        beacon_interval = struct.pack("<H", 100)
        capability = struct.pack("<H", 0x0431)

        body = timestamp + beacon_interval + capability

        ie_list = [
            IEBuilder.build_ssid(ssid),
            IEBuilder.build_supported_rates(),
            IEBuilder.build_dsss_param_set(channel),
            IEBuilder.build_extended_rates(),
        ]

        return self.craft_management_frame(
            ManagementSubtype.PROBE_RESPONSE, bssid,
            dest=dest, source=bssid,
            ie_list=ie_list, body=body
        )

    def craft_auth_frame(self, bssid: str, source: str,
                          auth_alg: int = 0, auth_seq: int = 1,
                          status: int = 0) -> bytes:
        """Craft an 802.11 Authentication frame."""
        body = struct.pack("<HHH", auth_alg, auth_seq, status)
        return self.craft_management_frame(
            ManagementSubtype.AUTHENTICATION, bssid,
            dest=bssid, source=source, body=body
        )

    def craft_assoc_request(self, bssid: str, source: str, ssid: str,
                             listen_interval: int = 10) -> bytes:
        """Craft an 802.11 Association Request frame."""
        capability = struct.pack("<H", 0x0431)
        listen = struct.pack("<H", listen_interval)

        ie_list = [
            IEBuilder.build_ssid(ssid),
            IEBuilder.build_supported_rates(),
            IEBuilder.build_extended_rates(),
        ]

        body = capability + listen
        return self.craft_management_frame(
            ManagementSubtype.ASSOCIATION_REQUEST, bssid,
            dest=bssid, source=source,
            ie_list=ie_list, body=body
        )

    def craft_control_frame(self, subtype: int, dest: str,
                             source: Optional[str] = None) -> bytes:
        """
        Craft an 802.11 control frame.

        Args:
            subtype: Control frame subtype.
            dest: Destination address.
            source: Source address (for RTS).

        Returns:
            Complete 802.11 control frame bytes.
        """
        if subtype == ControlSubtype.RTS:
            fc = self._build_frame_control(self.TYPE_CONTROL, subtype)
            duration = struct.pack("<H", 0x0000)
            addr1 = self._mac_to_bytes(dest)
            addr2 = self._mac_to_bytes(source or "00:00:00:00:00:00")
            return struct.pack("<H", fc) + duration + addr1 + addr2

        elif subtype == ControlSubtype.CTS or subtype == ControlSubtype.ACK:
            fc = self._build_frame_control(self.TYPE_CONTROL, subtype)
            duration = struct.pack("<H", 0x0000)
            addr1 = self._mac_to_bytes(dest)
            return struct.pack("<H", fc) + duration + addr1

        else:
            fc = self._build_frame_control(self.TYPE_CONTROL, subtype)
            duration = struct.pack("<H", 0x0000)
            frame = struct.pack("<H", fc) + duration
            if dest:
                frame += self._mac_to_bytes(dest)
            return frame

    def craft_data_frame(self, bssid: str, source: str, dest: str,
                          payload: bytes = b"",
                          to_ds: int = 0, from_ds: int = 0) -> bytes:
        """
        Craft an 802.11 data frame.

        Args:
            bssid: BSSID address.
            source: Source address.
            dest: Destination address.
            payload: Frame payload data.
            to_ds: To-DS flag.
            from_ds: From-DS flag.

        Returns:
            Complete 802.11 data frame bytes.
        """
        subtype = DataSubtype.DATA
        fc = self._build_frame_control(self.TYPE_DATA, subtype, to_ds=to_ds, from_ds=from_ds)
        duration = struct.pack("<H", 0x0000)
        seq_ctrl = struct.pack("<H", self._next_sequence() << 4)

        # Address ordering depends on To-DS/From-DS
        if to_ds and not from_ds:
            addr1 = self._mac_to_bytes(bssid)
            addr2 = self._mac_to_bytes(source)
            addr3 = self._mac_to_bytes(dest)
        elif from_ds and not to_ds:
            addr1 = self._mac_to_bytes(dest)
            addr2 = self._mac_to_bytes(bssid)
            addr3 = self._mac_to_bytes(source)
        else:
            addr1 = self._mac_to_bytes(dest)
            addr2 = self._mac_to_bytes(source)
            addr3 = self._mac_to_bytes(bssid)

        # Add LLC/SNAP header for data
        llc_snap = bytes([
            0xAA, 0xAA, 0x03,  # LLC
            0x00, 0x00, 0x00,  # OUI
            0x08, 0x00,        # EtherType: IP
        ])

        frame = struct.pack("<H", fc) + duration + addr1 + addr2 + addr3 + seq_ctrl
        if payload:
            frame += llc_snap + payload

        return frame

    def inject_frame(self, frame: bytes, count: int = 1,
                     delay: float = 0.01) -> InjectionResult:
        """
        Inject a frame using tcpreplay.

        FIX: Uses tcpreplay instead of aireplay-ng --inject.

        Args:
            frame: Raw 802.11 frame bytes.
            count: Number of times to inject.
            delay: Delay between injections.

        Returns:
            InjectionResult with outcome.
        """
        self._check_root()
        result = InjectionResult()
        start_time = time.time()

        # Add radiotap header
        radiotap = self._build_radiotap_header()
        full_frame = radiotap + frame

        # Write frame to temporary pcap file for tcpreplay
        pcap_path = self._write_pcap(full_frame)
        if not pcap_path:
            result.error = "Failed to create pcap file"
            return result

        try:
            for i in range(count):
                cmd = [
                    "tcpreplay",
                    "--intf1", self.interface,
                    "--preload-pcap",
                    pcap_path,
                ]

                try:
                    proc = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=10
                    )
                    if proc.returncode == 0:
                        result.frames_sent += 1
                        result.bytes_sent += len(full_frame)
                    else:
                        result.frames_failed += 1
                        logger.debug("tcpreplay injection failed: %s", proc.stderr)
                except subprocess.TimeoutExpired:
                    result.frames_failed += 1
                except FileNotFoundError:
                    raise WiFiInjectionError(
                        "tcpreplay not found. Install tcpreplay package."
                    )

                if delay > 0 and i < count - 1:
                    time.sleep(delay)

            result.success = result.frames_sent > 0
        finally:
            try:
                os.unlink(pcap_path)
            except OSError:
                pass

        result.time_elapsed = time.time() - start_time
        return result

    def _write_pcap(self, frame_data: bytes) -> Optional[str]:
        """
        Write frame data to a pcap file for tcpreplay.

        Args:
            frame_data: Raw frame bytes with radiotap header.

        Returns:
            Path to pcap file or None on failure.
        """
        try:
            fd, pcap_path = tempfile.mkstemp(suffix=".pcap")
            with os.fdopen(fd, "wb") as f:
                # Write pcap global header
                pcap_header = struct.pack(
                    "<IHHiIII",
                    0xa1b2c3d4,  # Magic number
                    2, 4,        # Version
                    0,           # Timezone offset
                    0,           # Sigfigs
                    65535,       # Snaplen
                    105,         # Link type: IEEE 802.11 with radiotap
                )
                f.write(pcap_header)

                # Write pcap packet record
                ts_sec = int(time.time())
                ts_usec = 0
                packet_header = struct.pack(
                    "<IIII",
                    ts_sec,
                    ts_usec,
                    len(frame_data),
                    len(frame_data),
                )
                f.write(packet_header)
                f.write(frame_data)

            return pcap_path
        except OSError as e:
            logger.error("Failed to write pcap: %s", e)
            return None

    def inject_continuous(self, frame: bytes, delay: float = 0.01,
                          duration: float = 0.0,
                          callback: Optional[Callable] = None) -> InjectionResult:
        """
        Continuously inject frames until stopped or duration elapsed.

        Args:
            frame: Raw 802.11 frame bytes.
            delay: Delay between injections.
            duration: Maximum duration (0 = infinite).
            callback: Optional callback after each injection.

        Returns:
            InjectionResult with outcome.
        """
        self._check_root()
        self._running = True
        result = InjectionResult()
        start_time = time.time()

        radiotap = self._build_radiotap_header()
        full_frame = radiotap + frame
        pcap_path = self._write_pcap(full_frame)

        if not pcap_path:
            result.error = "Failed to create pcap file"
            self._running = False
            return result

        try:
            while self._running:
                cmd = [
                    "tcpreplay",
                    "--intf1", self.interface,
                    "--preload-pcap",
                    pcap_path,
                ]

                try:
                    proc = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=10
                    )
                    if proc.returncode == 0:
                        result.frames_sent += 1
                        result.bytes_sent += len(full_frame)
                    else:
                        result.frames_failed += 1
                except subprocess.TimeoutExpired:
                    result.frames_failed += 1
                except FileNotFoundError:
                    raise WiFiInjectionError("tcpreplay not found")

                if callback:
                    callback(result)

                if duration > 0 and time.time() - start_time >= duration:
                    break

                if delay > 0:
                    time.sleep(delay)
        finally:
            try:
                os.unlink(pcap_path)
            except OSError:
                pass
            self._running = False

        result.time_elapsed = time.time() - start_time
        result.success = result.frames_sent > 0
        return result

    def fuzz_frame(self, base_frame: bytes, config: FuzzConfig) -> Generator[InjectionResult, None, None]:
        """
        Fuzz an 802.11 frame by mutating various fields.

        Args:
            base_frame: Base frame bytes to mutate.
            config: Fuzzing configuration.

        Yields:
            InjectionResult for each mutation attempt.
        """
        self._check_root()
        self._running = True
        mutations = 0

        frame = bytearray(base_frame)

        while self._running and mutations < config.max_mutations:
            mutated = bytearray(frame)

            if config.mutation_strategy == "random":
                # Random byte mutation
                offset = random.randint(0, len(mutated) - 1)
                mutated[offset] = random.randint(0, 255)

            elif config.mutation_strategy == "bitflip":
                # Single bit flip
                offset = random.randint(0, len(mutated) - 1)
                bit = random.randint(0, 7)
                mutated[offset] ^= (1 << bit)

            elif config.mutation_strategy == "boundary":
                # Boundary value injection
                offset = random.randint(0, len(mutated) - 1)
                boundary_values = [0x00, 0xFF, 0x7F, 0x80, 0xFE, 0x01]
                mutated[offset] = random.choice(boundary_values)

            elif config.mutation_strategy == "exhaustive":
                # Exhaustive byte mutation (slow)
                for byte_val in range(256):
                    if not self._running:
                        break
                    for offset in range(len(mutated)):
                        test_frame = bytearray(frame)
                        test_frame[offset] = byte_val
                        result = self.inject_frame(bytes(test_frame), count=1, delay=config.delay)
                        mutations += 1
                        yield result
                        if mutations >= config.max_mutations:
                            return
                continue

            result = self.inject_frame(bytes(mutated), count=1, delay=config.delay)
            mutations += 1
            yield result

    def stop(self) -> None:
        """Stop frame injection."""
        self._running = False
        logger.info("Frame injector stopped")

    def get_stats(self) -> InjectionResult:
        """Get current injection statistics."""
        return self._stats
