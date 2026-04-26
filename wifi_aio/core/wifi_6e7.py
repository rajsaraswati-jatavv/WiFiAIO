"""WiFi 6E/7 (6 GHz band) support.

Provides 6 GHz scanning, HE (802.11ax) and EHT (802.11be) capability
parsing, PSC (Preferred Scanning Channel) support, and MCS rate tables.
"""

import logging
import os
import re
import struct
import subprocess
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)

# 6 GHz UNII band definitions
BAND_6GHZ_UNII_5 = (5925, 6425)  # MHz - UNII-5
BAND_6GHZ_UNII_6 = (6425, 6525)  # MHz - UNII-6
BAND_6GHZ_UNII_7 = (6525, 6875)  # MHz - UNII-7
BAND_6GHZ_UNII_8 = (6875, 7125)  # MHz - UNII-8

# Preferred Scanning Channels (PSC) for 6 GHz
# PSC channels are spaced 80 MHz apart for efficient scanning
PSC_CHANNELS_6GHZ = [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45,
                     49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93,
                     97, 101, 105, 109, 113, 117, 121, 125, 129, 133,
                     137, 141, 145, 149, 153, 157, 161, 165, 169, 173,
                     177, 181, 185, 189, 193, 197, 201, 205, 209, 213,
                     217, 221, 225, 229, 233]

# 6 GHz channel to frequency mapping
def _build_6ghz_channel_map() -> Dict[int, int]:
    """Build channel-to-frequency mapping for 6 GHz band."""
    channel_map = {}
    # 6 GHz channels: 20 MHz channels from 1 to 233
    for ch in range(1, 234, 1):
        freq = 5950 + ch * 5
        if 5925 <= freq <= 7125:
            channel_map[ch] = freq
    return channel_map

CHANNEL_MAP_6GHZ = _build_6ghz_channel_map()

# Reverse mapping: frequency -> channel
FREQ_MAP_6GHZ = {v: k for k, v in CHANNEL_MAP_6GHZ.items()}

# HE (WiFi 6/6E) MCS rate tables
# Rates in Mbps for different bandwidths and spatial streams
HE_MCS_RATES = {
    # (mcs_index, spatial_streams, bandwidth_mhz) -> rate_mbps
    # 20 MHz rates (per spatial stream)
    20: {
        0: {1: 8.6, 2: 17.2, 3: 25.8, 4: 34.4, 5: 51.6, 6: 68.8, 7: 77.4, 8: 86.0, 9: 103.2, 10: 114.7, 11: 129.0},
    },
    # 40 MHz rates
    40: {
        0: {1: 17.2, 2: 34.4, 3: 51.6, 4: 68.8, 5: 103.2, 6: 137.6, 7: 154.9, 8: 172.1, 9: 206.5, 10: 229.4, 11: 258.1},
    },
    # 80 MHz rates
    80: {
        0: {1: 36.0, 2: 72.1, 3: 108.1, 4: 144.1, 5: 216.2, 6: 288.2, 7: 324.3, 8: 360.3, 9: 432.4, 10: 480.3, 11: 540.4},
    },
    # 160 MHz rates
    160: {
        0: {1: 72.1, 2: 144.1, 3: 216.2, 4: 288.2, 5: 432.4, 6: 576.5, 7: 648.5, 8: 720.6, 9: 864.7, 10: 960.7, 11: 1081.0},
    },
}

# EHT (WiFi 7) MCS rate tables - extends HE with 320 MHz and higher MCS
EHT_MCS_RATES = {
    320: {
        0: {1: 144.1, 2: 288.2, 3: 432.4, 4: 576.5, 5: 864.7, 6: 1152.9, 7: 1297.1, 8: 1441.2, 9: 1729.4, 10: 1921.3, 11: 2161.9, 12: 2402.0, 13: 2642.2},
    },
}

# WiFi 7 (802.11be) features
WIFI7_FEATURES = {
    "mlo": "Multi-Link Operation",
    "320mhz": "320 MHz channels",
    "4096qam": "4096-QAM modulation",
    "mr_mcs": "Multi-RU MCS",
    "preamble_puncturing": "Preamble puncturing",
    "ndp_feedback": "NDP feedback framework",
    "bqrp": "Beamforming QRP",
    "enhanced_mu_mimo": "Enhanced MU-MIMO (16 streams)",
}


class WiFi6E7:
    """WiFi 6E and WiFi 7 (6 GHz band) operations.

    Supports:
    - 6 GHz channel scanning
    - HE/EHT capability parsing
    - PSC (Preferred Scanning Channel) support
    - MCS rate table lookups
    """

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self._scan_results: List[Dict] = []

    # ------------------------------------------------------------------
    # 6 GHz Scanning
    # ------------------------------------------------------------------

    def scan_6ghz(
        self,
        interface: Optional[str] = None,
        psc_only: bool = False,
        timeout: int = 30,
    ) -> List[Dict]:
        """Scan for 6 GHz WiFi networks.

        Args:
            interface: Wireless interface.
            psc_only: Only scan PSC channels for faster discovery.
            timeout: Scan duration per channel in seconds.

        Returns:
            List of discovered 6 GHz network dicts.
        """
        iface = interface or self.interface
        if not iface:
            raise WiFiConnectionError("Interface required for 6 GHz scan")

        if os.geteuid() != 0:
            from wifi_aio.exceptions import WiFiPermissionError
            raise WiFiPermissionError("Root required for 6 GHz scanning")

        channels = PSC_CHANNELS_6GHZ if psc_only else list(CHANNEL_MAP_6GHZ.keys())
        networks: Dict[str, Dict] = {}

        for channel in channels:
            freq = CHANNEL_MAP_6GHZ.get(channel)
            if freq is None:
                continue

            # Set channel/frequency
            try:
                subprocess.run(
                    ["iw", "dev", iface, "set", "freq", str(freq), "HT20"],
                    capture_output=True, text=True, timeout=5,
                )
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                continue

            # Trigger scan
            try:
                subprocess.run(
                    ["iw", "dev", iface, "scan", "trigger"],
                    capture_output=True, text=True, timeout=5,
                )
                import time
                time.sleep(2)

                result = subprocess.run(
                    ["iw", "dev", iface, "scan"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    parsed = self._parse_scan_output(result.stdout)
                    for net in parsed:
                        bssid = net.get("bssid", "")
                        if bssid and bssid not in networks:
                            net["band"] = "6GHz"
                            net["channel"] = channel
                            net["frequency_mhz"] = freq
                            net["is_psc"] = channel in PSC_CHANNELS_6GHZ
                            networks[bssid] = net
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                continue

        self._scan_results = list(networks.values())
        return self._scan_results

    @staticmethod
    def _parse_scan_output(output: str) -> List[Dict]:
        """Parse iw scan output."""
        networks = []
        current: Dict = {}

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("BSS"):
                if current and current.get("ssid"):
                    networks.append(current)
                match = re.match(r"BSS ([0-9a-fA-F:]{17})", line)
                current = {"bssid": match.group(1)} if match else {}
            elif current:
                if "SSID:" in line:
                    current["ssid"] = line.split("SSID:")[1].strip()
                elif "signal:" in line:
                    match = re.search(r"(-?\d+\.\d+) dBm", line)
                    if match:
                        current["signal_dbm"] = float(match.group(1))
                elif "DS Parameter set:" in line:
                    match = re.search(r"channel (\d+)", line)
                    if match:
                        current["channel"] = int(match.group(1))
                elif "HE:" in line or "HE Capabilities" in line:
                    current["he_capable"] = True
                elif "EHT:" in line or "EHT Capabilities" in line:
                    current["eht_capable"] = True
                elif "RSN:" in line:
                    current["security"] = "WPA2/WPA3"
                elif "WPA:" in line:
                    current["security"] = "WPA"

        if current and current.get("ssid"):
            networks.append(current)

        return networks

    def scan_6ghz_quick(self, interface: Optional[str] = None) -> List[Dict]:
        """Quick scan of PSC channels only.

        PSC channels are spaced 80 MHz apart, allowing rapid 6 GHz
        discovery without scanning every 20 MHz channel.

        Returns:
            List of discovered 6 GHz networks.
        """
        return self.scan_6ghz(interface=interface, psc_only=True, timeout=5)

    # ------------------------------------------------------------------
    # Channel utilities
    # ------------------------------------------------------------------

    @staticmethod
    def get_psc_channels() -> List[int]:
        """Get the list of 6 GHz Preferred Scanning Channels.

        Returns:
            List of PSC channel numbers.
        """
        return list(PSC_CHANNELS_6GHZ)

    @staticmethod
    def channel_to_frequency(channel: int) -> Optional[int]:
        """Convert 6 GHz channel number to frequency in MHz.

        Args:
            channel: Channel number (1-233).

        Returns:
            Frequency in MHz, or None if invalid.
        """
        return CHANNEL_MAP_6GHZ.get(channel)

    @staticmethod
    def frequency_to_channel(freq_mhz: int) -> Optional[int]:
        """Convert 6 GHz frequency to channel number.

        Args:
            freq_mhz: Frequency in MHz.

        Returns:
            Channel number, or None if not in 6 GHz range.
        """
        return FREQ_MAP_6GHZ.get(freq_mhz)

    @staticmethod
    def is_6ghz_frequency(freq_mhz: int) -> bool:
        """Check if a frequency is in the 6 GHz range."""
        return 5925 <= freq_mhz <= 7125

    @staticmethod
    def is_psc_channel(channel: int) -> bool:
        """Check if a channel is a Preferred Scanning Channel."""
        return channel in PSC_CHANNELS_6GHZ

    @staticmethod
    def get_channel_bandwidth_options(channel: int) -> List[int]:
        """Get available bandwidth options for a 6 GHz channel.

        Args:
            channel: Channel number.

        Returns:
            List of supported bandwidths in MHz.
        """
        # All 6 GHz channels support 20 MHz
        bandwidths = [20]

        # 40 MHz requires even-numbered 20 MHz channels
        if channel % 2 == 1:
            bandwidths.append(40)

        # 80 MHz requires channel ≡ 1 (mod 4) or specific center channels
        if channel % 4 == 1:
            bandwidths.append(80)

        # 160 MHz requires specific center channels
        if channel % 8 == 1:
            bandwidths.append(160)

        # 320 MHz (WiFi 7) requires specific center channels
        if channel % 16 == 1:
            bandwidths.append(320)

        return bandwidths

    @staticmethod
    def get_unii_band(freq_mhz: int) -> str:
        """Get the UNII band designation for a 6 GHz frequency.

        Returns:
            UNII band name (UNII-5, UNII-6, UNII-7, UNII-8) or 'unknown'.
        """
        if BAND_6GHZ_UNII_5[0] <= freq_mhz < BAND_6GHZ_UNII_5[1]:
            return "UNII-5"
        elif BAND_6GHZ_UNII_6[0] <= freq_mhz < BAND_6GHZ_UNII_6[1]:
            return "UNII-6"
        elif BAND_6GHZ_UNII_7[0] <= freq_mhz < BAND_6GHZ_UNII_7[1]:
            return "UNII-7"
        elif BAND_6GHZ_UNII_8[0] <= freq_mhz <= BAND_6GHZ_UNII_8[1]:
            return "UNII-8"
        return "unknown"

    # ------------------------------------------------------------------
    # HE Capability Parsing (802.11ax)
    # ------------------------------------------------------------------

    @staticmethod
    def parse_he_capabilities(he_cap_bytes: bytes) -> Dict:
        """Parse HE (802.11ax) Capabilities element.

        Args:
            he_cap_bytes: Raw HE Capabilities IE bytes (after element ID and length).

        Returns:
            Dict with parsed HE capabilities.
        """
        if len(he_cap_bytes) < 4:
            return {"valid": False, "error": "HE Capabilities too short"}

        result: Dict = {"valid": True}

        # HE MAC Capabilities (6 bytes starting at offset 0)
        if len(he_cap_bytes) >= 6:
            mac_caps = he_cap_bytes[:6]
            mac_bits = int.from_bytes(mac_caps, "little")

            result["he_mac_capabilities"] = {
                "htc_he_support": bool(mac_bits & (1 << 0)),
                "twt_requestor": bool(mac_bits & (1 << 1)),
                "twt_responder": bool(mac_bits & (1 << 2)),
                "fragmentation_support": (mac_bits >> 3) & 0x03,
                "max_num_frag_msdus": [1, 2, 4, 8][(mac_bits >> 3) & 0x03],
                "min_frag_size": [128, 256, 512, 1024][(mac_bits >> 5) & 0x03],
                "trigger_frame_mac_pad_duration": (mac_bits >> 7) & 0x03,
                "multi_tid_aggregation_rx_support": (mac_bits >> 9) & 0x07,
                "he_link_adaptation": (mac_bits >> 12) & 0x03,
                "all_ack_support": bool(mac_bits & (1 << 14)),
                "trs_support": bool(mac_bits & (1 << 15)),
                "a_ctrl": bool(mac_bits & (1 << 16)),
                "bsr_support": bool(mac_bits & (1 << 18)),
                "broadcast_twt_support": bool(mac_bits & (1 << 19)),
                "32_bit_ba_bitmap_support": bool(mac_bits & (1 << 20)),
                "mu_cascading_support": bool(mac_bits & (1 << 21)),
                "ack_enabled_aggregation_support": bool(mac_bits & (1 << 23)),
                "oms_support": bool(mac_bits & (1 << 28)),
            }

        # HE PHY Capabilities (11 bytes starting at offset 6)
        if len(he_cap_bytes) >= 17:
            phy_bytes = he_cap_bytes[6:17]
            phy_bits = int.from_bytes(phy_bytes, "little")

            result["he_phy_capabilities"] = {
                "channel_width_set": {
                    "40mhz_2ghz": bool(phy_bits & (1 << 1)),
                    "40mhz_80mhz_5ghz": bool(phy_bits & (1 << 2)),
                    "160mhz_5ghz": bool(phy_bits & (1 << 3)),
                    "160mhz_80p80_5ghz": bool(phy_bits & (1 << 4)),
                    "242_tone_ruu_1mhz": bool(phy_bits & (1 << 5)),
                    "242_tone_ruu_2mhz": bool(phy_bits & (1 << 6)),
                },
                "preamble_puncturing_rx": {
                    "puncture_20mhz": bool(phy_bits & (1 << 7)),
                    "puncture_40mhz": bool(phy_bits & (1 << 8)),
                },
                "device_class": (phy_bits >> 9) & 0x03,
                "he_su_ppdu_1x_ltf_800ns_gi": bool(phy_bits & (1 << 11)),
                "he_su_ppdu_4x_ltf_3200ns_gi": bool(phy_bits & (1 << 14)),
                "he_mu_ppdu_4x_ltf_3200ns_gi": bool(phy_bits & (1 << 17)),
                "he_er_su_ppdu_1x_ltf_800ns_gi": bool(phy_bits & (1 << 19)),
                "he_er_su_ppdu_4x_ltf_3200ns_gi": bool(phy_bits & (1 << 21)),
                "nominal_packet_padding": (phy_bits >> 22) & 0x03,
                "dcm_max_ru": {
                    0: "242-tone",
                    1: "484-tone",
                    2: "996-tone",
                    3: "2x996-tone",
                }.get((phy_bits >> 24) & 0x03, "unknown"),
                "max_nc": (phy_bits >> 29) & 0x07,
            }

            # Supported HE-MCS and NSS sets
            mcs_offset = 17
            if len(he_cap_bytes) >= mcs_offset + 4:
                # 1-2 GHz HE-MCS NSS (2 bytes)
                mcs_2ghz = int.from_bytes(he_cap_bytes[mcs_offset:mcs_offset + 2], "little")
                result["he_mcs_nss_2ghz"] = WiFi6E7._parse_mcs_nss_set(mcs_2ghz)

            if len(he_cap_bytes) >= mcs_offset + 8:
                # 5/6 GHz HE-MCS NSS (2 bytes)
                mcs_5ghz = int.from_bytes(he_cap_bytes[mcs_offset + 4:mcs_offset + 6], "little")
                result["he_mcs_nss_5ghz"] = WiFi6E7._parse_mcs_nss_set(mcs_5ghz)

            if len(he_cap_bytes) >= mcs_offset + 12:
                # 6 GHz HE-MCS NSS (2 bytes)
                mcs_6ghz = int.from_bytes(he_cap_bytes[mcs_offset + 8:mcs_offset + 10], "little")
                result["he_mcs_nss_6ghz"] = WiFi6E7._parse_mcs_nss_set(mcs_6ghz)

        return result

    @staticmethod
    def _parse_mcs_nss_set(mcs_nss: int) -> Dict:
        """Parse HE-MCS and NSS set.

        Each byte encodes: bits 0-3 = max NSS for MCS 0-7,
        bits 4-7 = max NSS for MCS 8-11.
        """
        rx_mcs_0_7 = mcs_nss & 0x0F
        rx_mcs_8_11 = (mcs_nss >> 4) & 0x0F
        tx_mcs_0_7 = (mcs_nss >> 8) & 0x0F
        tx_mcs_8_11 = (mcs_nss >> 12) & 0x0F

        return {
            "rx_max_nss_mcs_0_7": rx_mcs_0_7,
            "rx_max_nss_mcs_8_11": rx_mcs_8_11,
            "tx_max_nss_mcs_0_7": tx_mcs_0_7,
            "tx_max_nss_mcs_8_11": tx_mcs_8_11,
            "max_spatial_streams": max(rx_mcs_0_7, rx_mcs_8_11, tx_mcs_0_7, tx_mcs_8_11),
        }

    # ------------------------------------------------------------------
    # EHT Capability Parsing (802.11be / WiFi 7)
    # ------------------------------------------------------------------

    @staticmethod
    def parse_eht_capabilities(eht_cap_bytes: bytes) -> Dict:
        """Parse EHT (802.11be) Capabilities element.

        Args:
            eht_cap_bytes: Raw EHT Capabilities IE bytes.

        Returns:
            Dict with parsed EHT capabilities.
        """
        if len(eht_cap_bytes) < 2:
            return {"valid": False, "error": "EHT Capabilities too short"}

        result: Dict = {"valid": True}

        # EHT MAC Capabilities (2 bytes)
        if len(eht_cap_bytes) >= 2:
            mac_caps = int.from_bytes(eht_cap_bytes[:2], "little")
            result["eht_mac_capabilities"] = {
                "epc_priority_access": bool(mac_caps & (1 << 0)),
                "eht_om_control": bool(mac_caps & (1 << 1)),
                "triggered_txop_sharing_mode1": bool(mac_caps & (1 << 2)),
                "triggered_txop_sharing_mode2": bool(mac_caps & (1 << 3)),
                "restricted_twt": bool(mac_caps & (1 << 4)),
                "scs_traffic_description": bool(mac_caps & (1 << 5)),
                "max_mpdu_length": {0: 7991, 1: 11454, 2: 1492}[min((mac_caps >> 6) & 0x03, 2)],
            }

        # EHT PHY Capabilities (8 bytes)
        if len(eht_cap_bytes) >= 10:
            phy_bytes = eht_cap_bytes[2:10]
            phy_bits = int.from_bytes(phy_bytes, "little")

            result["eht_phy_capabilities"] = {
                "320mhz_6ghz": bool(phy_bits & (1 << 1)),
                "242_tone_ru_6ghz": bool(phy_bits & (1 << 2)),
                "ndp_4x_ltf_3200ns_gi": bool(phy_bits & (1 << 3)),
                "partial_bandwidth_ul_mu_mimo": bool(phy_bits & (1 << 4)),
                "su_beamformer_80mhz": bool(phy_bits & (1 << 5)),
                "su_beamformer_160mhz": bool(phy_bits & (1 << 6)),
                "su_beamformer_320mhz": bool(phy_bits & (1 << 7)),
                "mu_beamformer_80mhz": bool(phy_bits & (1 << 9)),
                "mu_beamformer_160mhz": bool(phy_bits & (1 << 10)),
                "mu_beamformer_320mhz": bool(phy_bits & (1 << 11)),
                "tx_1024_4096_qam": bool(phy_bits & (1 << 12)),
                "rx_1024_4096_qam": bool(phy_bits & (1 << 13)),
                "preamble_puncturing_80mhz": bool(phy_bits & (1 << 14)),
                "preamble_puncturing_160mhz": bool(phy_bits & (1 << 15)),
                "preamble_puncturing_320mhz": bool(phy_bits & (1 << 16)),
                "non_ofdma_ul_mu_mimo_80mhz": bool(phy_bits & (1 << 17)),
                "non_ofdma_ul_mu_mimo_160mhz": bool(phy_bits & (1 << 18)),
                "non_ofdma_ul_mu_mimo_320mhz": bool(phy_bits & (1 << 19)),
                "mru_7x996_tone_support": bool(phy_bits & (1 << 20)),
                "max_nc_16": bool(phy_bits & (1 << 24)),
                "nsr_16": bool(phy_bits & (1 << 25)),
            }

        # EHT MCS-NSS set (4 bytes)
        if len(eht_cap_bytes) >= 14:
            mcs_bytes = eht_cap_bytes[10:14]
            mcs_bits = int.from_bytes(mcs_bytes, "little")

            result["eht_mcs_nss"] = {
                "rx_max_nss_mcs_0_9": (mcs_bits & 0x0F),
                "rx_max_nss_mcs_10_11": (mcs_bits >> 4) & 0x0F,
                "rx_max_nss_mcs_12_13": (mcs_bits >> 8) & 0x0F,
                "tx_max_nss_mcs_0_9": (mcs_bits >> 16) & 0x0F,
                "tx_max_nss_mcs_10_11": (mcs_bits >> 20) & 0x0F,
                "tx_max_nss_mcs_12_13": (mcs_bits >> 24) & 0x0F,
            }

        return result

    # ------------------------------------------------------------------
    # MCS Rate Tables
    # ------------------------------------------------------------------

    @staticmethod
    def get_he_rate(
        mcs_index: int,
        spatial_streams: int = 1,
        bandwidth_mhz: int = 80,
        guard_interval_ns: int = 800,
    ) -> Optional[float]:
        """Look up HE (WiFi 6/6E) data rate.

        Args:
            mcs_index: MCS index (0-11).
            spatial_streams: Number of spatial streams (1-8).
            bandwidth_mhz: Channel bandwidth (20, 40, 80, 160).
            guard_interval_ns: Guard interval (800, 1600, 3200 ns).

        Returns:
            Data rate in Mbps, or None if not found.
        """
        # Base rates from table
        bw_key = min(bandwidth_mhz, 160)
        if bw_key not in HE_MCS_RATES:
            return None

        mcs_table = HE_MCS_RATES[bw_key].get(0, {})
        base_rate = mcs_table.get(spatial_streams)
        if base_rate is None:
            # Interpolate from single-stream rate
            ss1_rate = mcs_table.get(1)
            if ss1_rate is None:
                return None
            base_rate = ss1_rate * spatial_streams

        # Adjust for guard interval
        gi_factor = {
            800: 1.0,       # Normal GI
            1600: 0.96,     # Long GI (slightly slower)
            3200: 0.92,     # Extended GI
        }.get(guard_interval_ns, 1.0)

        # Adjust for MCS index
        mcs_factor = {
            0: base_rate * 0.5,
            1: base_rate * 0.5,
            2: base_rate * 0.75,
            3: base_rate,
            4: base_rate * 1.0,
            5: base_rate * 1.5,
            6: base_rate * 2.0,
            7: base_rate * 2.25,
            8: base_rate * 2.5,
            9: base_rate * 3.0,
            10: base_rate * 3.33,
            11: base_rate * 3.75,
        }.get(mcs_index)

        if mcs_factor is not None:
            return round(mcs_factor * gi_factor, 2)

        return None

    @staticmethod
    def get_eht_rate(
        mcs_index: int,
        spatial_streams: int = 1,
        bandwidth_mhz: int = 320,
        guard_interval_ns: int = 800,
    ) -> Optional[float]:
        """Look up EHT (WiFi 7) data rate.

        Args:
            mcs_index: MCS index (0-13).
            spatial_streams: Number of spatial streams (1-16).
            bandwidth_mhz: Channel bandwidth (20, 40, 80, 160, 320).
            guard_interval_ns: Guard interval (800, 1600, 3200 ns).

        Returns:
            Data rate in Mbps, or None if not found.
        """
        if bandwidth_mhz == 320 and 320 in EHT_MCS_RATES:
            mcs_table = EHT_MCS_RATES[320].get(0, {})
            base_rate = mcs_table.get(spatial_streams)
            if base_rate is None:
                ss1_rate = mcs_table.get(1, 144.1)
                base_rate = ss1_rate * spatial_streams

            # Scale by MCS
            mcs_scale = {
                0: 0.5, 1: 0.5, 2: 0.75, 3: 1.0, 4: 1.0,
                5: 1.5, 6: 2.0, 7: 2.25, 8: 2.5, 9: 3.0,
                10: 3.33, 11: 3.75, 12: 4.17, 13: 4.58,
            }.get(mcs_index)

            if mcs_scale is not None:
                gi_factor = {800: 1.0, 1600: 0.96, 3200: 0.92}.get(guard_interval_ns, 1.0)
                return round(base_rate * mcs_scale * gi_factor, 2)

        # Fall back to HE rates for < 320 MHz
        return WiFi6E7.get_he_rate(mcs_index, spatial_streams, bandwidth_mhz, guard_interval_ns)

    # ------------------------------------------------------------------
    # Capability Summary
    # ------------------------------------------------------------------

    @staticmethod
    def summarize_capabilities(he_caps: Optional[Dict] = None, eht_caps: Optional[Dict] = None) -> Dict:
        """Generate a human-readable summary of WiFi 6E/7 capabilities.

        Args:
            he_caps: Parsed HE capabilities dict.
            eht_caps: Parsed EHT capabilities dict.

        Returns:
            Dict with capability summary.
        """
        summary: Dict = {
            "wifi_version": "unknown",
            "max_bandwidth_mhz": 20,
            "max_spatial_streams": 1,
            "max_mcs": 7,
            "features": [],
            "bands": ["2.4GHz", "5GHz"],
        }

        if he_caps:
            summary["wifi_version"] = "WiFi 6E"
            phy = he_caps.get("he_phy_capabilities", {})
            ch_width = phy.get("channel_width_set", {})

            if ch_width.get("160mhz_5ghz"):
                summary["max_bandwidth_mhz"] = 160
            elif ch_width.get("40mhz_80mhz_5ghz"):
                summary["max_bandwidth_mhz"] = 80
            elif ch_width.get("40mhz_2ghz"):
                summary["max_bandwidth_mhz"] = 40

            # Check for 6 GHz support
            mcs_6ghz = he_caps.get("he_mcs_nss_6ghz", {})
            if mcs_6ghz:
                summary["bands"].append("6GHz")

            # Max spatial streams
            for key in ["he_mcs_nss_2ghz", "he_mcs_nss_5ghz", "he_mcs_nss_6ghz"]:
                nss = he_caps.get(key, {})
                ms = nss.get("max_spatial_streams", 0)
                if ms > summary["max_spatial_streams"]:
                    summary["max_spatial_streams"] = ms

            # Features
            mac = he_caps.get("he_mac_capabilities", {})
            if mac.get("twt_requestor") or mac.get("twt_responder"):
                summary["features"].append("TWT (Target Wake Time)")
            if mac.get("broadcast_twt_support"):
                summary["features"].append("Broadcast TWT")
            if mac.get("oms_support"):
                summary["features"].append("OMS (Operating Mode Signaling)")
            if mac.get("multi_tid_aggregation_rx_support"):
                summary["features"].append("Multi-TID Aggregation")

            summary["max_mcs"] = 11  # HE supports MCS 0-11

        if eht_caps:
            summary["wifi_version"] = "WiFi 7"
            phy = eht_caps.get("eht_phy_capabilities", {})

            if phy.get("320mhz_6ghz"):
                summary["max_bandwidth_mhz"] = 320
                if "6GHz" not in summary["bands"]:
                    summary["bands"].append("6GHz")

            mcs_nss = eht_caps.get("eht_mcs_nss", {})
            max_nss = max(
                mcs_nss.get("rx_max_nss_mcs_0_9", 0),
                mcs_nss.get("tx_max_nss_mcs_0_9", 0),
                mcs_nss.get("rx_max_nss_mcs_12_13", 0),
                mcs_nss.get("tx_max_nss_mcs_12_13", 0),
            )
            if max_nss > summary["max_spatial_streams"]:
                summary["max_spatial_streams"] = max_nss

            summary["max_mcs"] = 13  # EHT supports MCS 0-13

            if phy.get("tx_1024_4096_qam") or phy.get("rx_1024_4096_qam"):
                summary["features"].append("4096-QAM")
            if phy.get("non_ofdma_ul_mu_mimo_320mhz"):
                summary["features"].append("UL MU-MIMO 320 MHz")
            if phy.get("mru_7x996_tone_support"):
                summary["features"].append("MRU 7x996 tone")
            if phy.get("max_nc_16"):
                summary["features"].append("16 Spatial Streams")

        return summary

