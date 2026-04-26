"""IEEE 802.11 Information Element (IE) parser.

Provides classes for parsing and constructing 802.11 Information
Elements found in management frames. Supports all major IE types
including SSID, Supported Rates, DS Parameter, RSN, HT/VHT/HE
Capabilities, and BSS Load.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple, Union

from wifi_aio.exceptions import WiFiConnectionError


# IE Element IDs
IE_SSID = 0
IE_SUPPORTED_RATES = 1
IE_FH_PARAMETER = 2
IE_DSSS_PARAMETER = 3  # DS Parameter Set
IE_CF_PARAMETER = 4
IE_TIM = 5
IE_IBSS_PARAMETER = 6
IE_COUNTRY = 7
IE_HOPPING_PARAMETER = 8
IE_HOPPING_TABLE = 9
IE_REQUEST = 10
IE_BSS_LOAD = 11
IE_EDCA_PARAMETER = 12
IE_TSPEC = 13
IE_TCLAS = 14
IE_SCHEDULE = 15
IE_CHALLENGE = 16
IE_POWER_CONSTRAINT = 32
IE_POWER_CAPABILITY = 33
IE_TPC_REQUEST = 34
IE_TPC_REPORT = 35
IE_SUPPORTED_CHANNELS = 36
IE_CHANNEL_SWITCH = 37
IE_MEASUREMENT_REQUEST = 38
IE_MEASUREMENT_REPORT = 39
IE_QUIET = 40
IE_IBSS_DFS = 41
IE_ERP = 42
IE_TS_DELAY = 43
IE_TCLAS_PROCESSING = 44
IE_HT_CAPABILITY = 45
IE_QOS_CAPABILITY = 46
IE_RSN = 48
IE_EXTENDED_SUPPORTED_RATES = 50
IE_AP_CHANNEL_REPORT = 51
IE_BSS_AVAILABLE_ADMISSION_CAPACITY = 67
IE_ANTENNA = 64
IE_RSNE = 48
IE_MOBILITY_DOMAIN = 54
IE_FAST_BSS_TRANSITION = 55
IE_TIMEOUT_INTERVAL = 56
IE_RIC_DATA = 57
IE_DSE_REGISTERED_LOCATION = 58
IE_EXTENDED_CHANNEL_SWITCH = 60
IE_HT_OPERATION = 61
IE_SECONDARY_CHANNEL_OFFSET = 62
IE_BSS_AVERAGE_ACCESS_DELAY = 63
IE_20_40_BSS_COEXISTENCE = 72
IE_20_40_BSS_INTOLERANT_CHANNEL_REPORT = 73
IE_OVERLAPPING_BSS_SCAN_PARAMETERS = 74
IE_RIC_DESCRIPTOR = 75
IE_MANAGEMENT_MIC = 76
IE_EVENT_REQUEST = 78
IE_EVENT_REPORT = 79
IE_DIAGNOSTIC_REQUEST = 80
IE_DIAGNOSTIC_REPORT = 81
IE_LOCATION_PARAMETERS = 82
IE_NONTRANSMITTED_BSSID_CAPABILITY = 83
IE_SSID_LIST = 84
IE_MULTIPLE_BSSID = 85
IE_FMS_DESCRIPTOR = 86
IE_FMS_REQUEST = 87
IE_FMS_RESPONSE = 88
IE_QOS_TRAFFIC_CAPABILITY = 89
IE_BSS_MAX_IDLE_PERIOD = 90
IE_TFS_REQUEST = 91
IE_TFS_RESPONSE = 92
IE_WNM_SLEEP_MODE = 93
IE_TIM_BROADCAST_REQUEST = 94
IE_TIM_BROADCAST_RESPONSE = 95
IE_COLLOCATED_INTERFERENCE_REPORT = 96
IE_CHANNEL_USAGE = 97
IE_TIME_ZONE = 98
IE_DMS_REQUEST = 99
IE_DMS_RESPONSE = 100
IE_LINK_IDENTIFIER = 101
IE_WAKEUP_SCHEDULE = 102
IE_CHANNEL_SWITCH_TIMING = 104
IE_PEER_CCK = 106
IE_PERR = 107
IE_VHT_CAPABILITY = 191
IE_VHT_OPERATION = 192
IE_EXTENDED_BSS_LOAD = 193
IE_WIDE_BANDWIDTH_CHANNEL_SWITCH = 194
IE_VHT_TRANSMIT_POWER_ENVELOPE = 195
IE_CHANNEL_SWITCH_WRAPPER = 196
IE_AID = 197
IE_QUIET_CHANNEL = 198
IE_OPERATING_MODE_NOTIFICATION = 199
IE_REDUCED_NEIGHBOR_REPORT = 201
IE_TVHT = 205
IE_HE_CAPABILITY = 255  # Extension ID 35
IE_HE_OPERATION = 255   # Extension ID 36

# RSN Cipher Suite OUI + Type
RSN_OUI = b"\x00\x0f\xac"
CIPHER_SUITE_USE_GROUP = 0
CIPHER_SUITE_WEP40 = 1
CIPHER_SUITE_TKIP = 2
CIPHER_SUITE_CCMP = 4
CIPHER_SUITE_WEP104 = 5
CIPHER_SUITE_BIP_CMAC_128 = 6
CIPHER_SUITE_GCMP = 8
CIPHER_SUITE_GCMP_256 = 9
CIPHER_SUITE_CCMP_256 = 10
CIPHER_SUITE_BIP_GMAC_128 = 11
CIPHER_SUITE_BIP_GMAC_256 = 12
CIPHER_SUITE_BIP_CMAC_256 = 13

# AKM Suite OUI + Type
AKM_NO_AUTH = 0
AKM_8021X = 1
AKM_PSK = 2
AKM_FT_8021X = 3
AKM_FT_PSK = 4
AKM_8021X_SHA256 = 5
AKM_PSK_SHA256 = 6
AKM_TDLS = 7
AKM_SAE = 8
AKM_FT_SAE = 9
AKM_AP_PEER_KEY = 10
AKM_8021X_SUITE_B = 11
AKM_8021X_SUITE_B_192 = 12
AKM_FT_8021X_SHA384 = 13
AKM_FILS_SHA256 = 14
AKM_FILS_SHA384 = 15
AKM_FT_FILS_SHA256 = 16
AKM_FT_FILS_SHA384 = 17
AKM_OWE = 18

CIPHER_NAMES = {
    CIPHER_SUITE_USE_GROUP: "Use Group Cipher",
    CIPHER_SUITE_WEP40: "WEP-40",
    CIPHER_SUITE_TKIP: "TKIP",
    CIPHER_SUITE_CCMP: "CCMP",
    CIPHER_SUITE_WEP104: "WEP-104",
    CIPHER_SUITE_BIP_CMAC_128: "BIP-CMAC-128",
    CIPHER_SUITE_GCMP: "GCMP",
    CIPHER_SUITE_GCMP_256: "GCMP-256",
    CIPHER_SUITE_CCMP_256: "CCMP-256",
    CIPHER_SUITE_BIP_GMAC_128: "BIP-GMAC-128",
    CIPHER_SUITE_BIP_GMAC_256: "BIP-GMAC-256",
    CIPHER_SUITE_BIP_CMAC_256: "BIP-CMAC-256",
}

AKM_NAMES = {
    AKM_NO_AUTH: "No Authentication",
    AKM_8021X: "802.1X/EAP",
    AKM_PSK: "PSK",
    AKM_FT_8021X: "FT-802.1X",
    AKM_FT_PSK: "FT-PSK",
    AKM_8021X_SHA256: "802.1X-SHA256",
    AKM_PSK_SHA256: "PSK-SHA256",
    AKM_TDLS: "TDLS",
    AKM_SAE: "SAE (WPA3)",
    AKM_FT_SAE: "FT-SAE",
    AKM_AP_PEER_KEY: "AP-Peer-Key",
    AKM_8021X_SUITE_B: "802.1X-Suite-B",
    AKM_8021X_SUITE_B_192: "802.1X-Suite-B-192",
    AKM_FT_8021X_SHA384: "FT-802.1X-SHA384",
    AKM_FILS_SHA256: "FILS-SHA256",
    AKM_FILS_SHA384: "FILS-SHA384",
    AKM_FT_FILS_SHA256: "FT-FILS-SHA256",
    AKM_FT_FILS_SHA384: "FT-FILS-SHA384",
    AKM_OWE: "OWE (Opportunistic Wireless Encryption)",
}


class InformationElement:
    """Base class for an IEEE 802.11 Information Element.

    An IE consists of an Element ID (1 byte), Length (1 byte),
    and variable-length data.
    """

    def __init__(self, element_id: int, data: bytes = b""):
        self.element_id = element_id
        self.data = data

    @property
    def length(self) -> int:
        """Length of the IE data (excluding ID and Length fields)."""
        return len(self.data)

    def to_bytes(self) -> bytes:
        """Serialize the IE to bytes (ID + Length + Data)."""
        if len(self.data) > 255:
            raise ValueError(f"IE data too long: {len(self.data)} bytes, max 255")
        return bytes([self.element_id, len(self.data)]) + self.data

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> Tuple["InformationElement", int]:
        """Parse a single IE from bytes at the given offset.

        Args:
            data: Raw bytes containing IEs.
            offset: Starting offset.

        Returns:
            Tuple of (InformationElement, next_offset).

        Raises:
            WiFiConnectionError: If the IE is malformed.
        """
        if offset + 2 > len(data):
            raise WiFiConnectionError(
                f"IE header out of bounds at offset {offset}"
            )
        element_id = data[offset]
        length = data[offset + 1]
        if offset + 2 + length > len(data):
            raise WiFiConnectionError(
                f"IE data out of bounds: id={element_id}, length={length}, "
                f"available={len(data) - offset - 2}"
            )
        ie_data = data[offset + 2 : offset + 2 + length]
        return cls(element_id=element_id, data=ie_data), offset + 2 + length

    def __repr__(self) -> str:
        return f"InformationElement(id={self.element_id}, length={self.length})"


class SSIDElement(InformationElement):
    """SSID (Service Set Identifier) Information Element.

    The SSID IE (Element ID 0) contains the network name.
    An empty SSID indicates a broadcast/hidden network.
    """

    def __init__(self, ssid: str = ""):
        self.ssid = ssid
        super().__init__(
            element_id=IE_SSID,
            data=ssid.encode("utf-8") if ssid else b"",
        )

    @classmethod
    def from_ie(cls, ie: InformationElement) -> "SSIDElement":
        """Create from a generic InformationElement."""
        ssid = ie.data.decode("utf-8", errors="replace") if ie.data else ""
        return cls(ssid=ssid)

    def is_hidden(self) -> bool:
        """Check if this SSID indicates a hidden network."""
        return len(self.ssid) == 0


class SupportedRatesElement(InformationElement):
    """Supported Rates Information Element.

    The Supported Rates IE (Element ID 1) lists the data rates
    supported by the station. A rate with the MSB set (0x80)
    indicates it is a basic (mandatory) rate.
    """

    # Common rate values in 0.5 Mbps units
    RATE_1_MBPS = 0x02
    RATE_2_MBPS = 0x04
    RATE_5_5_MBPS = 0x0B
    RATE_11_MBPS = 0x16
    RATE_6_MBPS = 0x0C
    RATE_9_MBPS = 0x12
    RATE_12_MBPS = 0x18
    RATE_18_MBPS = 0x24
    RATE_24_MBPS = 0x30
    RATE_36_MBPS = 0x48
    RATE_48_MBPS = 0x60
    RATE_54_MBPS = 0x6C

    RATE_NAMES = {
        0x02: "1 Mbps", 0x04: "2 Mbps", 0x0B: "5.5 Mbps",
        0x16: "11 Mbps", 0x0C: "6 Mbps", 0x12: "9 Mbps",
        0x18: "12 Mbps", 0x24: "18 Mbps", 0x30: "24 Mbps",
        0x48: "36 Mbps", 0x60: "48 Mbps", 0x6C: "54 Mbps",
    }

    def __init__(self, rates: Optional[List[int]] = None):
        self.rates = rates or [
            self.RATE_1_MBPS, self.RATE_2_MBPS, self.RATE_5_5_MBPS,
            self.RATE_11_MBPS, self.RATE_6_MBPS, self.RATE_9_MBPS,
            self.RATE_12_MBPS, self.RATE_18_MBPS,
        ]
        super().__init__(
            element_id=IE_SUPPORTED_RATES,
            data=bytes(self.rates),
        )

    @classmethod
    def from_ie(cls, ie: InformationElement) -> "SupportedRatesElement":
        """Create from a generic InformationElement."""
        rates = list(ie.data)
        return cls(rates=rates)

    def get_rate_mbps(self, rate_byte: int) -> float:
        """Convert a rate byte to Mbps value.

        Args:
            rate_byte: Raw rate byte (in 0.5 Mbps units, MSB may be set for basic).

        Returns:
            Rate in Mbps.
        """
        return (rate_byte & 0x7F) * 0.5

    def get_all_rates_mbps(self) -> List[float]:
        """Return all supported rates in Mbps."""
        return [self.get_rate_mbps(r) for r in self.rates]

    def get_basic_rates_mbps(self) -> List[float]:
        """Return basic (mandatory) rates in Mbps."""
        return [self.get_rate_mbps(r) for r in self.rates if r & 0x80]

    def is_basic(self, rate_byte: int) -> bool:
        """Check if a rate is a basic rate."""
        return bool(rate_byte & 0x80)


class DSParameterElement(InformationElement):
    """DS Parameter Set Information Element.

    The DS Parameter IE (Element ID 3) contains the current
    channel number for DSSS/HR-DSSS/ERP networks.
    """

    def __init__(self, channel: int = 1):
        self.channel = channel
        super().__init__(
            element_id=IE_DSSS_PARAMETER,
            data=bytes([channel & 0xFF]),
        )

    @classmethod
    def from_ie(cls, ie: InformationElement) -> "DSParameterElement":
        """Create from a generic InformationElement."""
        channel = ie.data[0] if ie.data else 0
        return cls(channel=channel)


class RSNElement(InformationElement):
    """RSN (Robust Security Network) Information Element.

    The RSN IE (Element ID 48) describes the security capabilities
    of the network including cipher suites and AKM suites.
    """

    def __init__(
        self,
        version: int = 1,
        group_cipher: int = CIPHER_SUITE_CCMP,
        pairwise_ciphers: Optional[List[int]] = None,
        akm_suites: Optional[List[int]] = None,
        rsn_capabilities: int = 0,
        pmkid_list: Optional[List[bytes]] = None,
        group_management_cipher: int = 0,
    ):
        self.version = version
        self.group_cipher = group_cipher
        self.pairwise_ciphers = pairwise_ciphers or [CIPHER_SUITE_CCMP]
        self.akm_suites = akm_suites or [AKM_PSK]
        self.rsn_capabilities = rsn_capabilities
        self.pmkid_list = pmkid_list or []
        self.group_management_cipher = group_management_cipher
        data = self._build_data()
        super().__init__(element_id=IE_RSN, data=data)

    def _build_data(self) -> bytes:
        """Build the RSN IE data field."""
        data = bytearray()
        # Version (2 bytes)
        data.extend(struct.pack("<H", self.version))
        # Group Cipher Suite (4 bytes: OUI + type)
        data.extend(RSN_OUI)
        data.append(self.group_cipher)
        # Pairwise Cipher Suite Count (2 bytes)
        data.extend(struct.pack("<H", len(self.pairwise_ciphers)))
        # Pairwise Cipher Suites
        for cipher in self.pairwise_ciphers:
            data.extend(RSN_OUI)
            data.append(cipher)
        # AKM Suite Count (2 bytes)
        data.extend(struct.pack("<H", len(self.akm_suites)))
        # AKM Suites
        for akm in self.akm_suites:
            data.extend(RSN_OUI)
            data.append(akm)
        # RSN Capabilities (2 bytes)
        data.extend(struct.pack("<H", self.rsn_capabilities))
        # PMKID List (optional)
        if self.pmkid_list:
            data.extend(struct.pack("<H", len(self.pmkid_list)))
            for pmkid in self.pmkid_list:
                data.extend(pmkid[:16])
        # Group Management Cipher Suite (optional)
        if self.group_management_cipher:
            data.extend(RSN_OUI)
            data.append(self.group_management_cipher)
        return bytes(data)

    @classmethod
    def from_ie(cls, ie: InformationElement) -> "RSNElement":
        """Create from a generic InformationElement."""
        data = ie.data
        if len(data) < 12:
            raise WiFiConnectionError(
                f"RSN IE data too short: {len(data)} bytes, minimum 12"
            )
        offset = 0
        version = struct.unpack("<H", data[offset:offset + 2])[0]
        offset += 2
        # Group Cipher Suite
        if data[offset:offset + 3] != RSN_OUI:
            raise WiFiConnectionError("Invalid RSN OUI in group cipher")
        group_cipher = data[offset + 3]
        offset += 4
        # Pairwise Cipher Suite Count
        pairwise_count = struct.unpack("<H", data[offset:offset + 2])[0]
        offset += 2
        pairwise_ciphers = []
        for _ in range(pairwise_count):
            if offset + 4 > len(data):
                break
            if data[offset:offset + 3] != RSN_OUI:
                offset += 4
                continue
            pairwise_ciphers.append(data[offset + 3])
            offset += 4
        # AKM Suite Count
        if offset + 2 > len(data):
            return cls(
                version=version, group_cipher=group_cipher,
                pairwise_ciphers=pairwise_ciphers, akm_suites=[],
            )
        akm_count = struct.unpack("<H", data[offset:offset + 2])[0]
        offset += 2
        akm_suites = []
        for _ in range(akm_count):
            if offset + 4 > len(data):
                break
            if data[offset:offset + 3] != RSN_OUI:
                offset += 4
                continue
            akm_suites.append(data[offset + 3])
            offset += 4
        # RSN Capabilities
        rsn_capabilities = 0
        if offset + 2 <= len(data):
            rsn_capabilities = struct.unpack("<H", data[offset:offset + 2])[0]
            offset += 2
        # PMKID List
        pmkid_list = []
        if offset + 2 <= len(data):
            pmkid_count = struct.unpack("<H", data[offset:offset + 2])[0]
            offset += 2
            for _ in range(pmkid_count):
                if offset + 16 > len(data):
                    break
                pmkid_list.append(data[offset:offset + 16])
                offset += 16
        # Group Management Cipher
        group_management_cipher = 0
        if offset + 4 <= len(data):
            group_management_cipher = data[offset + 3]
        return cls(
            version=version,
            group_cipher=group_cipher,
            pairwise_ciphers=pairwise_ciphers,
            akm_suites=akm_suites,
            rsn_capabilities=rsn_capabilities,
            pmkid_list=pmkid_list,
            group_management_cipher=group_management_cipher,
        )

    @property
    def group_cipher_name(self) -> str:
        """Human-readable name for the group cipher suite."""
        return CIPHER_NAMES.get(self.group_cipher, f"Unknown({self.group_cipher})")

    @property
    def pairwise_cipher_names(self) -> List[str]:
        """Human-readable names for pairwise cipher suites."""
        return [CIPHER_NAMES.get(c, f"Unknown({c})") for c in self.pairwise_ciphers]

    @property
    def akm_suite_names(self) -> List[str]:
        """Human-readable names for AKM suites."""
        return [AKM_NAMES.get(a, f"Unknown({a})") for a in self.akm_suites]

    @property
    def is_wpa3(self) -> bool:
        """Check if this RSN indicates WPA3 (SAE or OWE)."""
        return AKM_SAE in self.akm_suites or AKM_OWE in self.akm_suites

    @property
    def is_pmf_required(self) -> bool:
        """Check if Protected Management Frames is required."""
        return bool(self.rsn_capabilities & 0x0080)

    @property
    def is_pmf_capable(self) -> bool:
        """Check if Protected Management Frames is capable."""
        return bool(self.rsn_capabilities & 0x0040)

    def security_summary(self) -> Dict[str, Union[str, List[str], bool]]:
        """Return a summary of the security configuration."""
        return {
            "version": self.version,
            "group_cipher": self.group_cipher_name,
            "pairwise_ciphers": self.pairwise_cipher_names,
            "akm_suites": self.akm_suite_names,
            "pmf_required": self.is_pmf_required,
            "pmf_capable": self.is_pmf_capable,
            "is_wpa3": self.is_wpa3,
        }


class HTCapabilitiesElement(InformationElement):
    """HT (High Throughput) Capabilities Information Element (802.11n).

    The HT Capabilities IE (Element ID 45) describes the 802.11n
    capabilities including supported MCS rates, channel width, and
    other HT features.
    """

    def __init__(
        self,
        ht_capabilities_info: int = 0x0000,
        ampdu_param: int = 0x00,
        mcs_set: bytes = b"\x00" * 16,
        ht_extended_capabilities: int = 0x0000,
        tx_beamforming_capabilities: int = 0x00000000,
        asel_capabilities: int = 0x00,
    ):
        self.ht_capabilities_info = ht_capabilities_info
        self.ampdu_param = ampdu_param
        self.mcs_set = mcs_set.ljust(16, b"\x00")[:16]
        self.ht_extended_capabilities = ht_extended_capabilities
        self.tx_beamforming_capabilities = tx_beamforming_capabilities
        self.asel_capabilities = asel_capabilities
        data = self._build_data()
        super().__init__(element_id=IE_HT_CAPABILITY, data=data)

    def _build_data(self) -> bytes:
        """Build the HT Capabilities IE data field."""
        d = bytearray()
        d.extend(struct.pack("<H", self.ht_capabilities_info))
        d.append(self.ampdu_param)
        d.extend(self.mcs_set)
        d.extend(struct.pack("<H", self.ht_extended_capabilities))
        d.extend(struct.pack("<I", self.tx_beamforming_capabilities))
        d.append(self.asel_capabilities)
        return bytes(d)

    @classmethod
    def from_ie(cls, ie: InformationElement) -> "HTCapabilitiesElement":
        """Create from a generic InformationElement."""
        data = ie.data
        if len(data) < 26:
            raise WiFiConnectionError(
                f"HT Capabilities IE too short: {len(data)} bytes"
            )
        ht_caps = struct.unpack("<H", data[0:2])[0]
        ampdu = data[2]
        mcs = data[3:19]
        ht_ext = struct.unpack("<H", data[19:21])[0]
        txbf = struct.unpack("<I", data[21:25])[0]
        asel = data[25]
        return cls(
            ht_capabilities_info=ht_caps,
            ampdu_param=ampdu,
            mcs_set=mcs,
            ht_extended_capabilities=ht_ext,
            tx_beamforming_capabilities=txbf,
            asel_capabilities=asel,
        )

    @property
    def supports_40mhz(self) -> bool:
        """Whether 40 MHz channel width is supported."""
        return bool(self.ht_capabilities_info & 0x0001)

    @property
    def short_gi_20(self) -> bool:
        """Whether Short GI for 20 MHz is supported."""
        return bool(self.ht_capabilities_info & 0x0020)

    @property
    def short_gi_40(self) -> bool:
        """Whether Short GI for 40 MHz is supported."""
        return bool(self.ht_capabilities_info & 0x0040)

    @property
    def max_ampdu_length_exponent(self) -> int:
        """Maximum A-MPDU length exponent."""
        return self.ampdu_param & 0x03

    @property
    def max_ampdu_length(self) -> int:
        """Maximum A-MPDU length in bytes."""
        exponents = {0: 8191, 1: 16383, 2: 32767, 3: 65535}
        return exponents.get(self.max_ampdu_length_exponent, 8191)

    @property
    def rx_mcs_bitmask(self) -> bytes:
        """First 10 bytes of the MCS set define the RX MCS bitmask."""
        return self.mcs_set[:10]

    @property
    def highest_rx_mcs(self) -> int:
        """Highest supported RX MCS index (0-76)."""
        for byte_idx in range(min(10, len(self.mcs_set)) - 1, -1, -1):
            byte_val = self.mcs_set[byte_idx]
            if byte_val != 0:
                for bit_idx in range(7, -1, -1):
                    if byte_val & (1 << bit_idx):
                        return byte_idx * 8 + bit_idx
        return 0

    @property
    def num_rx_spatial_streams(self) -> int:
        """Number of RX spatial streams."""
        return (self.mcs_set[12] & 0x1F) + 1 if len(self.mcs_set) > 12 else 1

    @property
    def num_tx_spatial_streams(self) -> int:
        """Number of TX spatial streams."""
        return ((self.mcs_set[12] >> 5) & 0x07) + 1 if len(self.mcs_set) > 12 else 1


class VHTCapabilitiesElement(InformationElement):
    """VHT (Very High Throughput) Capabilities Information Element (802.11ac).

    The VHT Capabilities IE (Element ID 191) describes 802.11ac
    capabilities including supported MCS rates, channel widths,
    and other VHT features.
    """

    def __init__(
        self,
        vht_capabilities_info: int = 0x00000000,
        rx_mcs_map: int = 0x0000,
        rx_highest_data_rate: int = 0,
        tx_mcs_map: int = 0x0000,
        tx_highest_data_rate: int = 0,
    ):
        self.vht_capabilities_info = vht_capabilities_info
        self.rx_mcs_map = rx_mcs_map
        self.rx_highest_data_rate = rx_highest_data_rate
        self.tx_mcs_map = tx_mcs_map
        self.tx_highest_data_rate = tx_highest_data_rate
        data = self._build_data()
        super().__init__(element_id=IE_VHT_CAPABILITY, data=data)

    def _build_data(self) -> bytes:
        """Build the VHT Capabilities IE data field."""
        d = bytearray()
        d.extend(struct.pack("<I", self.vht_capabilities_info))
        d.extend(struct.pack("<H", self.rx_mcs_map))
        d.extend(struct.pack("<H", self.rx_highest_data_rate))
        d.extend(struct.pack("<H", self.tx_mcs_map))
        d.extend(struct.pack("<H", self.tx_highest_data_rate))
        return bytes(d)

    @classmethod
    def from_ie(cls, ie: InformationElement) -> "VHTCapabilitiesElement":
        """Create from a generic InformationElement."""
        data = ie.data
        if len(data) < 12:
            raise WiFiConnectionError(
                f"VHT Capabilities IE too short: {len(data)} bytes"
            )
        vht_caps = struct.unpack("<I", data[0:4])[0]
        rx_mcs = struct.unpack("<H", data[4:6])[0]
        rx_highest = struct.unpack("<H", data[6:8])[0]
        tx_mcs = struct.unpack("<H", data[8:10])[0]
        tx_highest = struct.unpack("<H", data[10:12])[0]
        return cls(
            vht_capabilities_info=vht_caps,
            rx_mcs_map=rx_mcs,
            rx_highest_data_rate=rx_highest,
            tx_mcs_map=tx_mcs,
            tx_highest_data_rate=tx_highest,
        )

    @property
    def max_mpdu_length(self) -> int:
        """Maximum MPDU length in bytes."""
        lengths = {0: 3895, 1: 7991, 2: 11454, 3: 11454}
        return lengths.get(self.vht_capabilities_info & 0x03, 3895)

    @property
    def supports_160mhz(self) -> bool:
        """Whether 160 MHz channel width is supported."""
        return bool(self.vht_capabilities_info & 0x04)

    @property
    def supports_80plus80(self) -> bool:
        """Whether 80+80 MHz channel width is supported."""
        return bool(self.vht_capabilities_info & 0x08)

    @property
    def short_gi_80(self) -> bool:
        """Whether Short GI for 80 MHz is supported."""
        return bool(self.vht_capabilities_info & 0x20)

    @property
    def short_gi_160(self) -> bool:
        """Whether Short GI for 160 MHz is supported."""
        return bool(self.vht_capabilities_info & 0x40)

    @property
    def max_rx_spatial_streams(self) -> int:
        """Maximum number of RX spatial streams from MCS map."""
        count = 0
        for i in range(8):
            mcs_val = (self.rx_mcs_map >> (i * 2)) & 0x03
            if mcs_val != 3:  # 3 = not supported
                count = i + 1
        return count

    @property
    def max_tx_spatial_streams(self) -> int:
        """Maximum number of TX spatial streams from MCS map."""
        count = 0
        for i in range(8):
            mcs_val = (self.tx_mcs_map >> (i * 2)) & 0x03
            if mcs_val != 3:
                count = i + 1
        return count

    def get_rx_mcs_for_stream(self, stream: int) -> str:
        """Get the RX MCS setting for a given spatial stream (1-8)."""
        if stream < 1 or stream > 8:
            return "Invalid"
        mcs_val = (self.rx_mcs_map >> ((stream - 1) * 2)) & 0x03
        mcs_names = {0: "MCS 0-7", 1: "MCS 0-8", 2: "MCS 0-9", 3: "Not Supported"}
        return mcs_names.get(mcs_val, "Unknown")


class HECapabilitiesElement(InformationElement):
    """HE (High Efficiency) Capabilities Information Element (802.11ax / WiFi 6).

    The HE Capabilities IE (Element ID 255, Extension ID 35) describes
    802.11ax capabilities including OFDMA, MU-MIMO, and other features.
    """

    EXTENSION_ID = 35

    def __init__(
        self,
        he_mac_capabilities: int = 0,
        he_phy_capabilities: int = 0,
        he_mcs_nss_set: bytes = b"\x00" * 4,
    ):
        self.he_mac_capabilities = he_mac_capabilities
        self.he_phy_capabilities = he_phy_capabilities
        self.he_mcs_nss_set = he_mcs_nss_set
        data = self._build_data()
        super().__init__(element_id=IE_HE_CAPABILITY, data=data)

    def _build_data(self) -> bytes:
        """Build the HE Capabilities IE data field."""
        d = bytearray()
        d.append(self.EXTENSION_ID)
        d.extend(struct.pack("<Q", self.he_mac_capabilities)[:6])
        d.extend(struct.pack("<Q", self.he_phy_capabilities)[:8])
        d.extend(self.he_mcs_nss_set[:4])
        return bytes(d)

    @classmethod
    def from_ie(cls, ie: InformationElement) -> "HECapabilitiesElement":
        """Create from a generic InformationElement."""
        data = ie.data
        if len(data) < 1 or data[0] != cls.EXTENSION_ID:
            raise WiFiConnectionError("Not an HE Capabilities IE")
        if len(data) < 19:
            raise WiFiConnectionError(
                f"HE Capabilities IE too short: {len(data)} bytes"
            )
        offset = 1
        he_mac = int.from_bytes(data[offset:offset + 6], "little")
        offset += 6
        he_phy = int.from_bytes(data[offset:offset + 8], "little")
        offset += 8
        he_mcs = data[offset:offset + 4]
        return cls(
            he_mac_capabilities=he_mac,
            he_phy_capabilities=he_phy,
            he_mcs_nss_set=he_mcs,
        )

    @property
    def supports_ofdma(self) -> bool:
        """Whether OFDMA (DL/UL) is supported."""
        return bool(self.he_mac_capabilities & 0x0002)

    @property
    def supports_ul_mu_mimo(self) -> bool:
        """Whether UL MU-MIMO is supported."""
        return bool(self.he_mac_capabilities & 0x0020)

    @property
    def supports_160mhz(self) -> bool:
        """Whether 160 MHz channel width is supported."""
        return bool(self.he_phy_capabilities & 0x0001)

    @property
    def supports_80plus80(self) -> bool:
        """Whether 80+80 MHz is supported."""
        return bool(self.he_phy_capabilities & 0x0002)

    @property
    def supports_he_su_ppdu(self) -> bool:
        """Whether HE SU PPDU is supported."""
        return bool(self.he_phy_capabilities & 0x0004)

    @property
    def supports_he_mu_ppdu(self) -> bool:
        """Whether HE MU PPDU is supported."""
        return bool(self.he_phy_capabilities & 0x0020)


class BSSLoadElement(InformationElement):
    """BSS Load Information Element.

    The BSS Load IE (Element ID 11) provides information about the
    current load on the BSS, including station count, channel
    utilization, and available admission capacity.
    """

    def __init__(
        self,
        station_count: int = 0,
        channel_utilization: int = 0,
        available_admission_capacity: int = 0,
    ):
        self.station_count = station_count
        self.channel_utilization = channel_utilization
        self.available_admission_capacity = available_admission_capacity
        data = self._build_data()
        super().__init__(element_id=IE_BSS_LOAD, data=data)

    def _build_data(self) -> bytes:
        """Build the BSS Load IE data field."""
        d = bytearray()
        d.extend(struct.pack("<H", self.station_count))
        d.append(self.channel_utilization)
        d.extend(struct.pack("<H", self.available_admission_capacity))
        return bytes(d)

    @classmethod
    def from_ie(cls, ie: InformationElement) -> "BSSLoadElement":
        """Create from a generic InformationElement."""
        data = ie.data
        if len(data) < 5:
            raise WiFiConnectionError(
                f"BSS Load IE too short: {len(data)} bytes, minimum 5"
            )
        station_count = struct.unpack("<H", data[0:2])[0]
        channel_utilization = data[2]
        available_admission = struct.unpack("<H", data[3:5])[0]
        return cls(
            station_count=station_count,
            channel_utilization=channel_utilization,
            available_admission_capacity=available_admission,
        )

    @property
    def channel_utilization_percent(self) -> float:
        """Channel utilization as a percentage (0-100%)."""
        return self.channel_utilization * 100.0 / 255.0

    @property
    def available_capacity_mbps(self) -> float:
        """Available admission capacity in Mbps (32 μs/s units)."""
        return self.available_admission_capacity * 32.0 / 1000000.0


class InformationElementParser:
    """Parser for IEEE 802.11 Information Elements.

    Parses a raw IE buffer from management frame bodies into
    a list of structured IE objects.
    """

    # IE type mapping for known element IDs
    IE_CLASS_MAP = {
        IE_SSID: SSIDElement,
        IE_SUPPORTED_RATES: SupportedRatesElement,
        IE_DSSS_PARAMETER: DSParameterElement,
        IE_RSN: RSNElement,
        IE_HT_CAPABILITY: HTCapabilitiesElement,
        IE_VHT_CAPABILITY: VHTCapabilitiesElement,
        IE_BSS_LOAD: BSSLoadElement,
    }

    def __init__(self, ie_data: bytes = b""):
        self._raw_data = ie_data
        self._elements: List[InformationElement] = []
        self._parse()

    def _parse(self) -> None:
        """Parse all IEs from the raw data."""
        self._elements = []
        offset = 0
        while offset + 2 <= len(self._raw_data):
            element_id = self._raw_data[offset]
            length = self._raw_data[offset + 1]
            if offset + 2 + length > len(self._raw_data):
                break
            ie_data = self._raw_data[offset + 2 : offset + 2 + length]

            # Handle extension IEs (Element ID 255)
            if element_id == 255 and length >= 1:
                ext_id = ie_data[0]
                if ext_id == HECapabilitiesElement.EXTENSION_ID:
                    ie = HECapabilitiesElement.__new__(HECapabilitiesElement)
                    InformationElement.__init__(ie, element_id=element_id, data=ie_data)
                    self._elements.append(ie)
                else:
                    ie = InformationElement(element_id=element_id, data=ie_data)
                    self._elements.append(ie)
            elif element_id in self.IE_CLASS_MAP:
                ie_class = self.IE_CLASS_MAP[element_id]
                try:
                    generic_ie = InformationElement(element_id=element_id, data=ie_data)
                    ie = ie_class.from_ie(generic_ie)
                    self._elements.append(ie)
                except Exception:
                    ie = InformationElement(element_id=element_id, data=ie_data)
                    self._elements.append(ie)
            else:
                ie = InformationElement(element_id=element_id, data=ie_data)
                self._elements.append(ie)

            offset += 2 + length

    @property
    def elements(self) -> List[InformationElement]:
        """List of all parsed Information Elements."""
        return self._elements

    def get_by_id(self, element_id: int) -> Optional[InformationElement]:
        """Get the first IE with the specified element ID.

        Args:
            element_id: The IE element ID to search for.

        Returns:
            The first matching IE, or None if not found.
        """
        for ie in self._elements:
            if ie.element_id == element_id:
                return ie
        return None

    def get_all_by_id(self, element_id: int) -> List[InformationElement]:
        """Get all IEs with the specified element ID.

        Args:
            element_id: The IE element ID to search for.

        Returns:
            List of all matching IEs.
        """
        return [ie for ie in self._elements if ie.element_id == element_id]

    def get_ssid(self) -> Optional[str]:
        """Get the SSID from the parsed IEs."""
        ie = self.get_by_id(IE_SSID)
        if ie and isinstance(ie, SSIDElement):
            return ie.ssid
        elif ie:
            return ie.data.decode("utf-8", errors="replace")
        return None

    def get_channel(self) -> Optional[int]:
        """Get the channel number from the DS Parameter IE."""
        ie = self.get_by_id(IE_DSSS_PARAMETER)
        if ie and isinstance(ie, DSParameterElement):
            return ie.channel
        elif ie and ie.data:
            return ie.data[0]
        return None

    def get_rsn(self) -> Optional[RSNElement]:
        """Get the RSN IE if present."""
        ie = self.get_by_id(IE_RSN)
        if ie and isinstance(ie, RSNElement):
            return ie
        elif ie:
            return RSNElement.from_ie(ie)
        return None

    def get_ht_capabilities(self) -> Optional[HTCapabilitiesElement]:
        """Get the HT Capabilities IE if present."""
        ie = self.get_by_id(IE_HT_CAPABILITY)
        if ie and isinstance(ie, HTCapabilitiesElement):
            return ie
        elif ie:
            return HTCapabilitiesElement.from_ie(ie)
        return None

    def get_vht_capabilities(self) -> Optional[VHTCapabilitiesElement]:
        """Get the VHT Capabilities IE if present."""
        ie = self.get_by_id(IE_VHT_CAPABILITY)
        if ie and isinstance(ie, VHTCapabilitiesElement):
            return ie
        elif ie:
            return VHTCapabilitiesElement.from_ie(ie)
        return None

    def get_bss_load(self) -> Optional[BSSLoadElement]:
        """Get the BSS Load IE if present."""
        ie = self.get_by_id(IE_BSS_LOAD)
        if ie and isinstance(ie, BSSLoadElement):
            return ie
        elif ie:
            return BSSLoadElement.from_ie(ie)
        return None

    def get_supported_rates(self) -> Optional[SupportedRatesElement]:
        """Get the Supported Rates IE if present."""
        ie = self.get_by_id(IE_SUPPORTED_RATES)
        if ie and isinstance(ie, SupportedRatesElement):
            return ie
        elif ie:
            return SupportedRatesElement.from_ie(ie)
        return None

    def summary(self) -> Dict[str, Union[str, int, List, Dict]]:
        """Return a summary of all parsed IEs."""
        result: Dict[str, Union[str, int, List, Dict]] = {}
        ssid = self.get_ssid()
        if ssid is not None:
            result["ssid"] = ssid
        channel = self.get_channel()
        if channel is not None:
            result["channel"] = channel
        rsn = self.get_rsn()
        if rsn:
            result["security"] = rsn.security_summary()
        ht = self.get_ht_capabilities()
        if ht:
            result["ht"] = {
                "40mhz": ht.supports_40mhz,
                "short_gi_20": ht.short_gi_20,
                "short_gi_40": ht.short_gi_40,
                "rx_streams": ht.num_rx_spatial_streams,
                "tx_streams": ht.num_tx_spatial_streams,
            }
        vht = self.get_vht_capabilities()
        if vht:
            result["vht"] = {
                "160mhz": vht.supports_160mhz,
                "80plus80": vht.supports_80plus80,
                "short_gi_80": vht.short_gi_80,
                "rx_streams": vht.max_rx_spatial_streams,
                "tx_streams": vht.max_tx_spatial_streams,
            }
        bss_load = self.get_bss_load()
        if bss_load:
            result["bss_load"] = {
                "station_count": bss_load.station_count,
                "channel_utilization": round(bss_load.channel_utilization_percent, 1),
            }
        result["ie_count"] = len(self._elements)
        return result
