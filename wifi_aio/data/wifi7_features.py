"""WiFi 7 (802.11be) feature definitions.

Defines Multi-Link Operation (MLO), EHT PPDU types, 320 MHz channel
data, 4096-QAM modulation parameters, and other WiFi 7 specific features.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ── WiFi 7 Core Feature Set ─────────────────────────────────────────────

WIFI7_FEATURES: Dict[str, object] = {
    "standard": "IEEE 802.11be",
    "amendment": "WiFi 7",
    "max_throughput": "46.1 Gbps",
    "max_mimo_streams": 16,
    "max_channel_width_mhz": 320,
    "modulation": "4096-QAM",
    "ofdma_max_rus": 2048,
    "multi_ru_support": True,
    "mlo_support": True,
    "preamble_puncturing": True,
    "link_adaptation": "Enhanced",
}


# ── Multi-Link Operation (MLO) Definitions ──────────────────────────────

@dataclass
class MLOLink:
    """Represents a single link in an MLO setup."""
    link_id: int
    band: str  # "2.4GHz", "5GHz", "6GHz"
    channel: int
    bandwidth_mhz: int
    mac_address: str


@dataclass
class MLOSetup:
    """Multi-Link Operation setup definition."""
    mld_address: str
    links: List[MLOLink] = field(default_factory=list)
    mode: str = "simultaneous"  # "simultaneous" or "strictroundrobin"

    def add_link(self, link: MLOLink) -> None:
        """Add a link to the MLO setup."""
        self.links.append(link)

    def get_link(self, link_id: int) -> Optional[MLOLink]:
        """Get a link by its ID."""
        for link in self.links:
            if link.link_id == link_id:
                return link
        return None

    def get_links_by_band(self, band: str) -> List[MLOLink]:
        """Get all links operating on a specific band."""
        return [link for link in self.links if link.band == band]

    @property
    def total_bandwidth(self) -> int:
        """Total aggregated bandwidth across all links in MHz."""
        return sum(link.bandwidth_mhz for link in self.links)

    @property
    def link_count(self) -> int:
        """Number of active links."""
        return len(self.links)


# MLO modes
MLO_MODES: Dict[str, Dict] = {
    "simultaneous": {
        "description": "STR - Simultaneous Transmit and Receive on different links",
        "max_links": 4,
        "requirement": "Links must be on non-overlapping bands",
    },
    "strictroundrobin": {
        "description": "SRR - Strict Round Robin, transmit on one link at a time",
        "max_links": 4,
        "requirement": "Links can be on any band",
    },
    "single_radio": {
        "description": "Single radio MLO - only one link active at a time",
        "max_links": 2,
        "requirement": "Switching between links",
    },
}

# ── EHT PPDU Types ─────────────────────────────────────────────────────

EHT_PPDU_TYPES: Dict[str, Dict] = {
    "EHT_SU": {
        "full_name": "EHT Single User",
        "description": "Single-user transmission",
        "max_ru_size": "996x2",
        "mcs_range": (0, 13),
    },
    "EHT_MU": {
        "full_name": "EHT Multi-User (OFDMA)",
        "description": "Multi-user OFDMA transmission",
        "max_ru_size": "996x2",
        "mcs_range": (0, 13),
    },
    "EHT_TB": {
        "full_name": "EHT Trigger-Based",
        "description": "Trigger-based uplink transmission",
        "max_ru_size": "996x2",
        "mcs_range": (0, 13),
    },
    "EHT_MU_MIMO": {
        "full_name": "EHT MU-MIMO",
        "description": "Multi-user MIMO with up to 16 streams",
        "max_ru_size": "996x2",
        "mcs_range": (0, 13),
    },
}

# ── 320 MHz Channel Definitions (6 GHz only) ────────────────────────────

WIFI7_320MHZ_CHANNELS: Dict[int, Dict] = {
    31: {
        "center_frequency": 5955 + 160,
        "band": "6GHz",
        "sub_channels": list(range(1, 65, 4)),
        "unii": "UNII-5",
    },
    63: {
        "center_frequency": 6115 + 160,
        "band": "6GHz",
        "sub_channels": list(range(33, 97, 4)),
        "unii": "UNII-5",
    },
    95: {
        "center_frequency": 6275 + 160,
        "band": "6GHz",
        "sub_channels": list(range(65, 129, 4)),
        "unii": "UNII-5/6",
    },
    127: {
        "center_frequency": 6435 + 160,
        "band": "6GHz",
        "sub_channels": list(range(97, 161, 4)),
        "unii": "UNII-6/7",
    },
    159: {
        "center_frequency": 6595 + 160,
        "band": "6GHz",
        "sub_channels": list(range(121, 185, 4)),
        "unii": "UNII-7",
    },
    191: {
        "center_frequency": 6755 + 160,
        "band": "6GHz",
        "sub_channels": list(range(153, 217, 4)),
        "unii": "UNII-7/8",
    },
    223: {
        "center_frequency": 6915 + 160,
        "band": "6GHz",
        "sub_channels": list(range(185, 249, 4)),
        "unii": "UNII-8",
    },
}

# ── 4096-QAM (12-bit) Modulation ────────────────────────────────────────

QAM_4096_PARAMS: Dict[str, Dict] = {
    "MCS_12": {
        "modulation": "4096-QAM",
        "coding_rate": "5/6",
        "bits_per_symbol": 12,
        "min_snr_db": 38,
        "data_rate_20mhz_1ss": "146 Mbps",
        "data_rate_40mhz_1ss": "293 Mbps",
        "data_rate_80mhz_1ss": "634 Mbps",
        "data_rate_160mhz_1ss": "1269 Mbps",
        "data_rate_320mhz_1ss": "2539 Mbps",
    },
    "MCS_13": {
        "modulation": "4096-QAM",
        "coding_rate": "3/4",
        "bits_per_symbol": 12,
        "min_snr_db": 35,
        "data_rate_20mhz_1ss": "131 Mbps",
        "data_rate_40mhz_1ss": "263 Mbps",
        "data_rate_80mhz_1ss": "570 Mbps",
        "data_rate_160mhz_1ss": "1141 Mbps",
        "data_rate_320mhz_1ss": "2282 Mbps",
    },
}

# Full MCS table for WiFi 7
WIFI7_MCS_TABLE: Dict[int, Dict] = {
    0:  {"modulation": "BPSK",    "coding_rate": "1/2",  "bits_per_symbol": 1},
    1:  {"modulation": "QPSK",    "coding_rate": "1/2",  "bits_per_symbol": 2},
    2:  {"modulation": "QPSK",    "coding_rate": "3/4",  "bits_per_symbol": 2},
    3:  {"modulation": "16-QAM",  "coding_rate": "1/2",  "bits_per_symbol": 4},
    4:  {"modulation": "16-QAM",  "coding_rate": "3/4",  "bits_per_symbol": 4},
    5:  {"modulation": "64-QAM",  "coding_rate": "2/3",  "bits_per_symbol": 6},
    6:  {"modulation": "64-QAM",  "coding_rate": "3/4",  "bits_per_symbol": 6},
    7:  {"modulation": "64-QAM",  "coding_rate": "5/6",  "bits_per_symbol": 6},
    8:  {"modulation": "256-QAM", "coding_rate": "3/4",  "bits_per_symbol": 8},
    9:  {"modulation": "256-QAM", "coding_rate": "5/6",  "bits_per_symbol": 8},
    10: {"modulation": "1024-QAM","coding_rate": "3/4",  "bits_per_symbol": 10},
    11: {"modulation": "1024-QAM","coding_rate": "5/6",  "bits_per_symbol": 10},
    12: {"modulation": "4096-QAM","coding_rate": "3/4",  "bits_per_symbol": 12},
    13: {"modulation": "4096-QAM","coding_rate": "5/6",  "bits_per_symbol": 12},
}

# ── RU Allocation Table for OFDMA ────────────────────────────────────────

RU_SIZES: Dict[str, Dict] = {
    "26-tone":   {"subcarriers": 26,  "max_per_20mhz": 9,  "max_per_320mhz": 148},
    "52-tone":   {"subcarriers": 52,  "max_per_20mhz": 4,  "max_per_320mhz": 68},
    "106-tone":  {"subcarriers": 106, "max_per_20mhz": 2,  "max_per_320mhz": 36},
    "242-tone":  {"subcarriers": 242, "max_per_20mhz": 1,  "max_per_320mhz": 16},
    "484-tone":  {"subcarriers": 484, "max_per_40mhz": 1,  "max_per_320mhz": 8},
    "996-tone":  {"subcarriers": 996, "max_per_80mhz": 1,  "max_per_320mhz": 4},
    "996x2-tone":{"subcarriers": 1992,"max_per_160mhz": 1, "max_per_320mhz": 2},
}

# ── Preamble Puncturing Patterns ─────────────────────────────────────────

PREAMBLE_PUNCTURING_PATTERNS: Dict[int, Dict] = {
    1: {"pattern": "20 MHz primary punctured",      "valid_bw": [40, 80, 160, 320]},
    2: {"pattern": "20 MHz secondary punctured",    "valid_bw": [40, 80, 160, 320]},
    3: {"pattern": "40 MHz secondary punctured",    "valid_bw": [80, 160, 320]},
    4: {"pattern": "20+20 MHz secondary punctured", "valid_bw": [80, 160, 320]},
    5: {"pattern": "80 MHz secondary punctured",    "valid_bw": [160, 320]},
    6: {"pattern": "40+40 MHz secondary punctured", "valid_bw": [160, 320]},
    7: {"pattern": "160 MHz secondary punctured",   "valid_bw": [320]},
    8: {"pattern": "80+80 MHz secondary punctured", "valid_bw": [320]},
}


@dataclass
class WiFi7FeatureSet:
    """Complete WiFi 7 feature set descriptor."""
    supports_mlo: bool = True
    supports_320mhz: bool = True
    supports_4096qam: bool = True
    supports_multi_ru: bool = True
    supports_preamble_puncturing: bool = True
    max_mimo_streams: int = 16
    max_links: int = 4
    mcs_range: tuple = (0, 13)

    def is_compatible(self, feature: str) -> bool:
        """Check if a specific WiFi 7 feature is supported.

        Args:
            feature: Feature name to check.

        Returns:
            True if the feature is supported.
        """
        feature_map = {
            "mlo": self.supports_mlo,
            "320mhz": self.supports_320mhz,
            "4096qam": self.supports_4096qam,
            "multi_ru": self.supports_multi_ru,
            "preamble_puncturing": self.supports_preamble_puncturing,
        }
        return feature_map.get(feature, False)

    def get_max_data_rate(self, bandwidth_mhz: int = 320, spatial_streams: int = 16) -> float:
        """Calculate theoretical max data rate in Gbps.

        Args:
            bandwidth_mhz: Channel bandwidth.
            spatial_streams: Number of spatial streams.

        Returns:
            Theoretical maximum data rate in Gbps.
        """
        base_rates = {
            20: 146, 40: 293, 80: 634, 160: 1269, 320: 2539
        }
        base = base_rates.get(bandwidth_mhz, 146)
        return (base * spatial_streams) / 1000.0
