"""WiFi channel and frequency tables for 2.4 GHz and 5 GHz bands.

Provides complete channel-to-frequency mappings, regulatory domain
information, and channel bandwidth details for WiFi operations.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# ── 2.4 GHz Channel Table ───────────────────────────────────────────────
# Channel: (center_frequency_mhz, band, allowed_bw, is_overlapping)
WIFI_CHANNELS_2GHZ: Dict[int, Dict] = {
    1:  {"frequency": 2412, "band": "2.4GHz", "bw": [20, 40], "overlap": False, "dfs": False},
    2:  {"frequency": 2417, "band": "2.4GHz", "bw": [20], "overlap": True, "dfs": False},
    3:  {"frequency": 2422, "band": "2.4GHz", "bw": [20], "overlap": True, "dfs": False},
    4:  {"frequency": 2427, "band": "2.4GHz", "bw": [20], "overlap": True, "dfs": False},
    5:  {"frequency": 2432, "band": "2.4GHz", "bw": [20, 40], "overlap": True, "dfs": False},
    6:  {"frequency": 2437, "band": "2.4GHz", "bw": [20, 40], "overlap": False, "dfs": False},
    7:  {"frequency": 2442, "band": "2.4GHz", "bw": [20], "overlap": True, "dfs": False},
    8:  {"frequency": 2447, "band": "2.4GHz", "bw": [20], "overlap": True, "dfs": False},
    9:  {"frequency": 2452, "band": "2.4GHz", "bw": [20], "overlap": True, "dfs": False},
    10: {"frequency": 2457, "band": "2.4GHz", "bw": [20, 40], "overlap": False, "dfs": False},
    11: {"frequency": 2462, "band": "2.4GHz", "bw": [20, 40], "overlap": False, "dfs": False},
    12: {"frequency": 2467, "band": "2.4GHz", "bw": [20], "overlap": True, "dfs": False},
    13: {"frequency": 2472, "band": "2.4GHz", "bw": [20], "overlap": True, "dfs": False},
    14: {"frequency": 2484, "band": "2.4GHz", "bw": [20], "overlap": True, "dfs": False},
}

# Non-overlapping channels for 20 MHz in 2.4 GHz
NON_OVERLAPPING_2GHZ_20MHZ: List[int] = [1, 6, 11]
NON_OVERLAPPING_2GHZ_40MHZ: List[int] = [1, 6, 11]

# ── 5 GHz Channel Table ─────────────────────────────────────────────────
# UNII-1 (5150-5250 MHz) - Indoor, no DFS
# UNII-2A (5250-5350 MHz) - DFS required
# UNII-2C (5470-5725 MHz) - DFS required
# UNII-3 (5725-5825 MHz) - Outdoor, no DFS
WIFI_CHANNELS_5GHZ: Dict[int, Dict] = {
    # UNII-1 (indoor only, no DFS)
    36:  {"frequency": 5180, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": False, "unii": "UNII-1"},
    40:  {"frequency": 5200, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": False, "unii": "UNII-1"},
    44:  {"frequency": 5220, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": False, "unii": "UNII-1"},
    48:  {"frequency": 5240, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": False, "unii": "UNII-1"},
    # UNII-2A (DFS required)
    52:  {"frequency": 5260, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2A"},
    56:  {"frequency": 5280, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2A"},
    60:  {"frequency": 5300, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2A"},
    64:  {"frequency": 5320, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2A"},
    # UNII-2C (DFS required)
    100: {"frequency": 5500, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2C"},
    104: {"frequency": 5520, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2C"},
    108: {"frequency": 5540, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2C"},
    112: {"frequency": 5560, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2C"},
    116: {"frequency": 5580, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2C"},
    120: {"frequency": 5600, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2C"},
    124: {"frequency": 5620, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2C"},
    128: {"frequency": 5640, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2C"},
    132: {"frequency": 5660, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2C"},
    136: {"frequency": 5680, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2C"},
    140: {"frequency": 5700, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2C"},
    144: {"frequency": 5720, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": True, "unii": "UNII-2C"},
    # UNII-3 (outdoor, no DFS)
    149: {"frequency": 5745, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": False, "unii": "UNII-3"},
    153: {"frequency": 5765, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": False, "unii": "UNII-3"},
    157: {"frequency": 5785, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": False, "unii": "UNII-3"},
    161: {"frequency": 5805, "band": "5GHz", "bw": [20, 40, 80, 160], "overlap": False, "dfs": False, "unii": "UNII-3"},
    165: {"frequency": 5825, "band": "5GHz", "bw": [20, 40, 80], "overlap": False, "dfs": False, "unii": "UNII-3"},
}

# 5 GHz 160 MHz channel groups (center frequencies)
FIVE_GHZ_160MHZ_GROUPS: Dict[int, List[int]] = {
    50:  [36, 40, 44, 48, 52, 56, 60, 64],
    114: [100, 104, 108, 112, 116, 120, 124, 128],
    163: [149, 153, 157, 161, 165],
}

# 5 GHz 80 MHz channel groups
FIVE_GHZ_80MHZ_GROUPS: Dict[int, List[int]] = {
    42:  [36, 40, 44, 48],
    58:  [52, 56, 60, 64],
    106: [100, 104, 108, 112],
    122: [116, 120, 124, 128],
    138: [132, 136, 140, 144],
    155: [149, 153, 157, 161],
}

# 5 GHz 40 MHz channel pairs
FIVE_GHZ_40MHZ_PAIRS: Dict[int, List[int]] = {
    38:  [36, 40],
    46:  [44, 48],
    54:  [52, 56],
    62:  [60, 64],
    102: [100, 104],
    110: [108, 112],
    118: [116, 120],
    126: [124, 128],
    134: [132, 136],
    142: [140, 144],
    151: [149, 153],
    159: [157, 161],
}


def channel_to_frequency(channel: int, band: str = "auto") -> Optional[int]:
    """Convert a WiFi channel number to its center frequency in MHz.

    Args:
        channel: Channel number.
        band: "2.4GHz", "5GHz", or "auto" (tries both).

    Returns:
        Center frequency in MHz, or None if channel is not valid.
    """
    if band in ("2.4GHz", "auto"):
        if channel in WIFI_CHANNELS_2GHZ:
            return WIFI_CHANNELS_2GHZ[channel]["frequency"]
    if band in ("5GHz", "auto"):
        if channel in WIFI_CHANNELS_5GHZ:
            return WIFI_CHANNELS_5GHZ[channel]["frequency"]
    return None


def frequency_to_channel(frequency: int) -> Optional[int]:
    """Convert a center frequency in MHz to a WiFi channel number.

    Args:
        frequency: Center frequency in MHz.

    Returns:
        Channel number, or None if frequency is not valid.
    """
    for ch, info in WIFI_CHANNELS_2GHZ.items():
        if info["frequency"] == frequency:
            return ch
    for ch, info in WIFI_CHANNELS_5GHZ.items():
        if info["frequency"] == frequency:
            return ch
    return None


def get_dfs_channels(band: str = "5GHz") -> List[int]:
    """Get list of DFS-required channels.

    Args:
        band: Frequency band to query.

    Returns:
        List of channel numbers requiring DFS.
    """
    if band == "5GHz":
        return sorted(ch for ch, info in WIFI_CHANNELS_5GHZ.items() if info.get("dfs"))
    return []


def get_non_dfs_channels(band: str = "5GHz") -> List[int]:
    """Get list of non-DFS channels.

    Args:
        band: Frequency band to query.

    Returns:
        List of channel numbers not requiring DFS.
    """
    if band == "5GHz":
        return sorted(ch for ch, info in WIFI_CHANNELS_5GHZ.items() if not info.get("dfs"))
    if band == "2.4GHz":
        return list(WIFI_CHANNELS_2GHZ.keys())
    return []


def get_channels_by_unii(unii_band: str) -> List[int]:
    """Get channels belonging to a specific UNII band.

    Args:
        unii_band: UNII band name (e.g., "UNII-1", "UNII-2A", "UNII-2C", "UNII-3").

    Returns:
        List of channel numbers in the specified UNII band.
    """
    return sorted(
        ch for ch, info in WIFI_CHANNELS_5GHZ.items()
        if info.get("unii") == unii_band
    )


def get_best_channels(band: str = "2.4GHz", bandwidth: int = 20) -> List[int]:
    """Get recommended non-overlapping channels for a band and bandwidth.

    Args:
        band: "2.4GHz" or "5GHz".
        bandwidth: Channel bandwidth in MHz.

    Returns:
        List of recommended channel numbers.
    """
    if band == "2.4GHz":
        if bandwidth <= 20:
            return NON_OVERLAPPING_2GHZ_20MHZ
        return NON_OVERLAPPING_2GHZ_40MHZ
    if band == "5GHz":
        non_dfs = get_non_dfs_channels("5GHz")
        if bandwidth == 160:
            center_channels = list(FIVE_GHZ_160MHZ_GROUPS.keys())
            return [c for c in center_channels]
        if bandwidth == 80:
            return list(FIVE_GHZ_80MHZ_GROUPS.keys())
        return non_dfs
    return []
