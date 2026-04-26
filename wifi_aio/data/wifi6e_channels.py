"""WiFi 6E 6 GHz channel data.

Provides channel-to-frequency mappings for the 6 GHz band (UNII-5
through UNII-8), Preferred Scanning Channels (PSC), and channel
groupings for 40/80/160 MHz bandwidths.
"""

from __future__ import annotations

from typing import Dict, List, Optional

# ── 6 GHz Channel Table ─────────────────────────────────────────────────
# UNII-5 (5925-6425 MHz) - Standard power / Indoor
# UNII-6 (6425-6525 MHz) - Indoor only
# UNII-7 (6525-6875 MHz) - Standard power
# UNII-8 (6875-7125 MHz) - Indoor / Very low power

WIFI6E_CHANNELS: Dict[int, Dict] = {
    # UNII-5 (5925-6425 MHz)
    1:   {"frequency": 5955, "band": "6GHz", "bw": [20, 40, 80, 160], "dfs": False, "unii": "UNII-5", "psc": True},
    5:   {"frequency": 5975, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    9:   {"frequency": 5995, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    13:  {"frequency": 6015, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    17:  {"frequency": 6035, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    21:  {"frequency": 6055, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    25:  {"frequency": 6075, "band": "6GHz", "bw": [20, 40, 80, 160], "dfs": False, "unii": "UNII-5", "psc": True},
    29:  {"frequency": 6095, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    33:  {"frequency": 6115, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    37:  {"frequency": 6135, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    41:  {"frequency": 6155, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    45:  {"frequency": 6175, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    49:  {"frequency": 6195, "band": "6GHz", "bw": [20, 40, 80, 160], "dfs": False, "unii": "UNII-5", "psc": True},
    53:  {"frequency": 6215, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    57:  {"frequency": 6235, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    61:  {"frequency": 6255, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    65:  {"frequency": 6275, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    69:  {"frequency": 6295, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    73:  {"frequency": 6315, "band": "6GHz", "bw": [20, 40, 80, 160], "dfs": False, "unii": "UNII-5", "psc": True},
    77:  {"frequency": 6335, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    81:  {"frequency": 6355, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    85:  {"frequency": 6375, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    89:  {"frequency": 6395, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    93:  {"frequency": 6415, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-5", "psc": False},
    # UNII-6 (6425-6525 MHz) - Indoor only
    97:  {"frequency": 6435, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-6", "psc": False},
    101: {"frequency": 6455, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-6", "psc": False},
    105: {"frequency": 6475, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-6", "psc": False},
    109: {"frequency": 6495, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-6", "psc": False},
    113: {"frequency": 6515, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-6", "psc": False},
    # UNII-7 (6525-6875 MHz)
    117: {"frequency": 6535, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    121: {"frequency": 6555, "band": "6GHz", "bw": [20, 40, 80, 160], "dfs": False, "unii": "UNII-7", "psc": True},
    125: {"frequency": 6575, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    129: {"frequency": 6595, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    133: {"frequency": 6615, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    137: {"frequency": 6635, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    141: {"frequency": 6655, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    145: {"frequency": 6675, "band": "6GHz", "bw": [20, 40, 80, 160], "dfs": False, "unii": "UNII-7", "psc": True},
    149: {"frequency": 6695, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    153: {"frequency": 6715, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    157: {"frequency": 6735, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    161: {"frequency": 6755, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    165: {"frequency": 6775, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    169: {"frequency": 6795, "band": "6GHz", "bw": [20, 40, 80, 160], "dfs": False, "unii": "UNII-7", "psc": True},
    173: {"frequency": 6815, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    177: {"frequency": 6835, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    181: {"frequency": 6855, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    185: {"frequency": 6875, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-7", "psc": False},
    # UNII-8 (6875-7125 MHz) - Indoor / Very low power
    189: {"frequency": 6895, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-8", "psc": False},
    193: {"frequency": 6915, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-8", "psc": False},
    197: {"frequency": 6935, "band": "6GHz", "bw": [20, 40, 80, 160], "dfs": False, "unii": "UNII-8", "psc": True},
    201: {"frequency": 6955, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-8", "psc": False},
    205: {"frequency": 6975, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-8", "psc": False},
    209: {"frequency": 6995, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-8", "psc": False},
    213: {"frequency": 7015, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-8", "psc": False},
    217: {"frequency": 7035, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-8", "psc": False},
    221: {"frequency": 7055, "band": "6GHz", "bw": [20, 40, 80, 160], "dfs": False, "unii": "UNII-8", "psc": True},
    225: {"frequency": 7075, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-8", "psc": False},
    229: {"frequency": 7095, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-8", "psc": False},
    233: {"frequency": 7115, "band": "6GHz", "bw": [20], "dfs": False, "unii": "UNII-8", "psc": False},
}

# Preferred Scanning Channels (PSC) - every 4th 20 MHz channel, spaced 80 MHz apart
WIFI6E_PSC_CHANNELS: List[int] = [1, 25, 49, 73, 121, 145, 169, 197, 221]

# 40 MHz channel groups in 6 GHz
WIFI6E_40MHZ_GROUPS: Dict[int, List[int]] = {
    3:   [1, 5],
    11:  [9, 13],
    19:  [17, 21],
    27:  [25, 29],
    35:  [33, 37],
    43:  [41, 45],
    51:  [49, 53],
    59:  [57, 61],
    67:  [65, 69],
    75:  [73, 77],
    83:  [81, 85],
    91:  [89, 93],
    123: [121, 125],
    131: [129, 133],
    139: [137, 141],
    147: [145, 149],
    155: [153, 157],
    163: [161, 165],
    171: [169, 173],
    199: [197, 201],
    207: [205, 209],
    215: [213, 217],
    223: [221, 225],
}

# 80 MHz channel groups in 6 GHz
WIFI6E_80MHZ_GROUPS: Dict[int, List[int]] = {
    7:   [1, 5, 9, 13],
    23:  [17, 21, 25, 29],
    39:  [33, 37, 41, 45],
    55:  [49, 53, 57, 61],
    71:  [65, 69, 73, 77],
    87:  [81, 85, 89, 93],
    127: [121, 125, 129, 133],
    143: [137, 141, 145, 149],
    159: [153, 157, 161, 165],
    175: [169, 173, 177, 181],
    203: [197, 201, 205, 209],
    219: [213, 217, 221, 225],
}

# 160 MHz channel groups in 6 GHz
WIFI6E_160MHZ_GROUPS: Dict[int, List[int]] = {
    15:  [1, 5, 9, 13, 17, 21, 25, 29],
    47:  [33, 37, 41, 45, 49, 53, 57, 61],
    79:  [65, 69, 73, 77, 81, 85, 89, 93],
    135: [121, 125, 129, 133, 137, 141, 145, 149],
    167: [153, 157, 161, 165, 169, 173, 177, 181],
    211: [197, 201, 205, 209, 213, 217, 221, 225],
}


def get_6ghz_channel_count() -> int:
    """Return total number of 6 GHz channels."""
    return len(WIFI6E_CHANNELS)


def get_psc_channels() -> List[int]:
    """Return list of Preferred Scanning Channels (PSC) in 6 GHz."""
    return list(WIFI6E_PSC_CHANNELS)


def get_channels_by_unii(unii_band: str) -> List[int]:
    """Get 6 GHz channels belonging to a specific UNII band.

    Args:
        unii_band: UNII band name ("UNII-5", "UNII-6", "UNII-7", "UNII-8").

    Returns:
        Sorted list of channel numbers in the specified UNII band.
    """
    return sorted(
        ch for ch, info in WIFI6E_CHANNELS.items()
        if info.get("unii") == unii_band
    )


def channel_6ghz_to_frequency(channel: int) -> Optional[int]:
    """Convert a 6 GHz channel number to its center frequency.

    Args:
        channel: 6 GHz channel number.

    Returns:
        Center frequency in MHz, or None if not valid.
    """
    info = WIFI6E_CHANNELS.get(channel)
    return info["frequency"] if info else None


def frequency_6ghz_to_channel(frequency: int) -> Optional[int]:
    """Convert a 6 GHz center frequency to its channel number.

    Args:
        frequency: Center frequency in MHz.

    Returns:
        Channel number, or None if not found.
    """
    for ch, info in WIFI6E_CHANNELS.items():
        if info["frequency"] == frequency:
            return ch
    return None


def get_bw_channels(bandwidth: int) -> Dict[int, List[int]]:
    """Get channel groups for a specific bandwidth.

    Args:
        bandwidth: Bandwidth in MHz (40, 80, or 160).

    Returns:
        Dict of center_channel -> list of 20 MHz channels.
    """
    if bandwidth == 40:
        return dict(WIFI6E_40MHZ_GROUPS)
    if bandwidth == 80:
        return dict(WIFI6E_80MHZ_GROUPS)
    if bandwidth == 160:
        return dict(WIFI6E_160MHZ_GROUPS)
    return {}
