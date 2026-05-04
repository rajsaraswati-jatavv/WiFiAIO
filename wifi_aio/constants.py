"""WiFiAIO constants and enumerations.

Central place for every magic value, enumeration and lookup table used
throughout the package.
"""

from enum import Enum, IntEnum
from typing import Dict, List

# ── Package metadata ─────────────────────────────────────────────────

VERSION = "3.0.0"
AUTHOR = "T3RMUXK1NG"


# ── Enumerations ─────────────────────────────────────────────────────

class WiFiStandards(str, Enum):
    """IEEE 802.11 standard amendments."""
    A = "802.11a"
    B = "802.11b"
    G = "802.11g"
    N = "802.11n"
    AC = "802.11ac"
    AX = "802.11ax"
    BE = "802.11be"


class SecurityType(str, Enum):
    """WiFi security protocol types."""
    OPEN = "OPEN"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA2_PSK = "WPA2-PSK"
    WPA2_ENTERPRISE = "WPA2-EAP"
    WPA3 = "WPA3"
    WPA3_SAE = "WPA3-SAE"
    WPA3_ENTERPRISE = "WPA3-EAP"
    WPA_WPA2_MIXED = "WPA/WPA2-MIXED"
    OWE = "OWE"


class FrameType(IntEnum):
    """IEEE 802.11 frame type/subtype constants."""
    MANAGEMENT = 0x00
    CONTROL = 0x01
    DATA = 0x02
    EXTENSION = 0x03

    # Management subtypes
    ASSOCIATION_REQUEST = 0x0000
    ASSOCIATION_RESPONSE = 0x0001
    REASSOCIATION_REQUEST = 0x0002
    REASSOCIATION_RESPONSE = 0x0003
    PROBE_REQUEST = 0x0004
    PROBE_RESPONSE = 0x0005
    BEACON = 0x0008
    ATIM = 0x0009
    DISASSOCIATION = 0x000A
    AUTHENTICATION = 0x000B
    DEAUTHENTICATION = 0x000C
    ACTION = 0x000D

    # Control subtypes
    RTS = 0x0101
    CTS = 0x0102
    ACK = 0x0103
    BLOCK_ACK = 0x0109

    # Data subtypes
    DATA_FRAME = 0x0200
    DATA_QOS = 0x0208
    NULL_FRAME = 0x0204
    QOS_NULL = 0x020C


class SeverityLevel(str, Enum):
    """Vulnerability / finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    NONE = "NONE"


# ── Channel tables ───────────────────────────────────────────────────

CHANNELS_2GHZ: Dict[int, int] = {
    1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432,
    6: 2437, 7: 2442, 8: 2447, 9: 2452, 10: 2457,
    11: 2462, 12: 2467, 13: 2472, 14: 2484,
}

CHANNELS_5GHZ: Dict[int, int] = {
    # UNII-1
    36: 5180, 40: 5200, 44: 5220, 48: 5240,
    # UNII-2
    52: 5260, 56: 5280, 60: 5300, 64: 5320,
    # UNII-2 Extended
    100: 5500, 104: 5520, 108: 5540, 112: 5560,
    116: 5580, 120: 5600, 124: 5620, 128: 5640,
    132: 5660, 136: 5680, 140: 5700, 144: 5720,
    # UNII-3
    149: 5745, 153: 5765, 157: 5785, 161: 5805,
    165: 5825,
    # 6 GHz (Wi-Fi 6E – included for completeness)
    169: 5845, 173: 5865, 177: 5885,
}


# ── Default configuration ────────────────────────────────────────────

DEFAULT_CONFIG: dict = {
    "version": VERSION,
    "interface": "wlan0",
    "scan_timeout": 30,
    "capture_timeout": 300,
    "deauth_count": 5,
    "deauth_interval": 1.0,
    "channel_hop_delay": 0.5,
    "wordlist": "/usr/share/wordlists/rockyou.txt",
    "output_dir": "/tmp/wifiaio",
    "log_level": "INFO",
    "log_file": "/tmp/wifiaio/wifiaio.log",
    "max_log_size_mb": 10,
    "log_backup_count": 5,
    "database_path": "/tmp/wifiaio/wifiaio.db",
    "auto_check_updates": True,
    "theme": "dark",
    "language": "en",
    "notifications": True,
    "plugin_dirs": [],
    "save_scan_results": True,
    "pmf_enforced": False,
    "capture_format": "pcapng",
    "cracking_engine": "auto",
    "max_threads": 4,
    "temp_dir": "/tmp/wifiaio/tmp",
}


# ── Well-known ports & defaults ──────────────────────────────────────

WPA_HANDSHAKE_PORT = 0  # not a TCP port – kept for API compat
BEACON_INTERVAL_DEFAULT = 100  # TU (Time Units ≈ 1024 µs)
DEFAULT_RATES: List[str] = ["1", "2", "5.5", "11", "6", "9", "12", "18", "24", "36", "48", "54"]
HT_CAPABILITIES_DEFAULT = 0x01FC
VHT_CAPABILITIES_DEFAULT = 0x03807120

DEFAULT_HOSTAPD_CONF = {
    "driver": "nl80211",
    "hw_mode": "g",
    "channel": "6",
    "ieee80211n": "1",
    "wmm_enabled": "1",
    "beacon_int": str(BEACON_INTERVAL_DEFAULT),
}

DEFAULT_DNSMASQ_CONF = {
    "interface": "wlan0",
    "dhcp_range": "10.0.0.10,10.0.0.50,12h",
    "listen_address": "10.0.0.1",
}

# GitHub update URL
GITHUB_API_URL = "https://api.github.com/repos/t3rmuxk1ng/WiFiAIO/releases/latest"
