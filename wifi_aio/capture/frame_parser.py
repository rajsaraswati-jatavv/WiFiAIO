"""IEEE 802.11 frame parser.

Parses raw 802.11 frames (with or without radiotap headers) into
structured objects with typed fields for frame control, addresses,
sequence control, and frame body.
"""

import struct
from typing import Dict, List, Optional, Tuple, Union

from wifi_aio.constants import FrameType
from wifi_aio.exceptions import CaptureError


# ── Frame control bit masks ────────────────────────────────────────────

FC_PROTOCOL_VERSION_MASK = 0x0003
FC_TYPE_MASK = 0x000C
FC_SUBTYPE_MASK = 0x00F0
FC_TO_DS_MASK = 0x0100
FC_FROM_DS_MASK = 0x0200
FC_MORE_FRAG_MASK = 0x0400
FC_RETRY_MASK = 0x0800
FC_PM_MASK = 0x1000
FC_MORE_DATA_MASK = 0x2000
FC_PROTECTED_MASK = 0x4000
FC_ORDER_MASK = 0x8000

# Type values
TYPE_MGT = 0
TYPE_CTL = 1
TYPE_DATA = 2
TYPE_EXT = 3

TYPE_NAMES = {0: "Management", 1: "Control", 2: "Data", 3: "Extension"}

# Management subtype names
MGT_SUBTYPE_NAMES = {
    0: "Association Request",
    1: "Association Response",
    2: "Reassociation Request",
    3: "Reassociation Response",
    4: "Probe Request",
    5: "Probe Response",
    8: "Beacon",
    9: "ATIM",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
    13: "Action",
}

# Control subtype names
CTL_SUBTYPE_NAMES = {
    1: "RTS",
    2: "CTS",
    3: "ACK",
    4: "CF-End",
    5: "CF-End+CF-Ack",
    6: "Block Ack Request",
    7: "Block Ack",
    8: "PS-Poll",
    9: "RTS",
    10: "CTS",
    11: "ACK",
}

# Data subtype names
DATA_SUBTYPE_NAMES = {
    0: "Data",
    1: "Data+CF-Ack",
    2: "Data+CF-Poll",
    3: "Data+CF-Ack+CF-Poll",
    4: "Null",
    5: "CF-Ack (no data)",
    6: "CF-Poll (no data)",
    7: "CF-Ack+CF-Poll (no data)",
    8: "QoS Data",
    9: "QoS Data+CF-Ack",
    10: "QoS Data+CF-Poll",
    11: "QoS Data+CF-Ack+CF-Poll",
    12: "QoS Null",
    14: "QoS CF-Poll (no data)",
    15: "QoS CF-Ack+CF-Poll (no data)",
}

# Reason codes
REASON_CODES: Dict[int, str] = {
    0: "Reserved",
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Station is leaving (or has left) BSS",
    4: "Disassociated due to inactivity",
    5: "AP unable to handle all connected stations",
    6: "Class 2 frame received from nonauthenticated station",
    7: "Class 3 frame received from nonassociated station",
    8: "Station leaving (roaming)",
    9: "Reassociation request not accepted",
    10: "Cannot support all requested capabilities",
    11: "Reassociation denied – cannot confirm association",
    12: "Association denied – reason outside scope of standard",
    13: "Station does not support the requested authentication algorithm",
    14: "Authentication sequence number unexpected",
    15: "Authentication rejected – challenge failure",
    16: "Authentication rejected – timeout",
    17: "Association denied – AP cannot handle additional stations",
    18: "Association denied – station does not support all basic rates",
    30: "Association denied – power capability unacceptable",
    31: "Association denied – supported channels unacceptable",
    32: "Association denied – station not permitted in BSS",
}

# Tag IDs for tagged parameters
TAG_SSID = 0
TAG_SUPPORTED_RATES = 1
TAG_DS_PARAMETER = 3
TAG_TIM = 5
TAG_COUNTRY = 7
TAG_HT_CAPABILITIES = 45
TAG_RSN = 48
TAG_EXTENDED_RATES = 50
TAG_HT_OPERATION = 61
TAG_VHT_CAPABILITIES = 191
TAG_VHT_OPERATION = 192
TAG_VENDOR_SPECIFIC = 221


class ParsedFrame:
    """Structured representation of a parsed 802.11 frame."""

    def __init__(self) -> None:
        # Frame control
        self.version: int = 0
        self.type: int = 0
        self.subtype: int = 0
        self.to_ds: bool = False
        self.from_ds: bool = False
        self.more_fragments: bool = False
        self.retry: bool = False
        self.power_management: bool = False
        self.more_data: bool = False
        self.protected: bool = False
        self.order: bool = False

        # Addresses
        self.addr1: str = ""
        self.addr2: str = ""
        self.addr3: str = ""
        self.addr4: str = ""

        # Sequence control
        self.fragment_number: int = 0
        self.sequence_number: int = 0

        # Frame body
        self.body: bytes = b""

        # Tagged parameters (for beacon/probe response)
        self.tagged_params: Dict[int, bytes] = {}

        # Computed
        self.ssid: str = ""
        self.channel: int = 0
        self.rsn_info: Optional[Dict] = None
        self.reason_code: int = 0
        self.auth_algorithm: int = 0
        self.auth_transaction: int = 0
        self.auth_status: int = 0

        # Radiotap
        self.radiotap_present: bool = False
        self.radiotap_length: int = 0
        self.signal_dbm: int = 0
        self.noise_dbm: int = 0
        self.data_rate: float = 0.0
        self.frequency_mhz: int = 0

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type, f"Unknown({self.type})")

    @property
    def subtype_name(self) -> str:
        if self.type == TYPE_MGT:
            return MGT_SUBTYPE_NAMES.get(self.subtype, f"MGT-Unknown({self.subtype})")
        elif self.type == TYPE_CTL:
            return CTL_SUBTYPE_NAMES.get(self.subtype, f"CTL-Unknown({self.subtype})")
        elif self.type == TYPE_DATA:
            return DATA_SUBTYPE_NAMES.get(self.subtype, f"DATA-Unknown({self.subtype})")
        return f"Unknown({self.type}/{self.subtype})"

    @property
    def reason_text(self) -> str:
        return REASON_CODES.get(self.reason_code, f"Unknown({self.reason_code})")

    @property
    def bssid(self) -> str:
        """Return the BSSID for this frame."""
        if not self.to_ds and not self.from_ds:
            return self.addr3
        elif self.to_ds and not self.from_ds:
            return self.addr1
        elif self.from_ds and not self.to_ds:
            return self.addr2
        else:
            return self.addr3  # WDS

    @property
    def source(self) -> str:
        """Return the source address."""
        if not self.to_ds and not self.from_ds:
            return self.addr2
        elif self.to_ds and not self.from_ds:
            return self.addr2
        elif self.from_ds and not self.to_ds:
            return self.addr3
        else:
            return self.addr4

    @property
    def destination(self) -> str:
        """Return the destination address."""
        if not self.to_ds and not self.from_ds:
            return self.addr1
        elif self.to_ds and not self.from_ds:
            return self.addr3
        elif self.from_ds and not self.to_ds:
            return self.addr1
        else:
            return self.addr3

    @property
    def is_beacon(self) -> bool:
        return self.type == TYPE_MGT and self.subtype == 8

    @property
    def is_probe_request(self) -> bool:
        return self.type == TYPE_MGT and self.subtype == 4

    @property
    def is_probe_response(self) -> bool:
        return self.type == TYPE_MGT and self.subtype == 5

    @property
    def is_authentication(self) -> bool:
        return self.type == TYPE_MGT and self.subtype == 11

    @property
    def is_deauthentication(self) -> bool:
        return self.type == TYPE_MGT and self.subtype == 12

    @property
    def is_disassociation(self) -> bool:
        return self.type == TYPE_MGT and self.subtype == 10

    @property
    def is_data(self) -> bool:
        return self.type == TYPE_DATA

    @property
    def is_qos_data(self) -> bool:
        return self.type == TYPE_DATA and (self.subtype & 0x08) != 0

    def to_dict(self) -> Dict:
        """Convert to a plain dictionary."""
        return {
            "type": self.type,
            "type_name": self.type_name,
            "subtype": self.subtype,
            "subtype_name": self.subtype_name,
            "to_ds": self.to_ds,
            "from_ds": self.from_ds,
            "addr1": self.addr1,
            "addr2": self.addr2,
            "addr3": self.addr3,
            "addr4": self.addr4,
            "bssid": self.bssid,
            "source": self.source,
            "destination": self.destination,
            "sequence_number": self.sequence_number,
            "fragment_number": self.fragment_number,
            "ssid": self.ssid,
            "channel": self.channel,
            "protected": self.protected,
            "retry": self.retry,
            "signal_dbm": self.signal_dbm,
            "frequency_mhz": self.frequency_mhz,
            "reason_code": self.reason_code if self.is_deauthentication or self.is_disassociation else None,
        }

    def __repr__(self) -> str:
        return (
            f"ParsedFrame({self.type_name}/{self.subtype_name}, "
            f"bssid={self.bssid}, src={self.source}, dst={self.destination})"
        )


class FrameParser:
    """Parse raw 802.11 frames into structured ParsedFrame objects.

    Handles both raw 802.11 frames and frames with a radiotap header
    prepended.
    """

    def __init__(self, strip_radiotap: bool = True) -> None:
        self.strip_radiotap = strip_radiotap
        self._frame_count = 0
        self._error_count = 0

    # ── Public API ─────────────────────────────────────────────────────

    def parse(self, raw: bytes) -> Optional[ParsedFrame]:
        """Parse a raw frame into a :class:`ParsedFrame`.

        Returns ``None`` if the frame is too short or malformed.
        """
        self._frame_count += 1

        if len(raw) < 2:
            self._error_count += 1
            return None

        frame = raw
        parsed = ParsedFrame()

        # Strip radiotap header if present
        if self.strip_radiotap and raw[0] == 0:
            rt_len = struct.unpack("<H", raw[2:4])[0]
            if 4 <= rt_len < len(raw):
                self._parse_radiotap(raw[:rt_len], parsed)
                frame = raw[rt_len:]
                parsed.radiotap_present = True
                parsed.radiotap_length = rt_len

        if len(frame) < 2:
            self._error_count += 1
            return None

        # Parse frame control
        self._parse_frame_control(frame, parsed)

        # Parse address fields based on frame type
        if not self._parse_addresses(frame, parsed):
            self._error_count += 1
            return None

        # Parse type-specific body
        self._parse_body(frame, parsed)

        return parsed

    def parse_many(self, frames: List[bytes]) -> List[ParsedFrame]:
        """Parse multiple frames, skipping any that fail."""
        results = []
        for raw in frames:
            parsed = self.parse(raw)
            if parsed is not None:
                results.append(parsed)
        return results

    @property
    def frame_count(self) -> int:
        return self._frame_count

    @property
    def error_count(self) -> int:
        return self._error_count

    @property
    def error_rate(self) -> float:
        if self._frame_count == 0:
            return 0.0
        return self._error_count / self._frame_count

    # ── Frame control ──────────────────────────────────────────────────

    @staticmethod
    def _parse_frame_control(frame: bytes, parsed: ParsedFrame) -> None:
        """Parse the 2-byte frame control field."""
        fc = struct.unpack("<H", frame[0:2])[0]

        parsed.version = fc & FC_PROTOCOL_VERSION_MASK
        parsed.type = (fc & FC_TYPE_MASK) >> 2
        parsed.subtype = (fc & FC_SUBTYPE_MASK) >> 4
        parsed.to_ds = bool(fc & FC_TO_DS_MASK)
        parsed.from_ds = bool(fc & FC_FROM_DS_MASK)
        parsed.more_fragments = bool(fc & FC_MORE_FRAG_MASK)
        parsed.retry = bool(fc & FC_RETRY_MASK)
        parsed.power_management = bool(fc & FC_PM_MASK)
        parsed.more_data = bool(fc & FC_MORE_DATA_MASK)
        parsed.protected = bool(fc & FC_PROTECTED_MASK)
        parsed.order = bool(fc & FC_ORDER_MASK)

    # ── Address parsing ────────────────────────────────────────────────

    @staticmethod
    def _parse_addresses(frame: bytes, parsed: ParsedFrame) -> bool:
        """Parse MAC address fields based on frame type and To/From DS."""
        if parsed.type == TYPE_CTL:
            # Control frames have variable format
            if len(frame) >= 10:
                parsed.addr1 = _mac_from_bytes(frame[4:10])
            if len(frame) >= 16:
                parsed.addr2 = _mac_from_bytes(frame[10:16])
            return True

        if len(frame) < 24:
            return False

        parsed.addr1 = _mac_from_bytes(frame[4:10])
        parsed.addr2 = _mac_from_bytes(frame[10:16])
        parsed.addr3 = _mac_from_bytes(frame[16:22])

        # Sequence control
        sc = struct.unpack("<H", frame[22:24])[0]
        parsed.fragment_number = sc & 0x000F
        parsed.sequence_number = (sc >> 4) & 0x0FFF

        # Address 4 for WDS frames
        if parsed.to_ds and parsed.from_ds:
            if len(frame) >= 30:
                parsed.addr4 = _mac_from_bytes(frame[24:30])

        return True

    # ── Body parsing ───────────────────────────────────────────────────

    @staticmethod
    def _parse_body(frame: bytes, parsed: ParsedFrame) -> None:
        """Parse the frame body based on type and subtype."""
        if parsed.type == TYPE_MGT:
            FrameParser._parse_management_body(frame, parsed)
        elif parsed.type == TYPE_CTL:
            pass  # Control frames have no body to parse
        elif parsed.type == TYPE_DATA:
            FrameParser._parse_data_body(frame, parsed)

    @staticmethod
    def _parse_management_body(frame: bytes, parsed: ParsedFrame) -> None:
        """Parse the body of a management frame."""
        body_offset = 24  # After fixed fields

        if parsed.is_beacon or parsed.is_probe_response:
            if len(frame) < 36:
                return
            # Fixed fields: timestamp(8), beacon_interval(2), capability(2)
            body_offset = 36
            parsed.body = frame[body_offset:]
            FrameParser._parse_tagged_params(frame[body_offset:], parsed)

        elif parsed.is_probe_request:
            parsed.body = frame[24:]
            FrameParser._parse_tagged_params(frame[24:], parsed)

        elif parsed.is_authentication:
            if len(frame) >= 30:
                parsed.auth_algorithm = struct.unpack("!H", frame[24:26])[0]
                parsed.auth_transaction = struct.unpack("!H", frame[26:28])[0]
                parsed.auth_status = struct.unpack("!H", frame[28:30])[0]
                parsed.body = frame[30:]
            else:
                parsed.body = frame[24:]

        elif parsed.is_deauthentication or parsed.is_disassociation:
            if len(frame) >= 26:
                parsed.reason_code = struct.unpack("!H", frame[24:26])[0]
                parsed.body = frame[26:]
            else:
                parsed.body = frame[24:]

        elif parsed.subtype in (0, 2):  # Association/Reassociation Request
            if len(frame) >= 28:
                body_offset = 28 if parsed.subtype == 0 else 34
                if len(frame) >= body_offset:
                    parsed.body = frame[body_offset:]
                    FrameParser._parse_tagged_params(frame[body_offset:], parsed)
            else:
                parsed.body = frame[24:]

        elif parsed.subtype in (1, 3):  # Association/Reassociation Response
            if len(frame) >= 26:
                parsed.body = frame[26:]
            else:
                parsed.body = frame[24:]

        else:
            if len(frame) > 24:
                parsed.body = frame[24:]

    @staticmethod
    def _parse_data_body(frame: bytes, parsed: ParsedFrame) -> None:
        """Parse the body of a data frame."""
        offset = 24
        if parsed.to_ds and parsed.from_ds:
            offset = 30

        # QoS data has an extra 2-byte QoS control field
        if parsed.is_qos_data:
            offset += 2

        if len(frame) > offset:
            parsed.body = frame[offset:]

    @staticmethod
    def _parse_tagged_params(data: bytes, parsed: ParsedFrame) -> None:
        """Parse 802.11 tagged parameters (TLV format)."""
        offset = 0
        while offset + 2 <= len(data):
            tag_id = data[offset]
            tag_len = data[offset + 1]
            offset += 2

            if offset + tag_len > len(data):
                break

            tag_data = data[offset: offset + tag_len]
            parsed.tagged_params[tag_id] = tag_data

            # Decode specific tags
            if tag_id == TAG_SSID:
                try:
                    parsed.ssid = tag_data.decode("utf-8")
                except UnicodeDecodeError:
                    parsed.ssid = tag_data.hex()

            elif tag_id == TAG_DS_PARAMETER:
                if tag_len >= 1:
                    parsed.channel = tag_data[0]

            elif tag_id == TAG_RSN:
                parsed.rsn_info = FrameParser._parse_rsn(tag_data)

            offset += tag_len

    @staticmethod
    def _parse_rsn(data: bytes) -> Dict:
        """Parse the RSN (Robust Security Network) IE."""
        if len(data) < 2:
            return {}

        rsn: Dict = {}
        offset = 0

        # Version
        rsn["version"] = struct.unpack("!H", data[offset: offset + 2])[0]
        offset += 2

        # Group cipher suite
        if offset + 4 <= len(data):
            oui = data[offset: offset + 3]
            cipher_type = data[offset + 3]
            rsn["group_cipher"] = {
                "oui": oui.hex(),
                "type": cipher_type,
                "name": _cipher_name(cipher_type),
            }
            offset += 4

        # Pairwise cipher count
        if offset + 2 <= len(data):
            count = struct.unpack("!H", data[offset: offset + 2])[0]
            offset += 2
            ciphers = []
            for _ in range(count):
                if offset + 4 <= len(data):
                    oui = data[offset: offset + 3]
                    ct = data[offset + 3]
                    ciphers.append({
                        "oui": oui.hex(),
                        "type": ct,
                        "name": _cipher_name(ct),
                    })
                    offset += 4
            rsn["pairwise_ciphers"] = ciphers

        # AKM count
        if offset + 2 <= len(data):
            count = struct.unpack("!H", data[offset: offset + 2])[0]
            offset += 2
            akms = []
            for _ in range(count):
                if offset + 4 <= len(data):
                    oui = data[offset: offset + 3]
                    akm_type = data[offset + 3]
                    akms.append({
                        "oui": oui.hex(),
                        "type": akm_type,
                        "name": _akm_name(akm_type),
                    })
                    offset += 4
            rsn["akm_suites"] = akms

        # RSN capabilities
        if offset + 2 <= len(data):
            rsn["capabilities"] = struct.unpack("!H", data[offset: offset + 2])[0]
            offset += 2

        return rsn

    # ── Radiotap parsing ───────────────────────────────────────────────

    @staticmethod
    def _parse_radiotap(data: bytes, parsed: ParsedFrame) -> None:
        """Parse the radiotap header for signal and channel info."""
        if len(data) < 8:
            return

        presence_flags = struct.unpack("<I", data[4:8])[0]
        offset = 8

        # TSFT
        if presence_flags & 0x00000001:
            if offset + 8 <= len(data):
                offset += 8
            else:
                return

        # Flags
        if presence_flags & 0x00000002:
            if offset + 1 <= len(data):
                offset += 1
            else:
                return

        # Rate
        if presence_flags & 0x00000004:
            if offset + 1 <= len(data):
                parsed.data_rate = data[offset] * 0.5  # 500 kbps units
                offset += 1
            else:
                return

        # Channel
        if presence_flags & 0x00000008:
            if offset + 4 <= len(data):
                parsed.frequency_mhz = struct.unpack("<H", data[offset: offset + 2])[0]
                offset += 4
            else:
                return

        # FHSS
        if presence_flags & 0x00000010:
            if offset + 2 <= len(data):
                offset += 2
            else:
                return

        # dBm signal
        if presence_flags & 0x00000020:
            if offset + 1 <= len(data):
                parsed.signal_dbm = struct.unpack("b", data[offset: offset + 1])[0]
                offset += 1
            else:
                return

        # dBm noise
        if presence_flags & 0x00000040:
            if offset + 1 <= len(data):
                parsed.noise_dbm = struct.unpack("b", data[offset: offset + 1])[0]
                offset += 1
            else:
                return


# ── Helper functions ────────────────────────────────────────────────────

def _mac_from_bytes(b: bytes) -> str:
    """Convert 6 bytes to a MAC address string."""
    return ":".join(f"{byte:02x}" for byte in b)


def _cipher_name(cipher_type: int) -> str:
    """Return a human-readable cipher suite name."""
    names = {
        0: "Use group cipher",
        1: "WEP-40",
        2: "TKIP",
        3: "RESERVED",
        4: "CCMP",
        5: "WEP-104",
        6: "BIP-CMAC-128",
        7: "GCMP",
        8: "GCMP-256",
        9: "CCMP-256",
        10: "BIP-GMAC-128",
        11: "BIP-GMAC-256",
        12: "BIP-CMAC-256",
    }
    return names.get(cipher_type, f"Unknown({cipher_type})")


def _akm_name(akm_type: int) -> str:
    """Return a human-readable AKM suite name."""
    names = {
        0: "Reserved",
        1: "802.1X",
        2: "PSK",
        3: "FT-802.1X",
        4: "FT-PSK",
        5: "WPA-SHA256",
        6: "PSK-SHA256",
        7: "TDLS",
        8: "SAE",
        9: "FT-SAE",
        11: "AP-PEER-KEY",
        12: "WPA-SHA256-SUITE-B",
        13: "WPA-SHA384-SUITE-B",
        14: "FT-802.1X-SHA384",
        15: "FILS-SHA256",
        16: "FILS-SHA384",
        17: "FT-FILS-SHA256",
        18: "FT-FILS-SHA384",
        19: "OWE",
    }
    return names.get(akm_type, f"Unknown({akm_type})")
