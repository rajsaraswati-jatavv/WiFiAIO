"""Base WiFi frame class for IEEE 802.11 frame construction and parsing.

Provides the foundational WiFiFrame class that all specific frame types
inherit from. Handles raw byte construction, field extraction, and
common 802.11 header parsing.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple, Union

from wifi_aio.exceptions import WiFiConnectionError, WiFiPermissionError, WiFiTimeoutError


# IEEE 802.11 Frame Type/Subtype constants
FRAME_TYPE_MANAGEMENT = 0x00
FRAME_TYPE_CONTROL = 0x01
FRAME_TYPE_DATA = 0x02
FRAME_TYPE_EXTENSION = 0x03

# Management subtypes
SUBTYPE_ASSOC_REQ = 0x00
SUBTYPE_ASSOC_RESP = 0x01
SUBTYPE_REASSOC_REQ = 0x02
SUBTYPE_REASSOC_RESP = 0x03
SUBTYPE_PROBE_REQ = 0x04
SUBTYPE_PROBE_RESP = 0x05
SUBTYPE_BEACON = 0x08
SUBTYPE_ATIM = 0x09
SUBTYPE_DISASSOC = 0x0A
SUBTYPE_AUTH = 0x0B
SUBTYPE_DEAUTH = 0x0C
SUBTYPE_ACTION = 0x0D

# Control subtypes
SUBTYPE_BLOCK_ACK_REQ = 0x08
SUBTYPE_BLOCK_ACK = 0x09
SUBTYPE_PSPOLL = 0x0A
SUBTYPE_RTS = 0x0B
SUBTYPE_CTS = 0x0C
SUBTYPE_ACK = 0x0D
SUBTYPE_CF_END = 0x0E
SUBTYPE_CF_END_ACK = 0x0F

# Data subtypes
SUBTYPE_DATA = 0x00
SUBTYPE_DATA_CF_ACK = 0x01
SUBTYPE_DATA_CF_POLL = 0x02
SUBTYPE_DATA_CF_ACK_POLL = 0x03
SUBTYPE_NULL = 0x04
SUBTYPE_CF_ACK_NULL = 0x05
SUBTYPE_CF_POLL_NULL = 0x06
SUBTYPE_CF_ACK_POLL_NULL = 0x07
SUBTYPE_QOS_DATA = 0x08
SUBTYPE_QOS_DATA_CF_ACK = 0x09
SUBTYPE_QOS_DATA_CF_POLL = 0x0A
SUBTYPE_QOS_DATA_CF_ACK_POLL = 0x0B
SUBTYPE_QOS_NULL = 0x0C
SUBTYPE_QOS_CF_POLL_NULL = 0x0E
SUBTYPE_QOS_CF_ACK_POLL_NULL = 0x0F

# ToDS / FromDS bit positions
TO_DS_BIT = 0x01
FROM_DS_BIT = 0x02

# MAC address constants
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
NULL_MAC = "00:00:00:00:00:00"


def mac_to_bytes(mac: str) -> bytes:
    """Convert a MAC address string to 6 bytes.

    Args:
        mac: MAC address in XX:XX:XX:XX:XX:XX format.

    Returns:
        6-byte representation of the MAC address.

    Raises:
        ValueError: If the MAC address format is invalid.
    """
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC address format: {mac}")
    result = bytearray(6)
    for i, part in enumerate(parts):
        result[i] = int(part, 16)
    return bytes(result)


def bytes_to_mac(data: bytes) -> str:
    """Convert 6 bytes to a MAC address string.

    Args:
        data: 6 bytes representing a MAC address.

    Returns:
        MAC address in XX:XX:XX:XX:XX:XX format.

    Raises:
        ValueError: If data is not exactly 6 bytes.
    """
    if len(data) != 6:
        raise ValueError(f"Expected 6 bytes for MAC, got {len(data)}")
    return ":".join(f"{b:02x}" for b in data)


class FrameControl:
    """Represents the IEEE 802.11 Frame Control field (2 bytes).

    The Frame Control field defines the frame type, subtype, and various
    protocol flags.
    """

    def __init__(
        self,
        frame_type: int = 0,
        subtype: int = 0,
        to_ds: bool = False,
        from_ds: bool = False,
        more_fragments: bool = False,
        retry: bool = False,
        power_management: bool = False,
        more_data: bool = False,
        protected_frame: bool = False,
        order: bool = False,
        protocol_version: int = 0,
    ):
        self.protocol_version = protocol_version
        self.frame_type = frame_type
        self.subtype = subtype
        self.to_ds = to_ds
        self.from_ds = from_ds
        self.more_fragments = more_fragments
        self.retry = retry
        self.power_management = power_management
        self.more_data = more_data
        self.protected_frame = protected_frame
        self.order = order

    def to_bytes(self) -> bytes:
        """Serialize the Frame Control field to 2 bytes."""
        first_byte = (
            (self.protocol_version & 0x03)
            | ((self.frame_type & 0x03) << 2)
            | ((self.subtype & 0x0F) << 4)
        )
        second_byte = (
            (int(self.to_ds) & 0x01)
            | ((int(self.from_ds) & 0x01) << 1)
            | ((int(self.more_fragments) & 0x01) << 2)
            | ((int(self.retry) & 0x01) << 3)
            | ((int(self.power_management) & 0x01) << 4)
            | ((int(self.more_data) & 0x01) << 5)
            | ((int(self.protected_frame) & 0x01) << 6)
            | ((int(self.order) & 0x01) << 7)
        )
        return bytes([first_byte, second_byte])

    @classmethod
    def from_bytes(cls, data: bytes) -> "FrameControl":
        """Parse a Frame Control field from 2 bytes.

        Args:
            data: 2 bytes representing the Frame Control field.

        Returns:
            A FrameControl instance.

        Raises:
            ValueError: If data is not exactly 2 bytes.
        """
        if len(data) != 2:
            raise ValueError(f"Frame Control requires 2 bytes, got {len(data)}")
        first_byte = data[0]
        second_byte = data[1]
        return cls(
            protocol_version=first_byte & 0x03,
            frame_type=(first_byte >> 2) & 0x03,
            subtype=(first_byte >> 4) & 0x0F,
            to_ds=bool(second_byte & 0x01),
            from_ds=bool(second_byte & 0x02),
            more_fragments=bool(second_byte & 0x04),
            retry=bool(second_byte & 0x08),
            power_management=bool(second_byte & 0x10),
            more_data=bool(second_byte & 0x20),
            protected_frame=bool(second_byte & 0x40),
            order=bool(second_byte & 0x80),
        )

    @property
    def type_name(self) -> str:
        """Return a human-readable name for the frame type."""
        type_names = {
            FRAME_TYPE_MANAGEMENT: "Management",
            FRAME_TYPE_CONTROL: "Control",
            FRAME_TYPE_DATA: "Data",
            FRAME_TYPE_EXTENSION: "Extension",
        }
        return type_names.get(self.frame_type, f"Unknown({self.frame_type})")

    def __repr__(self) -> str:
        return (
            f"FrameControl(type={self.type_name}, subtype=0x{self.subtype:01x}, "
            f"to_ds={self.to_ds}, from_ds={self.from_ds})"
        )


class WiFiFrame:
    """Base class for all IEEE 802.11 frames.

    Provides raw byte construction, field parsing, and common
    header manipulation for all 802.11 frame types.
    """

    def __init__(
        self,
        frame_control: Optional[FrameControl] = None,
        duration: int = 0,
        address1: str = BROADCAST_MAC,
        address2: str = NULL_MAC,
        address3: str = NULL_MAC,
        address4: Optional[str] = None,
        sequence_control: int = 0,
        payload: bytes = b"",
    ):
        self.frame_control = frame_control or FrameControl()
        self.duration = duration
        self.address1 = address1
        self.address2 = address2
        self.address3 = address3
        self.address4 = address4
        self.sequence_control = sequence_control
        self.payload = payload

    @property
    def fragment_number(self) -> int:
        """Extract the fragment number from the sequence control field."""
        return self.sequence_control & 0x0F

    @property
    def sequence_number(self) -> int:
        """Extract the sequence number from the sequence control field."""
        return (self.sequence_control >> 4) & 0x0FFF

    def set_sequence(self, seq_num: int, frag_num: int = 0) -> None:
        """Set the sequence and fragment numbers.

        Args:
            seq_num: Sequence number (0-4095).
            frag_num: Fragment number (0-15).
        """
        if not (0 <= seq_num <= 4095):
            raise ValueError(f"Sequence number must be 0-4095, got {seq_num}")
        if not (0 <= frag_num <= 15):
            raise ValueError(f"Fragment number must be 0-15, got {frag_num}")
        self.sequence_control = ((seq_num & 0x0FFF) << 4) | (frag_num & 0x0F)

    def header_bytes(self) -> bytes:
        """Serialize the frame header to bytes.

        Returns the minimal header including Frame Control, Duration,
        addresses, and Sequence Control as appropriate for the frame type.
        """
        header = bytearray()
        header.extend(self.frame_control.to_bytes())
        header.extend(struct.pack("<H", self.duration & 0xFFFF))
        header.extend(mac_to_bytes(self.address1))
        header.extend(mac_to_bytes(self.address2))
        header.extend(mac_to_bytes(self.address3))
        header.extend(struct.pack("<H", self.sequence_control))
        if self.address4 is not None:
            header.extend(mac_to_bytes(self.address4))
        return bytes(header)

    def to_bytes(self) -> bytes:
        """Serialize the entire frame to bytes including payload."""
        return self.header_bytes() + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "WiFiFrame":
        """Parse a raw 802.11 frame from bytes.

        Args:
            data: Raw frame bytes (without FCS).

        Returns:
            A WiFiFrame instance with parsed fields.

        Raises:
            WiFiConnectionError: If the frame data is too short or malformed.
        """
        if len(data) < 10:
            raise WiFiConnectionError(
                f"Frame too short: {len(data)} bytes, minimum 10 required",
                details="A valid 802.11 frame must have at least Frame Control, "
                "Duration, and Address 1 fields.",
            )

        fc = FrameControl.from_bytes(data[0:2])
        duration = struct.unpack("<H", data[2:4])[0]
        address1 = bytes_to_mac(data[4:10])

        address2 = NULL_MAC
        address3 = NULL_MAC
        sequence_control = 0
        address4 = None
        payload_offset = 10

        if fc.frame_type != FRAME_TYPE_CONTROL:
            if len(data) >= 16:
                address2 = bytes_to_mac(data[10:16])
                payload_offset = 16
            if len(data) >= 22:
                address3 = bytes_to_mac(data[16:22])
                payload_offset = 22
            if len(data) >= 24:
                sequence_control = struct.unpack("<H", data[22:24])[0]
                payload_offset = 24

            if fc.frame_type == FRAME_TYPE_DATA and fc.to_ds and fc.from_ds:
                if len(data) >= 30:
                    address4 = bytes_to_mac(data[24:30])
                    payload_offset = 30

        payload = data[payload_offset:] if payload_offset < len(data) else b""

        return cls(
            frame_control=fc,
            duration=duration,
            address1=address1,
            address2=address2,
            address3=address3,
            address4=address4,
            sequence_control=sequence_control,
            payload=payload,
        )

    def get_field(self, offset: int, size: int) -> bytes:
        """Extract a field from the raw frame at a given offset.

        Args:
            offset: Byte offset within the frame.
            size: Number of bytes to extract.

        Returns:
            The extracted bytes.

        Raises:
            WiFiConnectionError: If the offset/size exceeds frame length.
        """
        raw = self.to_bytes()
        if offset + size > len(raw):
            raise WiFiConnectionError(
                f"Field extraction out of bounds: offset={offset}, size={size}, "
                f"frame_length={len(raw)}",
                details="The requested field extends beyond the frame boundary.",
            )
        return raw[offset : offset + size]

    def set_field(self, offset: int, value: bytes) -> None:
        """Set a field in the raw frame at a given offset.

        Args:
            offset: Byte offset within the frame.
            value: Bytes to write at the offset.

        Raises:
            WiFiConnectionError: If the offset+value exceeds frame length.
        """
        raw = bytearray(self.to_bytes())
        if offset + len(value) > len(raw):
            raise WiFiConnectionError(
                f"Field write out of bounds: offset={offset}, "
                f"value_length={len(value)}, frame_length={len(raw)}",
                details="The value to write extends beyond the frame boundary.",
            )
        raw[offset : offset + len(value)] = value
        new_frame = WiFiFrame.from_bytes(bytes(raw))
        self.frame_control = new_frame.frame_control
        self.duration = new_frame.duration
        self.address1 = new_frame.address1
        self.address2 = new_frame.address2
        self.address3 = new_frame.address3
        self.address4 = new_frame.address4
        self.sequence_control = new_frame.sequence_control
        self.payload = new_frame.payload

    def field_summary(self) -> Dict[str, Union[str, int, bool]]:
        """Return a dictionary summarizing all frame fields."""
        summary: Dict[str, Union[str, int, bool]] = {
            "frame_type": self.frame_control.type_name,
            "subtype": self.frame_control.subtype,
            "to_ds": self.frame_control.to_ds,
            "from_ds": self.frame_control.from_ds,
            "duration": self.duration,
            "address1": self.address1,
            "address2": self.address2,
            "address3": self.address3,
            "sequence_number": self.sequence_number,
            "fragment_number": self.fragment_number,
            "payload_length": len(self.payload),
        }
        if self.address4 is not None:
            summary["address4"] = self.address4
        return summary

    def __len__(self) -> int:
        return len(self.to_bytes())

    def __repr__(self) -> str:
        return (
            f"WiFiFrame(type={self.frame_control.type_name}, "
            f"subtype=0x{self.frame_control.subtype:01x}, "
            f"addr1={self.address1}, len={len(self.payload)})"
        )
