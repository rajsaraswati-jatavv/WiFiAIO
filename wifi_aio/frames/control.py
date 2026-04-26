"""IEEE 802.11 Control frame types.

Provides classes for constructing and parsing control frames including
RTS (Request to Send), CTS (Clear to Send), ACK (Acknowledgment),
and BlockAck (Block Acknowledgment).
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Union

from wifi_aio.frames.base_frame import (
    BROADCAST_MAC,
    NULL_MAC,
    FRAME_TYPE_CONTROL,
    SUBTYPE_RTS,
    SUBTYPE_CTS,
    SUBTYPE_ACK,
    SUBTYPE_BLOCK_ACK,
    FrameControl,
    WiFiFrame,
    mac_to_bytes,
    bytes_to_mac,
)
from wifi_aio.exceptions import WiFiConnectionError


class ControlFrame(WiFiFrame):
    """Base class for all 802.11 control frames.

    Control frames assist in the delivery of data frames by managing
    access to the wireless medium and providing acknowledgment services.
    """

    def __init__(
        self,
        subtype: int = 0,
        duration: int = 0,
        address1: str = NULL_MAC,
        address2: str = NULL_MAC,
        payload: bytes = b"",
    ):
        fc = FrameControl(
            frame_type=FRAME_TYPE_CONTROL,
            subtype=subtype,
        )
        super().__init__(
            frame_control=fc,
            duration=duration,
            address1=address1,
            address2=address2,
            address3=NULL_MAC,
            sequence_control=0,
            payload=payload,
        )
        self.subtype = subtype


class RTSFrame(ControlFrame):
    """IEEE 802.11 RTS (Request to Send) frame.

    RTS frames are used in the RTS/CTS mechanism to reserve the
    wireless medium before transmitting a data frame.
    """

    def __init__(
        self,
        transmitter: str = NULL_MAC,
        receiver: str = NULL_MAC,
        duration: int = 0,
    ):
        super().__init__(
            subtype=SUBTYPE_RTS,
            duration=duration,
            address1=receiver,
            address2=transmitter,
        )
        self.transmitter = transmitter
        self.receiver = receiver

    @property
    def receiver_address(self) -> str:
        """The Receiver Address (RA) - the intended recipient."""
        return self.address1

    @property
    def transmitter_address(self) -> str:
        """The Transmitter Address (TA) - the station sending RTS."""
        return self.address2

    def header_bytes(self) -> bytes:
        """Serialize RTS frame to bytes (FC + Duration + RA + TA)."""
        result = bytearray()
        result.extend(self.frame_control.to_bytes())
        result.extend(struct.pack("<H", self.duration & 0xFFFF))
        result.extend(mac_to_bytes(self.address1))  # RA
        result.extend(mac_to_bytes(self.address2))  # TA
        return bytes(result)

    def to_bytes(self) -> bytes:
        """RTS frames have no payload."""
        return self.header_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "RTSFrame":
        """Parse an RTS frame from raw bytes.

        Args:
            data: Raw RTS frame bytes.

        Returns:
            An RTSFrame instance.
        """
        if len(data) < 16:
            raise WiFiConnectionError(
                f"RTS frame too short: {len(data)} bytes, minimum 16",
                details="RTS frame requires FC(2) + Duration(2) + RA(6) + TA(6).",
            )
        fc = FrameControl.from_bytes(data[0:2])
        duration = struct.unpack("<H", data[2:4])[0]
        receiver = bytes_to_mac(data[4:10])
        transmitter = bytes_to_mac(data[10:16])
        return cls(
            transmitter=transmitter,
            receiver=receiver,
            duration=duration,
        )


class CTSFrame(ControlFrame):
    """IEEE 802.11 CTS (Clear to Send) frame.

    CTS frames are sent in response to RTS frames to confirm that
    the medium is available for transmission.
    """

    def __init__(
        self,
        receiver: str = NULL_MAC,
        duration: int = 0,
    ):
        super().__init__(
            subtype=SUBTYPE_CTS,
            duration=duration,
            address1=receiver,
            address2=NULL_MAC,
        )
        self.receiver = receiver

    @property
    def receiver_address(self) -> str:
        """The Receiver Address (RA) of the CTS."""
        return self.address1

    def header_bytes(self) -> bytes:
        """Serialize CTS frame to bytes (FC + Duration + RA)."""
        result = bytearray()
        result.extend(self.frame_control.to_bytes())
        result.extend(struct.pack("<H", self.duration & 0xFFFF))
        result.extend(mac_to_bytes(self.address1))  # RA
        return bytes(result)

    def to_bytes(self) -> bytes:
        """CTS frames have no payload and no TA."""
        return self.header_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "CTSFrame":
        """Parse a CTS frame from raw bytes."""
        if len(data) < 10:
            raise WiFiConnectionError(
                f"CTS frame too short: {len(data)} bytes, minimum 10",
                details="CTS frame requires FC(2) + Duration(2) + RA(6).",
            )
        fc = FrameControl.from_bytes(data[0:2])
        duration = struct.unpack("<H", data[2:4])[0]
        receiver = bytes_to_mac(data[4:10])
        return cls(
            receiver=receiver,
            duration=duration,
        )


class ACKFrame(ControlFrame):
    """IEEE 802.11 ACK (Acknowledgment) frame.

    ACK frames are sent to acknowledge successful reception of
    a data or management frame.
    """

    def __init__(
        self,
        receiver: str = NULL_MAC,
        duration: int = 0,
    ):
        super().__init__(
            subtype=SUBTYPE_ACK,
            duration=duration,
            address1=receiver,
            address2=NULL_MAC,
        )
        self.receiver = receiver

    @property
    def receiver_address(self) -> str:
        """The Receiver Address (RA) - the station being acknowledged."""
        return self.address1

    def header_bytes(self) -> bytes:
        """Serialize ACK frame to bytes (FC + Duration + RA)."""
        result = bytearray()
        result.extend(self.frame_control.to_bytes())
        result.extend(struct.pack("<H", self.duration & 0xFFFF))
        result.extend(mac_to_bytes(self.address1))  # RA
        return bytes(result)

    def to_bytes(self) -> bytes:
        """ACK frames have no payload and no TA."""
        return self.header_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "ACKFrame":
        """Parse an ACK frame from raw bytes."""
        if len(data) < 10:
            raise WiFiConnectionError(
                f"ACK frame too short: {len(data)} bytes, minimum 10",
                details="ACK frame requires FC(2) + Duration(2) + RA(6).",
            )
        fc = FrameControl.from_bytes(data[0:2])
        duration = struct.unpack("<H", data[2:4])[0]
        receiver = bytes_to_mac(data[4:10])
        return cls(
            receiver=receiver,
            duration=duration,
        )


class BlockAckFrame(ControlFrame):
    """IEEE 802.11 Block Acknowledgment frame.

    BlockAck frames are used in 802.11e/QoS to acknowledge multiple
    MSDUs in a single frame, improving efficiency.
    """

    # Block Ack types
    BA_TYPE_BASIC = 0
    BA_TYPE_COMPRESSED = 1
    BA_TYPE_MULTI_TID = 2

    # BAR Control field bitmasks
    BAR_POLICY_IMMEDIATE = 0x0001
    BAR_POLICY_DELAYED = 0x0000
    BAR_TYPE_MASK = 0x0006
    BAR_TYPE_SHIFT = 1

    def __init__(
        self,
        transmitter: str = NULL_MAC,
        receiver: str = NULL_MAC,
        duration: int = 0,
        bar_control: int = 0,
        starting_sequence: int = 0,
        block_ack_bitmap: bytes = b"",
        ack_type: int = BA_TYPE_COMPRESSED,
    ):
        self.bar_control = bar_control
        self.starting_sequence = starting_sequence
        self.block_ack_bitmap = block_ack_bitmap
        self.ack_type = ack_type
        self.transmitter = transmitter
        self.receiver = receiver

        payload = self._build_payload()
        super().__init__(
            subtype=SUBTYPE_BLOCK_ACK,
            duration=duration,
            address1=receiver,
            address2=transmitter,
            payload=payload,
        )

    def _build_payload(self) -> bytes:
        """Build the BlockAck frame body."""
        body = bytearray()
        # BAR Control (2 bytes)
        bar_control = (self.bar_control & 0xFFF0) | (self.ack_type << self.BAR_TYPE_SHIFT)
        body.extend(struct.pack("<H", bar_control))
        # Starting Sequence Control (2 bytes)
        ssc = (self.starting_sequence & 0x0FFF) << 4
        body.extend(struct.pack("<H", ssc))
        # Block Ack Bitmap
        if self.ack_type == self.BA_TYPE_BASIC:
            if not self.block_ack_bitmap:
                self.block_ack_bitmap = bytes(128)
            body.extend(self.block_ack_bitmap[:128])
        elif self.ack_type == self.BA_TYPE_COMPRESSED:
            if not self.block_ack_bitmap:
                self.block_ack_bitmap = bytes(8)
            body.extend(self.block_ack_bitmap[:8])
        elif self.ack_type == self.BA_TYPE_MULTI_TID:
            if not self.block_ack_bitmap:
                self.block_ack_bitmap = bytes(8)
            body.extend(self.block_ack_bitmap)
        return bytes(body)

    @property
    def is_immediate(self) -> bool:
        """Check if this is an immediate Block Ack policy."""
        return bool(self.bar_control & self.BAR_POLICY_IMMEDIATE)

    @property
    def is_delayed(self) -> bool:
        """Check if this is a delayed Block Ack policy."""
        return not self.is_immediate

    def get_acknowledged_sequences(self) -> List[int]:
        """Return a list of sequence numbers that are acknowledged.

        Parses the Block Ack bitmap to determine which MSDUs
        were successfully received.
        """
        acked = []
        if self.ack_type == self.BA_TYPE_COMPRESSED:
            bitmap_data = self.block_ack_bitmap[:8] if self.block_ack_bitmap else bytes(8)
            for byte_idx, byte_val in enumerate(bitmap_data):
                for bit_idx in range(8):
                    if byte_val & (1 << bit_idx):
                        seq = self.starting_sequence + byte_idx * 8 + bit_idx
                        acked.append(seq % 4096)
        elif self.ack_type == self.BA_TYPE_BASIC:
            bitmap_data = self.block_ack_bitmap[:128] if self.block_ack_bitmap else bytes(128)
            for byte_idx in range(0, len(bitmap_data), 2):
                word = struct.unpack("<H", bitmap_data[byte_idx:byte_idx+2])[0] if byte_idx + 2 <= len(bitmap_data) else 0
                if word & 0x0001:
                    seq = self.starting_sequence + byte_idx // 2
                    acked.append(seq % 4096)
        return acked

    @classmethod
    def from_bytes(cls, data: bytes) -> "BlockAckFrame":
        """Parse a BlockAck frame from raw bytes."""
        if len(data) < 16:
            raise WiFiConnectionError(
                f"BlockAck frame too short: {len(data)} bytes, minimum 16"
            )
        fc = FrameControl.from_bytes(data[0:2])
        duration = struct.unpack("<H", data[2:4])[0]
        receiver = bytes_to_mac(data[4:10])
        transmitter = bytes_to_mac(data[10:16])

        body = data[16:]
        if len(body) < 4:
            raise WiFiConnectionError("BlockAck body too short")

        bar_control = struct.unpack("<H", body[0:2])[0]
        ssc = struct.unpack("<H", body[2:4])[0]
        starting_sequence = (ssc >> 4) & 0x0FFF
        ack_type = (bar_control >> cls.BAR_TYPE_SHIFT) & 0x03

        block_ack_bitmap = b""
        if ack_type == cls.BA_TYPE_BASIC:
            if len(body) >= 4 + 128:
                block_ack_bitmap = body[4:4 + 128]
        elif ack_type == cls.BA_TYPE_COMPRESSED:
            if len(body) >= 4 + 8:
                block_ack_bitmap = body[4:4 + 8]

        return cls(
            transmitter=transmitter,
            receiver=receiver,
            duration=duration,
            bar_control=bar_control,
            starting_sequence=starting_sequence,
            block_ack_bitmap=block_ack_bitmap,
            ack_type=ack_type,
        )
