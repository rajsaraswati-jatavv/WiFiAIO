"""IEEE 802.11 Data frame types.

Provides classes for constructing and parsing data frames including
regular Data frames, QoS Data frames, and Null function frames.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Union

from wifi_aio.frames.base_frame import (
    BROADCAST_MAC,
    NULL_MAC,
    FRAME_TYPE_DATA,
    SUBTYPE_DATA,
    SUBTYPE_QOS_DATA,
    SUBTYPE_NULL,
    SUBTYPE_QOS_NULL,
    FrameControl,
    WiFiFrame,
    mac_to_bytes,
    bytes_to_mac,
)
from wifi_aio.exceptions import WiFiConnectionError


class DataFrame(WiFiFrame):
    """IEEE 802.11 Data frame.

    Data frames carry higher-level protocol data between stations.
    The addressing mode depends on the ToDS and FromDS bits.
    """

    def __init__(
        self,
        destination: str = NULL_MAC,
        source: str = NULL_MAC,
        bssid: str = NULL_MAC,
        to_ds: bool = False,
        from_ds: bool = False,
        duration: int = 0,
        sequence_control: int = 0,
        address4: Optional[str] = None,
        payload: bytes = b"",
    ):
        fc = FrameControl(
            frame_type=FRAME_TYPE_DATA,
            subtype=SUBTYPE_DATA,
            to_ds=to_ds,
            from_ds=from_ds,
        )
        # Address mapping depends on ToDS/FromDS
        addr1, addr2, addr3 = self._map_addresses(
            destination, source, bssid, to_ds, from_ds
        )
        super().__init__(
            frame_control=fc,
            duration=duration,
            address1=addr1,
            address2=addr2,
            address3=addr3,
            address4=address4,
            sequence_control=sequence_control,
            payload=payload,
        )
        self.destination = destination
        self.source = source
        self.bssid = bssid

    @staticmethod
    def _map_addresses(
        dest: str, src: str, bssid: str, to_ds: bool, from_ds: bool
    ) -> tuple:
        """Map logical addresses to 802.11 header address fields.

        The mapping depends on the ToDS and FromDS bits:
          - ToDS=0, FromDS=0: IBSS (Addr1=DA, Addr2=SA, Addr3=BSSID)
          - ToDS=0, FromDS=1: From AP (Addr1=DA, Addr2=BSSID, Addr3=SA)
          - ToDS=1, FromDS=0: To AP (Addr1=BSSID, Addr2=SA, Addr3=DA)
          - ToDS=1, FromDS=1: WDS (Addr1=RA, Addr2=TA, Addr3=DA, Addr4=SA)
        """
        if not to_ds and not from_ds:
            return dest, src, bssid
        elif not to_ds and from_ds:
            return dest, bssid, src
        elif to_ds and not from_ds:
            return bssid, src, dest
        else:
            return dest, src, bssid

    def extract_logical_addresses(self) -> Dict[str, str]:
        """Extract logical DA, SA, and BSSID from the frame header.

        Returns:
            Dictionary with 'destination', 'source', and 'bssid' keys.
        """
        to_ds = self.frame_control.to_ds
        from_ds = self.frame_control.from_ds
        if not to_ds and not from_ds:
            return {
                "destination": self.address1,
                "source": self.address2,
                "bssid": self.address3,
            }
        elif not to_ds and from_ds:
            return {
                "destination": self.address1,
                "source": self.address3,
                "bssid": self.address2,
            }
        elif to_ds and not from_ds:
            return {
                "destination": self.address3,
                "source": self.address2,
                "bssid": self.address1,
            }
        else:
            return {
                "destination": self.address3,
                "source": self.address4 or NULL_MAC,
                "bssid": self.address1,
            }

    @classmethod
    def from_bytes(cls, data: bytes) -> "DataFrame":
        """Parse a Data frame from raw bytes."""
        if len(data) < 24:
            raise WiFiConnectionError(
                f"Data frame too short: {len(data)} bytes, minimum 24"
            )
        base = WiFiFrame.from_bytes(data)
        logical = DataFrame(
            to_ds=base.frame_control.to_ds,
            from_ds=base.frame_control.from_ds,
            duration=base.duration,
            sequence_control=base.sequence_control,
            payload=base.payload,
        )
        logical.frame_control = base.frame_control
        logical.address1 = base.address1
        logical.address2 = base.address2
        logical.address3 = base.address3
        logical.address4 = base.address4
        addrs = logical.extract_logical_addresses()
        logical.destination = addrs["destination"]
        logical.source = addrs["source"]
        logical.bssid = addrs["bssid"]
        return logical


class QoSDataFrame(DataFrame):
    """IEEE 802.11 QoS Data frame.

    QoS Data frames include a 2-byte QoS Control field after the
    sequence control field, providing traffic classification and
    prioritization per 802.11e.
    """

    # Access Category indices
    AC_BK = 0  # Background
    AC_BE = 1  # Best Effort
    AC_VI = 2  # Video
    AC_VO = 3  # Voice

    AC_NAMES = {
        0: "Background (AC_BK)",
        1: "Best Effort (AC_BE)",
        2: "Video (AC_VI)",
        3: "Voice (AC_VO)",
    }

    # TID to AC mapping
    TID_TO_AC = {
        0: 1, 1: 1, 2: 0, 3: 0,  # BE, BE, BK, BK
        4: 2, 5: 2, 6: 3, 7: 3,  # VI, VI, VO, VO
    }

    def __init__(
        self,
        destination: str = NULL_MAC,
        source: str = NULL_MAC,
        bssid: str = NULL_MAC,
        to_ds: bool = False,
        from_ds: bool = False,
        duration: int = 0,
        sequence_control: int = 0,
        address4: Optional[str] = None,
        qos_control: int = 0,
        payload: bytes = b"",
    ):
        self.qos_control = qos_control
        fc = FrameControl(
            frame_type=FRAME_TYPE_DATA,
            subtype=SUBTYPE_QOS_DATA,
            to_ds=to_ds,
            from_ds=from_ds,
        )
        addr1, addr2, addr3 = DataFrame._map_addresses(
            destination, source, bssid, to_ds, from_ds
        )
        # Build payload with QoS Control prepended
        full_payload = struct.pack("<H", qos_control) + payload
        super(DataFrame, self).__init__(
            frame_control=fc,
            duration=duration,
            address1=addr1,
            address2=addr2,
            address3=addr3,
            address4=address4,
            sequence_control=sequence_control,
            payload=full_payload,
        )
        self.destination = destination
        self.source = source
        self.bssid = bssid
        self._user_payload = payload

    @property
    def tid(self) -> int:
        """Traffic Identifier (TID) from the QoS Control field."""
        return self.qos_control & 0x000F

    @property
    def access_category(self) -> int:
        """Access Category (AC) derived from the TID."""
        return self.TID_TO_AC.get(self.tid, self.AC_BE)

    @property
    def access_category_name(self) -> str:
        """Human-readable Access Category name."""
        return self.AC_NAMES.get(self.access_category, "Unknown")

    @property
    def eosp(self) -> bool:
        """End of Service Period (EOSP) flag."""
        return bool(self.qos_control & 0x0010)

    @property
    def ack_policy(self) -> int:
        """Acknowledge policy (0=Normal ACK, 1=No ACK, 2=No Explicit ACK, 3=Block ACK)."""
        return (self.qos_control >> 5) & 0x03

    @property
    def a_msdu_present(self) -> bool:
        """Whether A-MSDU aggregation is present."""
        return bool(self.qos_control & 0x0080)

    @property
    def txop_limit(self) -> int:
        """TXOP Limit in 32μs units (only valid for QoS Data)."""
        return (self.qos_control >> 8) & 0xFF

    def get_user_payload(self) -> bytes:
        """Get the actual user payload (excluding QoS Control field)."""
        return self._user_payload

    def to_bytes(self) -> bytes:
        """Serialize QoS Data frame to bytes."""
        header = bytearray()
        header.extend(self.frame_control.to_bytes())
        header.extend(struct.pack("<H", self.duration & 0xFFFF))
        header.extend(mac_to_bytes(self.address1))
        header.extend(mac_to_bytes(self.address2))
        header.extend(mac_to_bytes(self.address3))
        header.extend(struct.pack("<H", self.sequence_control))
        if self.address4 is not None:
            header.extend(mac_to_bytes(self.address4))
        header.extend(struct.pack("<H", self.qos_control))
        header.extend(self._user_payload)
        return bytes(header)

    @classmethod
    def from_bytes(cls, data: bytes) -> "QoSDataFrame":
        """Parse a QoS Data frame from raw bytes."""
        if len(data) < 26:
            raise WiFiConnectionError(
                f"QoS Data frame too short: {len(data)} bytes, minimum 26"
            )
        base = WiFiFrame.from_bytes(data)
        payload = base.payload
        if len(payload) < 2:
            raise WiFiConnectionError("QoS Data payload too short for QoS Control")
        qos_control = struct.unpack("<H", payload[0:2])[0]
        user_payload = payload[2:]

        frame = cls(
            to_ds=base.frame_control.to_ds,
            from_ds=base.frame_control.from_ds,
            duration=base.duration,
            sequence_control=base.sequence_control,
            qos_control=qos_control,
            payload=user_payload,
        )
        frame.frame_control = base.frame_control
        frame.address1 = base.address1
        frame.address2 = base.address2
        frame.address3 = base.address3
        frame.address4 = base.address4
        frame._user_payload = user_payload
        addrs = frame.extract_logical_addresses()
        frame.destination = addrs["destination"]
        frame.source = addrs["source"]
        frame.bssid = addrs["bssid"]
        return frame


class NullFunctionFrame(DataFrame):
    """IEEE 802.11 Null Function frame.

    Null frames carry no data but are used for power management
    signaling and other control purposes.
    """

    def __init__(
        self,
        destination: str = NULL_MAC,
        source: str = NULL_MAC,
        bssid: str = NULL_MAC,
        to_ds: bool = False,
        from_ds: bool = False,
        duration: int = 0,
        sequence_control: int = 0,
        power_management: bool = False,
    ):
        fc = FrameControl(
            frame_type=FRAME_TYPE_DATA,
            subtype=SUBTYPE_NULL,
            to_ds=to_ds,
            from_ds=from_ds,
            power_management=power_management,
        )
        addr1, addr2, addr3 = DataFrame._map_addresses(
            destination, source, bssid, to_ds, from_ds
        )
        super(DataFrame, self).__init__(
            frame_control=fc,
            duration=duration,
            address1=addr1,
            address2=addr2,
            address3=addr3,
            sequence_control=sequence_control,
            payload=b"",
        )
        self.destination = destination
        self.source = source
        self.bssid = bssid

    @classmethod
    def from_bytes(cls, data: bytes) -> "NullFunctionFrame":
        """Parse a Null Function frame from raw bytes."""
        if len(data) < 24:
            raise WiFiConnectionError(
                f"Null frame too short: {len(data)} bytes, minimum 24"
            )
        base = WiFiFrame.from_bytes(data)
        return cls(
            to_ds=base.frame_control.to_ds,
            from_ds=base.frame_control.from_ds,
            duration=base.duration,
            sequence_control=base.sequence_control,
            power_management=base.frame_control.power_management,
        )


class QoSNullFunctionFrame(QoSDataFrame):
    """IEEE 802.11 QoS Null Function frame.

    QoS Null frames combine the null function concept with QoS
    control fields for power management with traffic indication.
    """

    def __init__(
        self,
        destination: str = NULL_MAC,
        source: str = NULL_MAC,
        bssid: str = NULL_MAC,
        to_ds: bool = False,
        from_ds: bool = False,
        duration: int = 0,
        sequence_control: int = 0,
        qos_control: int = 0,
        power_management: bool = False,
    ):
        self.qos_control = qos_control
        fc = FrameControl(
            frame_type=FRAME_TYPE_DATA,
            subtype=SUBTYPE_QOS_NULL,
            to_ds=to_ds,
            from_ds=from_ds,
            power_management=power_management,
        )
        addr1, addr2, addr3 = DataFrame._map_addresses(
            destination, source, bssid, to_ds, from_ds
        )
        super(DataFrame, self).__init__(
            frame_control=fc,
            duration=duration,
            address1=addr1,
            address2=addr2,
            address3=addr3,
            sequence_control=sequence_control,
            payload=struct.pack("<H", qos_control),
        )
        self.destination = destination
        self.source = source
        self.bssid = bssid
        self._user_payload = b""

    @classmethod
    def from_bytes(cls, data: bytes) -> "QoSNullFunctionFrame":
        """Parse a QoS Null Function frame from raw bytes."""
        if len(data) < 26:
            raise WiFiConnectionError(
                f"QoS Null frame too short: {len(data)} bytes, minimum 26"
            )
        base = WiFiFrame.from_bytes(data)
        payload = base.payload
        qos_control = struct.unpack("<H", payload[0:2])[0] if len(payload) >= 2 else 0
        return cls(
            to_ds=base.frame_control.to_ds,
            from_ds=base.frame_control.from_ds,
            duration=base.duration,
            sequence_control=base.sequence_control,
            qos_control=qos_control,
            power_management=base.frame_control.power_management,
        )
