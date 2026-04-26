"""IEEE 802.11 Management frame types.

Provides classes for constructing and parsing management frames including
Beacon, Probe Request/Response, Authentication, Deauthentication,
Association, Reassociation, and Disassociation frames.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Union

from wifi_aio.frames.base_frame import (
    BROADCAST_MAC,
    NULL_MAC,
    FRAME_TYPE_MANAGEMENT,
    SUBTYPE_ASSOC_REQ,
    SUBTYPE_ASSOC_RESP,
    SUBTYPE_REASSOC_REQ,
    SUBTYPE_REASSOC_RESP,
    SUBTYPE_PROBE_REQ,
    SUBTYPE_PROBE_RESP,
    SUBTYPE_BEACON,
    SUBTYPE_DISASSOC,
    SUBTYPE_AUTH,
    SUBTYPE_DEAUTH,
    FrameControl,
    WiFiFrame,
    mac_to_bytes,
    bytes_to_mac,
)
from wifi_aio.exceptions import WiFiConnectionError


class ManagementFrame(WiFiFrame):
    """Base class for all 802.11 management frames.

    Management frames carry management information between stations
    and access points for network discovery, authentication, and
    association procedures.
    """

    def __init__(
        self,
        subtype: int = 0,
        duration: int = 0,
        address1: str = BROADCAST_MAC,
        address2: str = NULL_MAC,
        address3: str = NULL_MAC,
        sequence_control: int = 0,
        payload: bytes = b"",
    ):
        fc = FrameControl(
            frame_type=FRAME_TYPE_MANAGEMENT,
            subtype=subtype,
        )
        super().__init__(
            frame_control=fc,
            duration=duration,
            address1=address1,
            address2=address2,
            address3=address3,
            sequence_control=sequence_control,
            payload=payload,
        )
        self.subtype = subtype


class BeaconFrame(ManagementFrame):
    """IEEE 802.11 Beacon frame.

    Beacons are periodically transmitted by access points to advertise
    the network's presence, capabilities, and parameters.
    """

    def __init__(
        self,
        source: str = NULL_MAC,
        bssid: str = NULL_MAC,
        ssid: str = "",
        beacon_interval: int = 100,
        capability: int = 0x0411,
        timestamp: int = 0,
        information_elements: bytes = b"",
        sequence_control: int = 0,
    ):
        self.ssid = ssid
        self.beacon_interval = beacon_interval
        self.capability = capability
        self.timestamp = timestamp
        self._raw_ies = information_elements
        payload = self._build_payload()
        super().__init__(
            subtype=SUBTYPE_BEACON,
            duration=0,
            address1=BROADCAST_MAC,
            address2=source,
            address3=bssid,
            sequence_control=sequence_control,
            payload=payload,
        )

    def _build_payload(self) -> bytes:
        """Build the beacon frame body (fixed fields + IEs)."""
        body = bytearray()
        # Timestamp (8 bytes)
        body.extend(struct.pack("<Q", self.timestamp & 0xFFFFFFFFFFFFFFFF))
        # Beacon Interval (2 bytes, in TUs)
        body.extend(struct.pack("<H", self.beacon_interval))
        # Capability Info (2 bytes)
        body.extend(struct.pack("<H", self.capability))
        # SSID IE (Element ID 0)
        if self.ssid:
            ssid_bytes = self.ssid.encode("utf-8")
            body.append(0)  # Element ID
            body.append(len(ssid_bytes))  # Length
            body.extend(ssid_bytes)
        else:
            body.append(0)  # Element ID
            body.append(0)  # Length (broadcast / hidden SSID)
        # Append any additional raw IEs
        if self._raw_ies:
            body.extend(self._raw_ies)
        return bytes(body)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BeaconFrame":
        """Parse a Beacon frame from raw bytes.

        Args:
            data: Raw beacon frame bytes including header.

        Returns:
            A BeaconFrame instance.
        """
        if len(data) < 36:
            raise WiFiConnectionError(
                f"Beacon frame too short: {len(data)} bytes",
                details="Beacon frame requires at least 36 bytes for header + fixed fields.",
            )
        base = WiFiFrame.from_bytes(data)
        body = base.payload
        if len(body) < 12:
            raise WiFiConnectionError(
                "Beacon body too short for fixed fields",
                details="Expected at least 12 bytes for timestamp, interval, and capability.",
            )
        timestamp = struct.unpack("<Q", body[0:8])[0]
        beacon_interval = struct.unpack("<H", body[8:10])[0]
        capability = struct.unpack("<H", body[10:12])[0]
        ssid = ""
        ie_data = body[12:]
        if len(ie_data) >= 2 and ie_data[0] == 0:
            ssid_len = ie_data[1]
            if len(ie_data) >= 2 + ssid_len:
                ssid = ie_data[2 : 2 + ssid_len].decode("utf-8", errors="replace")
        return cls(
            source=base.address2,
            bssid=base.address3,
            ssid=ssid,
            beacon_interval=beacon_interval,
            capability=capability,
            timestamp=timestamp,
            information_elements=body[12:],
            sequence_control=base.sequence_control,
        )

    @property
    def is_ess(self) -> bool:
        """Check if the ESS bit is set in capability info."""
        return bool(self.capability & 0x0001)

    @property
    def is_ibss(self) -> bool:
        """Check if the IBSS bit is set in capability info."""
        return bool(self.capability & 0x0002)

    @property
    def privacy_enabled(self) -> bool:
        """Check if the Privacy bit is set in capability info."""
        return bool(self.capability & 0x0010)


class ProbeRequestFrame(ManagementFrame):
    """IEEE 802.11 Probe Request frame.

    Stations send probe requests to actively scan for networks,
    optionally specifying desired SSID and supported rates.
    """

    def __init__(
        self,
        source: str = NULL_MAC,
        ssid: str = "",
        information_elements: bytes = b"",
        sequence_control: int = 0,
    ):
        self.ssid = ssid
        self._raw_ies = information_elements
        payload = self._build_payload()
        super().__init__(
            subtype=SUBTYPE_PROBE_REQ,
            duration=0,
            address1=BROADCAST_MAC,
            address2=source,
            address3=BROADCAST_MAC,
            sequence_control=sequence_control,
            payload=payload,
        )

    def _build_payload(self) -> bytes:
        """Build the probe request body (IEs only, no fixed fields)."""
        body = bytearray()
        if self.ssid:
            ssid_bytes = self.ssid.encode("utf-8")
            body.append(0)  # Element ID for SSID
            body.append(len(ssid_bytes))
            body.extend(ssid_bytes)
        else:
            body.append(0)
            body.append(0)  # Broadcast probe (wildcard SSID)
        if self._raw_ies:
            body.extend(self._raw_ies)
        return bytes(body)

    @classmethod
    def from_bytes(cls, data: bytes) -> "ProbeRequestFrame":
        """Parse a Probe Request frame from raw bytes."""
        base = WiFiFrame.from_bytes(data)
        body = base.payload
        ssid = ""
        if len(body) >= 2 and body[0] == 0:
            ssid_len = body[1]
            if len(body) >= 2 + ssid_len:
                ssid = body[2 : 2 + ssid_len].decode("utf-8", errors="replace")
        return cls(
            source=base.address2,
            ssid=ssid,
            information_elements=body,
            sequence_control=base.sequence_control,
        )


class ProbeResponseFrame(ManagementFrame):
    """IEEE 802.11 Probe Response frame.

    Access points respond to probe requests with probe response frames
    that contain the same information as beacon frames.
    """

    def __init__(
        self,
        source: str = NULL_MAC,
        destination: str = NULL_MAC,
        bssid: str = NULL_MAC,
        ssid: str = "",
        beacon_interval: int = 100,
        capability: int = 0x0411,
        timestamp: int = 0,
        information_elements: bytes = b"",
        sequence_control: int = 0,
    ):
        self.ssid = ssid
        self.beacon_interval = beacon_interval
        self.capability = capability
        self.timestamp = timestamp
        self._raw_ies = information_elements
        payload = self._build_payload()
        super().__init__(
            subtype=SUBTYPE_PROBE_RESP,
            duration=0,
            address1=destination,
            address2=source,
            address3=bssid,
            sequence_control=sequence_control,
            payload=payload,
        )

    def _build_payload(self) -> bytes:
        """Build the probe response body."""
        body = bytearray()
        body.extend(struct.pack("<Q", self.timestamp & 0xFFFFFFFFFFFFFFFF))
        body.extend(struct.pack("<H", self.beacon_interval))
        body.extend(struct.pack("<H", self.capability))
        if self.ssid:
            ssid_bytes = self.ssid.encode("utf-8")
            body.append(0)
            body.append(len(ssid_bytes))
            body.extend(ssid_bytes)
        else:
            body.append(0)
            body.append(0)
        if self._raw_ies:
            body.extend(self._raw_ies)
        return bytes(body)

    @classmethod
    def from_bytes(cls, data: bytes) -> "ProbeResponseFrame":
        """Parse a Probe Response frame from raw bytes."""
        if len(data) < 36:
            raise WiFiConnectionError(
                f"Probe Response frame too short: {len(data)} bytes",
                details="Probe Response requires header + fixed fields.",
            )
        base = WiFiFrame.from_bytes(data)
        body = base.payload
        if len(body) < 12:
            raise WiFiConnectionError("Probe Response body too short for fixed fields")
        timestamp = struct.unpack("<Q", body[0:8])[0]
        beacon_interval = struct.unpack("<H", body[8:10])[0]
        capability = struct.unpack("<H", body[10:12])[0]
        ssid = ""
        ie_data = body[12:]
        if len(ie_data) >= 2 and ie_data[0] == 0:
            ssid_len = ie_data[1]
            if len(ie_data) >= 2 + ssid_len:
                ssid = ie_data[2 : 2 + ssid_len].decode("utf-8", errors="replace")
        return cls(
            source=base.address2,
            destination=base.address1,
            bssid=base.address3,
            ssid=ssid,
            beacon_interval=beacon_interval,
            capability=capability,
            timestamp=timestamp,
            information_elements=body[12:],
            sequence_control=base.sequence_control,
        )


class AuthenticationFrame(ManagementFrame):
    """IEEE 802.11 Authentication frame.

    Authentication frames are exchanged during the authentication process.
    Supports both Open System and Shared Key authentication algorithms.
    """

    # Authentication algorithm numbers
    ALGO_OPEN_SYSTEM = 0
    ALGO_SHARED_KEY = 1
    ALGO_FILS_SK = 2
    ALGO_FILS_SK_PFS = 3
    ALGO_FILS_PK = 4

    # Authentication transaction sequence numbers
    SEQ_NUM_1 = 1
    SEQ_NUM_2 = 2
    SEQ_NUM_3 = 3
    SEQ_NUM_4 = 4

    # Status codes
    STATUS_SUCCESSFUL = 0
    STATUS_UNSPECIFIED_FAILURE = 1
    STATUS_AUTH_SEQ_OUT_OF_SEQ = 14
    STATUS_CHALLENGE_FAILURE = 15
    STATUS_AUTH_TIMEOUT = 18

    def __init__(
        self,
        source: str = NULL_MAC,
        destination: str = NULL_MAC,
        bssid: str = NULL_MAC,
        auth_algorithm: int = ALGO_OPEN_SYSTEM,
        auth_seq: int = SEQ_NUM_1,
        status_code: int = STATUS_SUCCESSFUL,
        challenge_text: bytes = b"",
        sequence_control: int = 0,
    ):
        self.auth_algorithm = auth_algorithm
        self.auth_seq = auth_seq
        self.status_code = status_code
        self.challenge_text = challenge_text
        payload = self._build_payload()
        super().__init__(
            subtype=SUBTYPE_AUTH,
            duration=0,
            address1=destination,
            address2=source,
            address3=bssid,
            sequence_control=sequence_control,
            payload=payload,
        )

    def _build_payload(self) -> bytes:
        """Build the authentication frame body."""
        body = bytearray()
        body.extend(struct.pack("<H", self.auth_algorithm))
        body.extend(struct.pack("<H", self.auth_seq))
        body.extend(struct.pack("<H", self.status_code))
        if self.challenge_text:
            body.append(16)  # Element ID for Challenge Text
            body.append(len(self.challenge_text))
            body.extend(self.challenge_text)
        return bytes(body)

    @classmethod
    def from_bytes(cls, data: bytes) -> "AuthenticationFrame":
        """Parse an Authentication frame from raw bytes."""
        if len(data) < 30:
            raise WiFiConnectionError(
                f"Authentication frame too short: {len(data)} bytes"
            )
        base = WiFiFrame.from_bytes(data)
        body = base.payload
        if len(body) < 6:
            raise WiFiConnectionError("Authentication body too short")
        auth_algorithm = struct.unpack("<H", body[0:2])[0]
        auth_seq = struct.unpack("<H", body[2:4])[0]
        status_code = struct.unpack("<H", body[4:6])[0]
        challenge_text = b""
        if len(body) > 6 and auth_algorithm == cls.ALGO_SHARED_KEY:
            if len(body) >= 8:
                ie_id = body[6]
                ie_len = body[7]
                if ie_id == 16 and len(body) >= 8 + ie_len:
                    challenge_text = body[8 : 8 + ie_len]
        return cls(
            source=base.address2,
            destination=base.address1,
            bssid=base.address3,
            auth_algorithm=auth_algorithm,
            auth_seq=auth_seq,
            status_code=status_code,
            challenge_text=challenge_text,
            sequence_control=base.sequence_control,
        )


class DeauthenticationFrame(ManagementFrame):
    """IEEE 802.11 Deauthentication frame.

    Deauthentication frames are sent to terminate an authenticated
    relationship between stations.
    """

    def __init__(
        self,
        source: str = NULL_MAC,
        destination: str = NULL_MAC,
        bssid: str = NULL_MAC,
        reason_code: int = 0x0007,
        sequence_control: int = 0,
    ):
        self.reason_code = reason_code
        payload = self._build_payload()
        super().__init__(
            subtype=SUBTYPE_DEAUTH,
            duration=0,
            address1=destination,
            address2=source,
            address3=bssid,
            sequence_control=sequence_control,
            payload=payload,
        )

    def _build_payload(self) -> bytes:
        """Build the deauthentication frame body (reason code only)."""
        return struct.pack("<H", self.reason_code)

    @classmethod
    def from_bytes(cls, data: bytes) -> "DeauthenticationFrame":
        """Parse a Deauthentication frame from raw bytes."""
        if len(data) < 26:
            raise WiFiConnectionError(
                f"Deauthentication frame too short: {len(data)} bytes"
            )
        base = WiFiFrame.from_bytes(data)
        body = base.payload
        if len(body) < 2:
            raise WiFiConnectionError("Deauthentication body too short")
        reason_code = struct.unpack("<H", body[0:2])[0]
        return cls(
            source=base.address2,
            destination=base.address1,
            bssid=base.address3,
            reason_code=reason_code,
            sequence_control=base.sequence_control,
        )


class AssociationRequestFrame(ManagementFrame):
    """IEEE 802.11 Association Request frame.

    Stations send association requests after successful authentication
    to request membership in a BSS.
    """

    def __init__(
        self,
        source: str = NULL_MAC,
        destination: str = NULL_MAC,
        bssid: str = NULL_MAC,
        capability: int = 0x0411,
        listen_interval: int = 10,
        ssid: str = "",
        information_elements: bytes = b"",
        sequence_control: int = 0,
    ):
        self.capability = capability
        self.listen_interval = listen_interval
        self.ssid = ssid
        self._raw_ies = information_elements
        payload = self._build_payload()
        super().__init__(
            subtype=SUBTYPE_ASSOC_REQ,
            duration=0,
            address1=destination,
            address2=source,
            address3=bssid,
            sequence_control=sequence_control,
            payload=payload,
        )

    def _build_payload(self) -> bytes:
        """Build the association request body."""
        body = bytearray()
        body.extend(struct.pack("<H", self.capability))
        body.extend(struct.pack("<H", self.listen_interval))
        if self.ssid:
            ssid_bytes = self.ssid.encode("utf-8")
            body.append(0)
            body.append(len(ssid_bytes))
            body.extend(ssid_bytes)
        else:
            body.append(0)
            body.append(0)
        if self._raw_ies:
            body.extend(self._raw_ies)
        return bytes(body)

    @classmethod
    def from_bytes(cls, data: bytes) -> "AssociationRequestFrame":
        """Parse an Association Request frame from raw bytes."""
        if len(data) < 28:
            raise WiFiConnectionError(
                f"Association Request frame too short: {len(data)} bytes"
            )
        base = WiFiFrame.from_bytes(data)
        body = base.payload
        if len(body) < 4:
            raise WiFiConnectionError("Association Request body too short")
        capability = struct.unpack("<H", body[0:2])[0]
        listen_interval = struct.unpack("<H", body[2:4])[0]
        ssid = ""
        ie_data = body[4:]
        if len(ie_data) >= 2 and ie_data[0] == 0:
            ssid_len = ie_data[1]
            if len(ie_data) >= 2 + ssid_len:
                ssid = ie_data[2 : 2 + ssid_len].decode("utf-8", errors="replace")
        return cls(
            source=base.address2,
            destination=base.address1,
            bssid=base.address3,
            capability=capability,
            listen_interval=listen_interval,
            ssid=ssid,
            information_elements=body[4:],
            sequence_control=base.sequence_control,
        )


class AssociationResponseFrame(ManagementFrame):
    """IEEE 802.11 Association Response frame.

    Access points send association responses to accept or reject
    a station's association request.
    """

    def __init__(
        self,
        source: str = NULL_MAC,
        destination: str = NULL_MAC,
        bssid: str = NULL_MAC,
        capability: int = 0x0411,
        status_code: int = 0,
        association_id: int = 1,
        information_elements: bytes = b"",
        sequence_control: int = 0,
    ):
        self.capability = capability
        self.status_code = status_code
        self.association_id = association_id
        self._raw_ies = information_elements
        payload = self._build_payload()
        super().__init__(
            subtype=SUBTYPE_ASSOC_RESP,
            duration=0,
            address1=destination,
            address2=source,
            address3=bssid,
            sequence_control=sequence_control,
            payload=payload,
        )

    def _build_payload(self) -> bytes:
        """Build the association response body."""
        body = bytearray()
        body.extend(struct.pack("<H", self.capability))
        body.extend(struct.pack("<H", self.status_code))
        # AID is stored with two MSBs set to 1 per spec
        aid_value = (self.association_id & 0x1FFF) | 0xC000
        body.extend(struct.pack("<H", aid_value))
        if self._raw_ies:
            body.extend(self._raw_ies)
        return bytes(body)

    @classmethod
    def from_bytes(cls, data: bytes) -> "AssociationResponseFrame":
        """Parse an Association Response frame from raw bytes."""
        if len(data) < 28:
            raise WiFiConnectionError(
                f"Association Response frame too short: {len(data)} bytes"
            )
        base = WiFiFrame.from_bytes(data)
        body = base.payload
        if len(body) < 6:
            raise WiFiConnectionError("Association Response body too short")
        capability = struct.unpack("<H", body[0:2])[0]
        status_code = struct.unpack("<H", body[2:4])[0]
        aid_raw = struct.unpack("<H", body[4:6])[0]
        association_id = aid_raw & 0x1FFF
        return cls(
            source=base.address2,
            destination=base.address1,
            bssid=base.address3,
            capability=capability,
            status_code=status_code,
            association_id=association_id,
            information_elements=body[6:],
            sequence_control=base.sequence_control,
        )


class ReassociationRequestFrame(ManagementFrame):
    """IEEE 802.11 Reassociation Request frame.

    Stations send reassociation requests when roaming between
    access points within the same ESS.
    """

    def __init__(
        self,
        source: str = NULL_MAC,
        destination: str = NULL_MAC,
        bssid: str = NULL_MAC,
        current_ap: str = NULL_MAC,
        capability: int = 0x0411,
        listen_interval: int = 10,
        ssid: str = "",
        information_elements: bytes = b"",
        sequence_control: int = 0,
    ):
        self.current_ap = current_ap
        self.capability = capability
        self.listen_interval = listen_interval
        self.ssid = ssid
        self._raw_ies = information_elements
        payload = self._build_payload()
        super().__init__(
            subtype=SUBTYPE_REASSOC_REQ,
            duration=0,
            address1=destination,
            address2=source,
            address3=bssid,
            sequence_control=sequence_control,
            payload=payload,
        )

    def _build_payload(self) -> bytes:
        """Build the reassociation request body."""
        body = bytearray()
        body.extend(struct.pack("<H", self.capability))
        body.extend(struct.pack("<H", self.listen_interval))
        body.extend(mac_to_bytes(self.current_ap))
        if self.ssid:
            ssid_bytes = self.ssid.encode("utf-8")
            body.append(0)
            body.append(len(ssid_bytes))
            body.extend(ssid_bytes)
        else:
            body.append(0)
            body.append(0)
        if self._raw_ies:
            body.extend(self._raw_ies)
        return bytes(body)

    @classmethod
    def from_bytes(cls, data: bytes) -> "ReassociationRequestFrame":
        """Parse a Reassociation Request frame from raw bytes."""
        if len(data) < 34:
            raise WiFiConnectionError(
                f"Reassociation Request frame too short: {len(data)} bytes"
            )
        base = WiFiFrame.from_bytes(data)
        body = base.payload
        if len(body) < 10:
            raise WiFiConnectionError("Reassociation Request body too short")
        capability = struct.unpack("<H", body[0:2])[0]
        listen_interval = struct.unpack("<H", body[2:4])[0]
        current_ap = bytes_to_mac(body[4:10])
        ssid = ""
        ie_data = body[10:]
        if len(ie_data) >= 2 and ie_data[0] == 0:
            ssid_len = ie_data[1]
            if len(ie_data) >= 2 + ssid_len:
                ssid = ie_data[2 : 2 + ssid_len].decode("utf-8", errors="replace")
        return cls(
            source=base.address2,
            destination=base.address1,
            bssid=base.address3,
            current_ap=current_ap,
            capability=capability,
            listen_interval=listen_interval,
            ssid=ssid,
            information_elements=body[10:],
            sequence_control=base.sequence_control,
        )


class ReassociationResponseFrame(ManagementFrame):
    """IEEE 802.11 Reassociation Response frame.

    Access points send reassociation responses to accept or reject
    a station's reassociation request.
    """

    def __init__(
        self,
        source: str = NULL_MAC,
        destination: str = NULL_MAC,
        bssid: str = NULL_MAC,
        capability: int = 0x0411,
        status_code: int = 0,
        association_id: int = 1,
        information_elements: bytes = b"",
        sequence_control: int = 0,
    ):
        self.capability = capability
        self.status_code = status_code
        self.association_id = association_id
        self._raw_ies = information_elements
        payload = self._build_payload()
        super().__init__(
            subtype=SUBTYPE_REASSOC_RESP,
            duration=0,
            address1=destination,
            address2=source,
            address3=bssid,
            sequence_control=sequence_control,
            payload=payload,
        )

    def _build_payload(self) -> bytes:
        """Build the reassociation response body."""
        body = bytearray()
        body.extend(struct.pack("<H", self.capability))
        body.extend(struct.pack("<H", self.status_code))
        aid_value = (self.association_id & 0x1FFF) | 0xC000
        body.extend(struct.pack("<H", aid_value))
        if self._raw_ies:
            body.extend(self._raw_ies)
        return bytes(body)

    @classmethod
    def from_bytes(cls, data: bytes) -> "ReassociationResponseFrame":
        """Parse a Reassociation Response frame from raw bytes."""
        if len(data) < 28:
            raise WiFiConnectionError(
                f"Reassociation Response frame too short: {len(data)} bytes"
            )
        base = WiFiFrame.from_bytes(data)
        body = base.payload
        if len(body) < 6:
            raise WiFiConnectionError("Reassociation Response body too short")
        capability = struct.unpack("<H", body[0:2])[0]
        status_code = struct.unpack("<H", body[2:4])[0]
        aid_raw = struct.unpack("<H", body[4:6])[0]
        association_id = aid_raw & 0x1FFF
        return cls(
            source=base.address2,
            destination=base.address1,
            bssid=base.address3,
            capability=capability,
            status_code=status_code,
            association_id=association_id,
            information_elements=body[6:],
            sequence_control=base.sequence_control,
        )


class DisassociationFrame(ManagementFrame):
    """IEEE 802.11 Disassociation frame.

    Disassociation frames are sent to terminate an association
    between stations.
    """

    def __init__(
        self,
        source: str = NULL_MAC,
        destination: str = NULL_MAC,
        bssid: str = NULL_MAC,
        reason_code: int = 0x0008,
        sequence_control: int = 0,
    ):
        self.reason_code = reason_code
        payload = self._build_payload()
        super().__init__(
            subtype=SUBTYPE_DISASSOC,
            duration=0,
            address1=destination,
            address2=source,
            address3=bssid,
            sequence_control=sequence_control,
            payload=payload,
        )

    def _build_payload(self) -> bytes:
        """Build the disassociation frame body (reason code only)."""
        return struct.pack("<H", self.reason_code)

    @classmethod
    def from_bytes(cls, data: bytes) -> "DisassociationFrame":
        """Parse a Disassociation frame from raw bytes."""
        if len(data) < 26:
            raise WiFiConnectionError(
                f"Disassociation frame too short: {len(data)} bytes"
            )
        base = WiFiFrame.from_bytes(data)
        body = base.payload
        if len(body) < 2:
            raise WiFiConnectionError("Disassociation body too short")
        reason_code = struct.unpack("<H", body[0:2])[0]
        return cls(
            source=base.address2,
            destination=base.address1,
            bssid=base.address3,
            reason_code=reason_code,
            sequence_control=base.sequence_control,
        )
