"""EAPOL (Extensible Authentication Protocol over LAN) frame handling.

Provides classes for constructing and parsing EAPOL frames, with
special focus on EAPOL-Key frames used in the 802.11 4-way handshake
(M1/M2/M3/M4).
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Dict, List, Optional, Tuple, Union

from wifi_aio.frames.base_frame import mac_to_bytes, bytes_to_mac
from wifi_aio.exceptions import WiFiConnectionError


# EAPOL Protocol Version
EAPOL_VERSION_1 = 1
EAPOL_VERSION_2 = 2  # WPA2
EAPOL_VERSION_3 = 3  # WPA3/Suite B

# EAPOL Packet Types
EAPOL_PACKET_EAP = 0
EAPOL_PACKET_START = 1
EAPOL_PACKET_LOGOFF = 2
EAPOL_PACKET_KEY = 3
EAPOL_PACKET_ENCAPSULATED = 4

# EAPOL-Key Descriptor Types
KEY_DESC_RC4 = 1      # WEP
KEY_DESC_RSN = 2      # WPA2
KEY_DESC_WPA = 254     # WPA

# Key Information bitmasks (for Key Information field in EAPOL-Key)
KEY_INFO_KEY_TYPE = 0x0008         # 0=Group, 1=Pairwise
KEY_INFO_KEY_INDEX_MASK = 0x0003   # Key Index for Group keys
KEY_INFO_INSTALL = 0x0040          # Install flag
KEY_INFO_KEY_ACK = 0x0080          # Key ACK (AP -> STA)
KEY_INFO_KEY_MIC = 0x0100          # Key MIC present
KEY_INFO_SECURE = 0x0200           # Secure flag
KEY_INFO_ERROR = 0x0400            # Error flag
KEY_INFO_REQUEST = 0x0800          # Request flag
KEY_INFO_ENCRYPTED_KEY_DATA = 0x1000  # Encrypted Key Data
KEY_INFO_SMOKE_SIGNAL = 0x2000     # Smoke Signal (unused/reserved)

# Handshake message types (determined from Key Info bits)
MSG_M1 = 1  # ANonce from AP
MSG_M2 = 2  # SNonce + MIC from STA
MSG_M3 = 3  # ANonce + MIC + GTK from AP
MSG_M4 = 4  # MIC from STA


class EAPOLKeyInfo:
    """Parsed representation of the EAPOL-Key Key Information field.

    The Key Information field is a 16-bit field that describes the
    key exchange state and flags.
    """

    def __init__(self, key_info: int = 0):
        self._raw = key_info

    @property
    def raw(self) -> int:
        """The raw 16-bit Key Information value."""
        return self._raw

    @property
    def descriptor_version(self) -> int:
        """Descriptor version (bits 0-2, but in practice bits 0-2 of key_info)."""
        return self._raw & 0x0007

    @property
    def key_type(self) -> str:
        """Key type: 'Pairwise' or 'Group'."""
        return "Pairwise" if self._raw & KEY_INFO_KEY_TYPE else "Group"

    @property
    def is_pairwise(self) -> bool:
        """Whether this is a pairwise key exchange."""
        return bool(self._raw & KEY_INFO_KEY_TYPE)

    @property
    def key_index(self) -> int:
        """Key index for Group key (bits 4-5)."""
        return (self._raw >> 4) & 0x03

    @property
    def install(self) -> bool:
        """Whether the Install flag is set."""
        return bool(self._raw & KEY_INFO_INSTALL)

    @property
    def key_ack(self) -> bool:
        """Whether the Key ACK flag is set (indicates AP -> STA direction)."""
        return bool(self._raw & KEY_INFO_KEY_ACK)

    @property
    def key_mic(self) -> bool:
        """Whether the Key MIC flag is set."""
        return bool(self._raw & KEY_INFO_KEY_MIC)

    @property
    def secure(self) -> bool:
        """Whether the Secure flag is set."""
        return bool(self._raw & KEY_INFO_SECURE)

    @property
    def error(self) -> bool:
        """Whether the Error flag is set."""
        return bool(self._raw & KEY_INFO_ERROR)

    @property
    def request(self) -> bool:
        """Whether the Request flag is set."""
        return bool(self._raw & KEY_INFO_REQUEST)

    @property
    def encrypted_key_data(self) -> bool:
        """Whether the Encrypted Key Data flag is set."""
        return bool(self._raw & KEY_INFO_ENCRYPTED_KEY_DATA)

    def determine_message_number(self) -> int:
        """Determine which message of the 4-way handshake this represents.

        Returns:
            1 for M1, 2 for M2, 3 for M3, 4 for M4, or 0 if unknown.

        Logic:
            M1: Pairwise + Key ACK (no MIC)
            M2: Pairwise + Key MIC (no Key ACK)
            M3: Pairwise + Key ACK + Key MIC + Install + Encrypted
            M4: Pairwise + Key MIC (no Key ACK, no Install)
        """
        if self.is_pairwise:
            if self.key_ack and not self.key_mic:
                return MSG_M1
            elif self.key_mic and not self.key_ack and not self.install:
                return MSG_M2
            elif self.key_ack and self.key_mic and self.install:
                return MSG_M3
            elif self.key_mic and not self.key_ack and not self.install and self.secure:
                return MSG_M4
            elif self.key_mic and not self.key_ack and not self.install:
                return MSG_M4
        return 0

    def to_dict(self) -> Dict[str, Union[int, bool, str]]:
        """Return a dictionary representation of the Key Info."""
        return {
            "raw": self._raw,
            "descriptor_version": self.descriptor_version,
            "key_type": self.key_type,
            "key_index": self.key_index,
            "install": self.install,
            "key_ack": self.key_ack,
            "key_mic": self.key_mic,
            "secure": self.secure,
            "error": self.error,
            "request": self.request,
            "encrypted_key_data": self.encrypted_key_data,
            "message_number": self.determine_message_number(),
        }


class HandshakeMessage:
    """Represents a single EAPOL-Key message in the 4-way handshake.

    Provides methods to identify the message type and extract
    key material for PMKID/PMK derivation.
    """

    def __init__(self, eapol_key_frame: "EAPOLKeyFrame"):
        self.frame = eapol_key_frame
        self._message_type = eapol_key_frame.key_info.determine_message_number()

    @property
    def message_type(self) -> int:
        """The handshake message number (1-4)."""
        return self._message_type

    @property
    def message_name(self) -> str:
        """Human-readable name for the message type."""
        names = {1: "M1", 2: "M2", 3: "M3", 4: "M4"}
        return names.get(self._message_type, "Unknown")

    @property
    def is_m1(self) -> bool:
        return self._message_type == MSG_M1

    @property
    def is_m2(self) -> bool:
        return self._message_type == MSG_M2

    @property
    def is_m3(self) -> bool:
        return self._message_type == MSG_M3

    @property
    def is_m4(self) -> bool:
        return self._message_type == MSG_M4

    @property
    def anonce(self) -> Optional[bytes]:
        """Extract the ANonce (Authenticator Nonce) from M1 or M3."""
        if self.is_m1 or self.is_m3:
            return self.frame.key_nonce
        return None

    @property
    def snonce(self) -> Optional[bytes]:
        """Extract the SNonce (Supplicant Nonce) from M2."""
        if self.is_m2:
            return self.frame.key_nonce
        return None

    @property
    def mic(self) -> Optional[bytes]:
        """Extract the Key MIC from M2, M3, or M4."""
        if self.is_m2 or self.is_m3 or self.is_m4:
            return self.frame.key_mic
        return None

    @property
    def pmkid(self) -> Optional[bytes]:
        """Extract the PMKID from M1 if present.

        PMKID is stored in the first 16 bytes of the Key Data field
        in M1 frames when the Key Data field starts with an
        RSN IE or has the PMKID KDE.
        """
        if self.is_m1 and self.frame.key_data_length >= 16:
            return self.frame.key_data[:16]
        return None

    def __repr__(self) -> str:
        return f"HandshakeMessage(type={self.message_name})"


class EAPOLFrame:
    """EAPOL (Extensible Authentication Protocol over LAN) frame.

    EAPOL frames are carried in 802.11 data frames and are used
    for authentication and key exchange in WPA/WPA2/WPA3 networks.
    """

    def __init__(
        self,
        version: int = EAPOL_VERSION_2,
        packet_type: int = EAPOL_PACKET_KEY,
        body: bytes = b"",
    ):
        self.version = version
        self.packet_type = packet_type
        self.body = body

    @property
    def packet_type_name(self) -> str:
        """Return human-readable packet type."""
        names = {
            EAPOL_PACKET_EAP: "EAP",
            EAPOL_PACKET_START: "Start",
            EAPOL_PACKET_LOGOFF: "Logoff",
            EAPOL_PACKET_KEY: "Key",
            EAPOL_PACKET_ENCAPSULATED: "Encapsulated",
        }
        return names.get(self.packet_type, f"Unknown({self.packet_type})")

    def to_bytes(self) -> bytes:
        """Serialize the EAPOL frame to bytes."""
        result = bytearray()
        result.append(self.version)
        result.append(self.packet_type)
        result.extend(struct.pack("!H", len(self.body)))
        result.extend(self.body)
        return bytes(result)

    @classmethod
    def from_bytes(cls, data: bytes) -> "EAPOLFrame":
        """Parse an EAPOL frame from raw bytes.

        Args:
            data: Raw EAPOL frame bytes.

        Returns:
            An EAPOLFrame instance.

        Raises:
            WiFiConnectionError: If the frame is too short or malformed.
        """
        if len(data) < 4:
            raise WiFiConnectionError(
                f"EAPOL frame too short: {len(data)} bytes, minimum 4"
            )
        version = data[0]
        packet_type = data[1]
        body_length = struct.unpack("!H", data[2:4])[0]
        body = data[4 : 4 + body_length] if len(data) >= 4 + body_length else data[4:]
        return cls(version=version, packet_type=packet_type, body=body)

    def is_key_frame(self) -> bool:
        """Check if this is an EAPOL-Key frame."""
        return self.packet_type == EAPOL_PACKET_KEY

    def as_key_frame(self) -> Optional["EAPOLKeyFrame"]:
        """Convert to EAPOLKeyFrame if this is a key frame.

        Returns:
            An EAPOLKeyFrame if this is a key frame, None otherwise.
        """
        if self.is_key_frame():
            return EAPOLKeyFrame.from_eapol_body(self.version, self.body)
        return None

    def __repr__(self) -> str:
        return f"EAPOLFrame(version={self.version}, type={self.packet_type_name}, body_len={len(self.body)})"


class EAPOLKeyFrame:
    """EAPOL-Key frame for WPA/WPA2/WPA3 key exchange.

    Contains the complete EAPOL-Key structure including descriptor type,
    key information, nonces, MIC, and key data used in the 4-way handshake.
    """

    # Fixed field sizes
    NONCE_SIZE = 32
    MIC_SIZE = 16
    RSC_SIZE = 8
    ID_SIZE = 8

    def __init__(
        self,
        version: int = EAPOL_VERSION_2,
        descriptor_type: int = KEY_DESC_RSN,
        key_info: int = 0,
        key_length: int = 16,
        replay_counter: int = 0,
        key_nonce: bytes = b"",
        key_iv: bytes = b"",
        key_rsc: bytes = b"",
        key_id: bytes = b"",
        key_mic: bytes = b"",
        key_data_length: int = 0,
        key_data: bytes = b"",
    ):
        self.version = version
        self.descriptor_type = descriptor_type
        self._key_info_raw = key_info
        self.key_info = EAPOLKeyInfo(key_info)
        self.key_length = key_length
        self.replay_counter = replay_counter
        self.key_nonce = key_nonce.ljust(self.NONCE_SIZE, b"\x00")[:self.NONCE_SIZE]
        self.key_iv = key_iv.ljust(16, b"\x00")[:16]
        self.key_rsc = key_rsc.ljust(self.RSC_SIZE, b"\x00")[:self.RSC_SIZE]
        self.key_id = key_id.ljust(self.ID_SIZE, b"\x00")[:self.ID_SIZE]
        self.key_mic = key_mic.ljust(self.MIC_SIZE, b"\x00")[:self.MIC_SIZE]
        self.key_data_length = key_data_length
        self.key_data = key_data

    def to_bytes(self) -> bytes:
        """Serialize the EAPOL-Key frame body (without EAPOL header)."""
        result = bytearray()
        result.append(self.descriptor_type)
        result.extend(struct.pack("!H", self._key_info_raw))
        result.extend(struct.pack("!H", self.key_length))
        result.extend(struct.pack("!Q", self.replay_counter))
        result.extend(self.key_nonce)
        result.extend(self.key_iv)
        result.extend(self.key_rsc)
        result.extend(self.key_id)
        result.extend(self.key_mic)
        result.extend(struct.pack("!H", self.key_data_length))
        result.extend(self.key_data[:self.key_data_length])
        return bytes(result)

    def to_eapol_bytes(self) -> bytes:
        """Serialize the complete EAPOL frame including EAPOL header."""
        body = self.to_bytes()
        result = bytearray()
        result.append(self.version)
        result.append(EAPOL_PACKET_KEY)
        result.extend(struct.pack("!H", len(body)))
        result.extend(body)
        return bytes(result)

    @classmethod
    def from_eapol_body(cls, version: int, body: bytes) -> "EAPOLKeyFrame":
        """Parse an EAPOL-Key frame from the body portion of an EAPOL frame.

        Args:
            version: EAPOL protocol version.
            body: The body bytes after the EAPOL header.

        Returns:
            An EAPOLKeyFrame instance.

        Raises:
            WiFiConnectionError: If the body is too short.
        """
        min_length = 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8 + 16 + 2  # 95 bytes
        if len(body) < min_length:
            raise WiFiConnectionError(
                f"EAPOL-Key body too short: {len(body)} bytes, minimum {min_length}"
            )
        offset = 0
        descriptor_type = body[offset]
        offset += 1
        key_info_raw = struct.unpack("!H", body[offset : offset + 2])[0]
        offset += 2
        key_length = struct.unpack("!H", body[offset : offset + 2])[0]
        offset += 2
        replay_counter = struct.unpack("!Q", body[offset : offset + 8])[0]
        offset += 8
        key_nonce = body[offset : offset + 32]
        offset += 32
        key_iv = body[offset : offset + 16]
        offset += 16
        key_rsc = body[offset : offset + 8]
        offset += 8
        key_id = body[offset : offset + 8]
        offset += 8
        key_mic = body[offset : offset + 16]
        offset += 16
        key_data_length = struct.unpack("!H", body[offset : offset + 2])[0]
        offset += 2
        key_data = body[offset : offset + key_data_length] if key_data_length > 0 else b""
        return cls(
            version=version,
            descriptor_type=descriptor_type,
            key_info=key_info_raw,
            key_length=key_length,
            replay_counter=replay_counter,
            key_nonce=key_nonce,
            key_iv=key_iv,
            key_rsc=key_rsc,
            key_id=key_id,
            key_mic=key_mic,
            key_data_length=key_data_length,
            key_data=key_data,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "EAPOLKeyFrame":
        """Parse an EAPOL-Key frame from complete EAPOL frame bytes."""
        if len(data) < 4:
            raise WiFiConnectionError(
                f"EAPOL frame too short: {len(data)} bytes, minimum 4"
            )
        version = data[0]
        packet_type = data[1]
        if packet_type != EAPOL_PACKET_KEY:
            raise WiFiConnectionError(
                f"Not an EAPOL-Key frame: packet_type={packet_type}"
            )
        body_length = struct.unpack("!H", data[2:4])[0]
        body = data[4 : 4 + body_length]
        return cls.from_eapol_body(version, body)

    def compute_mic(self, ptk: bytes) -> bytes:
        """Compute the MIC for this EAPOL-Key frame using the PTK.

        The MIC is computed over the EAPOL frame with the MIC field
        zeroed out, using HMAC-SHA1 for WPA2 or HMAC-MD5 for WPA.

        Args:
            ptk: The Pairwise Transient Key (KCK is first 16 bytes).

        Returns:
            The computed 16-byte MIC value.
        """
        kck = ptk[:16]
        # Build the frame with MIC zeroed out
        frame_data = bytearray(self.to_eapol_bytes())
        # MIC starts at offset: header(4) + desc_type(1) + key_info(2) +
        # key_length(2) + replay_counter(8) + nonce(32) + iv(16) +
        # rsc(8) + id(8) = 81
        mic_offset = 4 + 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8
        # Zero out the MIC field (16 bytes)
        for i in range(16):
            frame_data[mic_offset + i] = 0

        if self.descriptor_type == KEY_DESC_WPA:
            # WPA uses HMAC-MD5
            h = hmac.new(kck, bytes(frame_data), hashlib.md5)
        else:
            # WPA2 uses HMAC-SHA1, truncated to 16 bytes
            h = hmac.new(kck, bytes(frame_data), hashlib.sha1)
        return h.digest()[:16]

    def verify_mic(self, ptk: bytes) -> bool:
        """Verify the MIC of this EAPOL-Key frame.

        Args:
            ptk: The Pairwise Transient Key.

        Returns:
            True if the MIC is valid, False otherwise.
        """
        computed = self.compute_mic(ptk)
        return hmac.compare_digest(computed, self.key_mic[:16])

    def handshake_message(self) -> HandshakeMessage:
        """Create a HandshakeMessage wrapper for this frame."""
        return HandshakeMessage(self)

    def summary(self) -> Dict[str, Union[int, str, bool]]:
        """Return a summary of the EAPOL-Key frame."""
        msg = self.handshake_message()
        return {
            "version": self.version,
            "descriptor_type": self.descriptor_type,
            "key_info": self.key_info.to_dict(),
            "key_length": self.key_length,
            "replay_counter": self.replay_counter,
            "has_nonce": self.key_nonce != b"\x00" * 32,
            "has_mic": self.key_mic != b"\x00" * 16,
            "key_data_length": self.key_data_length,
            "handshake_message": msg.message_name,
        }

    def __repr__(self) -> str:
        msg = self.handshake_message()
        return f"EAPOLKeyFrame(msg={msg.message_name}, key_type={self.key_info.key_type})"
