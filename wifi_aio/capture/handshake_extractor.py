"""4-way handshake and PMKID extractor from PCAP files.

Parses captured 802.11 frames to identify complete WPA/WPA2 4-way
handshakes and PMKID frames, which are the two primary inputs for
offline WPA cracking.
"""

import struct
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import CaptureError, PCAPError
from wifi_aio.capture.pcap_reader import PCAPReader, PCAPPacket


# ── 802.11 constants ───────────────────────────────────────────────────

# Frame control field masks
FC_TYPE_MASK = 0x000C
FC_SUBTYPE_MASK = 0x00F0
FC_TYPE_MGT = 0x0000
FC_SUBTYPE_AUTH = 0x00B0
FC_SUBTYPE_ASSOC_REQ = 0x0000
FC_SUBTYPE_REASSOC_REQ = 0x0020

# EAPOL ethertype
EAPOL_ETHERTYPE = 0x888E

# Key information field bits
KEY_INFO_PAIRWISE = 0x0008
KEY_INFO_INSTALL = 0x0040
KEY_INFO_ACK = 0x0080
KEY_INFO_MIC = 0x0200
KEY_INFO_SECURED = 0x0300

# Radiotap header presence flags
RT_FLAGS_TSFT = 0x00000001
RT_FLAGS_FLAGS = 0x00000002
RT_FLAGS_RATE = 0x00000004
RT_FLAGS_CHANNEL = 0x00000008
RT_FLAGS_FHSS = 0x00000010
RT_FLAGS_DBM_SIGNAL = 0x00000020
RT_FLAGS_DBM_NOISE = 0x00000040
RT_FLAGS_LOCK_QUALITY = 0x00000080
RT_FLAGS_TX_ATTENUATION = 0x00000100
RT_FLAGS_DB_TX_ATTENUATION = 0x00000200
RT_FLAGS_DBM_TX_POWER = 0x00000400
RT_FLAGS_ANTENNA = 0x00000800
RT_FLAGS_DB_SIGNAL = 0x00001000
RT_FLAGS_DB_NOISE = 0x00002000
RT_FLAGS_RX_FLAGS = 0x00004000
RT_FLAGS_EXT = 0x10000000


class HandshakeInfo:
    """Information about a captured EAPOL handshake frame."""

    def __init__(
        self,
        bssid: str,
        client_mac: str,
        frame_number: int,
        replay_counter: int,
        key_nonce: bytes,
        key_mic: bytes,
        key_data: bytes,
        raw_frame: bytes,
        timestamp: float,
        anonce: Optional[bytes] = None,
        snonce: Optional[bytes] = None,
        mic: Optional[bytes] = None,
    ) -> None:
        self.bssid = bssid
        self.client_mac = client_mac
        self.frame_number = frame_number
        self.replay_counter = replay_counter
        self.key_nonce = key_nonce
        self.key_mic = key_mic
        self.key_data = key_data
        self.raw_frame = raw_frame
        self.timestamp = timestamp
        self.anonce = anonce
        self.snonce = snonce
        self.mic = mic

    @property
    def is_msg1(self) -> bool:
        return self.frame_number == 1

    @property
    def is_msg2(self) -> bool:
        return self.frame_number == 2

    @property
    def is_msg3(self) -> bool:
        return self.frame_number == 3

    @property
    def is_msg4(self) -> bool:
        return self.frame_number == 4

    def __repr__(self) -> str:
        return (
            f"HandshakeInfo(bssid={self.bssid}, client={self.client_mac}, "
            f"msg={self.frame_number}/4)"
        )


class PMKIDInfo:
    """Information about a captured PMKID from an EAPOL frame."""

    def __init__(
        self,
        bssid: str,
        client_mac: str,
        pmkid: bytes,
        anonce: bytes,
        raw_frame: bytes,
        timestamp: float,
    ) -> None:
        self.bssid = bssid
        self.client_mac = client_mac
        self.pmkid = pmkid
        self.anonce = anonce
        self.raw_frame = raw_frame
        self.timestamp = timestamp

    def __repr__(self) -> str:
        return (
            f"PMKIDInfo(bssid={self.bssid}, client={self.client_mac}, "
            f"pmkid={self.pmkid.hex()[:16]}...)"
        )


class HandshakeExtractor:
    """Extract 4-way handshakes and PMKIDs from a PCAP file.

    Parameters
    ----------
    pcap_path:
        Path to the PCAP/PCAPNG capture file.
    target_bssid:
        If set, only extract handshakes for this BSSID.
    """

    def __init__(
        self,
        pcap_path: str,
        target_bssid: Optional[str] = None,
    ) -> None:
        self.pcap_path = pcap_path
        self.target_bssid = target_bssid.lower() if target_bssid else None

        self._handshakes: Dict[str, Dict[int, HandshakeInfo]] = {}
        self._pmkids: List[PMKIDInfo] = []
        self._ssid_map: Dict[str, str] = {}

    # ── Public API ─────────────────────────────────────────────────────

    def extract(self) -> Dict:
        """Run the extraction and return results.

        Returns
        -------
        dict
            ``{"handshakes": [...], "pmkids": [...], "complete": [...]}`
            where *complete* lists BSSIDs with all 4 messages.
        """
        reader = PCAPReader(self.pcap_path)
        with reader:
            for pkt in reader.iter_packets():
                self._process_packet(pkt.data, pkt.timestamp)

        return self._build_result()

    def extract_handshakes(self) -> List[Dict]:
        """Return only handshake information."""
        result = self.extract()
        return result["handshakes"]

    def extract_pmkids(self) -> List[PMKIDInfo]:
        """Return only PMKID information."""
        result = self.extract()
        return result["pmkids"]

    def is_complete_handshake(self, bssid: str) -> bool:
        """Check whether a complete 4-way handshake exists for *bssid*."""
        bssid = bssid.lower()
        if bssid not in self._handshakes:
            return False
        return len(self._handshakes[bssid]) == 4

    def get_handshake_messages(self, bssid: str) -> Dict[int, HandshakeInfo]:
        """Return the captured handshake messages for *bssid*."""
        return self._handshakes.get(bssid.lower(), {})

    # ── Packet processing ──────────────────────────────────────────────

    def _process_packet(self, raw: bytes, timestamp: float) -> None:
        """Process a single raw packet looking for EAPOL frames."""
        # Strip radiotap header if present
        frame = self._strip_radiotap(raw)
        if frame is None:
            return

        # Check if this is a data frame carrying EAPOL
        if not self._is_data_frame(frame):
            return

        # Parse MAC addresses from the 802.11 header
        addrs = self._parse_mac_addresses(frame)
        if addrs is None:
            return

        bssid, src, dst = addrs

        # Filter by target BSSID
        if self.target_bssid and bssid.lower() != self.target_bssid:
            return

        # Find the EAPOL payload
        eapol_data = self._extract_eapol(frame)
        if eapol_data is None:
            return

        # Parse the EAPOL-Key frame
        key_info = self._parse_eapol_key(eapol_data)
        if key_info is None:
            return

        # Determine the message number
        msg_num = self._classify_message(key_info)
        if msg_num == 0:
            return

        # Check for PMKID in Message 1
        pmkid = self._extract_pmkid_from_eapol(eapol_data, key_info)

        # Build HandshakeInfo
        hs_info = HandshakeInfo(
            bssid=bssid.lower(),
            client_mac=dst.lower() if msg_num in (1, 3) else src.lower(),
            frame_number=msg_num,
            replay_counter=key_info["replay_counter"],
            key_nonce=key_info["nonce"],
            key_mic=key_info["mic"],
            key_data=key_info["key_data"],
            raw_frame=raw,
            timestamp=timestamp,
            anonce=key_info["nonce"] if msg_num in (1, 3) else None,
            snonce=key_info["nonce"] if msg_num in (2, 4) else None,
            mic=key_info["mic"],
        )

        bssid_key = bssid.lower()
        if bssid_key not in self._handshakes:
            self._handshakes[bssid_key] = {}
        self._handshakes[bssid_key][msg_num] = hs_info

        # Store PMKID if found
        if pmkid is not None:
            self._pmkids.append(
                PMKIDInfo(
                    bssid=bssid.lower(),
                    client_mac=dst.lower(),
                    pmkid=pmkid,
                    anonce=key_info["nonce"],
                    raw_frame=raw,
                    timestamp=timestamp,
                )
            )

    # ── Radiotap stripping ─────────────────────────────────────────────

    @staticmethod
    def _strip_radiotap(raw: bytes) -> Optional[bytes]:
        """Strip the radiotap header and return the 802.11 frame."""
        if len(raw) < 4:
            return None

        # Check for radiotap header (version 0)
        version = raw[0]
        if version != 0:
            # May be a raw 802.11 frame without radiotap
            return raw

        hdr_len = struct.unpack("<H", raw[2:4])[0]
        if hdr_len < 4 or hdr_len > len(raw):
            return raw

        return raw[hdr_len:]

    # ── 802.11 frame parsing ───────────────────────────────────────────

    @staticmethod
    def _is_data_frame(frame: bytes) -> bool:
        """Check if the frame is a data frame."""
        if len(frame) < 2:
            return False
        frame_control = struct.unpack("<H", frame[0:2])[0]
        frame_type = frame_control & FC_TYPE_MASK
        return frame_type == 0x0008  # Data frame

    @staticmethod
    def _parse_mac_addresses(frame: bytes) -> Optional[Tuple[str, str, str]]:
        """Extract BSSID, source, and destination MAC addresses.

        Returns ``(bssid, src, dst)`` or ``None`` if the frame is too short.
        """
        if len(frame) < 24:
            return None

        frame_control = struct.unpack("<H", frame[0:2])[0]
        to_ds = (frame_control >> 8) & 0x01
        from_ds = (frame_control >> 8) & 0x02

        # MAC address positions depend on To DS / From DS bits
        addr1 = ":".join(f"{b:02x}" for b in frame[4:10])
        addr2 = ":".join(f"{b:02x}" for b in frame[10:16])
        addr3 = ":".join(f"{b:02x}" for b in frame[16:22])

        if to_ds and not from_ds:
            # To DS: addr1=BSSID, addr2=SA, addr3=DA
            bssid, src, dst = addr1, addr2, addr3
        elif from_ds and not to_ds:
            # From DS: addr1=DA, addr2=BSSID, addr3=SA
            bssid, src, dst = addr2, addr3, addr1
        else:
            # Both or neither: addr1=DA, addr2=SA, addr3=BSSID
            bssid, src, dst = addr3, addr2, addr1

        return bssid, src, dst

    # ── EAPOL extraction ───────────────────────────────────────────────

    @staticmethod
    def _extract_eapol(frame: bytes) -> Optional[bytes]:
        """Extract the EAPOL payload from a data frame."""
        if len(frame) < 30:
            return None

        # Skip 802.11 header (24 bytes) + possible QoS (2 bytes)
        frame_control = struct.unpack("<H", frame[0:2])[0]
        subtype = (frame_control >> 4) & 0x0F
        offset = 24
        if subtype & 0x08:  # QoS data
            offset += 2

        # LLC/SNAP header: DSAP=0xAA, SSAP=0xAA, Ctrl=0x03
        if len(frame) < offset + 8:
            return None
        llc = frame[offset: offset + 8]
        if llc[0:3] != b"\xaa\xaa\x03":
            return None

        # Check ethertype
        ethertype = struct.unpack("!H", llc[5:7])[0]
        if ethertype != EAPOL_ETHERTYPE:
            return None

        return frame[offset + 8:]

    @staticmethod
    def _parse_eapol_key(eapol_data: bytes) -> Optional[Dict]:
        """Parse an EAPOL-Key frame and extract key fields."""
        # EAPOL header: version(1), type(1), length(2)
        # EAPOL-Key: descriptor_type(1), key_info(2), key_length(2),
        #            replay_counter(8), nonce(32), iv(16),
        #            rsc(8), id(8), mic(16), key_data_length(2), key_data(...)
        if len(eapol_data) < 99:
            return None

        # Verify this is an EAPOL-Key frame (type = 3)
        eapol_type = eapol_data[1]
        if eapol_type != 3:
            return None

        key_info = struct.unpack("!H", eapol_data[5:7])[0]
        key_length = struct.unpack("!H", eapol_data[7:9])[0]
        replay_counter = struct.unpack("!Q", eapol_data[9:17])[0]
        nonce = eapol_data[17:49]
        mic = eapol_data[81:97]
        key_data_length = struct.unpack("!H", eapol_data[97:99])[0]

        key_data = b""
        if key_data_length > 0 and len(eapol_data) >= 99 + key_data_length:
            key_data = eapol_data[99: 99 + key_data_length]

        return {
            "key_info": key_info,
            "key_length": key_length,
            "replay_counter": replay_counter,
            "nonce": nonce,
            "mic": mic,
            "key_data_length": key_data_length,
            "key_data": key_data,
        }

    @staticmethod
    def _classify_message(key_info: Dict) -> int:
        """Classify an EAPOL-Key frame into message 1/2/3/4.

        Uses the key_info bits:
          - Msg 1: Pairwise, no ACK, no MIC  (ANonce from AP)
          - Msg 2: Pairwise, MIC             (SNonce from client)
          - Msg 3: Pairwise, ACK, MIC, Install (ANonce from AP)
          - Msg 4: Pairwise, MIC             (no nonce)
        """
        ki = key_info["key_info"]
        has_pairwise = bool(ki & KEY_INFO_PAIRWISE)
        has_ack = bool(ki & KEY_INFO_ACK)
        has_mic = bool(ki & KEY_INFO_MIC)
        has_install = bool(ki & KEY_INFO_INSTALL)

        if not has_pairwise:
            return 0

        if has_ack and not has_mic:
            return 1  # Msg 1
        elif has_mic and not has_ack and not has_install:
            return 2  # Msg 2
        elif has_ack and has_mic and has_install:
            return 3  # Msg 3
        elif has_mic and not has_ack and not has_install:
            # Distinguish msg 4 from msg 2: msg 4 typically has empty nonce
            nonce = key_info.get("nonce", b"")
            if nonce == b"\x00" * 32:
                return 4
            return 2  # Assume msg 2 if nonce is present
        return 0

    @staticmethod
    def _extract_pmkid_from_eapol(eapol_data: bytes, key_info: Dict) -> Optional[bytes]:
        """Extract the PMKID from the Key Data field of an EAPOL-Key frame.

        The PMKID is in the first 16 bytes of the key data when the
        Key Data field starts with a KDE (Key Data Encapsulation) of
        type PMKID (OUI: 00:0F:AC, type: 01).
        """
        kd = key_info.get("key_data", b"")
        if len(kd) < 20:
            return None

        # KDE format: type(1), length(1), OUI(3), data_type(1), data(length-4)
        kde_type = kd[0]
        kde_length = kd[1]
        oui = kd[2:5]
        data_type = kd[5]

        # PMKID KDE: type=0xDD, OUI=00:0F:AC, data_type=0x01
        if kde_type == 0xDD and oui == b"\x00\x0f\xac" and data_type == 0x01:
            pmkid = kd[6:22]
            if len(pmkid) == 16:
                return pmkid

        return None

    # ── Result building ────────────────────────────────────────────────

    def _build_result(self) -> Dict:
        """Build the final extraction result dictionary."""
        handshake_list = []
        complete = []

        for bssid, messages in self._handshakes.items():
            hs_entry = {
                "bssid": bssid,
                "messages": {
                    str(k): {
                        "frame_number": v.frame_number,
                        "replay_counter": v.replay_counter,
                        "nonce": v.key_nonce.hex(),
                        "mic": v.key_mic.hex(),
                        "timestamp": v.timestamp,
                    }
                    for k, v in messages.items()
                },
                "complete": len(messages) >= 2,  # Need at least M1/M2 or M2/M3
                "has_all_four": len(messages) == 4,
            }
            handshake_list.append(hs_entry)
            if len(messages) >= 2:
                complete.append(bssid)

        return {
            "handshakes": handshake_list,
            "pmkids": self._pmkids,
            "complete": complete,
        }
