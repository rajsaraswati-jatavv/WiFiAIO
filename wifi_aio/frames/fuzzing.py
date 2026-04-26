"""IEEE 802.11 frame fuzzing utilities.

Provides mutation strategies and random field corruption for
fuzzing 802.11 frames to test implementation robustness and
discover vulnerabilities in WiFi stacks.
"""

from __future__ import annotations

import random
import struct
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Tuple, Union

from wifi_aio.frames.base_frame import (
    WiFiFrame,
    FrameControl,
    BROADCAST_MAC,
    NULL_MAC,
    mac_to_bytes,
    bytes_to_mac,
)
from wifi_aio.frames.fcs import FCS
from wifi_aio.exceptions import WiFiConnectionError


class MutationStrategy(Enum):
    """Available mutation strategies for frame fuzzing."""

    BIT_FLIP = auto()
    BYTE_REPLACE = auto()
    BYTE_INSERT = auto()
    BYTE_DELETE = auto()
    FIELD_CORRUPT = auto()
    ADDRESS_SWAP = auto()
    LENGTH_FUZZ = auto()
    DURATION_FUZZ = auto()
    SEQUENCE_FUZZ = auto()
    PAYLOAD_CORRUPT = auto()
    RANDOM_OVERWRITE = auto()
    IE_CORRUPT = auto()
    CHUNK_REPEAT = auto()
    CHUNK_SWAP = auto()


class FrameFuzzer:
    """Fuzzer for IEEE 802.11 frames.

    Applies various mutation strategies to frames to generate
    malformed inputs for testing WiFi stack implementations.
    """

    def __init__(
        self,
        seed: Optional[int] = None,
        mutation_rate: float = 0.1,
        update_fcs: bool = True,
    ):
        """Initialize the frame fuzzer.

        Args:
            seed: Random seed for reproducibility. None for non-deterministic.
            mutation_rate: Probability (0.0-1.0) of mutating each byte/field.
            update_fcs: Whether to update the FCS after mutation.
        """
        self._rng = random.Random(seed)
        self.mutation_rate = mutation_rate
        self.update_fcs = update_fcs
        self._strategy_handlers: Dict[MutationStrategy, Callable] = {
            MutationStrategy.BIT_FLIP: self._mutate_bit_flip,
            MutationStrategy.BYTE_REPLACE: self._mutate_byte_replace,
            MutationStrategy.BYTE_INSERT: self._mutate_byte_insert,
            MutationStrategy.BYTE_DELETE: self._mutate_byte_delete,
            MutationStrategy.FIELD_CORRUPT: self._mutate_field_corrupt,
            MutationStrategy.ADDRESS_SWAP: self._mutate_address_swap,
            MutationStrategy.LENGTH_FUZZ: self._mutate_length_fuzz,
            MutationStrategy.DURATION_FUZZ: self._mutate_duration_fuzz,
            MutationStrategy.SEQUENCE_FUZZ: self._mutate_sequence_fuzz,
            MutationStrategy.PAYLOAD_CORRUPT: self._mutate_payload_corrupt,
            MutationStrategy.RANDOM_OVERWRITE: self._mutate_random_overwrite,
            MutationStrategy.IE_CORRUPT: self._mutate_ie_corrupt,
            MutationStrategy.CHUNK_REPEAT: self._mutate_chunk_repeat,
            MutationStrategy.CHUNK_SWAP: self._mutate_chunk_swap,
        }

    def fuzz(
        self,
        frame: Union[WiFiFrame, bytes],
        strategies: Optional[List[MutationStrategy]] = None,
        num_mutations: int = 1,
    ) -> bytes:
        """Apply fuzzing mutations to a frame.

        Args:
            frame: The frame to fuzz (WiFiFrame object or raw bytes).
            strategies: List of mutation strategies to apply. If None,
                applies a random strategy for each mutation.
            num_mutations: Number of mutations to apply.

        Returns:
            The mutated frame as bytes.
        """
        if isinstance(frame, WiFiFrame):
            data = bytearray(frame.to_bytes())
        else:
            data = bytearray(frame)

        for _ in range(num_mutations):
            if strategies:
                strategy = self._rng.choice(strategies)
            else:
                strategy = self._rng.choice(list(MutationStrategy))

            handler = self._strategy_handlers.get(strategy)
            if handler:
                data = bytearray(handler(bytes(data)))

        if self.update_fcs and len(data) >= 4:
            data = bytearray(FCS.append(FCS.strip(bytes(data)) if len(data) > 4 else bytes(data)))

        return bytes(data)

    def fuzz_field(
        self,
        frame: Union[WiFiFrame, bytes],
        offset: int,
        size: int,
        strategy: MutationStrategy = MutationStrategy.BIT_FLIP,
    ) -> bytes:
        """Fuzz a specific field within a frame.

        Args:
            frame: The frame to fuzz.
            offset: Byte offset of the field.
            size: Size of the field in bytes.
            strategy: Mutation strategy to apply to the field.

        Returns:
            The mutated frame as bytes.
        """
        if isinstance(frame, WiFiFrame):
            data = bytearray(frame.to_bytes())
        else:
            data = bytearray(frame)

        if offset + size > len(data):
            raise WiFiConnectionError(
                f"Field offset/size out of bounds: offset={offset}, size={size}, "
                f"frame_length={len(data)}"
            )

        field_data = bytes(data[offset : offset + size])
        handler = self._strategy_handlers.get(strategy)
        if handler:
            mutated = handler(field_data)
            data[offset : offset + size] = mutated[:size]

        if self.update_fcs and len(data) >= 4:
            frame_without_fcs = bytes(data[:-4]) if len(data) > 4 else bytes(data)
            data = bytearray(FCS.append(frame_without_fcs))

        return bytes(data)

    def generate_corpus(
        self,
        frame: Union[WiFiFrame, bytes],
        count: int = 100,
        strategies: Optional[List[MutationStrategy]] = None,
        mutations_per_frame: int = 1,
    ) -> List[bytes]:
        """Generate a corpus of fuzzed frames.

        Args:
            frame: The base frame to mutate.
            count: Number of mutated frames to generate.
            strategies: Strategies to use. None for random.
            mutations_per_frame: Number of mutations per generated frame.

        Returns:
            List of mutated frame bytes.
        """
        corpus = []
        for _ in range(count):
            mutated = self.fuzz(frame, strategies, mutations_per_frame)
            corpus.append(mutated)
        return corpus

    def smart_fuzz_beacon(self, frame_bytes: bytes) -> List[bytes]:
        """Apply beacon-specific fuzzing strategies.

        Targets fields commonly processed in beacon frames such as
        SSID length, channel, RSN IE, and HT capabilities.

        Args:
            frame_bytes: Raw beacon frame bytes.

        Returns:
            List of mutated beacon frames.
        """
        results = []
        data = bytearray(frame_bytes)

        # Fuzz SSID length (offset 36 in typical beacon: FC(2)+Dur(2)+Addr1(6)+
        # Addr2(6)+Addr3(6)+SeqCtrl(2)+Timestamp(8)+BI(2)+Cap(2)+SSID_ID(1)+SSID_LEN(1))
        if len(data) > 37:
            for ssid_len in [0, 32, 64, 128, 255, self._rng.randint(0, 255)]:
                mutated = bytearray(data)
                mutated[37] = ssid_len
                results.append(bytes(mutated))

        # Fuzz channel in DS Parameter IE
        for ch_offset in self._find_ie_offsets(data, 3):
            for channel in [0, 1, 14, 165, 200, 255]:
                mutated = bytearray(data)
                if ch_offset + 2 < len(mutated):
                    mutated[ch_offset + 2] = channel
                    results.append(bytes(mutated))

        # Fuzz RSN IE
        for rsn_offset in self._find_ie_offsets(data, 48):
            mutated = bytearray(data)
            if rsn_offset + 2 < len(mutated):
                # Corrupt version field
                mutated[rsn_offset + 2] = self._rng.randint(0, 255)
                results.append(bytes(mutated))

        # Fuzz capability field
        if len(data) >= 24:
            for cap_offset in [22, 23]:
                mutated = bytearray(data)
                mutated[cap_offset] ^= 0xFF
                results.append(bytes(mutated))

        return results

    def smart_fuzz_eapol(self, frame_bytes: bytes) -> List[bytes]:
        """Apply EAPOL-specific fuzzing strategies.

        Targets key fields in EAPOL-Key frames used in the 4-way
        handshake including key info, nonce, and MIC.

        Args:
            frame_bytes: Raw EAPOL frame bytes.

        Returns:
            List of mutated EAPOL frames.
        """
        results = []
        data = bytearray(frame_bytes)

        if len(data) < 99:
            return results

        # Fuzz Key Information field (offset 5-6 in EAPOL-Key body)
        for key_info_val in [0x0000, 0xFFFF, 0x0088, 0x01C8, 0x13C8, self._rng.randint(0, 0xFFFF)]:
            mutated = bytearray(data)
            struct.pack_into("!H", mutated, 5, key_info_val)
            results.append(bytes(mutated))

        # Fuzz descriptor type
        for desc_type in [0, 1, 2, 254, 255]:
            mutated = bytearray(data)
            mutated[4] = desc_type
            results.append(bytes(mutated))

        # Fuzz key nonce (offset 9-40)
        for _ in range(5):
            mutated = bytearray(data)
            nonce_offset = 9
            for i in range(32):
                if nonce_offset + i < len(mutated) and self._rng.random() < 0.3:
                    mutated[nonce_offset + i] = self._rng.randint(0, 255)
            results.append(bytes(mutated))

        # Fuzz MIC (offset 81-96)
        for _ in range(5):
            mutated = bytearray(data)
            mic_offset = 81
            for i in range(16):
                if mic_offset + i < len(mutated):
                    mutated[mic_offset + i] = self._rng.randint(0, 255)
            results.append(bytes(mutated))

        # Fuzz replay counter (offset 1-8 in key body)
        for _ in range(3):
            mutated = bytearray(data)
            rc_offset = 1
            for i in range(8):
                if rc_offset + i < len(mutated):
                    mutated[rc_offset + i] = self._rng.randint(0, 255)
            results.append(bytes(mutated))

        return results

    # ── Mutation Strategy Implementations ──────────────────────────────

    def _mutate_bit_flip(self, data: bytes) -> bytes:
        """Flip random bits in the data."""
        result = bytearray(data)
        for i in range(len(result)):
            if self._rng.random() < self.mutation_rate:
                bit = self._rng.randint(0, 7)
                result[i] ^= (1 << bit)
        return bytes(result)

    def _mutate_byte_replace(self, data: bytes) -> bytes:
        """Replace random bytes with random values."""
        result = bytearray(data)
        for i in range(len(result)):
            if self._rng.random() < self.mutation_rate:
                result[i] = self._rng.randint(0, 255)
        return bytes(result)

    def _mutate_byte_insert(self, data: bytes) -> bytes:
        """Insert random bytes at random positions."""
        result = bytearray(data)
        num_inserts = max(1, int(len(data) * self.mutation_rate))
        for _ in range(num_inserts):
            pos = self._rng.randint(0, len(result))
            result.insert(pos, self._rng.randint(0, 255))
        return bytes(result)

    def _mutate_byte_delete(self, data: bytes) -> bytes:
        """Delete random bytes from the data."""
        if len(data) <= 2:
            return data
        result = bytearray(data)
        num_deletes = max(1, int(len(data) * self.mutation_rate))
        for _ in range(num_deletes):
            if len(result) <= 2:
                break
            pos = self._rng.randint(0, len(result) - 1)
            del result[pos]
        return bytes(result)

    def _mutate_field_corrupt(self, data: bytes) -> bytes:
        """Corrupt a random field in the 802.11 header."""
        result = bytearray(data)
        if len(result) < 24:
            return data

        # Define header field boundaries
        fields = [
            (0, 2, "Frame Control"),
            (2, 4, "Duration"),
            (4, 10, "Address 1"),
            (10, 16, "Address 2"),
            (16, 22, "Address 3"),
            (22, 24, "Sequence Control"),
        ]
        field = self._rng.choice(fields)
        start, end, name = field
        for i in range(start, min(end, len(result))):
            result[i] = self._rng.randint(0, 255)
        return bytes(result)

    def _mutate_address_swap(self, data: bytes) -> bytes:
        """Swap or corrupt MAC addresses in the frame header."""
        result = bytearray(data)
        if len(result) < 22:
            return data

        # Pick two address fields to swap
        addr_offsets = [4, 10, 16]
        choices = self._rng.sample(addr_offsets, 2)
        a1, a2 = choices[0], choices[1]
        if a1 + 6 <= len(result) and a2 + 6 <= len(result):
            result[a1:a1+6], result[a2:a2+6] = bytes(result[a2:a2+6]), bytes(result[a1:a1+6])
        return bytes(result)

    def _mutate_length_fuzz(self, data: bytes) -> bytes:
        """Fuzz length fields in the frame or IEs."""
        result = bytearray(data)
        if len(result) < 24:
            return data

        # Find and fuzz IE length fields in the payload
        offset = 24  # After standard header
        while offset + 2 <= len(result):
            ie_id = result[offset]
            ie_len = result[offset + 1]
            if self._rng.random() < self.mutation_rate:
                # Corrupt the IE length
                result[offset + 1] = self._rng.randint(0, 255)
            offset += 2 + ie_len
            if ie_len == 0 and self._rng.random() > 0.5:
                offset += 1  # Prevent infinite loop on zero-length IEs
        return bytes(result)

    def _mutate_duration_fuzz(self, data: bytes) -> bytes:
        """Fuzz the Duration/ID field."""
        result = bytearray(data)
        if len(result) < 4:
            return data
        # Set duration to extreme values
        duration_values = [0x0000, 0x7FFF, 0x8000, 0xFFFF, self._rng.randint(0, 0xFFFF)]
        dur = self._rng.choice(duration_values)
        result[2] = dur & 0xFF
        result[3] = (dur >> 8) & 0xFF
        return bytes(result)

    def _mutate_sequence_fuzz(self, data: bytes) -> bytes:
        """Fuzz the Sequence Control field."""
        result = bytearray(data)
        if len(result) < 24:
            return data
        # Fuzz sequence number and fragment number
        seq_values = [0x0000, 0x0FFF, 0xFFF0, 0xFFFF, self._rng.randint(0, 0xFFFF)]
        seq = self._rng.choice(seq_values)
        result[22] = seq & 0xFF
        result[23] = (seq >> 8) & 0xFF
        return bytes(result)

    def _mutate_payload_corrupt(self, data: bytes) -> bytes:
        """Corrupt bytes in the frame payload."""
        result = bytearray(data)
        if len(result) <= 24:
            return data
        for i in range(24, len(result)):
            if self._rng.random() < self.mutation_rate:
                result[i] = self._rng.randint(0, 255)
        return bytes(result)

    def _mutate_random_overwrite(self, data: bytes) -> bytes:
        """Overwrite a random contiguous chunk with random bytes."""
        result = bytearray(data)
        if len(result) == 0:
            return data
        chunk_size = self._rng.randint(1, max(1, len(result) // 4))
        start = self._rng.randint(0, max(0, len(result) - chunk_size))
        for i in range(start, min(start + chunk_size, len(result))):
            result[i] = self._rng.randint(0, 255)
        return bytes(result)

    def _mutate_ie_corrupt(self, data: bytes) -> bytes:
        """Corrupt Information Element structure in the frame body."""
        result = bytearray(data)
        if len(result) < 26:
            return data

        offset = 24  # Start of IEs in management frames
        ies = []
        while offset + 2 <= len(result):
            ie_id = result[offset]
            ie_len = result[offset + 1]
            ies.append((offset, ie_id, ie_len))
            offset += 2 + ie_len
            if ie_len == 0:
                offset += 1  # Prevent infinite loop

        if not ies:
            return data

        # Pick a random IE and corrupt it
        ie_offset, ie_id, ie_len = self._rng.choice(ies)
        corruption_type = self._rng.randint(0, 3)
        if corruption_type == 0:
            # Change IE ID
            result[ie_offset] = self._rng.randint(0, 255)
        elif corruption_type == 1:
            # Change IE length
            result[ie_offset + 1] = self._rng.randint(0, 255)
        elif corruption_type == 2 and ie_len > 0:
            # Corrupt IE data
            data_offset = ie_offset + 2
            if data_offset < len(result):
                result[data_offset] = self._rng.randint(0, 255)
        elif corruption_type == 3:
            # Overlap with next IE
            if ie_offset + 2 < len(result):
                result[ie_offset + 1] = min(255, ie_len + self._rng.randint(1, 10))
        return bytes(result)

    def _mutate_chunk_repeat(self, data: bytes) -> bytes:
        """Repeat a random chunk of data, inserting the duplicate adjacent."""
        result = bytearray(data)
        if len(result) < 4:
            return data
        chunk_size = self._rng.randint(1, min(32, len(result) // 2))
        start = self._rng.randint(0, len(result) - chunk_size)
        chunk = result[start:start + chunk_size]
        insert_pos = self._rng.randint(0, len(result))
        for i, b in enumerate(chunk):
            result.insert(insert_pos + i, b)
        return bytes(result)

    def _mutate_chunk_swap(self, data: bytes) -> bytes:
        """Swap two random chunks of data."""
        result = bytearray(data)
        if len(result) < 4:
            return data
        chunk_size = self._rng.randint(1, min(16, len(result) // 4))
        pos1 = self._rng.randint(0, len(result) - chunk_size * 2)
        pos2 = self._rng.randint(pos1 + chunk_size, min(pos1 + chunk_size * 3, len(result) - chunk_size))
        chunk1 = bytes(result[pos1:pos1 + chunk_size])
        chunk2 = bytes(result[pos2:pos2 + chunk_size])
        result[pos1:pos1 + chunk_size] = chunk2
        result[pos2:pos2 + chunk_size] = chunk1
        return bytes(result)

    @staticmethod
    def _find_ie_offsets(data: bytearray, ie_id: int) -> List[int]:
        """Find offsets of a specific IE in the frame body.

        Args:
            data: Frame data.
            ie_id: IE element ID to search for.

        Returns:
            List of offsets where the IE starts.
        """
        offsets = []
        offset = 24  # Start after standard header
        while offset + 2 <= len(data):
            current_id = data[offset]
            current_len = data[offset + 1]
            if current_id == ie_id:
                offsets.append(offset)
            offset += 2 + current_len
            if current_len == 0:
                offset += 1
        return offsets
