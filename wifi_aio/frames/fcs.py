"""Frame Check Sequence (FCS) computation and verification for 802.11 frames.

Implements the CRC-32 algorithm used in IEEE 802.11 frames for
error detection. The FCS is appended to the end of every 802.11
frame before transmission.
"""

from __future__ import annotations

from typing import Optional

from wifi_aio.exceptions import WiFiConnectionError


# CRC-32 lookup table using the IEEE 802.11 polynomial 0xEDB88320
# (bit-reversed representation of 0x04C11DB7)
_CRC32_TABLE: list[int] = []


def _build_crc32_table() -> None:
    """Build the CRC-32 lookup table for fast computation."""
    global _CRC32_TABLE
    _CRC32_TABLE = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
        _CRC32_TABLE.append(crc)


# Initialize the table on module load
_build_crc32_table()


def compute_crc32(data: bytes) -> int:
    """Compute the CRC-32 checksum for the given data.

    Uses the IEEE 802.11 polynomial (same as Ethernet, ZIP, etc.).

    Args:
        data: The bytes to compute the CRC-32 over.

    Returns:
        The 32-bit CRC value as an unsigned integer.
    """
    crc = 0xFFFFFFFF
    for byte in data:
        crc = (crc >> 8) ^ _CRC32_TABLE[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFFFFFF


def compute_fcs(data: bytes) -> bytes:
    """Compute the 4-byte FCS (Frame Check Sequence) for a frame.

    The FCS is a CRC-32 value computed over the entire frame
    (excluding the FCS itself), stored in little-endian order.

    Args:
        data: The frame bytes (without FCS).

    Returns:
        4-byte FCS value in little-endian order.
    """
    crc = compute_crc32(data)
    return crc.to_bytes(4, byteorder="little")


class FCS:
    """Frame Check Sequence handler for IEEE 802.11 frames.

    Provides methods to compute, append, verify, and strip
    the CRC-32 FCS from 802.11 frames.
    """

    @staticmethod
    def compute(data: bytes) -> int:
        """Compute the CRC-32 checksum for the given frame data.

        Args:
            data: Frame bytes (without FCS).

        Returns:
            The 32-bit CRC value as an unsigned integer.
        """
        return compute_crc32(data)

    @staticmethod
    def compute_bytes(data: bytes) -> bytes:
        """Compute the FCS as 4 bytes in little-endian order.

        Args:
            data: Frame bytes (without FCS).

        Returns:
            4-byte FCS in little-endian byte order.
        """
        return compute_fcs(data)

    @staticmethod
    def append(data: bytes) -> bytes:
        """Append the FCS to the frame data.

        Args:
            data: Frame bytes (without FCS).

        Returns:
            Frame bytes with FCS appended (4 bytes, little-endian).
        """
        return data + compute_fcs(data)

    @staticmethod
    def verify(data_with_fcs: bytes) -> bool:
        """Verify the FCS of a frame that includes the trailing FCS.

        The verification works by computing the CRC-32 of the
        entire frame (including FCS) and checking that the result
        is the magic residue value 0x2144DF1C (the "CRC residue"
        for a correctly received frame).

        Args:
            data_with_fcs: Frame bytes including the 4-byte FCS.

        Returns:
            True if the FCS is valid, False otherwise.
        """
        if len(data_with_fcs) < 4:
            return False
        # Compute CRC-32 over the entire frame including FCS
        crc = compute_crc32(data_with_fcs)
        # The CRC residue for a valid frame should be 0x2144DF1C
        return crc == 0x2144DF1C

    @staticmethod
    def verify_explicit(data: bytes, expected_fcs: bytes) -> bool:
        """Verify the FCS by comparing against an expected value.

        Args:
            data: Frame bytes (without FCS).
            expected_fcs: The expected 4-byte FCS value.

        Returns:
            True if the computed FCS matches the expected FCS.
        """
        if len(expected_fcs) != 4:
            return False
        computed = compute_fcs(data)
        return computed == expected_fcs

    @staticmethod
    def strip(data_with_fcs: bytes) -> bytes:
        """Remove the trailing 4-byte FCS from frame data.

        Args:
            data_with_fcs: Frame bytes including the FCS.

        Returns:
            Frame bytes without the FCS.

        Raises:
            WiFiConnectionError: If the data is too short to contain an FCS.
        """
        if len(data_with_fcs) < 4:
            raise WiFiConnectionError(
                f"Data too short to contain FCS: {len(data_with_fcs)} bytes, minimum 4",
                details="Cannot strip FCS from data shorter than 4 bytes.",
            )
        return data_with_fcs[:-4]

    @staticmethod
    def extract_fcs(data_with_fcs: bytes) -> int:
        """Extract the FCS value from the end of a frame.

        Args:
            data_with_fcs: Frame bytes including the FCS.

        Returns:
            The FCS value as an unsigned 32-bit integer.

        Raises:
            WiFiConnectionError: If the data is too short.
        """
        if len(data_with_fcs) < 4:
            raise WiFiConnectionError(
                f"Data too short to extract FCS: {len(data_with_fcs)} bytes"
            )
        return int.from_bytes(data_with_fcs[-4:], byteorder="little")

    @staticmethod
    def is_valid_frame(data: bytes) -> bool:
        """Check if data contains a valid frame with FCS.

        If the data is at least 4 bytes, verifies the FCS.
        If shorter, returns False.

        Args:
            data: Raw frame data possibly including FCS.

        Returns:
            True if the frame has a valid FCS.
        """
        return FCS.verify(data)
