"""Tests for wifi_aio.utils.

Covers random_mac, channel_to_freq / freq_to_channel,
sanitize_filename, and is_root.
"""

import os
from typing import Set

import pytest

from wifi_aio.utils import (
    channel_to_freq,
    freq_to_channel,
    is_root,
    mac_format,
    random_hex,
    random_mac,
    sanitize_filename,
)


# ── random_mac ───────────────────────────────────────────────────────────

class TestRandomMac:
    """Random MAC address generation."""

    def test_format(self) -> None:
        """Output must be XX:XX:XX:XX:XX:XX lowercase hex."""
        mac = random_mac()
        parts = mac.split(":")
        assert len(parts) == 6
        for part in parts:
            assert len(part) == 2
            int(part, 16)  # must be valid hex

    def test_locally_administered_bit(self) -> None:
        """The locally-administered bit (bit 1 of the first octet) must be set."""
        for _ in range(50):
            mac = random_mac()
            first_octet = int(mac.split(":")[0], 16)
            assert first_octet & 0x02, f"L/A bit not set in {mac}"

    def test_not_multicast(self) -> None:
        """The multicast bit (bit 0 of the first octet) must be clear."""
        for _ in range(50):
            mac = random_mac()
            first_octet = int(mac.split(":")[0], 16)
            assert not (first_octet & 0x01), f"Multicast bit set in {mac}"

    def test_uniqueness(self) -> None:
        """Two generated MACs should differ (probabilistically)."""
        macs: Set[str] = {random_mac() for _ in range(100)}
        assert len(macs) == 100


# ── random_hex ───────────────────────────────────────────────────────────

class TestRandomHex:
    """Random hex string generation."""

    def test_length(self) -> None:
        assert len(random_hex(16)) == 16

    def test_even_length(self) -> None:
        h = random_hex(10)
        assert len(h) == 10
        assert all(c in "0123456789abcdef" for c in h)


# ── mac_format ───────────────────────────────────────────────────────────

class TestMacFormat:
    """MAC address formatting / normalisation."""

    def test_dash_to_colon(self) -> None:
        assert mac_format("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"

    def test_no_sep(self) -> None:
        assert mac_format("AABBCCDDEEFF") == "aa:bb:cc:dd:ee:ff"

    def test_invalid_length_raises(self) -> None:
        with pytest.raises(ValueError):
            mac_format("AA:BB")


# ── channel_to_freq / freq_to_channel ────────────────────────────────────

class TestChannelFreq:
    """Channel ↔ frequency conversion."""

    def test_channel_1(self) -> None:
        assert channel_to_freq(1) == 2412

    def test_channel_6(self) -> None:
        assert channel_to_freq(6) == 2437

    def test_channel_11(self) -> None:
        assert channel_to_freq(11) == 2462

    def test_channel_36(self) -> None:
        assert channel_to_freq(36) == 5180

    def test_unknown_channel_returns_zero(self) -> None:
        assert channel_to_freq(999) == 0

    def test_freq_to_channel_2412(self) -> None:
        assert freq_to_channel(2412) == 1

    def test_freq_to_channel_2437(self) -> None:
        assert freq_to_channel(2437) == 6

    def test_freq_to_channel_5180(self) -> None:
        assert freq_to_channel(5180) == 36

    def test_unknown_freq_returns_zero(self) -> None:
        assert freq_to_channel(9999) == 0

    def test_roundtrip(self) -> None:
        """channel → freq → channel should return the original channel."""
        for ch in [1, 6, 11, 36, 149]:
            assert freq_to_channel(channel_to_freq(ch)) == ch


# ── sanitize_filename ────────────────────────────────────────────────────

class TestSanitizeFilename:
    """File-name sanitisation."""

    def test_simple_name(self) -> None:
        assert sanitize_filename("report.txt") == "report.txt"

    def test_strips_directory(self) -> None:
        assert sanitize_filename("/tmp/evil/report.txt") == "report.txt"

    def test_replaces_special_chars(self) -> None:
        result = sanitize_filename("my file (1).txt")
        assert " " not in result
        assert "(" not in result

    def test_collapses_underscores(self) -> None:
        result = sanitize_filename("a   b")
        assert "___" not in result

    def test_empty_returns_unnamed(self) -> None:
        assert sanitize_filename("") == "unnamed"

    def test_only_dots_returns_unnamed(self) -> None:
        assert sanitize_filename("...") == "unnamed"


# ── is_root ──────────────────────────────────────────────────────────────

class TestIsRoot:
    """Root-privilege check."""

    def test_returns_bool(self) -> None:
        result = is_root()
        assert isinstance(result, bool)

    def test_non_root_in_test_env(self) -> None:
        """In a typical test environment we're not root."""
        # This test documents expected behaviour; it will pass as root
        # only if tests are intentionally run with sudo.
        assert is_root() == (os.geteuid() == 0)
