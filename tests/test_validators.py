"""Tests for wifi_aio.validators.

Covers MAC, SSID, channel, IP, BSSID, and WPS-PIN validation with
both valid and invalid inputs.
"""

import pytest

from wifi_aio.exceptions import ConfigurationError
from wifi_aio.validators import (
    validate_channel,
    validate_ip,
    validate_mac,
    validate_ssid,
    validate_wps_pin,
)


# ── validate_mac ─────────────────────────────────────────────────────────

class TestValidateMac:
    """MAC address validation and normalisation."""

    def test_valid_colon_mac(self) -> None:
        assert validate_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

    def test_valid_dash_mac(self) -> None:
        assert validate_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"

    def test_valid_no_sep_mac(self) -> None:
        assert validate_mac("AABBCCDDEEFF") == "aa:bb:cc:dd:ee:ff"

    def test_lowercase_input(self) -> None:
        assert validate_mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"

    def test_mixed_case(self) -> None:
        assert validate_mac("Aa:Bb:Cc:Dd:Ee:Ff") == "aa:bb:cc:dd:ee:ff"

    def test_empty_mac_raises(self) -> None:
        with pytest.raises(ConfigurationError):
            validate_mac("")

    def test_invalid_mac_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="Invalid MAC"):
            validate_mac("ZZ:ZZ:ZZ:ZZ:ZZ:ZZ")

    def test_too_short_mac_raises(self) -> None:
        with pytest.raises(ConfigurationError):
            validate_mac("AA:BB:CC")

    def test_whitespace_stripped(self) -> None:
        assert validate_mac("  AA:BB:CC:DD:EE:FF  ") == "aa:bb:cc:dd:ee:ff"


# ── validate_ssid ────────────────────────────────────────────────────────

class TestValidateSsid:
    """SSID string validation."""

    def test_valid_ssid(self) -> None:
        assert validate_ssid("MyNetwork") == "MyNetwork"

    def test_valid_ssid_with_spaces(self) -> None:
        assert validate_ssid("My Network") == "My Network"

    def test_valid_ssid_max_length(self) -> None:
        ssid = "A" * 32
        assert validate_ssid(ssid) == ssid

    def test_empty_ssid_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="empty"):
            validate_ssid("")

    def test_ssid_too_long_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="too long"):
            validate_ssid("A" * 33)


# ── validate_channel ─────────────────────────────────────────────────────

class TestValidateChannel:
    """WiFi channel number validation."""

    def test_valid_2ghz_channel(self) -> None:
        assert validate_channel(1) == 1
        assert validate_channel(6) == 6
        assert validate_channel(11) == 11

    def test_valid_5ghz_channel(self) -> None:
        assert validate_channel(36) == 36
        assert validate_channel(149) == 149

    def test_channel_14_valid(self) -> None:
        """Channel 14 is valid in some regulatory domains (2.4 GHz)."""
        assert validate_channel(14) == 14

    def test_invalid_channel_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="Invalid channel"):
            validate_channel(0)

    def test_channel_15_raises(self) -> None:
        with pytest.raises(ConfigurationError):
            validate_channel(15)


# ── validate_ip ──────────────────────────────────────────────────────────

class TestValidateIp:
    """IPv4 address validation."""

    def test_valid_ip(self) -> None:
        assert validate_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_ip_zero(self) -> None:
        assert validate_ip("0.0.0.0") == "0.0.0.0"

    def test_valid_ip_max(self) -> None:
        assert validate_ip("255.255.255.255") == "255.255.255.255"

    def test_invalid_ip_octet_256(self) -> None:
        with pytest.raises(ConfigurationError, match="Invalid IPv4"):
            validate_ip("192.168.1.256")

    def test_invalid_ip_letters(self) -> None:
        with pytest.raises(ConfigurationError):
            validate_ip("abc.def.ghi.jkl")

    def test_invalid_ip_missing_octet(self) -> None:
        with pytest.raises(ConfigurationError):
            validate_ip("192.168.1")

    def test_whitespace_stripped(self) -> None:
        assert validate_ip("  10.0.0.1  ") == "10.0.0.1"


# ── validate_wps_pin ────────────────────────────────────────────────────

class TestValidateWpsPin:
    """WPS PIN validation (4-digit half-PIN and 8-digit with checksum)."""

    def test_valid_4digit_pin(self) -> None:
        assert validate_wps_pin("1234") == "1234"

    def test_valid_8digit_pin(self) -> None:
        """Verify a PIN that passes the WPS checksum algorithm.

        Uses the known checksum algorithm: compute the checksum for
        the first 7 digits and append it.
        """
        from wifi_aio.validators import _wps_checksum_ok
        # "00000000" passes the checksum (all-zero → checksum 0)
        assert _wps_checksum_ok("00000000")
        result = validate_wps_pin("00000000")
        assert result == "00000000"

    def test_invalid_8digit_bad_checksum(self) -> None:
        with pytest.raises(ConfigurationError, match="checksum"):
            validate_wps_pin("12345678")

    def test_non_numeric_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="Invalid WPS PIN"):
            validate_wps_pin("abcd")

    def test_wrong_length_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="4 or 8"):
            validate_wps_pin("123456")

    def test_whitespace_stripped(self) -> None:
        assert validate_wps_pin("  1234  ") == "1234"
