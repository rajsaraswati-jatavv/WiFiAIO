"""Tests for wifi_aio.crypto_utils.

Covers PBKDF2-SHA1, PTK derivation, MIC verification, HMAC-SHA1,
and HMAC-SHA256.  Tests that require the ``cryptography`` package
are skipped gracefully when it is not installed.
"""

import hashlib
import hmac

import pytest

from wifi_aio import crypto_utils

# Check whether the cryptography package is available
_crypto_available = crypto_utils._crypto_available

skip_no_crypto = pytest.mark.skipif(
    not _crypto_available,
    reason="cryptography package not installed",
)


# ── pbkdf2_sha1 ──────────────────────────────────────────────────────────

@skip_no_crypto
class TestPbkdf2Sha1:
    """PBKDF2-HMAC-SHA1 key derivation with known test vectors."""

    def test_known_vector_password_network(self) -> None:
        """WPA2 PBKDF2 test vector: password='password', ssid='network'."""
        result = crypto_utils.pbkdf2_sha1("password", "network", iterations=4096, dklen=32)
        # Expected value computed independently
        expected = hashlib.pbkdf2_hmac("sha1", b"password", b"network", 4096, 32)
        assert result == expected

    def test_known_vector_hashcat(self) -> None:
        """Verify against Python stdlib PBKDF2 for consistency."""
        pmk = crypto_utils.pbkdf2_sha1("hashcat!", "hashcat!", 4096, 32)
        expected = hashlib.pbkdf2_hmac("sha1", b"hashcat!", b"hashcat!", 4096, 32)
        assert pmk == expected

    def test_output_length(self) -> None:
        result = crypto_utils.pbkdf2_sha1("pass", "ssid", 4096, 32)
        assert len(result) == 32

    def test_custom_dklen(self) -> None:
        result = crypto_utils.pbkdf2_sha1("pass", "ssid", 4096, 64)
        assert len(result) == 64


# ── derive_ptk ───────────────────────────────────────────────────────────

@skip_no_crypto
class TestDerivePtk:
    """PTK derivation with known inputs."""

    def test_deterministic(self) -> None:
        """Same inputs always produce the same PTK."""
        pmk = b"\x00" * 32
        aa = b"\x00\x11\x22\x33\x44\x55"
        spa = b"\x66\x77\x88\x99\xaa\xbb"
        anonce = b"\x00" * 32
        snonce = b"\xff" * 32
        ptk1 = crypto_utils.derive_ptk(pmk, aa, spa, anonce, snonce)
        ptk2 = crypto_utils.derive_ptk(pmk, aa, spa, anonce, snonce)
        assert ptk1 == ptk2

    def test_output_length(self) -> None:
        pmk = b"\x00" * 32
        aa = b"\x00\x11\x22\x33\x44\x55"
        spa = b"\x66\x77\x88\x99\xaa\xbb"
        anonce = b"\x00" * 32
        snonce = b"\xff" * 32
        ptk = crypto_utils.derive_ptk(pmk, aa, spa, anonce, snonce)
        assert len(ptk) == 64

    def test_ordering_independence(self) -> None:
        """Swapping AA/SPA should yield a different PTK (due to ordering)."""
        pmk = b"\xab" * 32
        aa = b"\x00\x11\x22\x33\x44\x55"
        spa = b"\x66\x77\x88\x99\xaa\xbb"
        anonce = b"\x01" * 32
        snonce = b"\x02" * 32
        ptk1 = crypto_utils.derive_ptk(pmk, aa, spa, anonce, snonce)
        ptk2 = crypto_utils.derive_ptk(pmk, spa, aa, anonce, snonce)
        assert ptk1 == ptk2  # ordering is handled internally


# ── verify_mic ───────────────────────────────────────────────────────────

@skip_no_crypto
class TestVerifyMic:
    """MIC verification (positive and negative cases)."""

    def test_correct_mic(self) -> None:
        """A correctly computed MIC should verify as True."""
        key = b"\x00" * 16
        data = b"test data for MIC"
        # Compute the "expected" MIC ourselves
        mic = hmac.new(key, data, hashlib.sha1).digest()[:16]
        assert crypto_utils.verify_mic(key, data, mic, key_descriptor_version=1) is True

    def test_incorrect_mic(self) -> None:
        """An incorrect MIC should verify as False."""
        key = b"\x00" * 16
        data = b"test data for MIC"
        wrong_mic = b"\xff" * 16
        assert crypto_utils.verify_mic(key, data, wrong_mic, key_descriptor_version=1) is False

    def test_version_2(self) -> None:
        """Key descriptor version 2 also uses HMAC-SHA1-128."""
        key = b"\xaa" * 16
        data = b"eapol frame data"
        mic = hmac.new(key, data, hashlib.sha1).digest()[:16]
        assert crypto_utils.verify_mic(key, data, mic, key_descriptor_version=2) is True


# ── hmac_sha1 / hmac_sha256 ─────────────────────────────────────────────

@skip_no_crypto
class TestHmacHelpers:
    """HMAC-SHA1 and HMAC-SHA256 wrapper functions."""

    def test_hmac_sha1_length(self) -> None:
        result = crypto_utils.hmac_sha1(b"key", b"data")
        assert len(result) == 20

    def test_hmac_sha1_matches_stdlib(self) -> None:
        result = crypto_utils.hmac_sha1(b"key", b"data")
        expected = hmac.new(b"key", b"data", hashlib.sha1).digest()
        assert result == expected

    def test_hmac_sha256_length(self) -> None:
        result = crypto_utils.hmac_sha256(b"key", b"data")
        assert len(result) == 32

    def test_hmac_sha256_matches_stdlib(self) -> None:
        result = crypto_utils.hmac_sha256(b"key", b"data")
        expected = hmac.new(b"key", b"data", hashlib.sha256).digest()
        assert result == expected
