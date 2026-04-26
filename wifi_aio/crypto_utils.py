"""WiFiAIO cryptographic utilities.

Wraps the ``cryptography`` library to provide WiFi-specific crypto
operations used in WPA/WPA2 handshake analysis, MIC verification and
key derivation.  If the ``cryptography`` package is not installed every
function raises :class:`RuntimeError` with a clear message.
"""

import hashlib
import hmac
import struct
from typing import List, Optional

# ── Lazy import guard ────────────────────────────────────────────────

_crypto_available: bool = False
_AES: object = None
_Cipher: object = None
_modes: object = None
_padding: object = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, modes as _modes
    from cryptography.hazmat.primitives.ciphers.algorithms import AES as _AES
    from cryptography.hazmat.primitives import padding as _padding
    from cryptography.hazmat.backends import default_backend
    _crypto_available = True
except ImportError:
    pass


def _require_crypto() -> None:
    if not _crypto_available:
        raise RuntimeError(
            "The 'cryptography' package is required for crypto operations. "
            "Install it with: pip install cryptography"
        )


# ── PRF (Pseudo-Random Function) – WPA / WPA2 ───────────────────────

def prf(key: bytes, label: bytes, data: bytes, length: int) -> bytes:
    """WPA2 PRF-384 / PRF-X as defined in IEEE 802.11i.

    Parameters
    ----------
    key:
        The key material (PMK for PTK derivation).
    label:
        An ASCII label (e.g. b"Pairwise key expansion").
    data:
        Concatenated context data (AA || SPA || ANonce || SNonce).
    length:
        Desired output length in bytes.

    Returns
    -------
    bytes of *length* bytes.
    """
    _require_crypto()
    output = b""
    counter = 0
    while len(output) < length:
        hmac_input = label + b"\x00" + data + struct.pack(">I", counter)
        output += hmac_sha1(key, hmac_input)
        counter += 1
    return output[:length]


# ── PBKDF2 key derivation ───────────────────────────────────────────

def pbkdf2_sha1(password: str, ssid: str, iterations: int = 4096, dklen: int = 32) -> bytes:
    """Derive a WPA/WPA2 Pairwise Master Key (PMK) using PBKDF2-HMAC-SHA1.

    Parameters
    ----------
    password:
        The ASCII passphrase.
    ssid:
        The SSID (used as salt).
    iterations:
        Iteration count (4096 for WPA2).
    dklen:
        Output key length (32 bytes for WPA2, 64 for WPA3-SAE).
    """
    _require_crypto()
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=dklen,
        salt=ssid.encode("utf-8"),
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def pbkdf2_sha256(password: str, ssid: str, iterations: int = 4096, dklen: int = 32) -> bytes:
    """Derive a PMK using PBKDF2-HMAC-SHA256 (used in some WPA3 flows)."""
    _require_crypto()
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=dklen,
        salt=ssid.encode("utf-8"),
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


# ── PTK derivation ──────────────────────────────────────────────────

def derive_ptk(pmk: bytes, aa: bytes, spa: bytes, anonce: bytes, snonce: bytes) -> bytes:
    """Derive the Pairwise Transient Key (PTK) from the PMK.

    Parameters
    ----------
    pmk:
        32-byte Pairwise Master Key.
    aa:
        Authenticator Address (AP MAC, 6 bytes).
    spa:
        Supplicant Address (client MAC, 6 bytes).
    anonce:
        Authenticator Nonce (32 bytes).
    snonce:
        Supplicant Nonce (32 bytes).

    Returns
    -------
    64-byte PTK (KCK ‖ KEK ‖ TK ‖ misc).
    """
    _require_crypto()
    # The data input must use the lesser of the two MACs / nonces first
    if aa < spa:
        b1, b2 = aa, spa
    else:
        b1, b2 = spa, aa

    if anonce < snonce:
        n1, n2 = anonce, snonce
    else:
        n1, n2 = snonce, anonce

    data = b1 + b2 + n1 + n2
    return prf(pmk, b"Pairwise key expansion", data, 64)


# ── MIC verification ────────────────────────────────────────────────

def compute_mic(ptk: bytes, data: bytes, key_descriptor_version: int = 2) -> bytes:
    """Compute the Message Integrity Code for an EAPOL-Key frame.

    Parameters
    ----------
    ptk:
        The PTK (first 16 bytes used as KCK).
    data:
        The EAPOL frame bytes with the MIC field zeroed out.
    key_descriptor_version:
        1 = HMAC-SHA1-128, 2 = HMAC-SHA1-128 (WPA2), 3 = AES-CMAC-128.

    Returns
    -------
    16-byte MIC.
    """
    _require_crypto()
    kck = ptk[:16]

    if key_descriptor_version in (1, 2):
        return hmac_sha1(kck, data)[:16]
    elif key_descriptor_version == 3:
        return _aes_cmac(kck, data)
    else:
        raise ValueError(f"Unsupported key_descriptor_version: {key_descriptor_version}")


def verify_mic(
    ptk: bytes,
    data: bytes,
    expected_mic: bytes,
    key_descriptor_version: int = 2,
) -> bool:
    """Verify the MIC of an EAPOL-Key frame.

    Returns ``True`` if the computed MIC matches *expected_mic*.
    """
    computed = compute_mic(ptk, data, key_descriptor_version)
    return hmac.compare_digest(computed, expected_mic)


# ── HMAC helpers ────────────────────────────────────────────────────

def hmac_sha1(key: bytes, data: bytes) -> bytes:
    """Return HMAC-SHA1 of *data* under *key* (20 bytes)."""
    _require_crypto()
    return hmac.new(key, data, hashlib.sha1).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Return HMAC-SHA256 of *data* under *key* (32 bytes)."""
    _require_crypto()
    return hmac.new(key, data, hashlib.sha256).digest()


# ── AES unwrap (RFC 3394) ──────────────────────────────────────────

def aes_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    """AES Key Unwrap as per RFC 3394.

    Parameters
    ----------
    kek:
        Key Encryption Key (16 or 32 bytes).
    wrapped:
        Ciphertext including the IV (8 extra bytes).

    Returns
    -------
    Unwrapped plaintext.

    Raises
    ------
    RuntimeError
        If the ``cryptography`` package is not installed **or** if the
        integrity check fails (incorrect KEK / corrupted data).
    """
    _require_crypto()
    if len(wrapped) < 16 or len(wrapped) % 8 != 0:
        raise ValueError("Wrapped data must be at least 16 bytes and a multiple of 8")

    n = (len(wrapped) // 8) - 1
    # Split into A || R[1] … R[n]
    a = bytearray(wrapped[:8])
    r: List[bytearray] = [bytearray(wrapped[i * 8 : i * 8 + 8]) for i in range(1, n + 1)]

    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            t = (n * j) + i
            # XOR A with t (big-endian 64-bit)
            t_bytes = struct.pack(">Q", t)
            a_xor = bytearray(a[k] ^ t_bytes[k] for k in range(8))
            # AES decrypt
            cipher = _Cipher(_AES(kek), _modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            block = decryptor.update(bytes(a_xor + r[i - 1])) + decryptor.finalize()
            a = bytearray(block[:8])
            r[i - 1] = bytearray(block[8:])

    # Integrity check: A should equal the default IV
    default_iv = b"\xa6" * 8
    if bytes(a) != default_iv:
        raise RuntimeError("AES unwrap integrity check failed (incorrect KEK or corrupted data)")

    return b"".join(bytes(ri) for ri in r)


def aes_wrap(kek: bytes, plaintext: bytes) -> bytes:
    """AES Key Wrap as per RFC 3394.

    Returns the wrapped ciphertext (8 bytes longer than *plaintext*).
    """
    _require_crypto()
    if len(plaintext) % 8 != 0:
        raise ValueError("Plaintext length must be a multiple of 8 bytes")

    n = len(plaintext) // 8
    default_iv = b"\xa6" * 8
    a = bytearray(default_iv)
    r: List[bytearray] = [bytearray(plaintext[i * 8 : i * 8 + 8]) for i in range(n)]

    for j in range(6):
        for i in range(n):
            t = (n * j) + i + 1
            cipher = _Cipher(_AES(kek), _modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            block = encryptor.update(bytes(a + r[i])) + encryptor.finalize()
            a = bytearray(block[:8])
            r[i] = bytearray(block[8:])
            # XOR A with t
            t_bytes = struct.pack(">Q", t)
            a = bytearray(a[k] ^ t_bytes[k] for k in range(8))

    return bytes(a) + b"".join(bytes(ri) for ri in r)


# ── AES-CMAC (for key_descriptor_version 3) ────────────────────────

def _aes_cmac(key: bytes, data: bytes) -> bytes:
    """Compute AES-CMAC-128 (NIST SP 800-38B) – returns 16 bytes."""
    _require_crypto()
    # Generate subkeys
    cipher = _Cipher(_AES(key), _modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    l = encryptor.update(b"\x00" * 16) + encryptor.finalize()

    def _shift_left(block: bytes) -> bytes:
        result = bytearray(len(block))
        overflow = 0
        for i in range(len(block) - 1, -1, -1):
            result[i] = ((block[i] << 1) | overflow) & 0xFF
            overflow = (block[i] >> 7) & 1
        return bytes(result)

    rb = b"\x00" * 15 + b"\x87"
    if l[0] & 0x80:
        k1 = _shift_left(l)[:-1] + bytes([_shift_left(l)[-1] ^ rb[-1]])
    else:
        k1 = _shift_left(l)
    if k1[0] & 0x80:
        k2 = _shift_left(k1)[:-1] + bytes([_shift_left(k1)[-1] ^ rb[-1]])
    else:
        k2 = _shift_left(k1)

    # Pad last block
    if len(data) == 0:
        padded = data + b"\x80" + b"\x00" * 15
        last_block = bytes(padded[i] ^ k2[i] for i in range(16))
    elif len(data) % 16 == 0:
        last_block = bytes(data[-16 + i] ^ k1[i] for i in range(16))
        data = data[:-16]
    else:
        pad_len = 16 - (len(data) % 16)
        padded = data + b"\x80" + b"\x00" * (pad_len - 1)
        last_block = bytes(padded[-16 + i] ^ k2[i] for i in range(16))
        data = padded[:-16]

    # CBC-MAC
    x = b"\x00" * 16
    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        if len(block) < 16:
            block = block + b"\x00" * (16 - len(block))
        x = bytes(x[j] ^ block[j] for j in range(16))
        enc = _Cipher(_AES(key), _modes.ECB(), backend=default_backend())
        enc_update = enc.encryptor()
        x = enc_update.update(x) + enc_update.finalize()

    x = bytes(x[j] ^ last_block[j] for j in range(16))
    enc = _Cipher(_AES(key), _modes.ECB(), backend=default_backend())
    enc_update = enc.encryptor()
    result = enc_update.update(x) + enc_update.finalize()
    return result
