"""WiFiAIO input validators.

Each validator returns a normalised value on success or raises
:class:`~wifi_aio.exceptions.ConfigurationError` (for bad user input)
or :class:`ValueError` for programmatic misuse.
"""

import os
import re
from typing import Optional

from wifi_aio.exceptions import ConfigurationError

# ── Compiled patterns ────────────────────────────────────────────────

_MAC_RE = re.compile(
    r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$"
)
_MAC_NO_SEP_RE = re.compile(r"^[0-9a-fA-F]{12}$")

_SSID_RE = re.compile(r'^[\x20-\x7e\x80-\xff]{1,32}$')

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

_WPS_PIN_RE = re.compile(r"^\d{4,8}$")


# ── Validators ───────────────────────────────────────────────────────

def validate_mac(mac: str) -> str:
    """Validate and normalise a MAC address.

    Accepts ``AA:BB:CC:DD:EE:FF``, ``AA-BB-CC-DD-EE-FF`` or
    ``AABBCCDDEEFF``.  Returns the lower-case colon-separated form.

    Raises :class:`ConfigurationError` on invalid input.
    """
    if not mac:
        raise ConfigurationError("MAC address is empty")
    mac = mac.strip()
    if not (_MAC_RE.match(mac) or _MAC_NO_SEP_RE.match(mac)):
        raise ConfigurationError(f"Invalid MAC address: {mac!r}")

    digits = mac.replace(":", "").replace("-", "").lower()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def validate_ssid(ssid: str) -> str:
    """Validate an SSID string.

    SSIDs are 1–32 octets.  This check uses a printable + extended-ASCII
    heuristic.  Returns the SSID unchanged.

    Raises :class:`ConfigurationError` if the SSID is empty or too long.
    """
    if not ssid:
        raise ConfigurationError("SSID cannot be empty")
    if len(ssid.encode("utf-8", errors="replace")) > 32:
        raise ConfigurationError(f"SSID too long ({len(ssid)} chars, max 32 bytes)")
    if not _SSID_RE.match(ssid):
        raise ConfigurationError(f"Invalid SSID: {ssid!r}")
    return ssid


def validate_channel(channel: int) -> int:
    """Validate a WiFi channel number (2.4 GHz or 5 GHz).

    Returns the channel on success.  Raises :class:`ConfigurationError`.
    """
    from wifi_aio.constants import CHANNELS_2GHZ, CHANNELS_5GHZ

    valid = set(CHANNELS_2GHZ) | set(CHANNELS_5GHZ)
    if channel not in valid:
        raise ConfigurationError(
            f"Invalid channel {channel}. Must be one of {sorted(valid)}"
        )
    return channel


def validate_ip(ip: str) -> str:
    """Validate an IPv4 address string.

    Returns the address on success.  Raises :class:`ConfigurationError`.
    """
    ip = ip.strip()
    if not _IPV4_RE.match(ip):
        raise ConfigurationError(f"Invalid IPv4 address: {ip!r}")
    return ip


def validate_wps_pin(pin: str) -> str:
    """Validate a WPS PIN (4 or 8 digits, with optional checksum).

    The checksum digit (if 8 digits) is verified.  Returns the PIN
    string on success.

    Raises :class:`ConfigurationError` for an invalid PIN.
    """
    pin = pin.strip()
    if not _WPS_PIN_RE.match(pin):
        raise ConfigurationError(f"Invalid WPS PIN: {pin!r}")

    if len(pin) == 8:
        if not _wps_checksum_ok(pin):
            raise ConfigurationError(f"WPS PIN checksum failed: {pin}")
    elif len(pin) == 4:
        # 4-digit PINs are valid as-is (half-PIN)
        pass
    else:
        raise ConfigurationError(
            f"WPS PIN must be 4 or 8 digits, got {len(pin)}"
        )
    return pin


def validate_filepath(path: str, must_exist: bool = False) -> str:
    """Validate a file-system path.

    Checks for:
      * Null bytes (injection risk)
      * Path-traversal (``..``) that escapes the base

    If *must_exist* is ``True``, the path must point to an existing
    file.

    Returns the absolute, resolved path.
    """
    if not path:
        raise ConfigurationError("File path is empty")
    if "\x00" in path:
        raise ConfigurationError("File path contains null bytes")

    resolved = os.path.realpath(os.path.expanduser(path))

    # Path-traversal check: ensure the resolved path doesn't escape
    # above the original parent via ``..`` components
    # (only meaningful when the path is relative to a known base)
    parts = os.path.normpath(path).split(os.sep)
    if ".." in parts:
        # Allow if it still resolves inside cwd – but warn-level check
        cwd = os.path.realpath(os.getcwd())
        if not resolved.startswith(cwd):
            raise ConfigurationError(
                f"Path traversal detected: {path!r} resolves to {resolved}"
            )

    if must_exist and not os.path.isfile(resolved):
        raise ConfigurationError(f"File does not exist: {resolved}")

    return resolved


# ── Internal helpers ─────────────────────────────────────────────────

def _wps_checksum_ok(pin: str) -> bool:
    """Validate the checksum digit of an 8-digit WPS PIN.

    Algorithm per the Wi-Fi Simple Configuration specification.
    """
    accum = 0
    for i in range(7):
        digit = int(pin[i])
        if i % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        accum += digit
    check = (10 - (accum % 10)) % 10
    return check == int(pin[7])
