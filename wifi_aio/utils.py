"""WiFiAIO utility helpers.

Low-level helpers used throughout the package: MAC / hex generation,
frequency ↔ channel conversion, subprocess wrappers and file readers.
"""

import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple

from wifi_aio.constants import CHANNELS_2GHZ, CHANNELS_5GHZ
from wifi_aio.exceptions import WiFiAIOError, WiFiTimeoutError


# ── Random generators ────────────────────────────────────────────────

def random_mac() -> str:
    """Return a randomly generated, locally administered MAC address.

    Uses :func:`os.urandom` for cryptographic randomness.  The second
    nibble of the first octet is forced to **2** (locally administered,
    unicast) so the address is valid for 802.11 frames.
    """
    raw = os.urandom(6)
    # Set locally-administered bit (bit 1 of first octet), clear multicast bit
    first = (raw[0] & 0xFC) | 0x02
    return ":".join(f"{first:02x}" + "".join(f"{b:02x}" for b in raw[1:])) if False else \
        f"{first:02x}:{raw[1]:02x}:{raw[2]:02x}:{raw[3]:02x}:{raw[4]:02x}:{raw[5]:02x}"


def random_hex(length: int = 16) -> str:
    """Return *length* random hexadecimal characters using :func:`os.urandom`.

    ``length`` is the number of hex chars (i.e. *bytes* = length // 2
    rounded up).
    """
    byte_count = (length + 1) // 2
    return os.urandom(byte_count).hex()[:length]


# ── MAC formatting ───────────────────────────────────────────────────

def mac_format(mac: str, separator: str = ":") -> str:
    """Normalise a MAC address string to the given *separator*.

    Accepts ``:``, ``-`` or no separator and strips surrounding
    whitespace.  Returns lowercase hex digits.

    >>> mac_format("AA-BB-CC-DD-EE-FF")
    'aa:bb:cc:dd:ee:ff'
    """
    mac = mac.strip().replace(":", "").replace("-", "").replace(".", "")
    if len(mac) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    mac = mac.lower()
    return separator.join(mac[i : i + 2] for i in range(0, 12, 2))


# ── Channel / frequency helpers ──────────────────────────────────────

# Merge both band tables for reverse lookups
_FREQ_TO_CHAN: Dict[int, int] = {}
for _ch, _freq in {**CHANNELS_2GHZ, **CHANNELS_5GHZ}.items():
    _FREQ_TO_CHAN[_freq] = _ch


def freq_to_channel(freq: int) -> int:
    """Convert a frequency in MHz to its channel number.

    Returns 0 for unknown frequencies.
    """
    return _FREQ_TO_CHAN.get(freq, 0)


def channel_to_freq(channel: int) -> int:
    """Convert a channel number to its frequency in MHz.

    Returns 0 for unknown channels.
    """
    if channel in CHANNELS_2GHZ:
        return CHANNELS_2GHZ[channel]
    if channel in CHANNELS_5GHZ:
        return CHANNELS_5GHZ[channel]
    return 0


def is_5ghz_channel(channel: int) -> bool:
    """Return ``True`` if *channel* is in the 5 GHz band."""
    return channel in CHANNELS_5GHZ


def is_2ghz_channel(channel: int) -> bool:
    """Return ``True`` if *channel* is in the 2.4 GHz band."""
    return channel in CHANNELS_2GHZ


# ── Subprocess helper ────────────────────────────────────────────────

def run_command(
    cmd: List[str],
    timeout: Optional[float] = None,
    sudo: bool = False,
    capture_output: bool = True,
    input_data: Optional[str] = None,
) -> Tuple[int, str, str]:
    """Execute an external command and return ``(rc, stdout, stderr)``.

    Parameters
    ----------
    cmd:
        Command and arguments as a list.
    timeout:
        Maximum seconds to wait.  Raises :class:`WiFiTimeoutError` on
        expiry.
    sudo:
        Prepend ``sudo`` to the command if the effective UID is not 0.
    capture_output:
        Capture stdout/stderr rather than inheriting the parent's FDs.
    input_data:
        Optional string fed to the child's stdin.
    """
    if sudo and os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            stdin=subprocess.PIPE if input_data is not None else None,
            timeout=timeout,
            text=True,
        )
        return (
            proc.returncode,
            (proc.stdout or "") if capture_output else "",
            (proc.stderr or "") if capture_output else "",
        )
    except subprocess.TimeoutExpired as exc:
        raise WiFiTimeoutError(
            f"Command {' '.join(cmd)} timed out after {timeout}s"
        ) from exc
    except FileNotFoundError as exc:
        raise WiFiAIOError(
            f"Command not found: {cmd[0]}"
        ) from exc


# ── File helpers ─────────────────────────────────────────────────────

def sanitize_filename(name: str) -> str:
    """Sanitize a string so it is safe to use as a file name.

    Strips directory components, replaces non-alphanumeric characters
    (except ``-``, ``_``, ``.``) with underscores, and collapses
    consecutive underscores.

    Parameters
    ----------
    name:
        Raw file name to sanitize.

    Returns
    -------
    Sanitized file name string.
    """
    import os as _os
    # Remove any directory component
    name = _os.path.basename(name)
    # Replace unsafe characters
    import re as _re
    name = _re.sub(r"[^\w\-.]", "_", name)
    # Collapse consecutive underscores
    name = _re.sub(r"_+", "_", name)
    # Strip leading/trailing underscores and dots
    name = name.strip("_.")
    return name or "unnamed"


def is_root() -> bool:
    """Return ``True`` if the current process is running as root (UID 0)."""
    return os.geteuid() == 0


def read_file_lines(path: str, strip: bool = True, skip_empty: bool = True) -> List[str]:
    """Read a text file and return its lines as a list.

    Parameters
    ----------
    path:
        Path to the text file.
    strip:
        Strip whitespace from each line.
    skip_empty:
        Omit empty lines from the result.
    """
    if not os.path.isfile(path):
        from wifi_aio.exceptions import WordlistNotFoundError
        raise WordlistNotFoundError(f"File not found: {path}")

    lines: List[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip() if strip else raw_line
            if skip_empty and not line:
                continue
            if strip:
                line = line.rstrip("\n\r")
            lines.append(line)
    return lines
