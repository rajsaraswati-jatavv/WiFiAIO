"""Hashcat-style mask-based WPA cracking attack.

Implements mask attack using hashcat's mask syntax where each position
in the password can be constrained to a specific character set:
  ?l = lowercase, ?u = uppercase, ?d = digits, ?s = special,
  ?a = all printable, ?b = byte (0x00-0xff), ?h = hex lowercase,
  ?H = hex uppercase.
"""

import itertools
import re
import string
import time
from typing import Callable, Dict, Generator, List, Optional, Tuple

from wifi_aio.exceptions import CrackingError, WiFiTimeoutError


# ── Mask charset definitions ──────────────────────────────────────────

MASK_CHARSETS = {
    "l": string.ascii_lowercase,      # ?l
    "u": string.ascii_uppercase,      # ?u
    "d": string.digits,               # ?d
    "s": "!@#$%^&*()-_=+[]{}|;:',.<>?/~`\"\\",  # ?s
    "a": string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:',.<>?/~`\"\\",  # ?a
    "b": "".join(chr(i) for i in range(256)),  # ?b
    "h": "0123456789abcdef",          # ?h
    "H": "0123456789ABCDEF",          # ?H
}

# Regex to find mask placeholders
_MASK_RE = re.compile(r"\?[ludsabhH]")


class MaskPosition:
    """A single position in a mask, with its character set."""

    def __init__(self, charset: str, is_literal: bool = False) -> None:
        self.charset = charset
        self.is_literal = is_literal

    @property
    def size(self) -> int:
        return len(self.charset)

    def __repr__(self) -> str:
        if self.is_literal:
            return f"MaskPosition({self.charset!r}, literal=True)"
        return f"MaskPosition(size={self.size})"


def parse_mask(mask: str) -> List[MaskPosition]:
    """Parse a hashcat-style mask string into a list of MaskPositions.

    Examples::

        parse_mask("?l?l?l?l?d?d?d?d")
        parse_mask("password?d?d")
        parse_mask("?u?l?l?l?l?l?d?d")

    Returns
    -------
    list of MaskPosition
    """
    positions: List[MaskPosition] = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            key = mask[i + 1]
            if key in MASK_CHARSETS:
                positions.append(MaskPosition(MASK_CHARSETS[key]))
                i += 2
            else:
                # Unknown mask placeholder – treat as literal
                positions.append(MaskPosition(mask[i], is_literal=True))
                i += 1
        else:
            # Literal character
            positions.append(MaskPosition(mask[i], is_literal=True))
            i += 1

    return positions


def mask_candidates(mask: str) -> Generator[str, None, None]:
    """Generate all candidate passwords matching *mask*.

    Yields strings one at a time for memory efficiency.
    """
    positions = parse_mask(mask)

    # Build the cartesian product of all non-literal positions
    charsets = [p.charset for p in positions]

    for combo in itertools.product(*charsets):
        yield "".join(combo)


def mask_space_size(mask: str) -> int:
    """Return the total number of candidates for a mask."""
    positions = parse_mask(mask)
    total = 1
    for pos in positions:
        total *= pos.size
    return total


class MaskAttack:
    """Hashcat-style mask-based WPA/WPA2 PSK cracking.

    Parameters
    ----------
    handshake:
        A dict with keys ``ssid``, ``anonce``, ``snonce``, ``ap_mac``,
        ``client_mac``, ``mic``, ``eapol_frame``.
    mask:
        Hashcat-style mask string (e.g. ``"?l?l?l?l?d?d?d?d"``).
        Can be a single mask or a list of masks.
    engine:
        ``"python"`` for pure-Python or ``"hashcat"`` for external.
    """

    def __init__(
        self,
        handshake: Dict,
        mask: str = "?l?l?l?l?l?l?l?l",
        engine: str = "python",
    ) -> None:
        self.handshake = handshake
        self.mask = mask if isinstance(mask, list) else [mask]
        self.engine = engine

        self._found: Optional[str] = None
        self._tested = 0
        self._start_time: Optional[float] = None
        self._running = False
        self._callback: Optional[Callable[[int, Optional[str]], None]] = None

        # Pre-parse handshake
        self._ssid_bytes = handshake.get("ssid", "").encode("utf-8")
        self._anonce = bytes.fromhex(handshake.get("anonce", "")) if isinstance(handshake.get("anonce"), str) else handshake.get("anonce", b"")
        self._snonce = bytes.fromhex(handshake.get("snonce", "")) if isinstance(handshake.get("snonce"), str) else handshake.get("snonce", b"")
        self._ap_mac = bytes.fromhex(handshake.get("ap_mac", "").replace(":", "")) if isinstance(handshake.get("ap_mac"), str) else handshake.get("ap_mac", b"")
        self._client_mac = bytes.fromhex(handshake.get("client_mac", "").replace(":", "")) if isinstance(handshake.get("client_mac"), str) else handshake.get("client_mac", b"")
        self._target_mic = bytes.fromhex(handshake.get("mic", "")) if isinstance(handshake.get("mic"), str) else handshake.get("mic", b"")
        self._eapol_frame = bytes.fromhex(handshake.get("eapol_frame", "")) if isinstance(handshake.get("eapol_frame"), str) else handshake.get("eapol_frame", b"")

    # ── Public API ─────────────────────────────────────────────────────

    def run(
        self,
        callback: Optional[Callable[[int, Optional[str]], None]] = None,
        timeout: Optional[float] = None,
    ) -> Optional[str]:
        """Run the mask attack.

        Parameters
        ----------
        callback:
            Called periodically with ``(tested_count, password_or_none)``.
        timeout:
            Maximum seconds to run.

        Returns
        -------
        str or None
        """
        if self.engine == "hashcat":
            return self._run_hashcat(callback, timeout)
        return self._run_python(callback, timeout)

    def stop(self) -> None:
        """Stop a running attack."""
        self._running = False

    def estimate_total(self) -> int:
        """Estimate the total number of candidates across all masks."""
        return sum(mask_space_size(m) for m in self.mask)

    def preview_mask(self, mask: Optional[str] = None) -> Dict:
        """Return analysis of a mask's structure and size."""
        m = mask or (self.mask[0] if self.mask else "")
        positions = parse_mask(m)
        return {
            "mask": m,
            "positions": [
                {
                    "index": i,
                    "charset_size": p.size,
                    "is_literal": p.is_literal,
                }
                for i, p in enumerate(positions)
            ],
            "total_candidates": mask_space_size(m),
            "length": len(positions),
        }

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def tested(self) -> int:
        return self._tested

    @property
    def elapsed(self) -> float:
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time

    @property
    def speed(self) -> float:
        e = self.elapsed
        return self._tested / e if e > 0 else 0.0

    @property
    def found_password(self) -> Optional[str]:
        return self._found

    @property
    def progress(self) -> float:
        total = self.estimate_total()
        return self._tested / total if total > 0 else 0.0

    # ── Pure Python engine ─────────────────────────────────────────────

    def _run_python(
        self,
        callback: Optional[Callable] = None,
        timeout: Optional[float] = None,
    ) -> Optional[str]:
        """Run the mask attack in pure Python."""
        self._callback = callback
        self._found = None
        self._tested = 0
        self._running = True
        self._start_time = time.time()

        deadline = None if timeout is None else time.monotonic() + timeout

        try:
            for current_mask in self.mask:
                if not self._running:
                    break

                # Validate mask length (8-63 for WPA)
                positions = parse_mask(current_mask)
                if len(positions) < 8 or len(positions) > 63:
                    continue

                for candidate in mask_candidates(current_mask):
                    if not self._running:
                        break
                    if deadline is not None and time.monotonic() >= deadline:
                        break

                    if self._check_password(candidate):
                        self._found = candidate
                        if self._callback:
                            self._callback(self._tested, candidate)
                        return candidate

                    self._tested += 1
                    if self._callback and self._tested % 1000 == 0:
                        self._callback(self._tested, None)

        finally:
            self._running = False

        return None

    # ── Hashcat engine ─────────────────────────────────────────────────

    def _run_hashcat(
        self,
        callback: Optional[Callable] = None,
        timeout: Optional[float] = None,
    ) -> Optional[str]:
        """Run the mask attack using hashcat."""
        from wifi_aio.cracking.hash_extractor import HashExtractor
        from wifi_aio.utils import run_command
        import tempfile
        import os

        # Extract hash to a temp file
        extractor = HashExtractor()
        hash_file = extractor.extract_to_file(
            self.handshake, format="hashcat", output_path=None
        )

        try:
            # Write mask file if multiple masks
            if len(self.mask) > 1:
                fd, mask_file = tempfile.mkstemp(suffix=".hcmask")
                try:
                    with os.fdopen(fd, "w") as f:
                        for m in self.mask:
                            f.write(m + "\n")
                except Exception:
                    os.close(fd)
                    raise

                cmd = [
                    "hashcat", "-m", "22000", "-a", "3",
                    hash_file, mask_file,
                    "--force", "--potfile-disable",
                ]
            else:
                cmd = [
                    "hashcat", "-m", "22000", "-a", "3",
                    hash_file, self.mask[0],
                    "--force", "--potfile-disable",
                ]

            rc, stdout, stderr = run_command(cmd, timeout=timeout)

            for line in stdout.splitlines():
                if ":" in line and not line.startswith("#"):
                    parts = line.rsplit(":", 1)
                    if len(parts) == 2:
                        candidate = parts[1].strip()
                        if candidate:
                            self._found = candidate
                            return candidate

            return None
        finally:
            try:
                os.unlink(hash_file)
            except OSError:
                pass

    # ── Password verification ──────────────────────────────────────────

    def _check_password(self, password: str) -> bool:
        """Check a single password against the handshake."""
        import hashlib
        import hmac as hmac_mod

        if not self._anonce or not self._snonce:
            return False
        if not self._ap_mac or not self._client_mac:
            return False
        if not self._target_mic or not self._eapol_frame:
            return False

        pmk = hashlib.pbkdf2_hmac(
            "sha1", password.encode("utf-8"), self._ssid_bytes, 4096, dklen=32
        )

        ap_mac = self._ap_mac
        client_mac = self._client_mac
        if ap_mac < client_mac:
            mac_min, mac_max = ap_mac, client_mac
        else:
            mac_min, mac_max = client_mac, ap_mac

        anonce = self._anonce
        snonce = self._snonce
        if anonce < snonce:
            nonce_min, nonce_max = anonce, snonce
        else:
            nonce_min, nonce_max = snonce, anonce

        a = b"Pairwise key expansion"
        b = mac_min + mac_max + nonce_min + nonce_max
        ptk = b""
        for i in range(4):
            ptk += hmac_mod.new(pmk, a + b"\x00" + b + bytes([i]), hashlib.sha1).digest()
        ptk = ptk[:64]

        frame_copy = bytearray(self._eapol_frame)
        if len(frame_copy) >= 97:
            frame_copy[81:97] = b"\x00" * 16
        computed_mic = hmac_mod.new(ptk[:16], bytes(frame_copy), hashlib.sha1).digest()[:16]

        return hmac_mod.compare_digest(computed_mic, self._target_mic)
