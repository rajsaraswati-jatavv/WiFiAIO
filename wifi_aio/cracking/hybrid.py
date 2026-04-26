"""Hybrid WPA cracking attack combining wordlist with mutation rules.

A hybrid attack takes a base wordlist and applies rule-based mutations
(leet speak, capitalization, appending digits, etc.) to each word,
then tests the mutated candidates against the handshake.
"""

import time
from typing import Callable, Dict, Generator, List, Optional

from wifi_aio.exceptions import CrackingError, WordlistNotFoundError, WiFiTimeoutError
from wifi_aio.cracking.rule_engine import RuleEngine


class HybridAttack:
    """Wordlist + rules hybrid WPA/WPA2 PSK cracking.

    Parameters
    ----------
    handshake:
        A dict with keys ``ssid``, ``anonce``, ``snonce``, ``ap_mac``,
        ``client_mac``, ``mic``, ``eapol_frame``.
    wordlist:
        Path to the base wordlist file.
    rules:
        List of rule strings (hashcat rule syntax) or a path to a rule
        file.  If ``None``, a default set of common mutation rules is used.
    max_mutations:
        Maximum number of mutated candidates per base word (0 = unlimited).
    engine:
        ``"python"`` for pure-Python or ``"hashcat"`` for external.
    """

    # Default mutation rules
    DEFAULT_RULES = [
        ":",           # no change
        "c",           # capitalize
        "u",           # uppercase all
        "l",           # lowercase all
        "T0",          # toggle first char
        "$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$0",  # append digit
        "^1", "^2", "^3", "^4", "^5", "^6", "^7", "^8", "^9", "^0",  # prepend digit
        "r",           # reverse
        "d",           # duplicate
        "p2",          # duplicate twice
        "t",           # toggle case of all
        "'D",          # delete last char
        "^a", "^b", "^c",  # prepend common letters
        "$!", "$@", "$#", "$$",  # append special chars
        "c$1", "c$2", "c$123",  # capitalize + append
        "u$1", "u$123",       # uppercase + append
        "l$!", "l$1",         # lowercase + append
        "T0$1", "T0$2",       # toggle first + append
        "r$1", "r$2",         # reverse + append
        "c$!$1",              # capitalize + append two
        "cT0",                # capitalize then toggle first
    ]

    def __init__(
        self,
        handshake: Dict,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        rules: Optional[List[str]] = None,
        max_mutations: int = 0,
        engine: str = "python",
    ) -> None:
        self.handshake = handshake
        self.wordlist = wordlist
        self.max_mutations = max_mutations
        self.engine = engine

        # Parse rules
        self._rule_engine = RuleEngine()
        if rules is None:
            self._rules = list(self.DEFAULT_RULES)
        elif isinstance(rules, str):
            # Path to a rule file
            self._rules = self._load_rule_file(rules)
        else:
            self._rules = list(rules)

        self._found: Optional[str] = None
        self._tested = 0
        self._start_time: Optional[float] = None
        self._running = False
        self._callback: Optional[Callable[[int, Optional[str]], None]] = None
        self._base_words = 0

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
        """Run the hybrid attack.

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

    def generate_candidates(self, base_word: str) -> List[str]:
        """Generate all mutated candidates for a single base word."""
        candidates = set()
        for rule in self._rules:
            mutated = self._rule_engine.apply_rule(rule, base_word)
            if mutated and 8 <= len(mutated) <= 63:
                candidates.add(mutated)
            if self.max_mutations > 0 and len(candidates) >= self.max_mutations:
                break
        return list(candidates)

    def iter_candidates(self, wordlist_path: Optional[str] = None) -> Generator[str, None, None]:
        """Yield all candidates (base words + mutations) without testing."""
        path = wordlist_path or self.wordlist
        import os
        if not os.path.isfile(path):
            raise WordlistNotFoundError(f"Wordlist not found: {path}")

        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                base = line.strip()
                if not base:
                    continue
                # Yield the base word itself if valid
                if 8 <= len(base) <= 63:
                    yield base
                # Yield mutations
                for candidate in self.generate_candidates(base):
                    if candidate != base:
                        yield candidate

    def estimate_candidates(self, wordlist_path: Optional[str] = None) -> int:
        """Estimate the total number of candidates (expensive – reads full wordlist)."""
        path = wordlist_path or self.wordlist
        import os
        if not os.path.isfile(path):
            return 0

        count = 0
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                base = line.strip()
                if not base:
                    continue
                mutations = min(
                    len(self.generate_candidates(base)),
                    self.max_mutations if self.max_mutations > 0 else 999999,
                )
                count += mutations + 1  # +1 for the base word

        return count

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def tested(self) -> int:
        return self._tested

    @property
    def base_words_processed(self) -> int:
        return self._base_words

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
    def rule_count(self) -> int:
        return len(self._rules)

    # ── Pure Python engine ─────────────────────────────────────────────

    def _run_python(
        self,
        callback: Optional[Callable] = None,
        timeout: Optional[float] = None,
    ) -> Optional[str]:
        """Run the hybrid attack in pure Python."""
        import os

        if not os.path.isfile(self.wordlist):
            raise WordlistNotFoundError(f"Wordlist not found: {self.wordlist}")

        self._callback = callback
        self._found = None
        self._tested = 0
        self._base_words = 0
        self._running = True
        self._start_time = time.time()

        deadline = None if timeout is None else time.monotonic() + timeout

        try:
            with open(self.wordlist, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if not self._running:
                        break
                    if deadline is not None and time.monotonic() >= deadline:
                        break

                    base = line.strip()
                    if not base:
                        continue

                    self._base_words += 1

                    # Test base word
                    if 8 <= len(base) <= 63:
                        if self._check_password(base):
                            self._found = base
                            if self._callback:
                                self._callback(self._tested, base)
                            return base
                        self._tested += 1

                    # Test mutations
                    mutation_count = 0
                    for rule in self._rules:
                        if not self._running:
                            break
                        if deadline is not None and time.monotonic() >= deadline:
                            break

                        mutated = self._rule_engine.apply_rule(rule, base)
                        if not mutated or len(mutated) < 8 or len(mutated) > 63:
                            continue
                        if mutated == base:
                            continue  # already tested

                        if self._check_password(mutated):
                            self._found = mutated
                            if self._callback:
                                self._callback(self._tested, mutated)
                            return mutated

                        self._tested += 1
                        mutation_count += 1

                        if self.max_mutations > 0 and mutation_count >= self.max_mutations:
                            break

                    if self._callback and self._base_words % 100 == 0:
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
        """Run the hybrid attack using hashcat."""
        from wifi_aio.cracking.hash_extractor import HashExtractor
        from wifi_aio.utils import run_command
        import tempfile
        import os

        extractor = HashExtractor()
        hash_file = extractor.extract_to_file(
            self.handshake, format="hashcat", output_path=None
        )

        # Write rule file
        fd, rule_file = tempfile.mkstemp(suffix=".rule")
        try:
            with os.fdopen(fd, "w") as f:
                for rule in self._rules:
                    f.write(rule + "\n")
        except Exception:
            os.close(fd)
            raise

        try:
            cmd = [
                "hashcat", "-m", "22000", "-a", "0",
                hash_file, self.wordlist,
                "-r", rule_file,
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
            for path in (hash_file, rule_file):
                try:
                    os.unlink(path)
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

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _load_rule_file(path: str) -> List[str]:
        """Load hashcat-style rules from a file."""
        rules = []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    rules.append(line)
        return rules
