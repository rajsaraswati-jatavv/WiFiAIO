"""Hashcat wrapper for GPU-accelerated password cracking.

Supports dictionary, mask, hybrid, and rule-based attacks with
session management, restore capability, and output parsing.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from wifi_aio.exceptions import (
    CrackingError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


@dataclass
class HashcatResult:
    """Result of a hashcat cracking session.

    Attributes:
        success: Whether a password was recovered.
        password: The cracked password (empty if not found).
        hash_type: Hash type number used.
        attack_mode: Attack mode number used.
        speed: Cracking speed in H/s.
        time_elapsed: Seconds elapsed.
        tried: Number of candidates tried.
        output: Raw hashcat stdout.
        potfile: Path to the potfile used.
    """

    success: bool = False
    password: str = ""
    hash_type: int = 0
    attack_mode: int = 0
    speed: float = 0.0
    time_elapsed: float = 0.0
    tried: int = 0
    output: str = ""
    potfile: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "password": self.password,
            "hash_type": self.hash_type,
            "attack_mode": self.attack_mode,
            "speed": self.speed,
            "time_elapsed": self.time_elapsed,
            "tried": self.tried,
        }


class HashcatWrapper:
    """Run hashcat with various attack modes.

    Provides methods for dictionary, mask, hybrid, and rule-based attacks,
    as well as session management and benchmarking.

    Example::

        hc = HashcatWrapper()
        result = hc.dictionary_attack(
            hash_file="capture.hc22000",
            wordlist="/usr/share/wordlists/rockyou.txt",
            hash_type=22000,
        )
        if result.success:
            print(f"Password: {result.password}")
    """

    WIFI_HASH_TYPES = {
        "wpa_eapol": 22000,
        "wpa_pmkid": 16800,
        "wpa_eapol_old": 2500,
    }

    def __init__(
        self,
        hashcat_path: str = "hashcat",
        potfile_dir: str = "/tmp/wifiaio_hashcat_potfiles",
        force: bool = True,
    ) -> None:
        self.hashcat_path = hashcat_path
        self.potfile_dir = potfile_dir
        self.force = force
        self._process: Optional[subprocess.Popen] = None
        self._running = False

        os.makedirs(potfile_dir, exist_ok=True)

    def _is_available(self) -> bool:
        """Check if hashcat is installed and functional."""
        try:
            result = subprocess.run(
                [self.hashcat_path, "--version"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _build_base_cmd(
        self, hash_file: str, hash_type: int, attack_mode: int,
        potfile: str, extra_args: Optional[list[str]] = None,
    ) -> list[str]:
        """Build a base hashcat command."""
        cmd = [
            self.hashcat_path,
            "-m", str(hash_type),
            "-a", str(attack_mode),
            "--potfile-path", potfile,
        ]
        if self.force:
            cmd.append("--force")
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(hash_file)
        return cmd

    def _run_hashcat(
        self,
        cmd: list[str],
        timeout: int = 0,
    ) -> HashcatResult:
        """Execute a hashcat command and parse the output."""
        potfile = os.path.join(
            self.potfile_dir, f"potfile_{int(time.time())}"
        )

        start = time.time()
        self._running = True
        result = HashcatResult()

        try:
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                stdout, stderr = self._process.communicate(
                    timeout=timeout if timeout > 0 else None,
                )
            except subprocess.TimeoutExpired:
                self._process.kill()
                stdout, stderr = self._process.communicate()

            output = stdout + stderr
            result.output = output

            # Parse cracked password
            pw_match = re.search(r"([a-f0-9]+):(.+)", output)
            if pw_match:
                result.success = True
                result.password = pw_match.group(2).strip()

            # Check potfile
            if not result.success and os.path.isfile(potfile):
                try:
                    with open(potfile, "r") as f:
                        for line in f:
                            if ":" in line:
                                result.success = True
                                result.password = line.split(":")[-1].strip()
                                break
                except OSError:
                    pass

            # Parse speed
            speed_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:H/s|MH/s|kH/s|GH/s)", output)
            if speed_match:
                speed_val = float(speed_match.group(1))
                unit = output[speed_match.end() - 4:speed_match.end()].strip()
                multipliers = {"GH/s": 1e9, "MH/s": 1e6, "kH/s": 1e3, "H/s": 1}
                for u, mult in multipliers.items():
                    if u in (speed_match.group(0)):
                        speed_val *= mult
                        break
                result.speed = speed_val

            # Parse progress
            progress_match = re.search(r"Progress\.+:\s*(\d+)/(\d+)", output)
            if progress_match:
                result.tried = int(progress_match.group(1))

        except FileNotFoundError:
            raise CrackingError("hashcat not found. Install hashcat.")
        finally:
            self._running = False
            self._process = None

        result.time_elapsed = time.time() - start
        return result

    # ── Attack methods ─────────────────────────────────────────────────

    def dictionary_attack(
        self,
        hash_file: str,
        wordlist: str,
        hash_type: int = 22000,
        rule_file: Optional[str] = None,
        timeout: int = 0,
        extra_args: Optional[list[str]] = None,
    ) -> HashcatResult:
        """Run a dictionary (attack mode 0) attack.

        Args:
            hash_file: Path to the hash file.
            wordlist: Path to the wordlist.
            hash_type: Hash type number.
            rule_file: Optional rule file to apply.
            timeout: Maximum seconds (0 = unlimited).
            extra_args: Additional hashcat arguments.

        Returns:
            HashcatResult with the outcome.
        """
        if not os.path.isfile(hash_file):
            raise CrackingError(f"Hash file not found: {hash_file}")
        if not os.path.isfile(wordlist):
            raise CrackingError(f"Wordlist not found: {wordlist}")

        potfile = os.path.join(self.potfile_dir, f"dict_{int(time.time())}")
        cmd = self._build_base_cmd(hash_file, hash_type, 0, potfile, extra_args)
        cmd.append(wordlist)
        if rule_file:
            cmd.extend(["-r", rule_file])

        logger.info("hashcat dictionary attack: %s", " ".join(cmd))
        return self._run_hashcat(cmd, timeout)

    def mask_attack(
        self,
        hash_file: str,
        mask: str,
        hash_type: int = 22000,
        custom_charsets: Optional[dict[str, str]] = None,
        timeout: int = 0,
        extra_args: Optional[list[str]] = None,
    ) -> HashcatResult:
        """Run a mask (attack mode 3) attack.

        Mask syntax: ?l=lower, ?u=upper, ?d=digits, ?h=hex, ?a=all.

        Args:
            hash_file: Path to the hash file.
            mask: Hashcat mask pattern.
            hash_type: Hash type number.
            custom_charsets: Custom charset mappings ({"1": "abc"}).
            timeout: Maximum seconds (0 = unlimited).
            extra_args: Additional hashcat arguments.

        Returns:
            HashcatResult with the outcome.
        """
        potfile = os.path.join(self.potfile_dir, f"mask_{int(time.time())}")
        extra = list(extra_args) if extra_args else []
        if custom_charsets:
            for idx, chars in custom_charsets.items():
                extra.extend([f"-{idx}", chars])

        cmd = self._build_base_cmd(hash_file, hash_type, 3, potfile, extra)
        cmd.append(mask)

        logger.info("hashcat mask attack: %s", " ".join(cmd))
        return self._run_hashcat(cmd, timeout)

    def hybrid_attack(
        self,
        hash_file: str,
        wordlist: str,
        mask: str,
        mode: str = "dict_mask",
        hash_type: int = 22000,
        timeout: int = 0,
        extra_args: Optional[list[str]] = None,
    ) -> HashcatResult:
        """Run a hybrid (attack mode 6 or 7) attack.

        Args:
            hash_file: Path to the hash file.
            wordlist: Path to the wordlist.
            mask: Hashcat mask.
            mode: ``"dict_mask"`` (mode 6) or ``"mask_dict"`` (mode 7).
            hash_type: Hash type number.
            timeout: Maximum seconds (0 = unlimited).
            extra_args: Additional hashcat arguments.

        Returns:
            HashcatResult with the outcome.
        """
        attack_mode = 6 if mode == "dict_mask" else 7
        potfile = os.path.join(self.potfile_dir, f"hybrid_{int(time.time())}")
        cmd = self._build_base_cmd(hash_file, hash_type, attack_mode, potfile, extra_args)
        cmd.append(wordlist)
        cmd.append(mask)

        logger.info("hashcat hybrid attack (mode %d): %s", attack_mode, " ".join(cmd))
        return self._run_hashcat(cmd, timeout)

    def rule_attack(
        self,
        hash_file: str,
        wordlist: str,
        rule_file: str,
        hash_type: int = 22000,
        timeout: int = 0,
        extra_args: Optional[list[str]] = None,
    ) -> HashcatResult:
        """Run a rule-based dictionary (attack mode 0) attack.

        Args:
            hash_file: Path to the hash file.
            wordlist: Path to the wordlist.
            rule_file: Path to the rule file.
            hash_type: Hash type number.
            timeout: Maximum seconds (0 = unlimited).
            extra_args: Additional hashcat arguments.

        Returns:
            HashcatResult with the outcome.
        """
        return self.dictionary_attack(
            hash_file, wordlist, hash_type, rule_file, timeout, extra_args,
        )

    # ── Session management ─────────────────────────────────────────────

    def benchmark(self, hash_type: int = 22000) -> dict[str, Any]:
        """Run hashcat benchmark for the given hash type."""
        try:
            result = subprocess.run(
                [self.hashcat_path, "-m", str(hash_type), "-b", "--force"],
                capture_output=True, text=True, timeout=120,
            )
            output = result.stdout + result.stderr
            speed_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:H/s|MH/s|kH/s|GH/s)", output)
            speed = float(speed_match.group(1)) if speed_match else 0.0
            return {"output": output, "speed": speed}
        except FileNotFoundError:
            raise CrackingError("hashcat not found")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("hashcat benchmark timed out")

    def check_cracked(self, hash_file: str, hash_type: int = 22000) -> Optional[str]:
        """Check if a hash has already been cracked (show mode)."""
        try:
            result = subprocess.run(
                [self.hashcat_path, "-m", str(hash_type), "--show", hash_file, "--force"],
                capture_output=True, text=True, timeout=30,
            )
            output = result.stdout.strip()
            if ":" in output:
                return output.split(":")[-1].strip()
            return None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def stop(self) -> None:
        """Stop the running hashcat process."""
        self._running = False
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
        self._process = None

    def is_running(self) -> bool:
        return self._running

    def __repr__(self) -> str:
        available = self._is_available()
        return f"HashcatWrapper(path={self.hashcat_path!r}, available={available})"
