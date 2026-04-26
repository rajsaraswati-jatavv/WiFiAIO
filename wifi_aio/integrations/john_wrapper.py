"""John the Ripper wrapper for WiFi password cracking.

Supports dictionary, incremental, and wordlist-based attacks
against WPA/WPA2 handshake captures.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Optional

from wifi_aio.exceptions import (
    CrackingError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


@dataclass
class JohnResult:
    """Result of a John the Ripper cracking session."""

    success: bool = False
    password: str = ""
    time_elapsed: float = 0.0
    speed: float = 0.0
    output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "password": self.password,
            "time_elapsed": self.time_elapsed,
            "speed": self.speed,
        }


class JohnWrapper:
    """Run John the Ripper for WiFi cracking.

    Handles conversion from pcap to John-compatible formats and
    execution of various cracking modes.

    Example::

        john = JohnWrapper()
        result = john.crack_hash(
            hash_file="capture.hccapx",
            wordlist="/usr/share/wordlists/rockyou.txt",
        )
        if result.success:
            print(f"Password: {result.password}")
    """

    def __init__(
        self,
        john_path: str = "john",
        john_dir: str = "/tmp/wifiaio_john",
    ) -> None:
        self.john_path = john_path
        self.john_dir = john_dir
        self._process: Optional[subprocess.Popen] = None
        self._running = False

        os.makedirs(john_dir, exist_ok=True)

    def _is_available(self) -> bool:
        try:
            result = subprocess.run(
                [self.john_path, "--list=build-info"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def convert_pcap(
        self,
        pcap_file: str,
        output_file: Optional[str] = None,
    ) -> str:
        """Convert a pcap capture to John-compatible format.

        Uses ``wpapcap2john`` (or the Jumbo version's conversion).

        Args:
            pcap_file: Path to the .cap or .pcap file.
            output_file: Destination path (default: same name + .john).

        Returns:
            Path to the converted hash file.
        """
        if not os.path.isfile(pcap_file):
            raise CrackingError(f"Capture file not found: {pcap_file}")

        if output_file is None:
            output_file = pcap_file.rsplit(".", 1)[0] + ".john"

        # Try wpapcap2john from john jumbo
        for converter in ["wpapcap2john", "john", "/usr/sbin/wpapcap2john"]:
            try:
                cmd = [converter, pcap_file] if "wpapcap2john" in converter else [
                    converter, "--format=wpapsk", pcap_file,
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0 and result.stdout.strip():
                    with open(output_file, "w") as f:
                        f.write(result.stdout.strip() + "\n")
                    logger.info("Converted %s → %s", pcap_file, output_file)
                    return output_file
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        raise CrackingError(
            "Failed to convert pcap. Install john jumbo (wpapcap2john)."
        )

    def crack_hash(
        self,
        hash_file: str,
        wordlist: Optional[str] = None,
        format_type: str = "wpapsk",
        rules: Optional[str] = None,
        timeout: int = 0,
        incremental: bool = False,
    ) -> JohnResult:
        """Run John the Ripper against a hash file.

        Args:
            hash_file: Path to the John-format hash file.
            wordlist: Path to the wordlist (None for incremental).
            format_type: John format (default ``"wpapsk"``).
            rules: Rule name to apply.
            timeout: Maximum seconds (0 = unlimited).
            incremental: Use incremental (brute-force) mode.

        Returns:
            JohnResult with the outcome.
        """
        if not os.path.isfile(hash_file):
            raise CrackingError(f"Hash file not found: {hash_file}")

        cmd = [self.john_path, f"--format={format_type}"]

        if incremental:
            cmd.append("--incremental")
        elif wordlist:
            cmd.extend(["--wordlist", wordlist])
            if rules:
                cmd.extend(["--rules", rules])
        else:
            cmd.append("--incremental")

        cmd.append(hash_file)

        start = time.time()
        self._running = True
        result = JohnResult()

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

            # Check if password was found
            if "loaded" in output.lower() and "remaining" not in output.lower():
                pass  # Still processing info

            # Try to show cracked passwords
            show_result = subprocess.run(
                [self.john_path, "--show", f"--format={format_type}", hash_file],
                capture_output=True, text=True, timeout=10,
            )
            show_output = show_result.stdout

            if "0 password hashes cracked" not in show_output and ":" in show_output:
                for line in show_output.splitlines():
                    if ":" in line and not line.startswith(" "):
                        parts = line.split(":")
                        if len(parts) >= 2 and parts[1]:
                            result.success = True
                            result.password = parts[1]
                            break

            # Parse speed
            speed_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:c/s|g/s)", output)
            if speed_match:
                result.speed = float(speed_match.group(1))

        except FileNotFoundError:
            raise CrackingError("john not found. Install John the Ripper.")
        finally:
            self._running = False
            self._process = None

        result.time_elapsed = time.time() - start

        if result.success:
            logger.info("John found password: %s", result.password)
        else:
            logger.info("John did not find the password")

        return result

    def crack_pcap(
        self,
        pcap_file: str,
        wordlist: Optional[str] = None,
        format_type: str = "wpapsk",
        timeout: int = 0,
    ) -> JohnResult:
        """Convert a pcap file and crack it in one step.

        Args:
            pcap_file: Path to the .cap/.pcap file.
            wordlist: Path to the wordlist.
            format_type: John format.
            timeout: Maximum seconds (0 = unlimited).

        Returns:
            JohnResult with the outcome.
        """
        hash_file = self.convert_pcap(pcap_file)
        return self.crack_hash(hash_file, wordlist, format_type, timeout=timeout)

    def stop(self) -> None:
        """Stop the running John process."""
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
        return f"JohnWrapper(path={self.john_path!r}, available={available})"
