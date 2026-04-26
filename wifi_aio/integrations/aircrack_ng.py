"""Aircrack-ng suite wrapper.

Provides a unified Python API for airodump-ng, aireplay-ng, aircrack-ng,
and airmon-ng, handling subprocess management, output parsing, and
error translation.
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
    CaptureError,
    CrackingError,
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


@dataclass
class AirodumpAP:
    """Parsed access-point row from airodump-ng output.

    Attributes:
        bssid: MAC address of the AP.
        ssid: Network name.
        channel: WiFi channel.
        frequency: Frequency in MHz.
        encryption: Security string (e.g. ``"WPA2"``).
        cipher: Cipher suite (e.g. ``"CCMP"``).
        authentication: Authentication method.
        signal_dbm: Signal strength.
        power: Power reading from airodump.
        beacons: Beacon frame count.
        ivs: IV count (relevant for WEP).
        data_frames: Data frame count.
        clients: List of associated client MACs.
        first_seen: Epoch timestamp.
        last_seen: Epoch timestamp.
    """

    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    frequency: int = 0
    encryption: str = ""
    cipher: str = ""
    authentication: str = ""
    signal_dbm: int = 0
    power: int = 0
    beacons: int = 0
    ivs: int = 0
    data_frames: int = 0
    clients: list[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "frequency": self.frequency,
            "encryption": self.encryption,
            "cipher": self.cipher,
            "authentication": self.authentication,
            "signal_dbm": self.signal_dbm,
            "power": self.power,
            "beacons": self.beacons,
            "ivs": self.ivs,
            "data_frames": self.data_frames,
            "clients": self.clients,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class AirodumpClient:
    """Parsed client/station row from airodump-ng output."""

    mac: str = ""
    bssid: str = ""
    ssid: str = ""
    signal_dbm: int = 0
    power: int = 0
    packets: int = 0
    probes: list[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "mac": self.mac,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "signal_dbm": self.signal_dbm,
            "power": self.power,
            "packets": self.packets,
            "probes": self.probes,
        }


@dataclass
class AircrackResult:
    """Result of an aircrack-ng cracking attempt."""

    success: bool = False
    password: str = ""
    key_found: bool = False
    elapsed: float = 0.0
    output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "password": self.password,
            "key_found": self.key_found,
            "elapsed": self.elapsed,
        }


class AircrackNG:
    """Wrapper for the aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng).

    Example::

        air = AircrackNG()
        air.start_monitor("wlan0")
        aps = air.scan("wlan0mon", duration=20)
        for ap in aps:
            print(ap.ssid, ap.bssid, ap.channel)
    """

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout
        self._airodump_proc: Optional[subprocess.Popen] = None

    # ── airmon-ng ──────────────────────────────────────────────────────

    def start_monitor(self, interface: str) -> str:
        """Enable monitor mode on *interface* using airmon-ng.

        Returns:
            The monitor-mode interface name (e.g. ``"wlan0mon"``).
        """
        self._check_root()
        try:
            # Kill interfering processes first
            subprocess.run(
                ["airmon-ng", "check", "kill"],
                capture_output=True, text=True, timeout=15,
            )

            result = subprocess.run(
                ["airmon-ng", "start", interface],
                capture_output=True, text=True, timeout=self.timeout,
            )
            output = result.stdout + result.stderr

            # Parse monitor interface name
            match = re.search(r"monitor mode enabled on (\S+)", output, re.IGNORECASE)
            if match:
                mon_iface = match.group(1)
                logger.info("Monitor mode enabled on %s", mon_iface)
                return mon_iface

            # Fallback: common naming convention
            mon_iface = interface + "mon"
            logger.info("Assuming monitor interface: %s", mon_iface)
            return mon_iface

        except FileNotFoundError:
            raise WiFiPermissionError("airmon-ng not found. Install aircrack-ng suite.")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"airmon-ng timed out after {self.timeout}s")

    def stop_monitor(self, interface: str) -> None:
        """Disable monitor mode on *interface*."""
        self._check_root()
        try:
            subprocess.run(
                ["airmon-ng", "stop", interface],
                capture_output=True, text=True, timeout=self.timeout,
            )
            # Restart network manager
            subprocess.run(
                ["systemctl", "start", "NetworkManager"],
                capture_output=True, text=True, timeout=10,
            )
            logger.info("Monitor mode stopped on %s", interface)
        except FileNotFoundError:
            raise WiFiPermissionError("airmon-ng not found")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("airmon-ng stop timed out")

    # ── airodump-ng ────────────────────────────────────────────────────

    def scan(
        self,
        interface: str,
        duration: int = 30,
        channel: Optional[int] = None,
        bssid: Optional[str] = None,
        band: str = "bg",
        output_prefix: str = "/tmp/wifiaio_airodump",
    ) -> list[AirodumpAP]:
        """Run airodump-ng and return discovered APs.

        Args:
            interface: Monitor-mode interface.
            duration: Scan duration in seconds.
            channel: Lock to a specific channel (None = hop).
            bssid: Lock to a specific BSSID.
            band: Band to scan (``"a"``, ``"b"``, ``"g"``, ``"bg"``).
            output_prefix: File prefix for airodump output.

        Returns:
            List of AirodumpAP objects.
        """
        self._check_root()

        cmd = [
            "airodump-ng", interface,
            "-w", output_prefix,
            "--output-format", "csv",
            "--band", band,
        ]
        if channel is not None:
            cmd.extend(["-c", str(channel)])
        if bssid is not None:
            cmd.extend(["--bssid", bssid])

        try:
            self._airodump_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            logger.info("airodump-ng scanning for %d seconds", duration)
            time.sleep(duration)
            self._airodump_proc.terminate()
            self._airodump_proc.wait(timeout=10)
        except FileNotFoundError:
            raise CaptureError("airodump-ng not found. Install aircrack-ng suite.")
        except subprocess.TimeoutExpired:
            if self._airodump_proc:
                self._airodump_proc.kill()
                self._airodump_proc.wait()
        finally:
            self._airodump_proc = None

        csv_file = f"{output_prefix}-01.csv"
        if os.path.isfile(csv_file):
            return self._parse_csv(csv_file)

        logger.warning("airodump CSV not found at %s", csv_file)
        return []

    def _parse_csv(self, csv_path: str) -> list[AirodumpAP]:
        """Parse airodump-ng CSV output into AirodumpAP objects."""
        now = time.time()
        aps: list[AirodumpAP] = []

        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as exc:
            raise CaptureError(f"Cannot read airodump CSV: {exc}")

        sections = content.split("\r\n\r\n") if "\r\n\r\n" in content else content.split("\n\n")

        for section in sections:
            lines = section.strip().splitlines()
            if not lines:
                continue
            header = lines[0].lower()
            if "bssid" in header and "station" not in header:
                for line in lines[1:]:
                    line = line.strip()
                    if not line:
                        continue
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) < 14:
                        continue

                    ap = AirodumpAP(
                        bssid=parts[0].strip().lower(),
                        channel=int(parts[3].strip()) if parts[3].strip() else 0,
                        power=int(parts[8].strip()) if parts[8].strip() else 0,
                        signal_dbm=int(parts[8].strip()) if parts[8].strip() else 0,
                        encryption=parts[5].strip(),
                        cipher=parts[6].strip() if len(parts) > 6 else "",
                        authentication=parts[7].strip() if len(parts) > 7 else "",
                        beacons=int(parts[9].strip()) if parts[9].strip() else 0,
                        ivs=int(parts[10].strip()) if parts[10].strip() else 0,
                        data_frames=int(parts[10].strip()) if parts[10].strip() else 0,
                        ssid=parts[13].strip() if len(parts) > 13 else "",
                        first_seen=now,
                        last_seen=now,
                    )
                    aps.append(ap)

        return aps

    # ── aireplay-ng ────────────────────────────────────────────────────

    def deauth(
        self,
        interface: str,
        bssid: str,
        client_mac: str = "FF:FF:FF:FF:FF:FF",
        count: int = 5,
    ) -> dict[str, Any]:
        """Send deauthentication frames via aireplay-ng.

        Returns:
            Dict with output and frame count.
        """
        self._check_root()
        cmd = [
            "aireplay-ng",
            "-0", str(count),
            "-a", bssid,
            "-c", client_mac,
            interface,
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout,
            )
            output = result.stdout + result.stderr
            sent_match = re.search(r"Sending\s+(\d+)\s+DeAuth", output)
            frames_sent = int(sent_match.group(1)) if sent_match else count
            logger.info("aireplay-ng deauth: %d frames sent to %s", frames_sent, bssid)
            return {"output": output, "frames_sent": frames_sent}
        except FileNotFoundError:
            raise WiFiPermissionError("aireplay-ng not found")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("aireplay-ng deauth timed out")

    def fake_auth(self, interface: str, bssid: str) -> dict[str, Any]:
        """Perform fake authentication via aireplay-ng.

        Returns:
            Dict with output and success status.
        """
        self._check_root()
        cmd = ["aireplay-ng", "-1", "0", "-a", bssid, interface]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout,
            )
            output = result.stdout + result.stderr
            success = "association successful" in output.lower()
            return {"output": output, "success": success}
        except FileNotFoundError:
            raise WiFiPermissionError("aireplay-ng not found")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("aireplay-ng fake auth timed out")

    def arp_replay(
        self,
        interface: str,
        bssid: str,
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Run ARP replay attack via aireplay-ng.

        Returns:
            Dict with output and packets sent.
        """
        self._check_root()
        cmd = ["aireplay-ng", "-3", "-b", bssid, interface]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            output = result.stdout + result.stderr
            return {"output": output}
        except FileNotFoundError:
            raise WiFiPermissionError("aireplay-ng not found")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("aireplay-ng ARP replay timed out")

    # ── aircrack-ng ────────────────────────────────────────────────────

    def crack(
        self,
        capture_file: str,
        wordlist: Optional[str] = None,
        bssid: Optional[str] = None,
    ) -> AircrackResult:
        """Attempt to crack a captured handshake using aircrack-ng.

        Args:
            capture_file: Path to .cap or .pcap file.
            wordlist: Path to wordlist (None = aircrack uses built-in).
            bssid: Target BSSID to select the right ESSID.

        Returns:
            AircrackResult with the outcome.
        """
        cmd = ["aircrack-ng"]
        if wordlist:
            cmd.extend(["-w", wordlist])
        if bssid:
            cmd.extend(["-b", bssid])
        cmd.append(capture_file)

        start = time.time()
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
                input="\n",
            )
            output = result.stdout + result.stderr
            elapsed = time.time() - start

            # Check for success
            key_match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output)
            if key_match:
                password = key_match.group(1)
                logger.info("aircrack-ng found key: %s", password)
                return AircrackResult(
                    success=True,
                    password=password,
                    key_found=True,
                    elapsed=elapsed,
                    output=output,
                )

            return AircrackResult(
                success=False,
                elapsed=elapsed,
                output=output,
            )

        except FileNotFoundError:
            raise CrackingError("aircrack-ng not found. Install aircrack-ng suite.")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("aircrack-ng timed out")

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _check_root() -> None:
        if os.geteuid() != 0:
            raise WiFiPermissionError("Aircrack-ng operations require root privileges")

    def stop_scan(self) -> None:
        """Stop any running airodump-ng process."""
        if self._airodump_proc and self._airodump_proc.poll() is None:
            self._airodump_proc.terminate()
            try:
                self._airodump_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._airodump_proc.kill()
                self._airodump_proc.wait()
            self._airodump_proc = None

    def __repr__(self) -> str:
        return f"AircrackNG(timeout={self.timeout})"
