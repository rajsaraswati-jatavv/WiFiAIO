"""Bettercap wrapper for MITM and network attack operations.

Provides a Python API for bettercap's REST API and command-line
interface for man-in-the-middle, sniffing, spoofing, and proxying.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from wifi_aio.exceptions import (
    AutomationError,
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


@dataclass
class BettercapSession:
    """State of a bettercap session.

    Attributes:
        running: Whether the bettercap process is active.
        pid: Process ID.
        api_url: REST API endpoint.
        api_username: API auth username.
        api_password: API auth password.
    """

    running: bool = False
    pid: int = 0
    api_url: str = "http://localhost:8081"
    api_username: str = "bettercap"
    api_password: str = "bettercap"


class BettercapWrapper:
    """Run bettercap for MITM and network operations.

    Supports both CLI and REST API interaction modes.

    Example::

        bc = BettercapWrapper(interface="eth0")
        bc.start()
        bc.run_command("net.probe on")
        bc.run_command("set arp.spoof.targets 192.168.1.100")
        bc.run_command("arp.spoof on")
        # ... later
        bc.stop()
    """

    def __init__(
        self,
        interface: str = "eth0",
        bettercap_path: str = "bettercap",
        api_port: int = 8081,
        api_username: str = "bettercap",
        api_password: str = "bettercap",
        timeout: int = 30,
    ) -> None:
        self.interface = interface
        self.bettercap_path = bettercap_path
        self.api_port = api_port
        self.api_username = api_username
        self.api_password = api_password
        self.timeout = timeout

        self._session = BettercapSession(
            api_url=f"http://localhost:{api_port}",
            api_username=api_username,
            api_password=api_password,
        )
        self._process: Optional[subprocess.Popen] = None

    def _check_root(self) -> None:
        if os.geteuid() != 0:
            raise WiFiPermissionError("bettercap requires root privileges")

    # ── Lifecycle ──────────────────────────────────────────────────────

    def start(self, commands: Optional[list[str]] = None) -> BettercapSession:
        """Start bettercap as a background process.

        Args:
            commands: Optional list of bettercap commands to execute on start.

        Returns:
            The active BettercapSession.
        """
        self._check_root()

        cmd = [
            self.bettercap_path,
            "-iface", self.interface,
            "-api-address", "127.0.0.1",
            "-api-port", str(self.api_port),
            "-api-user", self.api_username,
            "-api-pass", self.api_password,
            "-no-colors",
        ]

        # Build initial commands
        if commands:
            eval_cmds = "; ".join(commands)
            cmd.extend(["-eval", eval_cmds])

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self._session.pid = self._process.pid
            self._session.running = True

            # Wait for API to become available
            self._wait_for_api(max_wait=10)
            logger.info("bettercap started (PID %d)", self._process.pid)

        except FileNotFoundError:
            raise AutomationError("bettercap not found. Install bettercap.")

        return self._session

    def stop(self) -> None:
        """Stop the bettercap process."""
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
            logger.info("bettercap stopped")

        self._session.running = False
        self._process = None

    def _wait_for_api(self, max_wait: float = 10.0) -> None:
        """Wait for the bettercap REST API to become responsive."""
        deadline = time.time() + max_wait
        while time.time() < deadline:
            try:
                req = Request(self._session.api_url + "/api/session")
                cred = f"{self.api_username}:{self.api_password}"
                import base64
                req.add_header("Authorization", f"Basic {base64.b64encode(cred.encode()).decode()}")
                with urlopen(req, timeout=2) as resp:
                    if resp.status == 200:
                        return
            except (URLError, OSError):
                pass
            time.sleep(0.5)

        logger.warning("bettercap API did not respond within %.1fs", max_wait)

    # ── REST API ───────────────────────────────────────────────────────

    def _api_request(
        self, method: str, endpoint: str, data: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Make an authenticated request to the bettercap REST API.

        Args:
            method: HTTP method (``"GET"``, ``"POST"``, ``"PATCH"``).
            endpoint: API path (e.g. ``"/api/session"``).
            data: JSON payload for POST/PATCH requests.

        Returns:
            Parsed JSON response dict.
        """
        url = self._session.api_url + endpoint
        import base64

        cred = f"{self.api_username}:{self.api_password}"
        headers = {
            "Authorization": f"Basic {base64.b64encode(cred.encode()).decode()}",
            "Content-Type": "application/json",
        }

        body = json.dumps(data).encode() if data else None
        req = Request(url, data=body, headers=headers, method=method)

        try:
            with urlopen(req, timeout=self.timeout) as resp:
                response_text = resp.read().decode("utf-8")
                return json.loads(response_text) if response_text else {}
        except URLError as exc:
            raise WiFiConnectionError(
                f"bettercap API request failed: {exc}",
                details=str(exc),
            )

    def get_session(self) -> dict[str, Any]:
        """Retrieve the current bettercap session state."""
        return self._api_request("GET", "/api/session")

    def run_command(self, command: str) -> dict[str, Any]:
        """Execute a bettercap command via the REST API.

        Args:
            command: bettercap command string (e.g. ``"net.probe on"``).

        Returns:
            API response dict.
        """
        return self._api_request("POST", "/api/session", {"cmd": command})

    # ── Convenience methods ────────────────────────────────────────────

    def arp_spoof(self, targets: str, full_duplex: bool = True) -> dict[str, Any]:
        """Enable ARP spoofing on specified targets.

        Args:
            targets: Comma-separated IP addresses or ``"auto"``.
            full_duplex: Spoof both directions.

        Returns:
            API response dict.
        """
        self.run_command(f"set arp.spoof.targets {targets}")
        if full_duplex:
            self.run_command("set arp.spoof.fullduplex true")
        return self.run_command("arp.spoof on")

    def dns_spoof(self, domain: str = "all", address: Optional[str] = None) -> dict[str, Any]:
        """Enable DNS spoofing.

        Args:
            domain: Domain to spoof (``"all"`` for wildcard).
            address: IP to resolve to (defaults to local IP).

        Returns:
            API response dict.
        """
        if address:
            self.run_command(f"set dns.spoof.address {address}")
        self.run_command(f"set dns.spoof.domains {domain}")
        return self.run_command("dns.spoof on")

    def net_probe(self) -> dict[str, Any]:
        """Start network probing to discover hosts."""
        return self.run_command("net.probe on")

    def net_sniff(self, output_file: Optional[str] = None) -> dict[str, Any]:
        """Start network sniffing.

        Args:
            output_file: Optional PCAP output file path.

        Returns:
            API response dict.
        """
        if output_file:
            self.run_command(f"set net.sniff.output {output_file}")
        return self.run_command("net.sniff on")

    def wifi_deauth(self, bssid: str, channel: int) -> dict[str, Any]:
        """Send WiFi deauth frames via bettercap.

        Args:
            bssid: Target AP BSSID.
            channel: Target channel.

        Returns:
            API response dict.
        """
        self.run_command(f"set wifi.deauth.channel {channel}")
        self.run_command("wifi.deauth on")
        # Wait briefly
        time.sleep(3)
        self.run_command("wifi.deauth off")
        return {"bssid": bssid, "channel": channel, "deauthed": True}

    def set_wifi_interface(self, interface: str, channel: int = 0) -> dict[str, Any]:
        """Configure the WiFi interface for bettercap.

        Args:
            interface: WiFi interface name.
            channel: Channel to set (0 = hop).

        Returns:
            API response dict.
        """
        self.run_command(f"set wifi.interface {interface}")
        if channel > 0:
            self.run_command(f"set wifi.channel {channel}")
        return self.run_command("wifi.recon on")

    def is_running(self) -> bool:
        return self._session.running and self._process is not None and self._process.poll() is None

    def __repr__(self) -> str:
        return f"BettercapWrapper(interface={self.interface!r}, running={self.is_running()})"
