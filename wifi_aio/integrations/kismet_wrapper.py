"""Kismet wrapper for WiFi monitoring and IDS.

Provides integration with Kismet for passive monitoring, alerting,
and device tracking via its REST API.
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
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


@dataclass
class KismetDevice:
    """A device seen by Kismet.

    Attributes:
        mac: MAC address.
        ssid: SSID (for APs).
        type: Device type (``"AP"``, ``"client"``, etc.).
        channel: Channel number.
        signal_dbm: Signal strength.
        frequency: Frequency in MHz.
        first_seen: Epoch first seen.
        last_seen: Epoch last seen.
        packets: Packet count.
        vendor: Vendor string from OUI.
        encryption: Encryption type string.
    """

    mac: str = ""
    ssid: str = ""
    type: str = ""
    channel: int = 0
    signal_dbm: int = 0
    frequency: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    packets: int = 0
    vendor: str = ""
    encryption: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "mac": self.mac,
            "ssid": self.ssid,
            "type": self.type,
            "channel": self.channel,
            "signal_dbm": self.signal_dbm,
            "frequency": self.frequency,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "packets": self.packets,
            "vendor": self.vendor,
            "encryption": self.encryption,
        }


class KismetWrapper:
    """Integrate with Kismet for WiFi monitoring and alerting.

    Supports starting/stopping Kismet, querying devices via the REST
    API, and subscribing to alerts.

    Example::

        kismet = KismetWrapper(interface="wlan0mon")
        kismet.start()
        devices = kismet.get_devices()
        for dev in devices:
            print(dev.mac, dev.ssid, dev.channel)
        kismet.stop()
    """

    def __init__(
        self,
        interface: str = "wlan0mon",
        kismet_path: str = "kismet",
        api_port: int = 2501,
        api_username: str = "kismet",
        api_password: str = "kismet",
        timeout: int = 30,
    ) -> None:
        self.interface = interface
        self.kismet_path = kismet_path
        self.api_port = api_port
        self.api_username = api_username
        self.api_password = api_password
        self.timeout = timeout

        self._process: Optional[subprocess.Popen] = None
        self._running = False
        self._api_url = f"http://localhost:{api_port}"

    def _check_root(self) -> None:
        if os.geteuid() != 0:
            raise WiFiPermissionError(
                "Kismet requires root privileges"
            )

    # ── Lifecycle ──────────────────────────────────────────────────────

    def start(self, extra_args: Optional[list[str]] = None) -> None:
        """Start Kismet as a background process.

        Args:
            extra_args: Additional command-line arguments.
        """
        self._check_root()

        cmd = [
            self.kismet_path,
            "-c", self.interface,
            "--daemonize",
            "-p", str(self.api_port),
        ]
        if extra_args:
            cmd.extend(extra_args)

        try:
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self._running = True
            self._wait_for_api(max_wait=15)
            logger.info("Kismet started on port %d", self.api_port)
        except FileNotFoundError:
            raise AutomationError("kismet not found. Install kismet.")

    def stop(self) -> None:
        """Stop the Kismet process."""
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()

        # Also try via API
        try:
            self._api_request("POST", "/system/shutdown")
        except Exception:
            pass

        self._running = False
        self._process = None
        logger.info("Kismet stopped")

    def _wait_for_api(self, max_wait: float = 15.0) -> None:
        """Wait for the Kismet REST API to be ready."""
        deadline = time.time() + max_wait
        while time.time() < deadline:
            try:
                req = Request(self._api_url + "/system/status")
                import base64
                cred = f"{self.api_username}:{self.api_password}"
                req.add_header(
                    "Authorization",
                    f"Basic {base64.b64encode(cred.encode()).decode()}",
                )
                with urlopen(req, timeout=2) as resp:
                    if resp.status == 200:
                        return
            except (URLError, OSError):
                pass
            time.sleep(1)

        logger.warning("Kismet API did not respond within %.1fs", max_wait)

    # ── REST API ───────────────────────────────────────────────────────

    def _api_request(
        self, method: str, endpoint: str, data: Optional[dict[str, Any]] = None,
    ) -> Any:
        """Make an authenticated request to the Kismet REST API."""
        url = self._api_url + endpoint
        import base64

        cred = f"{self.api_username}:{self.api_password}"
        headers = {
            "Authorization": f"Basic {base64.b64encode(cred.encode()).decode()}",
        }
        body = json.dumps(data).encode() if data else None
        if body:
            headers["Content-Type"] = "application/json"

        req = Request(url, data=body, headers=headers, method=method)
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                text = resp.read().decode("utf-8")
                if text:
                    return json.loads(text)
                return {}
        except URLError as exc:
            raise WiFiConnectionError(
                f"Kismet API request failed: {exc}", details=str(exc),
            )

    def get_status(self) -> dict[str, Any]:
        """Get Kismet system status."""
        return self._api_request("GET", "/system/status")

    # ── Device queries ─────────────────────────────────────────────────

    def get_devices(
        self,
        device_type: Optional[str] = None,
    ) -> list[KismetDevice]:
        """Query all devices seen by Kismet.

        Args:
            device_type: Filter by type (``"AP"``, ``"client"``, etc.).

        Returns:
            List of KismetDevice objects.
        """
        endpoint = "/devices/all/devices.json"
        if device_type:
            endpoint += f"?type={device_type}"

        raw = self._api_request("GET", endpoint)
        devices: list[KismetDevice] = []

        # Handle both list and dict responses
        device_list = raw if isinstance(raw, list) else raw.get("devices", [])

        for entry in device_list:
            if not isinstance(entry, dict):
                continue
            dev = KismetDevice(
                mac=entry.get("kismet.device.base.macaddr", entry.get("mac", "")),
                ssid=entry.get("kismet.device.base.name", entry.get("ssid", "")),
                type=entry.get("kismet.device.base.type", entry.get("type", "")),
                channel=entry.get("kismet.device.base.channel", entry.get("channel", 0)),
                signal_dbm=entry.get("kismet.device.base.signal_dbm",
                                     entry.get("signal_dbm", 0)),
                frequency=entry.get("kismet.device.base.frequency",
                                    entry.get("frequency", 0)),
                first_seen=entry.get("kismet.device.base.first_time",
                                     entry.get("first_seen", 0.0)),
                last_seen=entry.get("kismet.device.base.last_time",
                                    entry.get("last_seen", 0.0)),
                packets=entry.get("kismet.device.base.packets.total",
                                  entry.get("packets", 0)),
                vendor=entry.get("kismet.device.base.manuf", entry.get("vendor", "")),
                encryption=entry.get("kismet.device.base.crypt",
                                     entry.get("encryption", "")),
            )
            devices.append(dev)

        return devices

    def get_access_points(self) -> list[KismetDevice]:
        """Get all access points seen by Kismet."""
        return self.get_devices(device_type="Wi-Fi AP")

    def get_alerts(self) -> list[dict[str, Any]]:
        """Retrieve recent Kismet alerts."""
        try:
            raw = self._api_request("GET", "/alerts/alerts.json")
            if isinstance(raw, list):
                return raw
            return raw.get("alerts", [])
        except (WiFiConnectionError, Exception):
            return []

    def get_channels(self) -> list[dict[str, Any]]:
        """Get channel usage information from Kismet."""
        try:
            raw = self._api_request("GET", "/channels/channels.json")
            if isinstance(raw, list):
                return raw
            return raw.get("channels", [])
        except (WiFiConnectionError, Exception):
            return []

    # ── Capture ────────────────────────────────────────────────────────

    def start_pcap_capture(self, output_file: str) -> dict[str, Any]:
        """Start a PCAP capture via Kismet.

        Args:
            output_file: Path for the PCAP output.

        Returns:
            API response dict.
        """
        return self._api_request("POST", "/pcap/by-id/new", {
            "path": output_file,
        })

    # ── Properties ─────────────────────────────────────────────────────

    def is_running(self) -> bool:
        return self._running and (self._process is not None and self._process.poll() is None)

    def __repr__(self) -> str:
        return f"KismetWrapper(interface={self.interface!r}, running={self.is_running()})"
