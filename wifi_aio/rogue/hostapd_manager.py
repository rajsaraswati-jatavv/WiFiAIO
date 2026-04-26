"""HostapdManager – manage hostapd processes for rogue access points.

Generates hostapd configuration files for open, WPA2-PSK, and WPA3-SAE
networks, then starts / stops the daemon and reports its status.
"""

import os
import signal
import subprocess
import time
from typing import Dict, Optional

from wifi_aio.exceptions import (
    HostAPDError,
    WiFiPermissionError,
    WiFiTimeoutError,
)
from wifi_aio.logger import get_logger

logger = get_logger("rogue.hostapd_manager")

# ── Default configuration fragments ───────────────────────────────────

_OPEN_BASE: Dict[str, str] = {
    "driver": "nl80211",
    "ieee80211n": "1",
    "wmm_enabled": "1",
    "beacon_int": "100",
}

_WPA2_BASE: Dict[str, str] = {
    **_OPEN_BASE,
    "wpa": "2",
    "wpa_key_mgmt": "WPA-PSK",
    "rsn_pairwise": "CCMP",
    "wpa_pairwise": "CCMP",
}

_WPA3_BASE: Dict[str, str] = {
    **_OPEN_BASE,
    "wpa": "2",
    "wpa_key_mgmt": "SAE",
    "rsn_pairwise": "CCMP",
    "ieee80211w": "2",
    "sae_password": "",  # filled at runtime
}


class HostapdManager:
    """Manage a hostapd daemon instance for a rogue access point.

    Parameters
    ----------
    interface:
        Wireless interface name (e.g. ``wlan0``).
    ssid:
        SSID to broadcast.
    channel:
        Channel number (1–14 for 2.4 GHz, 36–165 for 5 GHz).
    config_dir:
        Directory where the generated config file will be written.
    hostapd_bin:
        Path to the ``hostapd`` binary.
    """

    def __init__(
        self,
        interface: str = "wlan0",
        ssid: str = "WiFiAIO",
        channel: int = 6,
        config_dir: str = "/tmp/wifiaio/rogue",
        hostapd_bin: str = "hostapd",
    ) -> None:
        self.interface = interface
        self.ssid = ssid
        self.channel = channel
        self.config_dir = config_dir
        self.hostapd_bin = hostapd_bin
        self._process: Optional[subprocess.Popen] = None
        self._config_path: Optional[str] = None
        self._security_mode: str = "open"

    # ── Config generation ──────────────────────────────────────────────

    def generate_open_config(self) -> str:
        """Generate a hostapd config for an **open** (no encryption) AP.

        Returns the path to the written configuration file.
        """
        self._security_mode = "open"
        params: Dict[str, str] = {
            **_OPEN_BASE,
            "interface": self.interface,
            "ssid": self.ssid,
            "channel": str(self.channel),
            "hw_mode": self._hw_mode(),
        }
        return self._write_config(params)

    def generate_wpa2_config(self, passphrase: str) -> str:
        """Generate a hostapd config for a **WPA2-PSK** AP.

        Parameters
        ----------
        passphrase:
            The WPA2 passphrase (8–63 characters).

        Returns the path to the written configuration file.
        """
        if len(passphrase) < 8 or len(passphrase) > 63:
            raise HostAPDError("WPA2 passphrase must be 8–63 characters")
        self._security_mode = "wpa2"
        params: Dict[str, str] = {
            **_WPA2_BASE,
            "interface": self.interface,
            "ssid": self.ssid,
            "channel": str(self.channel),
            "hw_mode": self._hw_mode(),
            "wpa_passphrase": passphrase,
        }
        return self._write_config(params)

    def generate_wpa3_config(self, password: str) -> str:
        """Generate a hostapd config for a **WPA3-SAE** AP.

        Parameters
        ----------
        password:
            The SAE password.

        Returns the path to the written configuration file.
        """
        if len(password) < 1:
            raise HostAPDError("WPA3 password must not be empty")
        self._security_mode = "wpa3"
        params: Dict[str, str] = {
            **_WPA3_BASE,
            "interface": self.interface,
            "ssid": self.ssid,
            "channel": str(self.channel),
            "hw_mode": self._hw_mode(),
            "sae_password": password,
        }
        return self._write_config(params)

    # ── Process management ─────────────────────────────────────────────

    def start(self, timeout: float = 5.0) -> None:
        """Start the hostapd daemon with the previously generated config.

        Raises
        ------
        HostAPDError
            If no config has been generated or the process fails to start.
        WiFiPermissionError
            If not running as root.
        WiFiTimeoutError
            If the daemon does not become ready within *timeout* seconds.
        """
        if os.geteuid() != 0:
            raise WiFiPermissionError("hostapd requires root privileges")

        if self._config_path is None:
            raise HostAPDError("No config generated yet; call generate_*_config() first")

        if self.is_running():
            logger.warning("hostapd is already running (pid %s)", self._process.pid)
            return

        cmd = [self.hostapd_bin, self._config_path]
        logger.info("Starting hostapd: %s", " ".join(cmd))

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise HostAPDError(
                f"hostapd binary not found: {self.hostapd_bin}"
            ) from exc

        # Give it a moment to initialise, then check it is still alive.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            poll = self._process.poll()
            if poll is not None:
                stderr = self._process.stderr.read() if self._process.stderr else ""
                raise HostAPDError(
                    f"hostapd exited with code {poll}: {stderr.strip()}"
                )
            # If still running after a short wait, assume success.
            time.sleep(0.2)
            if self._process.poll() is None:
                logger.info("hostapd started (pid %d)", self._process.pid)
                return

        # Process still running – consider it ready.
        logger.info("hostapd running (pid %d)", self._process.pid)

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the running hostapd daemon gracefully.

        Sends SIGTERM first; escalates to SIGKILL after *timeout* seconds.
        """
        if self._process is None or self._process.poll() is not None:
            logger.debug("hostapd not running – nothing to stop")
            self._process = None
            return

        pid = self._process.pid
        logger.info("Stopping hostapd (pid %d)", pid)
        self._process.terminate()

        try:
            self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.warning("hostapd did not terminate – sending SIGKILL")
            self._process.kill()
            self._process.wait(timeout=2)

        logger.info("hostapd stopped (pid %d)", pid)
        self._process = None

    def is_running(self) -> bool:
        """Return ``True`` if the hostapd process is alive."""
        return self._process is not None and self._process.poll() is None

    def status(self) -> Dict[str, object]:
        """Return a status dictionary for the current hostapd instance.

        Keys: ``running``, ``pid``, ``interface``, ``ssid``, ``channel``,
        ``security_mode``, ``config_path``.
        """
        return {
            "running": self.is_running(),
            "pid": self._process.pid if self.is_running() else None,
            "interface": self.interface,
            "ssid": self.ssid,
            "channel": self.channel,
            "security_mode": self._security_mode,
            "config_path": self._config_path,
        }

    # ── Internals ──────────────────────────────────────────────────────

    def _hw_mode(self) -> str:
        """Determine the ``hw_mode`` value for hostapd from the channel."""
        if self.channel <= 14:
            return "g"
        return "a"

    def _write_config(self, params: Dict[str, str]) -> str:
        """Serialise *params* to a hostapd config file and return the path."""
        os.makedirs(self.config_dir, exist_ok=True)
        config_path = os.path.join(self.config_dir, "hostapd.conf")
        with open(config_path, "w", encoding="utf-8") as fh:
            for key, value in params.items():
                fh.write(f"{key}={value}\n")
        self._config_path = config_path
        logger.debug("Wrote hostapd config to %s", config_path)
        return config_path
