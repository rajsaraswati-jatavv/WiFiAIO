"""Network connection management for WiFi networks.

Provides functionality to connect to WiFi networks using wpa_supplicant,
disconnect, and check connection status.
"""

import os
import re
import subprocess
import logging
import shutil
import signal
import time
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    InterfaceError,
)

logger = logging.getLogger(__name__)

WPA_SUPPLICANT_CONF_TEMPLATE = """\
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=US

network={{
    ssid="{ssid}"
    {psk_line}
    {key_mgmt_line}
}}
"""


class NetworkConnector:
    """Connect to WiFi networks, manage WPA supplicant and nmcli, and check status."""

    def __init__(self, interface: str = "wlan0", prefer_nmcli: bool = False):
        self.interface = interface
        self.prefer_nmcli = prefer_nmcli
        self._wpa_supplicant_pid: Optional[int] = None
        self._dhclient_pid: Optional[int] = None
        self._config_path = "/tmp/wifiaio_wpa.conf"
        self._connected_ssid: Optional[str] = None
        self._nmcli_available: Optional[bool] = None

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(
        self,
        ssid: str,
        password: Optional[str] = None,
        interface: Optional[str] = None,
        timeout: int = 30,
        hidden: bool = False,
        key_mgmt: str = "WPA-PSK",
    ) -> Dict[str, str]:
        """Connect to a WiFi network.

        Args:
            ssid: Network SSID.
            password: Network password (None for open networks).
            interface: Override the default interface.
            timeout: Connection timeout in seconds.
            hidden: Whether the network is hidden.
            key_mgmt: Key management type (WPA-PSK, WPA-EAP, NONE).

        Returns:
            Dict with connection details.

        Raises:
            WiFiConnectionError: If connection fails.
            WiFiPermissionError: If not root.
        """
        iface = interface or self.interface
        self._require_root("connect to WiFi")

        # Ensure interface is in managed mode
        try:
            self._ensure_managed_mode(iface)
        except Exception as exc:
            raise WiFiConnectionError(f"Could not set managed mode: {exc}")

        # Generate wpa_supplicant config
        self._generate_wpa_config(ssid, password, hidden, key_mgmt)

        # Kill any existing wpa_supplicant on this interface
        self._kill_wpa_supplicant(iface)

        # Start wpa_supplicant
        self._start_wpa_supplicant(iface)

        # Wait for connection
        connected = self._wait_for_connection(iface, ssid, timeout)
        if not connected:
            self._kill_wpa_supplicant(iface)
            raise WiFiConnectionError(f"Failed to connect to '{ssid}' within {timeout}s")

        # Obtain DHCP lease
        self._obtain_dhcp(iface)

        self._connected_ssid = ssid
        logger.info("Connected to %s on %s", ssid, iface)

        return self.get_connection_status(iface)

    # ------------------------------------------------------------------
    # nmcli-based connection
    # ------------------------------------------------------------------

    def _check_nmcli(self) -> bool:
        """Check if nmcli is available and NetworkManager is running."""
        if self._nmcli_available is not None:
            return self._nmcli_available
        try:
            result = subprocess.run(
                ["nmcli", "general", "status"],
                capture_output=True, text=True, timeout=5,
            )
            self._nmcli_available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._nmcli_available = False
        return self._nmcli_available

    def connect_nmcli(
        self,
        ssid: str,
        password: Optional[str] = None,
        interface: Optional[str] = None,
        timeout: int = 30,
        hidden: bool = False,
    ) -> Dict[str, str]:
        """Connect to a WiFi network using nmcli (NetworkManager).

        Args:
            ssid: Network SSID.
            password: Network password (None for open networks).
            interface: Override the default interface.
            timeout: Connection timeout in seconds.
            hidden: Whether the network is hidden.

        Returns:
            Dict with connection details.

        Raises:
            WiFiConnectionError: If connection fails.
            WiFiPermissionError: If not root.
        """
        if not self._check_nmcli():
            raise WiFiConnectionError("nmcli not available or NetworkManager not running")

        iface = interface or self.interface

        # Build nmcli command
        cmd = [
            "nmcli", "device", "wifi", "connect", ssid,
            "ifname", iface,
            "--timeout", str(timeout),
        ]
        if password:
            cmd.extend(["password", password])
        if hidden:
            cmd.append("hidden")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 10,
            )
        except FileNotFoundError:
            raise WiFiConnectionError("nmcli command not found")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"nmcli connection to '{ssid}' timed out")

        if result.returncode != 0:
            raise WiFiConnectionError(
                f"nmcli failed to connect to '{ssid}': {result.stderr.strip()}"
            )

        self._connected_ssid = ssid
        logger.info("Connected to %s on %s via nmcli", ssid, iface)
        return self.get_connection_status(iface)

    def disconnect_nmcli(self, interface: Optional[str] = None) -> bool:
        """Disconnect from WiFi using nmcli.

        Args:
            interface: Override the default interface.

        Returns:
            True if successfully disconnected.
        """
        if not self._check_nmcli():
            return False

        iface = interface or self.interface
        try:
            result = subprocess.run(
                ["nmcli", "device", "disconnect", iface],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                self._connected_ssid = None
                logger.info("Disconnected %s via nmcli", iface)
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False

    def scan_nmcli(self, interface: Optional[str] = None) -> List[Dict[str, str]]:
        """Scan for available WiFi networks using nmcli.

        Args:
            interface: Override the default interface.

        Returns:
            List of dicts with network information.
        """
        iface = interface or self.interface
        networks: List[Dict[str, str]] = []

        if not self._check_nmcli():
            return networks

        try:
            result = subprocess.run(
                [
                    "nmcli", "-t", "-f",
                    "SSID,BSSID,SIGNAL,FREQ,SECURITY,CHAN,RATE",
                    "device", "wifi", "list", "ifname", iface,
                    "--rescan", "yes",
                ],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return networks

            for line in result.stdout.splitlines():
                parts = line.split(":")
                if len(parts) >= 7:
                    ssid = parts[0]
                    if not ssid or ssid == "--":
                        continue
                    networks.append({
                        "ssid": ssid,
                        "bssid": parts[1],
                        "signal": parts[2],
                        "frequency": parts[3],
                        "security": parts[4],
                        "channel": parts[5],
                        "rate": parts[6],
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Sort by signal strength (strongest first)
        networks.sort(
            key=lambda n: int(n.get("signal", "0")),
            reverse=True,
        )
        return networks

    def get_saved_nmcli_networks(self) -> List[Dict[str, str]]:
        """Get list of saved NetworkManager connections.

        Returns:
            List of dicts with connection details.
        """
        networks = []
        if not self._check_nmcli():
            return networks

        try:
            result = subprocess.run(
                [
                    "nmcli", "-t", "-f",
                    "NAME,TYPE,DEVICE",
                    "connection", "show",
                ],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return networks

            for line in result.stdout.splitlines():
                parts = line.split(":")
                if len(parts) >= 3 and "wifi" in parts[1]:
                    networks.append({
                        "name": parts[0],
                        "type": parts[1],
                        "device": parts[2] if parts[2] != "" else "not active",
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return networks

    def forget_nmcli_network(self, ssid: str) -> bool:
        """Remove a saved NetworkManager WiFi connection.

        Returns:
            True if the connection was removed.
        """
        if not self._check_nmcli():
            return False

        try:
            result = subprocess.run(
                ["nmcli", "connection", "delete", ssid],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def get_connection_status_nmcli(self, interface: Optional[str] = None) -> Dict[str, str]:
        """Get connection status using nmcli.

        Returns:
            Dict with connection details.
        """
        iface = interface or self.interface
        status: Dict[str, str] = {
            "ssid": "",
            "bssid": "",
            "frequency": "",
            "signal_level": "",
            "security": "",
            "ip_address": "",
            "state": "disconnected",
        }

        if not self._check_nmcli():
            return status

        try:
            result = subprocess.run(
                [
                    "nmcli", "-t", "-f",
                    "GENERAL.STATE,802-11-wireless.ssid,802-11-wireless.bssid,"
                    "802-11-wireless.freq,802-11-wireless.signal,"
                    "802-11-wireless-security.key-mgmt,IP4.ADDRESS",
                    "device", "show", iface,
                ],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    key, _, value = line.partition(":")
                    key = key.strip().upper()
                    value = value.strip()
                    if "STATE" in key:
                        if "connected" in value.lower():
                            status["state"] = "connected"
                    elif "SSID" in key:
                        status["ssid"] = value
                    elif "BSSID" in key:
                        status["bssid"] = value
                    elif "FREQ" in key:
                        status["frequency"] = value
                    elif "SIGNAL" in key:
                        status["signal_level"] = value
                    elif "KEY-MGMT" in key:
                        status["security"] = value
                    elif "IP4.ADDRESS" in key:
                        status["ip_address"] = value.split("/")[0] if "/" in value else value
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return status

    def disconnect(self, interface: Optional[str] = None) -> bool:
        """Disconnect from the current WiFi network.

        Args:
            interface: Override the default interface.

        Returns:
            True if successfully disconnected.
        """
        iface = interface or self.interface
        self._require_root("disconnect from WiFi")

        # Release DHCP lease
        self._release_dhcp(iface)

        # Stop wpa_supplicant
        self._kill_wpa_supplicant(iface)

        # Bring interface down and up
        try:
            subprocess.run(
                ["ip", "link", "set", iface, "down"],
                capture_output=True, text=True, timeout=10,
            )
            subprocess.run(
                ["ip", "link", "set", iface, "up"],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            pass

        self._connected_ssid = None
        logger.info("Disconnected %s", iface)
        return True

    def get_connection_status(self, interface: Optional[str] = None) -> Dict[str, str]:
        """Check the current connection status.

        Returns:
            Dict with keys: ssid, bssid, frequency, signal_level, security,
            ip_address, state.
        """
        iface = interface or self.interface
        status: Dict[str, str] = {
            "ssid": "",
            "bssid": "",
            "frequency": "",
            "signal_level": "",
            "security": "",
            "ip_address": "",
            "state": "disconnected",
        }

        # Try iwconfig
        try:
            result = subprocess.run(
                ["iwconfig", iface],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout
            if "ESSID:" in output:
                match = re.search(r'ESSID:"([^"]*)"', output)
                if match:
                    status["ssid"] = match.group(1)
                    status["state"] = "connected"
            if "Access Point:" in output:
                match = re.search(r"Access Point: ([0-9A-Fa-f:]{17})", output)
                if match:
                    status["bssid"] = match.group(1)
            if "Frequency:" in output:
                match = re.search(r"Frequency:([\d.]+ GHz)", output)
                if match:
                    status["frequency"] = match.group(1)
            if "Signal level=" in output:
                match = re.search(r"Signal level=(-?\d+) dBm", output)
                if match:
                    status["signal_level"] = match.group(1) + " dBm"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try wpa_cli for more details
        try:
            result = subprocess.run(
                ["wpa_cli", "-i", iface, "status"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "=" in line:
                        key, _, value = line.partition("=")
                        key = key.strip().lower()
                        if key == "ssid":
                            status["ssid"] = value.strip()
                        elif key == "bssid":
                            status["bssid"] = value.strip()
                        elif key == "freq":
                            status["frequency"] = value.strip()
                        elif key == "key_mgmt":
                            status["security"] = value.strip()
                        elif key == "wpa_state":
                            status["state"] = (
                                "connected" if value.strip() == "COMPLETED"
                                else value.strip().lower()
                            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Get IP address
        status["ip_address"] = self._get_ip_address(iface)

        return status

    def scan_networks(self, interface: Optional[str] = None) -> List[Dict[str, str]]:
        """Scan for available WiFi networks.

        Returns:
            List of dicts with network information.
        """
        iface = interface or self.interface
        networks: List[Dict[str, str]] = []
        seen_ssids: set = set()

        try:
            # Trigger scan
            subprocess.run(
                ["iw", "dev", iface, "scan", "trigger"],
                capture_output=True, text=True, timeout=5,
            )
            time.sleep(2)

            # Get scan results
            result = subprocess.run(
                ["iw", "dev", iface, "scan"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                return networks

            current: Dict[str, str] = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("BSS"):
                    if current and current.get("ssid"):
                        if current["ssid"] not in seen_ssids:
                            networks.append(current)
                            seen_ssids.add(current["ssid"])
                    match = re.match(r"BSS ([0-9a-fA-F:]{17})", line)
                    current = {"bssid": match.group(1)} if match else {}
                elif "SSID:" in line:
                    current["ssid"] = line.split("SSID:")[1].strip()
                elif "signal:" in line:
                    match = re.search(r"(-?\d+\.\d+) dBm", line)
                    if match:
                        current["signal"] = match.group(1) + " dBm"
                elif "DS Parameter set:" in line:
                    match = re.search(r"channel (\d+)", line)
                    if match:
                        current["channel"] = match.group(1)
                elif "WPA:" in line:
                    current["security"] = "WPA"
                elif "RSN:" in line:
                    current["security"] = "WPA2"
                elif "HE:" in line:
                    current["security"] = "WPA3"

            # Don't forget last entry
            if current and current.get("ssid"):
                if current["ssid"] not in seen_ssids:
                    networks.append(current)

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Sort by signal strength (strongest first)
        networks.sort(
            key=lambda n: float(n.get("signal", "-100").replace(" dBm", "")),
            reverse=True,
        )
        return networks

    # ------------------------------------------------------------------
    # WPA Supplicant management
    # ------------------------------------------------------------------

    def _generate_wpa_config(
        self,
        ssid: str,
        password: Optional[str],
        hidden: bool,
        key_mgmt: str,
    ) -> str:
        """Generate a wpa_supplicant configuration file."""
        if password is None or key_mgmt == "NONE":
            psk_line = ""
            key_mgmt_line = "key_mgmt=NONE"
        else:
            psk_line = f'psk="{password}"'
            key_mgmt_line = f"key_mgmt={key_mgmt}"

        scan_ssid_line = "scan_ssid=1" if hidden else ""

        config = f"""\
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=US

network={{
    ssid="{ssid}"
    {psk_line}
    {key_mgmt_line}
    {scan_ssid_line}
}}
"""
        with open(self._config_path, "w") as fh:
            fh.write(config)
        os.chmod(self._config_path, 0o600)
        return self._config_path

    def _start_wpa_supplicant(self, interface: str) -> None:
        """Start wpa_supplicant daemon for the given interface."""
        cmd = [
            "wpa_supplicant",
            "-B",  # daemonize
            "-i", interface,
            "-c", self._config_path,
            "-P", f"/var/run/wpa_supplicant_{interface}.pid",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                raise WiFiConnectionError(
                    f"wpa_supplicant failed: {result.stderr.strip()}"
                )
        except FileNotFoundError:
            raise WiFiConnectionError("wpa_supplicant not found. Install wpasupplicant.")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("wpa_supplicant startup timed out")

        # Read PID
        pid_file = f"/var/run/wpa_supplicant_{interface}.pid"
        try:
            with open(pid_file, "r") as fh:
                self._wpa_supplicant_pid = int(fh.read().strip())
        except (OSError, ValueError):
            pass

    def _kill_wpa_supplicant(self, interface: str) -> None:
        """Kill any running wpa_supplicant for this interface."""
        try:
            subprocess.run(
                ["wpa_cli", "-i", interface, "terminate"],
                capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Also try to kill by PID
        pid_file = f"/var/run/wpa_supplicant_{interface}.pid"
        try:
            with open(pid_file, "r") as fh:
                pid = int(fh.read().strip())
                os.kill(pid, signal.SIGTERM)
        except (OSError, ValueError, ProcessLookupError):
            pass

        self._wpa_supplicant_pid = None

    def _wait_for_connection(
        self, interface: str, ssid: str, timeout: int
    ) -> bool:
        """Poll wpa_cli until connection is established or timeout."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                result = subprocess.run(
                    ["wpa_cli", "-i", interface, "status"],
                    capture_output=True, text=True, timeout=5,
                )
                if "wpa_state=COMPLETED" in result.stdout:
                    # Verify SSID matches
                    for line in result.stdout.splitlines():
                        if line.startswith("ssid="):
                            if ssid in line:
                                return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
            time.sleep(1)
        return False

    # ------------------------------------------------------------------
    # DHCP
    # ------------------------------------------------------------------

    def _obtain_dhcp(self, interface: str) -> None:
        """Obtain a DHCP lease on the interface."""
        # Try dhclient first, then dhcpcd
        for client in ["dhclient", "dhcpcd"]:
            if shutil.which(client):
                try:
                    subprocess.run(
                        [client, interface],
                        capture_output=True, text=True, timeout=30,
                    )
                    return
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    continue

        # Fallback: try with busybox udhcpc
        if shutil.which("udhcpc"):
            try:
                subprocess.run(
                    ["udhcpc", "-i", interface, "-q"],
                    capture_output=True, text=True, timeout=30,
                )
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                pass

    def _release_dhcp(self, interface: str) -> None:
        """Release the DHCP lease."""
        if shutil.which("dhclient"):
            try:
                subprocess.run(
                    ["dhclient", "-r", interface],
                    capture_output=True, text=True, timeout=10,
                )
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _require_root(action: str) -> None:
        if os.geteuid() != 0:
            raise WiFiPermissionError(f"Root privileges required to {action}")

    def _ensure_managed_mode(self, interface: str) -> None:
        """Ensure the interface is in managed mode."""
        try:
            result = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True, text=True, timeout=5,
            )
            if "type managed" not in result.stdout:
                subprocess.run(
                    ["ip", "link", "set", interface, "down"],
                    check=True, capture_output=True, text=True, timeout=10,
                )
                subprocess.run(
                    ["iw", interface, "set", "type", "managed"],
                    check=True, capture_output=True, text=True, timeout=10,
                )
                subprocess.run(
                    ["ip", "link", "set", interface, "up"],
                    check=True, capture_output=True, text=True, timeout=10,
                )
        except subprocess.CalledProcessError as exc:
            raise InterfaceError(f"Cannot set managed mode: {exc.stderr.strip()}")

    @staticmethod
    def _get_ip_address(interface: str) -> str:
        """Get the IP address for an interface."""
        try:
            result = subprocess.run(
                ["ip", "addr", "show", interface],
                capture_output=True, text=True, timeout=5,
            )
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return ""

    @staticmethod
    def get_wifi_interface() -> Optional[str]:
        """Auto-detect the primary wireless interface."""
        try:
            result = subprocess.run(
                ["iw", "dev"], capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Interface"):
                    return line.split()[-1]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback to /sys/class/net
        net_dir = "/sys/class/net"
        if os.path.isdir(net_dir):
            for ifname in os.listdir(net_dir):
                if os.path.isdir(os.path.join(net_dir, ifname, "wireless")):
                    return ifname
        return None

    def forget_network(self, ssid: str) -> bool:
        """Remove a network from wpa_supplicant configuration.

        Returns:
            True if the network was removed.
        """
        try:
            result = subprocess.run(
                ["wpa_cli", "-i", self.interface, "list_networks"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if ssid in line:
                    network_id = line.split()[0]
                    subprocess.run(
                        ["wpa_cli", "-i", self.interface, "remove_network", network_id],
                        capture_output=True, text=True, timeout=10,
                    )
                    subprocess.run(
                        ["wpa_cli", "-i", self.interface, "save_config"],
                        capture_output=True, text=True, timeout=10,
                    )
                    return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False

    def get_saved_networks(self) -> List[Dict[str, str]]:
        """Get list of saved/configured networks.

        Returns:
            List of dicts with network_id, ssid, bssid, flags.
        """
        networks = []
        try:
            result = subprocess.run(
                ["wpa_cli", "-i", self.interface, "list_networks"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines()[1:]:
                parts = line.split("\t")
                if len(parts) >= 3:
                    networks.append({
                        "network_id": parts[0],
                        "ssid": parts[1],
                        "bssid": parts[2],
                        "flags": parts[3] if len(parts) > 3 else "",
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return networks
