"""Interface management for WiFi network interfaces.

Provides functionality to list, configure, and manage wireless network
interfaces including mode switching, channel selection, and MAC address
manipulation.
"""

import os
import re
import subprocess
import logging
import time
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    InterfaceError,
)

logger = logging.getLogger(__name__)


class InterfaceManager:
    """Manage wireless network interfaces.

    Supports listing interfaces, switching between monitor and managed modes,
    setting channels, changing MAC addresses, and enabling/disabling interfaces.
    """

    def __init__(self):
        self._current_interface: Optional[str] = None
        self._original_mac_addresses: Dict[str, str] = {}
        self._original_modes: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Interface listing
    # ------------------------------------------------------------------

    def list_interfaces(self) -> List[Dict[str, str]]:
        """List all wireless network interfaces on the system.

        Returns:
            List of dicts with keys: name, driver, mode, mac, channel, state.
        """
        interfaces = []
        try:
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except FileNotFoundError:
            raise InterfaceError("'iw' command not found. Install iw package.")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("Timed out listing interfaces with 'iw dev'.")

        if result.returncode != 0:
            raise InterfaceError(f"iw dev failed: {result.stderr.strip()}")

        # Parse iw dev output
        current_ifname = None
        iface_data: Dict[str, str] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                if current_ifname and iface_data:
                    interfaces.append(self._enrich_interface(current_ifname, iface_data))
                current_ifname = line.split()[-1]
                iface_data = {"name": current_ifname}
            elif current_ifname:
                if line.startswith("ifindex"):
                    iface_data["ifindex"] = line.split()[-1]
                elif line.startswith("wdev"):
                    iface_data["wdev"] = line.split()[-1]
                elif line.startswith("addr"):
                    iface_data["mac"] = line.split()[-1]
                elif line.startswith("type"):
                    iface_data["mode"] = line.split()[-1]
                elif line.startswith("channel"):
                    iface_data["channel"] = line.split()[1]
                elif "txpower" in line:
                    iface_data["txpower"] = line.split()[-2]

        if current_ifname and iface_data:
            interfaces.append(self._enrich_interface(current_ifname, iface_data))

        if not interfaces:
            # Fallback: try /sys/class/net
            interfaces = self._list_interfaces_sysfs()

        return interfaces

    def _enrich_interface(self, name: str, data: Dict[str, str]) -> Dict[str, str]:
        """Add additional interface metadata (driver, state)."""
        data.setdefault("name", name)
        data.setdefault("mode", "unknown")
        data.setdefault("mac", self._get_mac_sysfs(name))
        data.setdefault("channel", "0")
        data["driver"] = self._get_driver(name)
        data["state"] = self._get_operstate(name)
        return data

    def _list_interfaces_sysfs(self) -> List[Dict[str, str]]:
        """Fallback to enumerate wireless interfaces via /sys/class/net."""
        interfaces = []
        net_dir = "/sys/class/net"
        if not os.path.isdir(net_dir):
            return interfaces
        for ifname in os.listdir(net_dir):
            wireless_path = os.path.join(net_dir, ifname, "wireless")
            if os.path.isdir(wireless_path):
                interfaces.append({
                    "name": ifname,
                    "mac": self._get_mac_sysfs(ifname),
                    "mode": "unknown",
                    "driver": self._get_driver(ifname),
                    "channel": "0",
                    "state": self._get_operstate(ifname),
                })
        return interfaces

    @staticmethod
    def _get_mac_sysfs(ifname: str) -> str:
        addr_path = f"/sys/class/net/{ifname}/address"
        try:
            with open(addr_path, "r") as fh:
                return fh.read().strip()
        except OSError:
            return "00:00:00:00:00:00"

    @staticmethod
    def _get_driver(ifname: str) -> str:
        driver_link = f"/sys/class/net/{ifname}/device/driver"
        try:
            return os.path.basename(os.readlink(driver_link))
        except OSError:
            return "unknown"

    @staticmethod
    def _get_operstate(ifname: str) -> str:
        state_path = f"/sys/class/net/{ifname}/operstate"
        try:
            with open(state_path, "r") as fh:
                return fh.read().strip()
        except OSError:
            return "unknown"

    # ------------------------------------------------------------------
    # Mode switching
    # ------------------------------------------------------------------

    def set_monitor_mode(self, interface: str) -> bool:
        """Switch interface to monitor mode.

        Args:
            interface: Network interface name (e.g., wlan0).

        Returns:
            True if successful.

        Raises:
            WiFiPermissionError: If not running as root.
            InterfaceError: If mode switch fails.
        """
        self._require_root("set monitor mode")
        self._save_original_state(interface)

        try:
            # Bring interface down
            subprocess.run(
                ["ip", "link", "set", interface, "down"],
                check=True, capture_output=True, text=True, timeout=10,
            )
            # Kill interfering processes
            self._kill_interfering_processes()
            # Set monitor mode
            subprocess.run(
                ["iw", interface, "set", "monitor", "none"],
                check=True, capture_output=True, text=True, timeout=10,
            )
            # Bring interface up
            subprocess.run(
                ["ip", "link", "set", interface, "up"],
                check=True, capture_output=True, text=True, timeout=10,
            )
        except subprocess.CalledProcessError as exc:
            raise InterfaceError(
                f"Failed to set monitor mode on {interface}: {exc.stderr.strip()}"
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"Timeout setting monitor mode on {interface}")

        self._current_interface = interface
        logger.info("Interface %s switched to monitor mode", interface)
        return True

    def set_managed_mode(self, interface: str) -> bool:
        """Switch interface to managed (station) mode.

        Args:
            interface: Network interface name.

        Returns:
            True if successful.
        """
        self._require_root("set managed mode")

        try:
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
            raise InterfaceError(
                f"Failed to set managed mode on {interface}: {exc.stderr.strip()}"
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"Timeout setting managed mode on {interface}")

        logger.info("Interface %s switched to managed mode", interface)
        return True

    # ------------------------------------------------------------------
    # Channel
    # ------------------------------------------------------------------

    def set_channel(self, interface: str, channel: int) -> bool:
        """Set the channel on a monitor-mode interface.

        Args:
            interface: Interface name.
            channel: Channel number (1–165 for 2.4/5 GHz).

        Returns:
            True if successful.
        """
        self._require_root("set channel")
        if not 1 <= channel <= 165:
            raise InterfaceError(f"Invalid channel number: {channel}")

        try:
            subprocess.run(
                ["iw", "dev", interface, "set", "channel", str(channel)],
                check=True, capture_output=True, text=True, timeout=10,
            )
        except subprocess.CalledProcessError as exc:
            raise InterfaceError(
                f"Failed to set channel {channel} on {interface}: {exc.stderr.strip()}"
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"Timeout setting channel on {interface}")

        logger.info("Interface %s set to channel %d", interface, channel)
        return True

    def set_frequency(self, interface: str, freq_mhz: int, width: str = "HT20") -> bool:
        """Set the frequency (and optionally bandwidth) on an interface.

        Args:
            interface: Interface name.
            freq_mhz: Frequency in MHz (e.g., 5180).
            width: Channel bandwidth (HT20, HT40+, HT40-, 80MHz).

        Returns:
            True if successful.
        """
        self._require_root("set frequency")
        cmd = ["iw", "dev", interface, "set", "freq", str(freq_mhz), width]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)
        except subprocess.CalledProcessError as exc:
            raise InterfaceError(f"Failed to set frequency: {exc.stderr.strip()}")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("Timeout setting frequency")

        logger.info("Interface %s set to %d MHz (%s)", interface, freq_mhz, width)
        return True

    # ------------------------------------------------------------------
    # MAC address
    # ------------------------------------------------------------------

    @staticmethod
    def random_mac() -> str:
        """Generate a random, locally-administered unicast MAC address.

        Uses os.urandom for cryptographic randomness. Sets the
        locally-administered bit (second-least-significant of first octet)
        and clears the multicast bit.

        Returns:
            MAC address string like 'XX:XX:XX:XX:XX:XX'.
        """
        octets = bytearray(os.urandom(6))
        # Set locally-administered bit, clear multicast bit
        octets[0] = (octets[0] & 0xFC) | 0x02
        return ":".join(f"{b:02x}" for b in octets)

    def set_mac(self, interface: str, mac: Optional[str] = None) -> bool:
        """Change the MAC address of an interface.

        Args:
            interface: Interface name.
            mac: New MAC address. If None, a random one is generated.

        Returns:
            True if successful.
        """
        self._require_root("set MAC address")
        if mac is None:
            mac = self.random_mac()

        # Validate MAC format
        if not re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac):
            raise InterfaceError(f"Invalid MAC address format: {mac}")

        # Save original MAC if not already saved
        if interface not in self._original_mac_addresses:
            self._original_mac_addresses[interface] = self._get_mac_sysfs(interface)

        try:
            subprocess.run(
                ["ip", "link", "set", interface, "down"],
                check=True, capture_output=True, text=True, timeout=10,
            )
            subprocess.run(
                ["ip", "link", "set", interface, "address", mac],
                check=True, capture_output=True, text=True, timeout=10,
            )
            subprocess.run(
                ["ip", "link", "set", interface, "up"],
                check=True, capture_output=True, text=True, timeout=10,
            )
        except subprocess.CalledProcessError as exc:
            raise InterfaceError(
                f"Failed to set MAC on {interface}: {exc.stderr.strip()}"
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"Timeout setting MAC on {interface}")

        logger.info("Interface %s MAC changed to %s", interface, mac)
        return True

    def restore_mac(self, interface: str) -> bool:
        """Restore the original MAC address for an interface.

        Returns:
            True if successful, False if no original MAC was saved.
        """
        original = self._original_mac_addresses.get(interface)
        if original is None:
            logger.warning("No original MAC saved for %s", interface)
            return False
        self.set_mac(interface, original)
        del self._original_mac_addresses[interface]
        return True

    # ------------------------------------------------------------------
    # Enable / Disable
    # ------------------------------------------------------------------

    def enable_interface(self, interface: str) -> bool:
        """Bring an interface up.

        Returns:
            True if successful.
        """
        self._require_root("enable interface")
        try:
            subprocess.run(
                ["ip", "link", "set", interface, "up"],
                check=True, capture_output=True, text=True, timeout=10,
            )
        except subprocess.CalledProcessError as exc:
            raise InterfaceError(
                f"Failed to enable {interface}: {exc.stderr.strip()}"
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"Timeout enabling {interface}")

        logger.info("Interface %s enabled", interface)
        return True

    def disable_interface(self, interface: str) -> bool:
        """Bring an interface down.

        Returns:
            True if successful.
        """
        self._require_root("disable interface")
        try:
            subprocess.run(
                ["ip", "link", "set", interface, "down"],
                check=True, capture_output=True, text=True, timeout=10,
            )
        except subprocess.CalledProcessError as exc:
            raise InterfaceError(
                f"Failed to disable {interface}: {exc.stderr.strip()}"
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"Timeout disabling {interface}")

        logger.info("Interface %s disabled", interface)
        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def get_interface_info(self, interface: str) -> Dict[str, str]:
        """Get detailed information for a specific interface.

        Returns:
            Dict with interface details.
        """
        for iface in self.list_interfaces():
            if iface["name"] == interface:
                return iface
        raise InterfaceError(f"Interface {interface} not found")

    def is_monitor_mode(self, interface: str) -> bool:
        """Check if the interface is in monitor mode."""
        info = self.get_interface_info(interface)
        return info.get("mode", "").lower() == "monitor"

    def restore_interface(self, interface: str) -> bool:
        """Restore an interface to its original state (mode + MAC)."""
        if interface in self._original_mac_addresses:
            self.restore_mac(interface)
        if interface in self._original_modes:
            if self._original_modes[interface] == "managed":
                self.set_managed_mode(interface)
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _require_root(action: str) -> None:
        if os.geteuid() != 0:
            raise WiFiPermissionError(f"Root privileges required to {action}")

    def _save_original_state(self, interface: str) -> None:
        """Save the current mode and MAC before making changes."""
        if interface not in self._original_mac_addresses:
            self._original_mac_addresses[interface] = self._get_mac_sysfs(interface)
        if interface not in self._original_modes:
            try:
                info = self.get_interface_info(interface)
                self._original_modes[interface] = info.get("mode", "managed")
            except InterfaceError:
                self._original_modes[interface] = "managed"

    @staticmethod
    def _kill_interfering_processes() -> None:
        """Kill processes that may interfere with monitor mode (NetworkManager, wpa_supplicant, etc.)."""
        interfering = [
            "NetworkManager",
            "wpa_supplicant",
            "avahi-daemon",
            "dhclient",
            "dhcpcd",
        ]
        for proc in interfering:
            try:
                subprocess.run(
                    ["killall", proc],
                    capture_output=True, text=True, timeout=5,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
