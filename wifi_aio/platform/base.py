"""Base platform abstract class for WiFiAIO platform adapters.

Defines the interface that all platform-specific adapters must
implement for WiFi scanning, connection, and management operations.
"""

from __future__ import annotations

import abc
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import WiFiConnectionError, WiFiPermissionError, WiFiTimeoutError


class BasePlatform(abc.ABC):
    """Abstract base class for platform-specific WiFi adapters.

    All platform adapters (Linux, Windows, macOS, Termux) must
    implement these methods to provide consistent WiFi functionality
    across different operating systems.
    """

    # ── Interface Management ──────────────────────────────────────────

    @abc.abstractmethod
    def get_interfaces(self) -> List[Dict[str, str]]:
        """List available wireless network interfaces.

        Returns:
            List of dictionaries with interface information:
            - 'name': Interface name (e.g., 'wlan0')
            - 'mac': MAC address
            - 'state': Current state ('up', 'down', 'unknown')
            - 'mode': Current mode ('managed', 'monitor', 'unknown')
        """

    @abc.abstractmethod
    def get_interface_state(self, interface: str) -> str:
        """Get the current state of a wireless interface.

        Args:
            interface: The interface name (e.g., 'wlan0').

        Returns:
            State string: 'up', 'down', or 'unknown'.
        """

    @abc.abstractmethod
    def set_interface_state(self, interface: str, state: str) -> bool:
        """Set the state of a wireless interface (up/down).

        Args:
            interface: The interface name.
            state: 'up' or 'down'.

        Returns:
            True if the state change succeeded.

        Raises:
            WiFiPermissionError: If insufficient privileges.
            WiFiConnectionError: If the interface doesn't exist.
        """

    @abc.abstractmethod
    def enable_monitor_mode(self, interface: str) -> bool:
        """Enable monitor mode on a wireless interface.

        Args:
            interface: The interface name.

        Returns:
            True if monitor mode was enabled.

        Raises:
            WiFiPermissionError: If not running as root/admin.
            WiFiConnectionError: If the interface doesn't support monitor mode.
        """

    @abc.abstractmethod
    def disable_monitor_mode(self, interface: str) -> bool:
        """Disable monitor mode and return to managed mode.

        Args:
            interface: The interface name.

        Returns:
            True if managed mode was restored.
        """

    @abc.abstractmethod
    def set_channel(self, interface: str, channel: int) -> bool:
        """Set the channel on a wireless interface in monitor mode.

        Args:
            interface: The interface name.
            channel: Channel number to set.

        Returns:
            True if the channel was set.

        Raises:
            WiFiPermissionError: If not running as root/admin.
        """

    @abc.abstractmethod
    def get_channel(self, interface: str) -> int:
        """Get the current channel of a wireless interface.

        Args:
            interface: The interface name.

        Returns:
            Current channel number, or 0 if unknown.
        """

    # ── Scanning ──────────────────────────────────────────────────────

    @abc.abstractmethod
    def scan_networks(self, interface: str) -> List[Dict[str, object]]:
        """Scan for available wireless networks.

        Args:
            interface: The interface to scan on.

        Returns:
            List of network dictionaries with keys:
            - 'ssid': Network SSID
            - 'bssid': BSSID (MAC address of AP)
            - 'channel': Channel number
            - 'frequency': Frequency in MHz
            - 'signal_dbm': Signal strength in dBm
            - 'encryption': Encryption type string
            - 'privacy': Whether privacy is enabled
            - 'wps': Whether WPS is supported

        Raises:
            WiFiPermissionError: If insufficient privileges.
            WiFiTimeoutError: If the scan times out.
        """

    @abc.abstractmethod
    def get_connected_network(self, interface: str) -> Optional[Dict[str, object]]:
        """Get information about the currently connected network.

        Args:
            interface: The interface name.

        Returns:
            Network dictionary if connected, None otherwise.
        """

    # ── Connection ────────────────────────────────────────────────────

    @abc.abstractmethod
    def connect(
        self,
        interface: str,
        ssid: str,
        password: Optional[str] = None,
        bssid: Optional[str] = None,
        timeout: int = 30,
    ) -> bool:
        """Connect to a wireless network.

        Args:
            interface: The interface to use.
            ssid: Network SSID.
            password: Network password (None for open networks).
            bssid: Specific BSSID to connect to (optional).
            timeout: Connection timeout in seconds.

        Returns:
            True if connection succeeded.

        Raises:
            WiFiConnectionError: If connection fails.
            WiFiTimeoutError: If connection times out.
            WiFiPermissionError: If insufficient privileges.
        """

    @abc.abstractmethod
    def disconnect(self, interface: str) -> bool:
        """Disconnect from the current wireless network.

        Args:
            interface: The interface name.

        Returns:
            True if disconnection succeeded.
        """

    # ── Access Point ──────────────────────────────────────────────────

    @abc.abstractmethod
    def start_access_point(
        self,
        interface: str,
        ssid: str,
        password: Optional[str] = None,
        channel: int = 6,
        bandwidth: str = "20",
    ) -> bool:
        """Start an access point on the given interface.

        Args:
            interface: The interface to use.
            ssid: AP SSID.
            password: AP password (None for open AP).
            channel: Channel number.
            bandwidth: Channel bandwidth ('20', '40', '80').

        Returns:
            True if the AP was started.

        Raises:
            WiFiPermissionError: If insufficient privileges.
            WiFiConnectionError: If the AP fails to start.
        """

    @abc.abstractmethod
    def stop_access_point(self, interface: str) -> bool:
        """Stop a running access point.

        Args:
            interface: The interface the AP is running on.

        Returns:
            True if the AP was stopped.
        """

    # ── Network Information ───────────────────────────────────────────

    @abc.abstractmethod
    def get_ip_address(self, interface: str) -> Optional[str]:
        """Get the IPv4 address of the interface.

        Args:
            interface: The interface name.

        Returns:
            IPv4 address string, or None if not available.
        """

    @abc.abstractmethod
    def get_mac_address(self, interface: str) -> Optional[str]:
        """Get the MAC address of the interface.

        Args:
            interface: The interface name.

        Returns:
            MAC address string, or None if not available.
        """

    @abc.abstractmethod
    def get_signal_strength(self, interface: str) -> Optional[int]:
        """Get the current signal strength in dBm.

        Args:
            interface: The interface name.

        Returns:
            Signal strength in dBm, or None if not available.
        """

    @abc.abstractmethod
    def get_network_stats(self, interface: str) -> Dict[str, int]:
        """Get network statistics for the interface.

        Args:
            interface: The interface name.

        Returns:
            Dictionary with keys:
            - 'rx_bytes': Bytes received
            - 'tx_bytes': Bytes transmitted
            - 'rx_packets': Packets received
            - 'tx_packets': Packets transmitted
            - 'rx_errors': Receive errors
            - 'tx_errors': Transmit errors
        """

    # ── Firewall / Packet Operations ──────────────────────────────────

    @abc.abstractmethod
    def enable_ip_forwarding(self) -> bool:
        """Enable IP forwarding.

        Returns:
            True if IP forwarding was enabled.

        Raises:
            WiFiPermissionError: If insufficient privileges.
        """

    @abc.abstractmethod
    def disable_ip_forwarding(self) -> bool:
        """Disable IP forwarding.

        Returns:
            True if IP forwarding was disabled.
        """

    @abc.abstractmethod
    def set_iptables_rule(self, rule: str) -> bool:
        """Apply an iptables rule (or platform equivalent).

        Args:
            rule: The rule string in iptables format.

        Returns:
            True if the rule was applied.

        Raises:
            WiFiPermissionError: If insufficient privileges.
        """

    # ── Utility Methods ───────────────────────────────────────────────

    @abc.abstractmethod
    def is_root(self) -> bool:
        """Check if the current process has root/admin privileges.

        Returns:
            True if running with elevated privileges.
        """

    @abc.abstractmethod
    def get_platform_name(self) -> str:
        """Return the platform name string.

        Returns:
            Platform name (e.g., 'linux', 'windows', 'macos', 'termux').
        """

    @abc.abstractmethod
    def get_platform_version(self) -> str:
        """Return the platform version string.

        Returns:
            OS version string.
        """

    @abc.abstractmethod
    def check_tool_available(self, tool_name: str) -> bool:
        """Check if a required external tool is available.

        Args:
            tool_name: Name of the tool to check (e.g., 'iw', 'hostapd').

        Returns:
            True if the tool is available in the system PATH.
        """

    @abc.abstractmethod
    def install_tool(self, tool_name: str) -> bool:
        """Install a required external tool.

        Args:
            tool_name: Name of the tool to install.

        Returns:
            True if installation succeeded.

        Raises:
            WiFiPermissionError: If insufficient privileges.
        """

    def require_root(self) -> None:
        """Check for root/admin privileges and raise if not present.

        Raises:
            WiFiPermissionError: If not running with elevated privileges.
        """
        if not self.is_root():
            raise WiFiPermissionError(
                "This operation requires root/admin privileges",
                details="Re-run the application with sudo or as administrator.",
            )

    def require_tool(self, tool_name: str) -> None:
        """Check that a required tool is available.

        Args:
            tool_name: Name of the tool.

        Raises:
            WiFiConnectionError: If the tool is not available.
        """
        if not self.check_tool_available(tool_name):
            raise WiFiConnectionError(
                f"Required tool '{tool_name}' is not available",
                details=f"Install '{tool_name}' using your package manager or "
                f"call install_tool('{tool_name}').",
            )
