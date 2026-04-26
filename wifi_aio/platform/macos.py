"""macOS platform adapter for WiFiAIO.

Implements WiFi operations on macOS using the airport utility,
networksetup, and other macOS-specific tools.
"""

from __future__ import annotations

import os
import plistlib
import re
import subprocess
import shutil
from typing import Dict, List, Optional, Tuple

from wifi_aio.platform.base import BasePlatform
from wifi_aio.exceptions import WiFiConnectionError, WiFiPermissionError, WiFiTimeoutError


class MacOSPlatform(BasePlatform):
    """macOS platform adapter using airport and networksetup."""

    # Path to the airport utility on various macOS versions
    AIRPORT_PATHS = [
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
        "/usr/sbin/airport",
    ]

    def __init__(self):
        self._airport_path: Optional[str] = self._find_airport()

    def _find_airport(self) -> Optional[str]:
        """Find the airport utility path."""
        for path in self.AIRPORT_PATHS:
            if os.path.isfile(path):
                return path
        return None

    def _run_command(
        self,
        cmd: List[str],
        timeout: int = 30,
    ) -> Tuple[int, str, str]:
        """Execute a system command on macOS."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(
                f"Command timed out: {' '.join(cmd)}",
                details=f"Timeout was {timeout} seconds.",
            )
        except FileNotFoundError:
            return 127, "", f"Command not found: {cmd[0]}"

    def _get_airport(self) -> str:
        """Get airport utility path, raising if not found."""
        if self._airport_path:
            return self._airport_path
        raise WiFiConnectionError(
            "airport utility not found",
            details="The airport utility is required for WiFi operations on macOS. "
            "It is typically located at "
            "/System/Library/PrivateFrameworks/Apple80211.framework/"
            "Versions/Current/Resources/airport",
        )

    # ── Interface Management ──────────────────────────────────────────

    def get_interfaces(self) -> List[Dict[str, str]]:
        """List wireless interfaces using networksetup."""
        interfaces = []
        rc, stdout, _ = self._run_command(
            ["networksetup", "-listallhardwareports"]
        )
        if rc != 0:
            return interfaces

        current_name = None
        current_device = None
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("Device:"):
                current_device = line.split(":")[1].strip()
            elif line.startswith("Hardware Port:"):
                current_name = line.split(":")[1].strip()
            elif current_device and "Wi-Fi" in (current_name or ""):
                mac = self.get_mac_address(current_device) or "unknown"
                state = self.get_interface_state(current_device)
                interfaces.append({
                    "name": current_device,
                    "mac": mac,
                    "state": state,
                    "mode": "managed",
                })
                current_name = None
                current_device = None
            else:
                if not line.startswith("Ethernet Address:"):
                    current_name = None
                    current_device = None

        return interfaces

    def get_interface_state(self, interface: str) -> str:
        """Get interface state using ifconfig."""
        rc, stdout, _ = self._run_command(["ifconfig", interface])
        if rc != 0:
            return "unknown"
        if "status: active" in stdout:
            return "up"
        elif "status: inactive" in stdout:
            return "down"
        return "unknown"

    def set_interface_state(self, interface: str, state: str) -> bool:
        """Set interface state using ifconfig."""
        if not self.is_root():
            raise WiFiPermissionError(
                "Changing interface state requires root privileges"
            )
        if state not in ("up", "down"):
            raise ValueError(f"Invalid state: {state}")
        rc, _, stderr = self._run_command(["ifconfig", interface, state])
        if rc != 0:
            raise WiFiConnectionError(
                f"Failed to set {interface} {state}",
                details=stderr.strip(),
            )
        return True

    def enable_monitor_mode(self, interface: str) -> bool:
        """Enable monitor mode using airport or en0.

        macOS has limited monitor mode support. The airport utility
        can sniff frames on a channel using 'airport sniff'.
        """
        if not self.is_root():
            raise WiFiPermissionError(
                "Monitor mode requires root privileges on macOS"
            )
        # macOS doesn't have a true monitor mode like Linux
        # but we can use airport sniff for frame capture
        airport = self._get_airport()
        # Create a VIF in monitor mode if supported
        rc, _, stderr = self._run_command(
            ["ifconfig", interface, "monitor"]
        )
        if rc == 0:
            return True

        # Alternative: use airport to set to promiscuous
        rc, _, stderr = self._run_command(
            [airport, "--disassociate"]
        )
        if rc == 0:
            return True

        raise WiFiConnectionError(
            f"Failed to enable monitor mode on {interface}",
            details="macOS has limited monitor mode support. "
            "Consider using a Linux VM or external WiFi adapter.",
        )

    def disable_monitor_mode(self, interface: str) -> bool:
        """Disable monitor mode on macOS."""
        rc, _, _ = self._run_command(
            ["ifconfig", interface, "-monitor"]
        )
        if rc != 0:
            # Just re-associate with a network
            airport = self._get_airport()
            self._run_command([airport, "--associate"])
        return True

    def set_channel(self, interface: str, channel: int) -> bool:
        """Set channel using airport utility."""
        if not self.is_root():
            raise WiFiPermissionError("Setting channel requires root")
        airport = self._get_airport()
        rc, _, stderr = self._run_command(
            [airport, f"--channel={channel}"]
        )
        if rc != 0:
            raise WiFiConnectionError(
                f"Failed to set channel {channel}",
                details=stderr.strip(),
            )
        return True

    def get_channel(self, interface: str) -> int:
        """Get current channel from airport info."""
        info = self._get_airport_info()
        return info.get("channel", 0)

    def _get_airport_info(self) -> Dict[str, object]:
        """Get current airport/wifi information."""
        info: Dict[str, object] = {}
        airport = self._get_airport()
        rc, stdout, _ = self._run_command([airport, "--getinfo"])
        if rc != 0:
            return info

        for line in stdout.splitlines():
            line = line.strip()
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                if key == "channel":
                    try:
                        info["channel"] = int(value)
                    except ValueError:
                        pass
                elif key == "ssid":
                    info["ssid"] = value
                elif key == "bssid":
                    info["bssid"] = value.lower()
                elif key == "rssi":
                    try:
                        info["signal_dbm"] = int(value)
                    except ValueError:
                        pass
                elif key == "op_mode":
                    info["mode"] = value
        return info

    # ── Scanning ──────────────────────────────────────────────────────

    def scan_networks(self, interface: str) -> List[Dict[str, object]]:
        """Scan for networks using airport scan."""
        networks = []
        airport = self._get_airport()
        rc, stdout, _ = self._run_command(
            [airport, "--scan"], timeout=30
        )
        if rc != 0:
            return networks

        lines = stdout.splitlines()
        if len(lines) < 2:
            return networks

        # Parse the tabular output
        header = lines[0]
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue

            ssid = " ".join(parts[:-5]).strip()
            bssid = parts[-5] if len(parts) >= 6 else "unknown"
            rssi_str = parts[-4] if len(parts) >= 5 else "-100"
            channel_str = parts[-3] if len(parts) >= 4 else "0"
            security = parts[-1] if len(parts) >= 2 else "Open"

            try:
                signal_dbm = int(rssi_str)
            except ValueError:
                signal_dbm = -100

            try:
                # Channel may be in format like "6" or "6,+1" for 40MHz
                channel = int(channel_str.split(",")[0])
            except ValueError:
                channel = 0

            encryption = "Open"
            if security:
                if "WPA3" in security:
                    encryption = "WPA3"
                elif "WPA2" in security:
                    encryption = "WPA2"
                elif "WPA" in security:
                    encryption = "WPA"
                elif "WEP" in security:
                    encryption = "WEP"

            networks.append({
                "ssid": ssid,
                "bssid": bssid.lower(),
                "channel": channel,
                "frequency": self._channel_to_freq(channel),
                "signal_dbm": signal_dbm,
                "encryption": encryption,
                "privacy": encryption != "Open",
                "wps": False,
            })

        return networks

    @staticmethod
    def _channel_to_freq(channel: int) -> int:
        """Convert channel to frequency in MHz."""
        if 1 <= channel <= 13:
            return 2407 + channel * 5
        elif channel == 14:
            return 2484
        elif 36 <= channel <= 177:
            return 5000 + channel * 5
        return 0

    def get_connected_network(self, interface: str) -> Optional[Dict[str, object]]:
        """Get connected network info from airport."""
        info = self._get_airport_info()
        if info.get("ssid"):
            return info
        return None

    # ── Connection ────────────────────────────────────────────────────

    def connect(
        self,
        interface: str,
        ssid: str,
        password: Optional[str] = None,
        bssid: Optional[str] = None,
        timeout: int = 30,
    ) -> bool:
        """Connect to a network using networksetup."""
        if password:
            rc, _, stderr = self._run_command(
                ["networksetup", "-setairportnetwork",
                 interface, ssid, password],
                timeout=timeout,
            )
        else:
            rc, _, stderr = self._run_command(
                ["networksetup", "-setairportnetwork",
                 interface, ssid],
                timeout=timeout,
            )

        if rc != 0:
            raise WiFiConnectionError(
                f"Failed to connect to '{ssid}'",
                details=stderr.strip(),
            )

        # Verify connection
        time_elapsed = 0
        import time
        while time_elapsed < timeout:
            time.sleep(2)
            time_elapsed += 2
            info = self._get_airport_info()
            if info.get("ssid") == ssid:
                return True

        raise WiFiTimeoutError(
            f"Connection to '{ssid}' timed out after {timeout}s"
        )

    def disconnect(self, interface: str) -> bool:
        """Disconnect using airport utility."""
        airport = self._get_airport()
        rc, _, _ = self._run_command([airport, "--disassociate"])
        return rc == 0

    # ── Access Point ──────────────────────────────────────────────────

    def start_access_point(
        self,
        interface: str,
        ssid: str,
        password: Optional[str] = None,
        channel: int = 6,
        bandwidth: str = "20",
    ) -> bool:
        """Start an AP using internet-sharing or hostapd.

        macOS can share internet via System Preferences, but
        programmatic AP creation requires hostapd or the
        internet-sharing framework.
        """
        if not self.is_root():
            raise WiFiPermissionError("Starting AP requires root on macOS")

        # Try using macOS internet sharing via launchd
        # Create a hostapd config as fallback
        if self.check_tool_available("hostapd"):
            config_lines = [
                f"interface={interface}",
                f"ssid={ssid}",
                f"channel={channel}",
                "driver=bsd",
                "hw_mode=g",
            ]
            if password:
                config_lines.extend([
                    "wpa=2",
                    f"wpa_passphrase={password}",
                    "wpa_key_mgmt=WPA-PSK",
                    "rsn_pairwise=CCMP",
                ])

            config_path = f"/tmp/wifi_aio_hostapd_{interface}.conf"
            try:
                with open(config_path, "w") as f:
                    f.write("\n".join(config_lines) + "\n")
            except OSError as e:
                raise WiFiConnectionError(f"Failed to write hostapd config: {e}")

            rc, _, stderr = self._run_command(
                ["hostapd", "-B", config_path],
                timeout=10,
            )
            if rc == 0:
                return True

        # Fall back to internet sharing via sysctl
        raise WiFiConnectionError(
            "Starting AP on macOS requires hostapd or internet sharing. "
            "Install hostapd via Homebrew: brew install hostapd",
            details="Alternatively, enable Internet Sharing in System Preferences > Sharing.",
        )

    def stop_access_point(self, interface: str) -> bool:
        """Stop the AP."""
        rc, _, _ = self._run_command(["pkill", "-f", f"hostapd.*{interface}"])
        return rc == 0

    # ── Network Information ───────────────────────────────────────────

    def get_ip_address(self, interface: str) -> Optional[str]:
        """Get IPv4 address using ifconfig."""
        rc, stdout, _ = self._run_command(["ifconfig", interface])
        if rc != 0:
            return None
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", stdout)
        return match.group(1) if match else None

    def get_mac_address(self, interface: str) -> Optional[str]:
        """Get MAC address using ifconfig."""
        rc, stdout, _ = self._run_command(["ifconfig", interface])
        if rc != 0:
            return None
        match = re.search(r"ether\s+([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})", stdout)
        return match.group(1).lower() if match else None

    def get_signal_strength(self, interface: str) -> Optional[int]:
        """Get signal strength from airport info."""
        info = self._get_airport_info()
        return info.get("signal_dbm") if isinstance(info.get("signal_dbm"), int) else None

    def get_network_stats(self, interface: str) -> Dict[str, int]:
        """Get network stats using netstat."""
        stats = {
            "rx_bytes": 0,
            "tx_bytes": 0,
            "rx_packets": 0,
            "tx_packets": 0,
            "rx_errors": 0,
            "tx_errors": 0,
        }
        rc, stdout, _ = self._run_command(["netstat", "-I", interface, "-b"])
        if rc == 0:
            lines = stdout.splitlines()
            if len(lines) >= 2:
                parts = lines[1].split()
                if len(parts) >= 10:
                    try:
                        stats["rx_packets"] = int(parts[4])
                        stats["rx_errors"] = int(parts[5])
                        stats["tx_packets"] = int(parts[6])
                        stats["tx_errors"] = int(parts[7])
                        stats["rx_bytes"] = int(parts[8])
                        stats["tx_bytes"] = int(parts[9])
                    except (ValueError, IndexError):
                        pass
        return stats

    # ── Firewall / Packet Operations ──────────────────────────────────

    def enable_ip_forwarding(self) -> bool:
        """Enable IP forwarding via sysctl."""
        if not self.is_root():
            raise WiFiPermissionError("Enabling IP forwarding requires root")
        rc, _, _ = self._run_command(
            ["sysctl", "-w", "net.inet.ip.forwarding=1"]
        )
        return rc == 0

    def disable_ip_forwarding(self) -> bool:
        """Disable IP forwarding via sysctl."""
        if not self.is_root():
            raise WiFiPermissionError("Disabling IP forwarding requires root")
        rc, _, _ = self._run_command(
            ["sysctl", "-w", "net.inet.ip.forwarding=0"]
        )
        return rc == 0

    def set_iptables_rule(self, rule: str) -> bool:
        """Apply a firewall rule using pf (Packet Filter) on macOS."""
        if not self.is_root():
            raise WiFiPermissionError("Firewall rules require root on macOS")
        # Translate iptables rule to pf rule syntax
        pf_rule = self._translate_to_pf_rule(rule)
        rc, _, stderr = self._run_command(
            ["pfctl", "-ef", f'"{pf_rule}"'],
            timeout=10,
        )
        return rc == 0

    def _translate_to_pf_rule(self, iptables_rule: str) -> str:
        """Translate an iptables rule to pf rule syntax."""
        parts = iptables_rule.split()
        action = "pass"
        direction = "in"
        proto = "tcp"
        port = ""

        if "DROP" in parts or "REJECT" in parts:
            action = "block"
        elif "ACCEPT" in parts:
            action = "pass"

        for i, p in enumerate(parts):
            if p == "-p" and i + 1 < len(parts):
                proto = parts[i + 1]
            elif p == "--dport" and i + 1 < len(parts):
                port = f"port {parts[i + 1]}"
            elif p == "-s" and i + 1 < len(parts):
                direction = f"from {parts[i + 1]}"

        return f"{action} {direction} proto {proto} {port}"

    # ── Utility Methods ───────────────────────────────────────────────

    def is_root(self) -> bool:
        """Check if running as root."""
        return os.geteuid() == 0

    def get_platform_name(self) -> str:
        """Return 'macos'."""
        return "macos"

    def get_platform_version(self) -> str:
        """Return macOS version using sw_vers."""
        rc, stdout, _ = self._run_command(["sw_vers", "-productVersion"])
        return stdout.strip() if rc == 0 else "unknown"

    def check_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available."""
        return shutil.which(tool_name) is not None

    def install_tool(self, tool_name: str) -> bool:
        """Install a tool using Homebrew."""
        if not self.is_root():
            raise WiFiPermissionError("Installing tools may require privileges")

        # Map common tool names to Homebrew packages
        package_map = {
            "hostapd": "hostapd",
            "dnsmasq": "dnsmasq",
            "aircrack-ng": "aircrack-ng",
            "airmon-ng": "aircrack-ng",
            "hashcat": "hashcat",
            "john": "john-jumbo",
            "tshark": "wireshark",
            "tcpdump": "tcpdump",
            "nmap": "nmap",
        }

        package = package_map.get(tool_name, tool_name)

        if self.check_tool_available("brew"):
            rc, _, _ = self._run_command(
                ["brew", "install", package],
                timeout=300,
            )
            return rc == 0

        return False
