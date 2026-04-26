"""Linux platform adapter for WiFiAIO.

Implements WiFi operations on Linux using standard tools:
- iw: Wireless interface configuration and scanning
- ip: Network interface management
- nmcli: NetworkManager CLI for connection management
- hostapd: Access point creation
- airmon-ng: Monitor mode management
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Tuple

from wifi_aio.platform.base import BasePlatform
from wifi_aio.exceptions import WiFiConnectionError, WiFiPermissionError, WiFiTimeoutError


class LinuxPlatform(BasePlatform):
    """Linux platform adapter using iw, ip, nmcli, and hostapd."""

    def __init__(self):
        self._iw_path: Optional[str] = None
        self._ip_path: Optional[str] = None
        self._nmcli_path: Optional[str] = None
        self._hostapd_path: Optional[str] = None
        self._airmon_path: Optional[str] = None
        self._dnsmasq_path: Optional[str] = None
        self._original_managed_ifaces: Dict[str, str] = {}

    def _run_command(
        self,
        cmd: List[str],
        timeout: int = 30,
        require_root: bool = False,
    ) -> Tuple[int, str, str]:
        """Execute a system command and return (returncode, stdout, stderr).

        Args:
            cmd: Command and arguments as a list.
            timeout: Command timeout in seconds.
            require_root: Whether to prepend sudo if not root.

        Raises:
            WiFiTimeoutError: If the command times out.
        """
        if require_root and os.geteuid() != 0:
            cmd = ["sudo"] + cmd
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

    def _find_tool(self, name: str) -> Optional[str]:
        """Find the full path of a tool."""
        return shutil.which(name)

    # ── Interface Management ──────────────────────────────────────────

    def get_interfaces(self) -> List[Dict[str, str]]:
        """List wireless interfaces using iw and ip."""
        interfaces = []
        rc, stdout, _ = self._run_command(["iw", "dev"])
        if rc != 0:
            return interfaces

        current_iface = None
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                current_iface = line.split()[1]
                if current_iface:
                    state = self.get_interface_state(current_iface)
                    mode = self._get_interface_mode(current_iface)
                    mac = self.get_mac_address(current_iface) or "unknown"
                    interfaces.append({
                        "name": current_iface,
                        "mac": mac,
                        "state": state,
                        "mode": mode,
                    })
        return interfaces

    def get_interface_state(self, interface: str) -> str:
        """Get interface state using ip link."""
        rc, stdout, _ = self._run_command(["ip", "link", "show", interface])
        if rc != 0:
            return "unknown"
        for line in stdout.splitlines():
            if "state UP" in line:
                return "up"
            elif "state DOWN" in line:
                return "down"
        return "unknown"

    def set_interface_state(self, interface: str, state: str) -> bool:
        """Set interface state using ip link."""
        if state not in ("up", "down"):
            raise ValueError(f"Invalid state: {state}. Must be 'up' or 'down'.")
        if not self.is_root():
            raise WiFiPermissionError(
                "Changing interface state requires root privileges",
                details="Run with sudo.",
            )
        rc, _, stderr = self._run_command(["ip", "link", "set", interface, state])
        if rc != 0:
            raise WiFiConnectionError(
                f"Failed to set {interface} {state}",
                details=stderr.strip(),
            )
        return True

    def _get_interface_mode(self, interface: str) -> str:
        """Get the current mode of a wireless interface."""
        rc, stdout, _ = self._run_command(["iw", "dev", interface, "info"])
        if rc != 0:
            return "unknown"
        for line in stdout.splitlines():
            if "type " in line:
                mode = line.split("type")[1].strip()
                return mode
        return "unknown"

    def enable_monitor_mode(self, interface: str) -> bool:
        """Enable monitor mode using iw.

        Attempts airmon-ng first if available, falls back to iw.
        """
        if not self.is_root():
            raise WiFiPermissionError(
                "Monitor mode requires root privileges",
                details="Run with sudo.",
            )

        # Save current mode for restoration
        current_mode = self._get_interface_mode(interface)
        self._original_managed_ifaces[interface] = current_mode

        # Method 1: airmon-ng if available
        if self.check_tool_available("airmon-ng"):
            rc, stdout, stderr = self._run_command(
                ["airmon-ng", "start", interface]
            )
            if rc == 0:
                # airmon-ng typically creates a mon interface
                for line in stdout.splitlines():
                    if "monitor" in line.lower():
                        return True

        # Method 2: Direct iw commands
        self._run_command(["ip", "link", "set", interface, "down"])
        rc, _, stderr = self._run_command(
            ["iw", interface, "set", "type", "monitor"]
        )
        if rc != 0:
            # Try to restore
            self._run_command(["iw", interface, "set", "type", "managed"])
            raise WiFiConnectionError(
                f"Failed to enable monitor mode on {interface}",
                details=stderr.strip(),
            )
        self._run_command(["ip", "link", "set", interface, "up"])
        return True

    def disable_monitor_mode(self, interface: str) -> bool:
        """Disable monitor mode and restore managed mode."""
        if not self.is_root():
            raise WiFiPermissionError(
                "Disabling monitor mode requires root privileges"
            )

        # Try airmon-ng stop first
        if self.check_tool_available("airmon-ng"):
            rc, _, _ = self._run_command(["airmon-ng", "stop", interface])
            if rc == 0:
                return True

        # Fall back to iw
        self._run_command(["ip", "link", "set", interface, "down"])
        rc, _, stderr = self._run_command(
            ["iw", interface, "set", "type", "managed"]
        )
        if rc != 0:
            raise WiFiConnectionError(
                f"Failed to disable monitor mode on {interface}",
                details=stderr.strip(),
            )
        self._run_command(["ip", "link", "set", interface, "up"])

        # Restore NetworkManager if it was stopped
        if self.check_tool_available("systemctl"):
            self._run_command(
                ["systemctl", "start", "NetworkManager"],
                timeout=10,
            )

        return True

    def set_channel(self, interface: str, channel: int) -> bool:
        """Set channel using iw."""
        if not self.is_root():
            raise WiFiPermissionError("Setting channel requires root privileges")
        rc, _, stderr = self._run_command(
            ["iw", "dev", interface, "set", "channel", str(channel)]
        )
        if rc != 0:
            raise WiFiConnectionError(
                f"Failed to set channel {channel} on {interface}",
                details=stderr.strip(),
            )
        return True

    def get_channel(self, interface: str) -> int:
        """Get current channel from iw."""
        rc, stdout, _ = self._run_command(["iw", "dev", interface, "info"])
        if rc != 0:
            return 0
        for line in stdout.splitlines():
            if "channel" in line.lower():
                match = re.search(r"channel\s+(\d+)", line, re.IGNORECASE)
                if match:
                    return int(match.group(1))
        return 0

    # ── Scanning ──────────────────────────────────────────────────────

    def scan_networks(self, interface: str) -> List[Dict[str, object]]:
        """Scan for networks using iw or nmcli."""
        networks = []

        # Try iw scan first (more detailed)
        if self.check_tool_available("iw"):
            rc, stdout, _ = self._run_command(
                ["iw", "dev", interface, "scan"],
                timeout=30,
            )
            if rc == 0:
                networks = self._parse_iw_scan(stdout)

        # Fall back to nmcli
        if not networks and self.check_tool_available("nmcli"):
            rc, stdout, _ = self._run_command(
                ["nmcli", "-t", "-f", "all", "dev", "wifi", "list"],
                timeout=30,
            )
            if rc == 0:
                networks = self._parse_nmcli_scan(stdout)

        return networks

    def _parse_iw_scan(self, scan_output: str) -> List[Dict[str, object]]:
        """Parse output from 'iw dev scan'."""
        networks = []
        current: Optional[Dict[str, object]] = None

        for line in scan_output.splitlines():
            line = line.strip()

            # New BSS entry
            if line.startswith("BSS"):
                if current:
                    networks.append(current)
                current = {}
                match = re.match(r"BSS\s+([0-9a-fA-F:]+)", line)
                if match:
                    current["bssid"] = match.group(1).lower()
                continue

            if current is None:
                continue

            if "SSID:" in line:
                current["ssid"] = line.split("SSID:")[1].strip()
            elif "freq:" in line:
                freq_str = line.split("freq:")[1].strip()
                try:
                    freq = int(freq_str)
                    current["frequency"] = freq
                    current["channel"] = self._freq_to_channel(freq)
                except ValueError:
                    pass
            elif "signal:" in line:
                match = re.search(r"signal:\s+(-?\d+\.\d+)", line)
                if match:
                    current["signal_dbm"] = float(match.group(1))
            elif "WPA" in line:
                current["encryption"] = "WPA"
            elif "RSN" in line:
                current["encryption"] = "WPA2"
            elif "WPS" in line:
                current["wps"] = True
            elif "capability:" in line.lower() or "CAPABILITY" in line:
                if "Privacy" in line or "privacy" in line:
                    current["privacy"] = True

        if current:
            networks.append(current)

        # Fill in defaults
        for net in networks:
            net.setdefault("ssid", "")
            net.setdefault("bssid", "unknown")
            net.setdefault("channel", 0)
            net.setdefault("frequency", 0)
            net.setdefault("signal_dbm", -100)
            net.setdefault("encryption", "Open")
            net.setdefault("privacy", False)
            net.setdefault("wps", False)

        return networks

    def _parse_nmcli_scan(self, scan_output: str) -> List[Dict[str, object]]:
        """Parse output from 'nmcli dev wifi list'."""
        networks = []
        for line in scan_output.splitlines():
            if not line.strip():
                continue
            fields = line.split(":")
            if len(fields) < 10:
                continue
            ssid = fields[0].strip() if len(fields) > 0 else ""
            bssid = fields[1].strip() if len(fields) > 1 else ""
            mode = fields[2].strip() if len(fields) > 2 else ""
            chan_str = fields[3].strip() if len(fields) > 3 else "0"
            freq_str = fields[4].strip() if len(fields) > 4 else "0"
            signal_str = fields[6].strip() if len(fields) > 6 else "0"
            security = fields[8].strip() if len(fields) > 8 else ""

            try:
                channel = int(chan_str)
            except ValueError:
                channel = 0
            try:
                frequency = int(freq_str)
            except ValueError:
                frequency = 0
            try:
                signal_pct = int(signal_str)
                signal_dbm = int(signal_pct / 100 * 60 - 100)
            except ValueError:
                signal_dbm = -100

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
                "bssid": bssid.lower() if bssid else "unknown",
                "channel": channel,
                "frequency": frequency,
                "signal_dbm": signal_dbm,
                "encryption": encryption,
                "privacy": encryption != "Open",
                "wps": "WPS" in security if security else False,
            })

        return networks

    @staticmethod
    def _freq_to_channel(freq: int) -> int:
        """Convert frequency in MHz to channel number."""
        if 2412 <= freq <= 2484:
            if freq == 2484:
                return 14
            return (freq - 2407) // 5
        elif 5170 <= freq <= 5825:
            return (freq - 5000) // 5
        elif 5950 <= freq <= 7125:
            return (freq - 5950) // 5 + 1
        return 0

    def get_connected_network(self, interface: str) -> Optional[Dict[str, object]]:
        """Get connected network info using nmcli or iw."""
        if self.check_tool_available("nmcli"):
            rc, stdout, _ = self._run_command(
                ["nmcli", "-t", "-f", "active,ssid,bssid,freq,signal,security",
                 "dev", "wifi", "list", "--rescan", "no"],
                timeout=10,
            )
            if rc == 0:
                for line in stdout.splitlines():
                    if line.startswith("yes:"):
                        fields = line.split(":")
                        if len(fields) >= 5:
                            return {
                                "ssid": fields[1],
                                "bssid": fields[2],
                                "frequency": int(fields[3]) if fields[3].isdigit() else 0,
                                "signal_dbm": int(fields[4]) * 60 // 100 - 100 if fields[4].isdigit() else -100,
                                "encryption": fields[5] if len(fields) > 5 else "Open",
                            }

        # Fall back to iw
        rc, stdout, _ = self._run_command(
            ["iw", "dev", interface, "link"]
        )
        if rc == 0 and "Connected to" in stdout:
            result: Dict[str, object] = {}
            for line in stdout.splitlines():
                if "Connected to" in line:
                    result["bssid"] = line.split("Connected to")[1].strip()
                elif "SSID:" in line:
                    result["ssid"] = line.split("SSID:")[1].strip()
                elif "signal:" in line:
                    match = re.search(r"signal:\s+(-?\d+)", line)
                    if match:
                        result["signal_dbm"] = int(match.group(1))
            return result if result else None

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
        """Connect to a network using nmcli."""
        if not self.check_tool_available("nmcli"):
            raise WiFiConnectionError(
                "nmcli is required for network connection",
                details="Install NetworkManager: apt install network-manager",
            )

        cmd = ["nmcli", "dev", "wifi", "connect", ssid]
        if password:
            cmd.extend(["password", password])
        if bssid:
            cmd.extend(["bssid", bssid])
        cmd.extend(["ifname", interface])

        try:
            rc, stdout, stderr = self._run_command(cmd, timeout=timeout)
        except WiFiTimeoutError:
            raise WiFiTimeoutError(
                f"Connection to '{ssid}' timed out after {timeout}s"
            )

        if rc != 0:
            raise WiFiConnectionError(
                f"Failed to connect to '{ssid}'",
                details=stderr.strip() or stdout.strip(),
            )
        return True

    def disconnect(self, interface: str) -> bool:
        """Disconnect using nmcli or iw."""
        if self.check_tool_available("nmcli"):
            rc, _, _ = self._run_command(
                ["nmcli", "dev", "disconnect", interface]
            )
            return rc == 0

        # Fall back to iw
        rc, _, _ = self._run_command(
            ["iw", "dev", interface, "disconnect"]
        )
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
        """Start an AP using nmcli or hostapd."""
        if not self.is_root():
            raise WiFiPermissionError("Starting AP requires root privileges")

        # Try nmcli hotspot first
        if self.check_tool_available("nmcli"):
            cmd = [
                "nmcli", "dev", "wifi", "hotspot",
                "ifname", interface,
                "ssid", ssid,
                "channel", str(channel),
            ]
            if password:
                cmd.extend(["password", password])
            rc, _, stderr = self._run_command(cmd, timeout=15)
            if rc == 0:
                return True

        # Fall back to hostapd
        if self.check_tool_available("hostapd"):
            config = self._generate_hostapd_config(
                interface, ssid, password, channel, bandwidth
            )
            config_path = f"/tmp/wifi_aio_hostapd_{interface}.conf"
            try:
                with open(config_path, "w") as f:
                    f.write(config)
            except OSError as e:
                raise WiFiConnectionError(
                    f"Failed to write hostapd config: {e}"
                )

            rc, _, stderr = self._run_command(
                ["hostapd", "-B", config_path],
                timeout=10,
            )
            if rc != 0:
                raise WiFiConnectionError(
                    f"hostapd failed to start",
                    details=stderr.strip(),
                )
            return True

        raise WiFiConnectionError(
            "No AP tool available (nmcli or hostapd required)",
            details="Install hostapd: apt install hostapd",
        )

    def _generate_hostapd_config(
        self,
        interface: str,
        ssid: str,
        password: Optional[str],
        channel: int,
        bandwidth: str,
    ) -> str:
        """Generate a hostapd configuration file."""
        lines = [
            f"interface={interface}",
            f"ssid={ssid}",
            f"channel={channel}",
            "driver=nl80211",
            "hw_mode=g",
        ]

        if channel > 14:
            lines[4] = "hw_mode=a"

        if password:
            lines.extend([
                "wpa=2",
                f"wpa_passphrase={password}",
                "wpa_key_mgmt=WPA-PSK",
                "rsn_pairwise=CCMP",
            ])
        else:
            lines.append("wpa=0")

        if bandwidth in ("40", "80"):
            lines.extend([
                "ieee80211n=1",
                f"ht_capab=[HT40{'-+'[channel > 14]}]",
            ])
            if bandwidth == "80":
                lines.extend([
                    "ieee80211ac=1",
                    "vht_oper_chwidth=1",
                    f"vht_oper_centr_freq_seg0_idx={channel + 6}",
                ])

        return "\n".join(lines) + "\n"

    def stop_access_point(self, interface: str) -> bool:
        """Stop the running AP."""
        # Kill hostapd
        rc, _, _ = self._run_command(["pkill", "-f", f"hostapd.*{interface}"])
        # Also try nmcli
        if self.check_tool_available("nmcli"):
            rc2, _, _ = self._run_command(
                ["nmcli", "connection", "down", "Hotspot"]
            )
            return rc2 == 0 or rc == 0
        return rc == 0

    # ── Network Information ───────────────────────────────────────────

    def get_ip_address(self, interface: str) -> Optional[str]:
        """Get IPv4 address using ip."""
        rc, stdout, _ = self._run_command(
            ["ip", "-4", "addr", "show", interface]
        )
        if rc != 0:
            return None
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", stdout)
        return match.group(1) if match else None

    def get_mac_address(self, interface: str) -> Optional[str]:
        """Get MAC address using ip."""
        rc, stdout, _ = self._run_command(["ip", "link", "show", interface])
        if rc != 0:
            return None
        match = re.search(
            r"link/ether\s+([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})",
            stdout,
        )
        return match.group(1).lower() if match else None

    def get_signal_strength(self, interface: str) -> Optional[int]:
        """Get signal strength from /proc or iw."""
        # Try iw
        rc, stdout, _ = self._run_command(
            ["iw", "dev", interface, "link"]
        )
        if rc == 0:
            match = re.search(r"signal:\s+(-?\d+)", stdout)
            if match:
                return int(match.group(1))

        # Try /proc/net/wireless
        try:
            with open("/proc/net/wireless", "r") as f:
                for line in f:
                    if interface in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            try:
                                return int(float(parts[3]))
                            except (ValueError, IndexError):
                                pass
        except (OSError, IOError):
            pass

        return None

    def get_network_stats(self, interface: str) -> Dict[str, int]:
        """Get network stats from /proc/net/dev."""
        stats = {
            "rx_bytes": 0,
            "tx_bytes": 0,
            "rx_packets": 0,
            "tx_packets": 0,
            "rx_errors": 0,
            "tx_errors": 0,
        }
        try:
            with open("/proc/net/dev", "r") as f:
                for line in f:
                    if f"{interface}:" in line:
                        parts = line.split(f"{interface}:")[1].strip().split()
                        if len(parts) >= 8:
                            stats["rx_bytes"] = int(parts[0])
                            stats["rx_packets"] = int(parts[1])
                            stats["rx_errors"] = int(parts[2])
                            stats["tx_bytes"] = int(parts[8])
                            stats["tx_packets"] = int(parts[9])
                            stats["tx_errors"] = int(parts[10])
                        break
        except (OSError, ValueError, IndexError):
            pass
        return stats

    # ── Firewall / Packet Operations ──────────────────────────────────

    def enable_ip_forwarding(self) -> bool:
        """Enable IP forwarding via /proc/sys."""
        if not self.is_root():
            raise WiFiPermissionError("Enabling IP forwarding requires root")
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            return True
        except OSError as e:
            raise WiFiConnectionError(f"Failed to enable IP forwarding: {e}")

    def disable_ip_forwarding(self) -> bool:
        """Disable IP forwarding via /proc/sys."""
        if not self.is_root():
            raise WiFiPermissionError("Disabling IP forwarding requires root")
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
            return True
        except OSError as e:
            raise WiFiConnectionError(f"Failed to disable IP forwarding: {e}")

    def set_iptables_rule(self, rule: str) -> bool:
        """Apply an iptables rule."""
        if not self.is_root():
            raise WiFiPermissionError("iptables requires root privileges")
        rc, _, stderr = self._run_command(
            ["iptables"] + rule.split()
        )
        if rc != 0:
            raise WiFiConnectionError(
                f"iptables rule failed: {rule}",
                details=stderr.strip(),
            )
        return True

    # ── Utility Methods ───────────────────────────────────────────────

    def is_root(self) -> bool:
        """Check if running as root."""
        return os.geteuid() == 0

    def get_platform_name(self) -> str:
        """Return 'linux'."""
        return "linux"

    def get_platform_version(self) -> str:
        """Return Linux kernel version."""
        try:
            return os.uname().release
        except AttributeError:
            rc, stdout, _ = self._run_command(["uname", "-r"])
            return stdout.strip() if rc == 0 else "unknown"

    def check_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available in PATH."""
        return shutil.which(tool_name) is not None

    def install_tool(self, tool_name: str) -> bool:
        """Install a tool using apt (Debian/Ubuntu) or dnf (Fedora)."""
        if not self.is_root():
            raise WiFiPermissionError("Installing tools requires root privileges")

        # Map tool names to package names
        package_map = {
            "iw": "iw",
            "hostapd": "hostapd",
            "dnsmasq": "dnsmasq",
            "aircrack-ng": "aircrack-ng",
            "airmon-ng": "aircrack-ng",
            "hashcat": "hashcat",
            "john": "john",
            "tshark": "tshark",
            "tcpdump": "tcpdump",
            "nmap": "nmap",
            "nmcli": "network-manager",
        }

        package = package_map.get(tool_name, tool_name)

        # Try apt first
        if self.check_tool_available("apt"):
            rc, _, _ = self._run_command(
                ["apt", "install", "-y", package], timeout=120
            )
            return rc == 0

        # Try dnf
        if self.check_tool_available("dnf"):
            rc, _, _ = self._run_command(
                ["dnf", "install", "-y", package], timeout=120
            )
            return rc == 0

        # Try pacman
        if self.check_tool_available("pacman"):
            rc, _, _ = self._run_command(
                ["pacman", "-S", "--noconfirm", package], timeout=120
            )
            return rc == 0

        return False
