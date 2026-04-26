"""Termux platform adapter for WiFiAIO.

Implements WiFi operations on Android via Termux using the
termux-api commands for WiFi scanning, connection, and
interface management.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import shutil
from typing import Dict, List, Optional, Tuple

from wifi_aio.platform.base import BasePlatform
from wifi_aio.exceptions import WiFiConnectionError, WiFiPermissionError, WiFiTimeoutError


class TermuxPlatform(BasePlatform):
    """Termux platform adapter using termux-api for WiFi operations.

    Requires the Termux:API app and termux-api package to be installed.
    """

    def __init__(self):
        self._api_available: Optional[bool] = None

    def _check_api(self) -> bool:
        """Check if termux-api is available."""
        if self._api_available is None:
            self._api_available = shutil.which("termux-wifi-scaninfo") is not None
        return self._api_available

    def _run_command(
        self,
        cmd: List[str],
        timeout: int = 30,
    ) -> Tuple[int, str, str]:
        """Execute a system command."""
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

    def _require_api(self) -> None:
        """Ensure termux-api is available."""
        if not self._check_api():
            raise WiFiConnectionError(
                "termux-api is required for WiFi operations in Termux",
                details="Install termux-api: pkg install termux-api "
                "and install the Termux:API app from F-Droid or Google Play.",
            )

    # ── Interface Management ──────────────────────────────────────────

    def get_interfaces(self) -> List[Dict[str, str]]:
        """List wireless interfaces on Android/Termux."""
        interfaces = []
        # On Android, the primary WiFi interface is typically wlan0
        ifaces = ["wlan0"]

        # Try to get actual interfaces from /sys/class/net
        try:
            net_dir = "/sys/class/net"
            if os.path.isdir(net_dir):
                ifaces = [
                    d for d in os.listdir(net_dir)
                    if d.startswith("wl") or d.startswith("eth")
                ]
                if not ifaces:
                    ifaces = ["wlan0"]
        except OSError:
            pass

        for iface in ifaces:
            mac = self.get_mac_address(iface) or "unknown"
            state = self.get_interface_state(iface)
            interfaces.append({
                "name": iface,
                "mac": mac,
                "state": state,
                "mode": "managed",
            })

        return interfaces

    def get_interface_state(self, interface: str) -> str:
        """Get interface state from /sys or ip."""
        # Try /sys/class/net/wlan0/operstate
        try:
            with open(f"/sys/class/net/{interface}/operstate", "r") as f:
                state = f.read().strip().lower()
                if state == "up":
                    return "up"
                elif state == "down":
                    return "down"
        except OSError:
            pass

        # Try ip command (if available in Termux)
        rc, stdout, _ = self._run_command(["ip", "link", "show", interface])
        if rc == 0:
            if "state UP" in stdout:
                return "up"
            elif "state DOWN" in stdout:
                return "down"

        # Fall back to checking if WiFi is enabled via termux-api
        self._require_api()
        rc, stdout, _ = self._run_command(
            ["termux-wifi-connectioninfo"], timeout=10
        )
        if rc == 0 and stdout.strip():
            return "up"
        return "down"

    def set_interface_state(self, interface: str, state: str) -> bool:
        """Set WiFi enabled/disabled using termux-api."""
        if state not in ("up", "down"):
            raise ValueError(f"Invalid state: {state}")
        self._require_api()
        if state == "up":
            rc, _, stderr = self._run_command(
                ["termux-wifi-enable", "true"], timeout=10
            )
        else:
            rc, _, stderr = self._run_command(
                ["termux-wifi-enable", "false"], timeout=10
            )
        if rc != 0:
            raise WiFiConnectionError(
                f"Failed to set WiFi {state}",
                details=stderr.strip(),
            )
        return True

    def enable_monitor_mode(self, interface: str) -> bool:
        """Monitor mode is not supported in standard Termux.

        Raises:
            WiFiConnectionError: Monitor mode requires a rooted device
                with custom WiFi driver support.
        """
        raise WiFiConnectionError(
            "Monitor mode is not supported in standard Termux",
            details="Monitor mode requires a rooted Android device with a "
            "compatible WiFi chipset and custom drivers (e.g., bcmon, PwnPad). "
            "Consider using an external WiFi adapter with rtl8812au drivers.",
        )

    def disable_monitor_mode(self, interface: str) -> bool:
        """Monitor mode is not supported in Termux."""
        return True

    def set_channel(self, interface: str, channel: int) -> bool:
        """Channel setting is not supported in Termux."""
        raise WiFiConnectionError(
            "Channel setting is not supported in Termux",
            details="Android WiFi drivers do not expose channel setting APIs.",
        )

    def get_channel(self, interface: str) -> int:
        """Get channel from connection info."""
        info = self._get_connection_info()
        if info:
            freq = info.get("frequency_mhz", 0)
            if isinstance(freq, (int, float)):
                return self._freq_to_channel(int(freq))
        return 0

    # ── Scanning ──────────────────────────────────────────────────────

    def scan_networks(self, interface: str) -> List[Dict[str, object]]:
        """Scan for networks using termux-wifi-scaninfo."""
        self._require_api()
        rc, stdout, stderr = self._run_command(
            ["termux-wifi-scaninfo"], timeout=30
        )
        if rc != 0:
            raise WiFiConnectionError(
                "WiFi scan failed",
                details=stderr.strip() or "Ensure WiFi is enabled and location permission is granted.",
            )

        networks = []
        try:
            scan_results = json.loads(stdout)
        except json.JSONDecodeError:
            return networks

        if isinstance(scan_results, list):
            for entry in scan_results:
                network = self._parse_scan_entry(entry)
                if network:
                    networks.append(network)
        elif isinstance(scan_results, dict):
            network = self._parse_scan_entry(scan_results)
            if network:
                networks.append(network)

        return networks

    def _parse_scan_entry(self, entry: dict) -> Optional[Dict[str, object]]:
        """Parse a single scan result entry from termux-wifi-scaninfo."""
        if not isinstance(entry, dict):
            return None

        ssid = entry.get("ssid", entry.get("SSID", ""))
        bssid = entry.get("bssid", entry.get("BSSID", entry.get("mac", "unknown")))
        if isinstance(bssid, str):
            bssid = bssid.lower()

        # Signal strength
        signal = entry.get("level", entry.get("rssi", entry.get("signal_level", -100)))
        if isinstance(signal, str):
            try:
                signal = int(signal)
            except ValueError:
                signal = -100

        # Frequency
        freq = entry.get("frequency", entry.get("frequency_mhz", 0))
        if isinstance(freq, str):
            try:
                freq = int(freq)
            except ValueError:
                freq = 0

        # Channel
        channel = entry.get("channel", 0)
        if not channel and freq:
            channel = self._freq_to_channel(int(freq))

        # Security
        security = entry.get("security", entry.get("capabilities", ""))
        encryption = "Open"
        if isinstance(security, str):
            if "WPA3" in security:
                encryption = "WPA3"
            elif "WPA2" in security:
                encryption = "WPA2"
            elif "WPA" in security:
                encryption = "WPA"
            elif "WEP" in security:
                encryption = "WEP"
        elif isinstance(security, list):
            for s in security:
                s_str = str(s)
                if "WPA3" in s_str:
                    encryption = "WPA3"
                    break
                elif "WPA2" in s_str:
                    encryption = "WPA2"
                    break
                elif "WPA" in s_str:
                    encryption = "WPA"
                    break

        return {
            "ssid": ssid,
            "bssid": bssid,
            "channel": channel,
            "frequency": freq,
            "signal_dbm": signal,
            "encryption": encryption,
            "privacy": encryption != "Open",
            "wps": "WPS" in str(security),
        }

    @staticmethod
    def _freq_to_channel(freq: int) -> int:
        """Convert frequency to channel number."""
        if 2412 <= freq <= 2484:
            if freq == 2484:
                return 14
            return (freq - 2407) // 5
        elif 5170 <= freq <= 5825:
            return (freq - 5000) // 5
        elif 5950 <= freq <= 7125:
            return (freq - 5950) // 5 + 1
        return 0

    def _get_connection_info(self) -> Optional[Dict[str, object]]:
        """Get current WiFi connection info from termux-api."""
        self._require_api()
        rc, stdout, _ = self._run_command(
            ["termux-wifi-connectioninfo"], timeout=10
        )
        if rc != 0:
            return None
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return None

    def get_connected_network(self, interface: str) -> Optional[Dict[str, object]]:
        """Get connected network info using termux-wifi-connectioninfo."""
        info = self._get_connection_info()
        if not info:
            return None

        ssid = info.get("ssid", info.get("SSID", ""))
        if not ssid:
            return None

        bssid = info.get("bssid", info.get("BSSID", info.get("mac", "unknown")))
        if isinstance(bssid, str):
            bssid = bssid.lower()

        freq = info.get("frequency_mhz", info.get("frequency", 0))
        if isinstance(freq, str):
            try:
                freq = int(freq)
            except ValueError:
                freq = 0

        signal = info.get("rssi", info.get("level", -100))
        if isinstance(signal, str):
            try:
                signal = int(signal)
            except ValueError:
                signal = -100

        return {
            "ssid": ssid,
            "bssid": bssid,
            "frequency": freq,
            "channel": self._freq_to_channel(int(freq)) if freq else 0,
            "signal_dbm": signal,
            "encryption": "Unknown",
        }

    # ── Connection ────────────────────────────────────────────────────

    def connect(
        self,
        interface: str,
        ssid: str,
        password: Optional[str] = None,
        bssid: Optional[str] = None,
        timeout: int = 30,
    ) -> bool:
        """Connect to WiFi using termux-wifi-connect.

        Note: Android WiFi connection is typically managed by the system.
        termux-wifi-connect may require additional setup.
        """
        self._require_api()

        # Try termux-wifi-connect if available
        if shutil.which("termux-wifi-connect"):
            cmd = ["termux-wifi-connect", ssid]
            if password:
                cmd.append(password)
            rc, _, stderr = self._run_command(cmd, timeout=timeout)
            if rc == 0:
                return True

        # Alternative: use Android am command to open WiFi settings
        # This is a best-effort approach for Termux
        rc, _, _ = self._run_command(
            [
                "am", "start",
                "-a", "android.settings.WIFI_SETTINGS",
            ],
            timeout=5,
        )

        raise WiFiConnectionError(
            f"Cannot programmatically connect to '{ssid}' in Termux",
            details="Android restricts programmatic WiFi connections. "
            "Use Android WiFi Settings or install the Termux:API plugin "
            "with termux-wifi-connect support.",
        )

    def disconnect(self, interface: str) -> bool:
        """Disable WiFi using termux-api."""
        self._require_api()
        rc, _, _ = self._run_command(
            ["termux-wifi-enable", "false"], timeout=10
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
        """Start a WiFi hotspot on Android.

        Requires Android hotspot settings or rooted device.
        """
        # Try using Android settings intent for hotspot
        rc, _, _ = self._run_command(
            [
                "am", "start",
                "-a", "android.settings.WIFI_HOTSPOT_SETTINGS",
            ],
            timeout=5,
        )

        raise WiFiConnectionError(
            "Starting a WiFi AP is not directly supported in Termux",
            details="Configure the WiFi hotspot via Android Settings > "
            "Hotspot & Tethering. Rooted devices can use hostapd via Termux.",
        )

    def stop_access_point(self, interface: str) -> bool:
        """Stop WiFi hotspot."""
        return True

    # ── Network Information ───────────────────────────────────────────

    def get_ip_address(self, interface: str) -> Optional[str]:
        """Get IP address from ifconfig or termux-api."""
        info = self._get_connection_info()
        if info:
            ip = info.get("ip", info.get("ip_address", info.get("ipv4")))
            if ip:
                return str(ip)

        # Fall back to ifconfig
        rc, stdout, _ = self._run_command(["ifconfig", interface])
        if rc == 0:
            match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", stdout)
            if match:
                return match.group(1)

        return None

    def get_mac_address(self, interface: str) -> Optional[str]:
        """Get MAC address from ifconfig or /sys."""
        # Try /sys/class/net
        try:
            with open(f"/sys/class/net/{interface}/address", "r") as f:
                return f.read().strip().lower()
        except OSError:
            pass

        # Try ifconfig
        rc, stdout, _ = self._run_command(["ifconfig", interface])
        if rc == 0:
            match = re.search(
                r"ether\s+([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})",
                stdout,
            )
            if not match:
                match = re.search(
                    r"HWaddr\s+([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})",
                    stdout,
                )
            return match.group(1).lower() if match else None

        return None

    def get_signal_strength(self, interface: str) -> Optional[int]:
        """Get signal strength from connection info."""
        info = self._get_connection_info()
        if info:
            signal = info.get("rssi", info.get("level"))
            if isinstance(signal, (int, float)):
                return int(signal)
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
                        if len(parts) >= 11:
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
        """Enable IP forwarding on Android (requires root)."""
        if not self.is_root():
            raise WiFiPermissionError("Enabling IP forwarding requires root")
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            return True
        except OSError as e:
            raise WiFiConnectionError(f"Failed to enable IP forwarding: {e}")

    def disable_ip_forwarding(self) -> bool:
        """Disable IP forwarding on Android (requires root)."""
        if not self.is_root():
            raise WiFiPermissionError("Disabling IP forwarding requires root")
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
            return True
        except OSError as e:
            raise WiFiConnectionError(f"Failed to disable IP forwarding: {e}")

    def set_iptables_rule(self, rule: str) -> bool:
        """Apply an iptables rule (requires root)."""
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
        """Return 'termux'."""
        return "termux"

    def get_platform_version(self) -> str:
        """Return Android version."""
        try:
            rc, stdout, _ = self._run_command(["getprop", "ro.build.version.release"])
            if rc == 0:
                return stdout.strip()
        except Exception:
            pass
        return "unknown"

    def check_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available."""
        return shutil.which(tool_name) is not None

    def install_tool(self, tool_name: str) -> bool:
        """Install a tool using pkg (Termux package manager)."""
        # Map tool names to Termux packages
        package_map = {
            "iw": "iw",
            "ip": "iproute2",
            "nmap": "nmap",
            "tcpdump": "tcpdump",
            "aircrack-ng": "aircrack-ng",
            "hashcat": "hashcat",
            "john": "john",
            "termux-api": "termux-api",
            "termux-wifi-scaninfo": "termux-api",
        }

        package = package_map.get(tool_name, tool_name)

        if self.check_tool_available("pkg"):
            rc, _, _ = self._run_command(
                ["pkg", "install", "-y", package],
                timeout=120,
            )
            return rc == 0

        if self.check_tool_available("apt"):
            rc, _, _ = self._run_command(
                ["apt", "install", "-y", package],
                timeout=120,
            )
            return rc == 0

        return False
