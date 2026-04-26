"""Windows platform adapter for WiFiAIO.

Implements WiFi operations on Windows using netsh, wlan APIs,
and other Windows-specific tools.
"""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple

from wifi_aio.platform.base import BasePlatform
from wifi_aio.exceptions import WiFiConnectionError, WiFiPermissionError, WiFiTimeoutError


class WindowsPlatform(BasePlatform):
    """Windows platform adapter using netsh and wlan APIs."""

    def __init__(self):
        self._wlan_handle = None

    def _run_command(
        self,
        cmd: List[str],
        timeout: int = 30,
    ) -> Tuple[int, str, str]:
        """Execute a system command on Windows."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=True if len(cmd) == 1 else False,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(
                f"Command timed out: {' '.join(cmd)}",
                details=f"Timeout was {timeout} seconds.",
            )
        except FileNotFoundError:
            return 127, "", f"Command not found: {cmd[0]}"

    def _run_netsh(self, args: str, timeout: int = 30) -> Tuple[int, str, str]:
        """Run a netsh wlan command."""
        return self._run_command(
            ["netsh", "wlan"] + args.split(),
            timeout=timeout,
        )

    # ── Interface Management ──────────────────────────────────────────

    def get_interfaces(self) -> List[Dict[str, str]]:
        """List wireless interfaces using netsh."""
        interfaces = []
        rc, stdout, _ = self._run_netsh("show interfaces")
        if rc != 0:
            return interfaces

        current: Dict[str, str] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current and current.get("name"):
                    current.setdefault("state", "unknown")
                    current.setdefault("mode", "managed")
                    current.setdefault("mac", "unknown")
                    interfaces.append(current)
                current = {}
                continue

            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()

                if "name" in key:
                    current["name"] = value
                elif "state" in key:
                    current["state"] = value.lower() if value else "unknown"
                elif "physical address" in key or "mac" in key:
                    current["mac"] = value.lower() if value else "unknown"
                elif "radio" in key:
                    current["mode"] = "managed" if "on" in value.lower() else "down"

        if current and current.get("name"):
            current.setdefault("state", "unknown")
            current.setdefault("mode", "managed")
            current.setdefault("mac", "unknown")
            interfaces.append(current)

        return interfaces

    def get_interface_state(self, interface: str) -> str:
        """Get interface state from netsh."""
        rc, stdout, _ = self._run_netsh(f"show interface name=\"{interface}\"")
        if rc != 0:
            return "unknown"
        for line in stdout.splitlines():
            if "state" in line.lower():
                _, _, value = line.partition(":")
                return value.strip().lower()
        return "unknown"

    def set_interface_state(self, interface: str, state: str) -> bool:
        """Enable or disable a wireless interface."""
        if not self.is_root():
            raise WiFiPermissionError(
                "Changing interface state requires administrator privileges"
            )
        if state == "up":
            rc, _, stderr = self._run_command(
                ["netsh", "interface", "set", "interface", interface, "enable"]
            )
        elif state == "down":
            rc, _, stderr = self._run_command(
                ["netsh", "interface", "set", "interface", interface, "disable"]
            )
        else:
            raise ValueError(f"Invalid state: {state}")

        if rc != 0:
            raise WiFiConnectionError(
                f"Failed to set {interface} {state}",
                details="Run as administrator.",
            )
        return True

    def enable_monitor_mode(self, interface: str) -> bool:
        """Monitor mode is not natively supported on Windows.

        Raises:
            WiFiConnectionError: Windows does not natively support monitor mode.
        """
        raise WiFiConnectionError(
            "Monitor mode is not natively supported on Windows",
            details="Use a compatible USB WiFi adapter with specialized drivers "
            "(e.g., AirPcap, or Npcap with monitor support) or use a Linux VM.",
        )

    def disable_monitor_mode(self, interface: str) -> bool:
        """Monitor mode is not supported on Windows."""
        return True

    def set_channel(self, interface: str, channel: int) -> bool:
        """Channel setting is not directly supported on Windows via netsh."""
        # Windows does not expose a direct channel setting API for WiFi
        # Some specialized drivers may support it
        raise WiFiConnectionError(
            "Channel setting is not directly supported on Windows",
            details="Use a specialized WiFi adapter driver or Linux platform.",
        )

    def get_channel(self, interface: str) -> int:
        """Get channel from network connection info."""
        network = self.get_connected_network(interface)
        if network and "channel" in network:
            return int(network["channel"])
        return 0

    # ── Scanning ──────────────────────────────────────────────────────

    def scan_networks(self, interface: str = "") -> List[Dict[str, object]]:
        """Scan for networks using netsh."""
        networks = []
        rc, stdout, _ = self._run_netsh("show networks mode=bssid", timeout=30)
        if rc != 0:
            return networks

        current: Optional[Dict[str, object]] = None
        current_bssid: Optional[Dict[str, object]] = None

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("SSID"):
                if current and current_bssid:
                    networks.append(current)
                current = {"ssid": "", "bssid": "unknown", "channel": 0,
                           "frequency": 0, "signal_dbm": -100,
                           "encryption": "Open", "privacy": False, "wps": False}
                current_bssid = None
                if ":" in line:
                    current["ssid"] = line.partition(":")[2].strip()
            elif current is None:
                continue
            elif "Network type" in line:
                net_type = line.partition(":")[2].strip()
                if "infrastructure" in net_type.lower():
                    pass  # We only handle infrastructure mode
            elif "Authentication" in line:
                auth = line.partition(":")[2].strip()
                if "WPA3" in auth:
                    current["encryption"] = "WPA3"
                elif "WPA2" in auth:
                    current["encryption"] = "WPA2"
                elif "WPA" in auth:
                    current["encryption"] = "WPA"
                elif "WEP" in auth:
                    current["encryption"] = "WEP"
                elif "open" in auth.lower():
                    current["encryption"] = "Open"
                current["privacy"] = current["encryption"] != "Open"
            elif "Encryption" in line:
                enc = line.partition(":")[2].strip()
                # Update encryption info
                if "CCMP" in enc or "AES" in enc:
                    current["encryption"] = current.get("encryption", "WPA2")
            elif "BSSID" in line:
                current_bssid = {}
                bssid_val = line.partition(":")[2].strip()
                current["bssid"] = bssid_val.lower()
            elif "Signal" in line and current_bssid is not None:
                signal_str = line.partition(":")[2].strip()
                try:
                    signal_pct = int(signal_str.replace("%", ""))
                    current["signal_dbm"] = signal_pct // 2 - 100
                except ValueError:
                    pass
            elif "Channel" in line and current_bssid is not None:
                chan_str = line.partition(":")[2].strip()
                try:
                    current["channel"] = int(chan_str)
                    current["frequency"] = self._channel_to_freq(int(chan_str))
                except ValueError:
                    pass

        if current:
            networks.append(current)

        return networks

    @staticmethod
    def _channel_to_freq(channel: int) -> int:
        """Convert channel number to frequency in MHz."""
        if 1 <= channel <= 13:
            return 2407 + channel * 5
        elif channel == 14:
            return 2484
        elif 36 <= channel <= 177:
            return 5000 + channel * 5
        return 0

    def get_connected_network(self, interface: str = "") -> Optional[Dict[str, object]]:
        """Get connected network info using netsh."""
        rc, stdout, _ = self._run_netsh("show interfaces")
        if rc != 0:
            return None

        result: Dict[str, object] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if "SSID" in line and "BSSID" not in line:
                _, _, value = line.partition(":")
                result["ssid"] = value.strip()
            elif "BSSID" in line:
                _, _, value = line.partition(":")
                result["bssid"] = value.strip().lower()
            elif "channel" in line.lower():
                _, _, value = line.partition(":")
                try:
                    result["channel"] = int(value.strip())
                except ValueError:
                    pass
            elif "signal" in line.lower():
                _, _, value = line.partition(":")
                try:
                    signal_pct = int(value.strip().replace("%", ""))
                    result["signal_dbm"] = signal_pct // 2 - 100
                except ValueError:
                    pass
            elif "authentication" in line.lower():
                _, _, value = line.partition(":")
                result["encryption"] = value.strip()

        return result if result.get("ssid") else None

    # ── Connection ────────────────────────────────────────────────────

    def connect(
        self,
        interface: str,
        ssid: str,
        password: Optional[str] = None,
        bssid: Optional[str] = None,
        timeout: int = 30,
    ) -> bool:
        """Connect to a network using netsh.

        Creates a profile XML, adds it, and connects.
        """
        # First, try to connect to an existing profile
        rc, stdout, stderr = self._run_netsh(f'connect name="{ssid}"', timeout=timeout)
        if rc == 0 and "successfully" in stdout.lower():
            return True

        # Create a new profile
        profile_xml = self._create_profile_xml(ssid, password)
        profile_path = os.path.join(os.environ.get("TEMP", "."), f"wifi_aio_{ssid}.xml")
        try:
            with open(profile_path, "w", encoding="utf-8") as f:
                f.write(profile_xml)
        except OSError as e:
            raise WiFiConnectionError(f"Failed to write profile: {e}")

        # Add profile
        rc, stdout, stderr = self._run_command(
            ["netsh", "wlan", "add", "profile",
             f'filename="{profile_path}"'],
            timeout=10,
        )
        if rc != 0:
            raise WiFiConnectionError(
                f"Failed to add WiFi profile for '{ssid}'",
                details=stderr.strip(),
            )

        # Connect
        rc, stdout, stderr = self._run_netsh(
            f'connect name="{ssid}"', timeout=timeout
        )
        if rc != 0:
            raise WiFiConnectionError(
                f"Failed to connect to '{ssid}'",
                details=stderr.strip(),
            )
        return True

    def _create_profile_xml(self, ssid: str, password: Optional[str]) -> str:
        """Create a Windows WLAN profile XML."""
        if password:
            auth = "WPA2PSK"
            encryption = "AES"
            shared_key = f"""
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>"""
        else:
            auth = "open"
            encryption = "open"
            shared_key = ""

        return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{auth}</authentication>
                <encryption>{encryption}</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            {shared_key}
        </security>
    </MSM>
</WLANProfile>"""

    def disconnect(self, interface: str) -> bool:
        """Disconnect using netsh."""
        rc, _, _ = self._run_netsh("disconnect")
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
        """Start a hosted network (mobile hotspot) using netsh."""
        if not self.is_root():
            raise WiFiPermissionError(
                "Starting AP requires administrator privileges"
            )

        # Set hosted network parameters
        cmd_args = f'set hostednetwork mode=allow ssid="{ssid}"'
        if password:
            cmd_args += f' key="{password}"'
        rc, _, stderr = self._run_netsh(cmd_args)
        if rc != 0:
            raise WiFiConnectionError(
                f"Failed to configure hosted network",
                details=stderr.strip(),
            )

        # Start hosted network
        rc, _, stderr = self._run_netsh("start hostednetwork")
        if rc != 0:
            raise WiFiConnectionError(
                "Failed to start hosted network",
                details=stderr.strip() + " Ensure the Wireless Hosted Network is supported.",
            )
        return True

    def stop_access_point(self, interface: str) -> bool:
        """Stop the hosted network."""
        rc, _, _ = self._run_netsh("stop hostednetwork")
        return rc == 0

    # ── Network Information ───────────────────────────────────────────

    def get_ip_address(self, interface: str) -> Optional[str]:
        """Get IPv4 address using ipconfig."""
        rc, stdout, _ = self._run_command(["ipconfig"], timeout=10)
        if rc != 0:
            return None
        # Find the adapter section and extract IP
        in_adapter = False
        for line in stdout.splitlines():
            if interface.lower() in line.lower() or "Wireless" in line:
                in_adapter = True
            elif in_adapter and "IPv4 Address" in line:
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    return match.group(1)
            elif in_adapter and line.strip() and not line.startswith(" "):
                in_adapter = False
        return None

    def get_mac_address(self, interface: str) -> Optional[str]:
        """Get MAC address using getmac or ipconfig."""
        rc, stdout, _ = self._run_command(["getmac", "/v", "/fo", "csv"])
        if rc == 0:
            for line in stdout.splitlines():
                if interface.lower() in line.lower() or "Wi-Fi" in line:
                    parts = line.split(",")
                    if len(parts) >= 3:
                        mac = parts[2].strip().strip('"')
                        return mac.lower().replace("-", ":")
        return None

    def get_signal_strength(self, interface: str) -> Optional[int]:
        """Get signal strength from netsh."""
        rc, stdout, _ = self._run_netsh("show interfaces")
        if rc == 0:
            for line in stdout.splitlines():
                if "signal" in line.lower():
                    _, _, value = line.partition(":")
                    try:
                        pct = int(value.strip().replace("%", ""))
                        return pct // 2 - 100
                    except ValueError:
                        pass
        return None

    def get_network_stats(self, interface: str) -> Dict[str, int]:
        """Get network statistics from netsh or WMI."""
        stats = {
            "rx_bytes": 0,
            "tx_bytes": 0,
            "rx_packets": 0,
            "tx_packets": 0,
            "rx_errors": 0,
            "tx_errors": 0,
        }
        try:
            import wmi
            c = wmi.WMI()
            for adapter in c.Win32_NetworkAdapter(Name=interface):
                for config in adapter.associators(wmi_result_class="Win32_NetworkAdapterConfiguration"):
                    stats["rx_bytes"] = getattr(config, "BytesReceivedPersec", 0) or 0
                    stats["tx_bytes"] = getattr(config, "BytesSentPersec", 0) or 0
        except ImportError:
            # Fall back to netsh statistics
            rc, stdout, _ = self._run_netsh("show interfaces")
            if rc == 0:
                for line in stdout.splitlines():
                    if "receive" in line.lower() and "byte" in line.lower():
                        try:
                            _, _, val = line.partition(":")
                            stats["rx_bytes"] = int(val.strip().replace(",", ""))
                        except (ValueError, AttributeError):
                            pass
                    elif "transmit" in line.lower() and "byte" in line.lower():
                        try:
                            _, _, val = line.partition(":")
                            stats["tx_bytes"] = int(val.strip().replace(",", ""))
                        except (ValueError, AttributeError):
                            pass
        return stats

    # ── Firewall / Packet Operations ──────────────────────────────────

    def enable_ip_forwarding(self) -> bool:
        """Enable IP forwarding via registry."""
        if not self.is_root():
            raise WiFiPermissionError("Enabling IP forwarding requires admin")
        try:
            key = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
            return True
        except (OSError, ImportError) as e:
            raise WiFiConnectionError(f"Failed to enable IP forwarding: {e}")

    def disable_ip_forwarding(self) -> bool:
        """Disable IP forwarding via registry."""
        if not self.is_root():
            raise WiFiPermissionError("Disabling IP forwarding requires admin")
        try:
            key = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "IPEnableRouter", 0, winreg.REG_DWORD, 0)
            return True
        except (OSError, ImportError) as e:
            raise WiFiConnectionError(f"Failed to disable IP forwarding: {e}")

    def set_iptables_rule(self, rule: str) -> bool:
        """Apply a firewall rule using netsh advfirewall."""
        if not self.is_root():
            raise WiFiPermissionError("Firewall rules require admin privileges")
        # Translate iptables-style rule to netsh advfirewall format
        # Basic translation for common patterns
        parts = rule.split()
        cmd = ["netsh", "advfirewall", "firewall"]
        if "ACCEPT" in rule:
            cmd.extend(["add", "rule"])
            cmd.extend(["action=allow"])
        elif "DROP" in rule or "REJECT" in rule:
            cmd.extend(["add", "rule"])
            cmd.extend(["action=block"])
        else:
            cmd.extend(["add", "rule"])
            cmd.extend(["action=allow"])

        cmd.extend([f'name=wifi_aio_rule_{hash(rule) % 10000}'])

        # Try to extract port
        for i, p in enumerate(parts):
            if p == "--dport" and i + 1 < len(parts):
                cmd.extend([f'localport={parts[i+1]}'])
            elif p == "-p" and i + 1 < len(parts):
                proto = parts[i + 1]
                cmd.extend([f'protocol={proto}'])
            elif p == "-s" and i + 1 < len(parts):
                cmd.extend([f'remoteip={parts[i+1]}'])

        cmd.extend(["dir=in"])
        rc, _, _ = self._run_command(cmd, timeout=10)
        return rc == 0

    # ── Utility Methods ───────────────────────────────────────────────

    def is_root(self) -> bool:
        """Check for administrator privileges on Windows."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except AttributeError:
            return False

    def get_platform_name(self) -> str:
        """Return 'windows'."""
        return "windows"

    def get_platform_version(self) -> str:
        """Return Windows version string."""
        try:
            result = subprocess.run(
                ["cmd", "/c", "ver"],
                capture_output=True, text=True, timeout=5,
            )
            match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        return os.environ.get("OS", "unknown")

    def check_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available on Windows."""
        # Check common Windows paths
        common_paths = [
            os.environ.get("SystemRoot", r"C:\Windows") + r"\System32",
            os.environ.get("ProgramFiles", r"C:\Program Files"),
        ]
        for search_dir in common_paths:
            if os.path.isfile(os.path.join(search_dir, f"{tool_name}.exe")):
                return True
        # Try shutil.which
        import shutil
        return shutil.which(tool_name) is not None

    def install_tool(self, tool_name: str) -> bool:
        """Install a tool using winget or choco."""
        if not self.is_root():
            raise WiFiPermissionError("Installing tools requires admin")

        # Try winget
        if self.check_tool_available("winget"):
            rc, _, _ = self._run_command(
                ["winget", "install", "--id", tool_name, "-e", "--accept-package-agreements"],
                timeout=120,
            )
            if rc == 0:
                return True

        # Try choco
        if self.check_tool_available("choco"):
            rc, _, _ = self._run_command(
                ["choco", "install", tool_name, "-y"],
                timeout=120,
            )
            return rc == 0

        return False
