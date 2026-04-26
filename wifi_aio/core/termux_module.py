"""Termux/Android-specific WiFi operations.

Provides WiFi scanning, connection, and hotspot management on Android
devices running Termux with appropriate API access.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import time
from typing import Dict, List, Optional

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


class TermuxModule:
    """Android/Termux-specific WiFi operations.

    Requires Termux:API package (com.termux.api) for most operations.
    Install with: pkg install termux-api
    """

    def __init__(self):
        self._is_termux = self._detect_termux()
        self._api_available = self._check_api()

    @staticmethod
    def _detect_termux() -> bool:
        """Detect if running in Termux environment."""
        return (
            os.path.isdir("/data/data/com.termux")
            or "TERMUX_VERSION" in os.environ
            or os.path.isfile("/data/data/com.termux/files/usr/bin/termux-open")
            or os.environ.get("PREFIX", "").startswith("/data/data/com.termux")
        )

    @staticmethod
    def _check_api() -> bool:
        """Check if Termux:API is available."""
        try:
            result = subprocess.run(
                ["termux-wifi-connectioninfo"],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0 or "Not connected" in result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def is_termux(self) -> bool:
        """Check if running in Termux.

        Returns:
            True if in Termux environment.
        """
        return self._is_termux

    def is_api_available(self) -> bool:
        """Check if Termux:API is available.

        Returns:
            True if API is accessible.
        """
        return self._api_available

    def _require_api(self) -> None:
        """Ensure Termux API is available."""
        if not self._is_termux:
            raise WiFiConnectionError("Not running in Termux environment")
        if not self._api_available:
            raise WiFiConnectionError(
                "Termux:API not available. Install with: pkg install termux-api"
            )

    # ------------------------------------------------------------------
    # WiFi Scanning
    # ------------------------------------------------------------------

    def scan_wifi(self) -> List[Dict]:
        """Scan for WiFi networks using Termux API.

        Returns:
            List of network dicts with SSID, BSSID, signal, security, etc.
        """
        self._require_api()

        try:
            result = subprocess.run(
                ["termux-wifi-scaninfo"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                raise WiFiConnectionError(f"WiFi scan failed: {result.stderr}")

            data = json.loads(result.stdout)
            if not isinstance(data, list):
                data = [data]

            networks = []
            for entry in data:
                network = {
                    "ssid": entry.get("ssid", ""),
                    "bssid": entry.get("bssid", ""),
                    "frequency": entry.get("frequency", 0),
                    "level": entry.get("level", entry.get("rssi", 0)),
                    "capabilities": entry.get("capabilities", ""),
                    "security": self._parse_security(entry.get("capabilities", "")),
                    "channel": self._freq_to_channel(entry.get("frequency", 0)),
                }
                networks.append(network)

            return networks

        except json.JSONDecodeError as exc:
            raise WiFiConnectionError(f"Failed to parse scan results: {exc}")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("WiFi scan timed out")

    # ------------------------------------------------------------------
    # WiFi Connection
    # ------------------------------------------------------------------

    def get_connection_info(self) -> Dict:
        """Get current WiFi connection information.

        Returns:
            Dict with connection details.
        """
        self._require_api()

        try:
            result = subprocess.run(
                ["termux-wifi-connectioninfo"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return {"connected": False}

            data = json.loads(result.stdout)
            if not isinstance(data, dict):
                data = {}

            return {
                "connected": True,
                "ssid": data.get("ssid", ""),
                "bssid": data.get("bssid", ""),
                "ip_address": data.get("ip", data.get("ip_address", "")),
                "gateway": data.get("gateway", ""),
                "netmask": data.get("netmask", ""),
                "dns": data.get("dns", ""),
                "frequency": data.get("frequency", 0),
                "link_speed": data.get("link_speed", 0),
                "rssi": data.get("rssi", data.get("level", 0)),
                "network_id": data.get("network_id", -1),
            }

        except json.JSONDecodeError:
            return {"connected": False}
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("Connection info request timed out")

    def connect_wifi(self, ssid: str, password: Optional[str] = None) -> bool:
        """Connect to a WiFi network.

        Args:
            ssid: Network SSID.
            password: Network password (None for open networks).

        Returns:
            True if connection was initiated successfully.
        """
        self._require_api()

        cmd = ["termux-wifi-connect", ssid]
        if password:
            cmd.append(password)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                # Verify connection
                time.sleep(3)
                info = self.get_connection_info()
                return info.get("connected", False) and info.get("ssid") == ssid
            return False
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("WiFi connection timed out")

    def disconnect_wifi(self) -> bool:
        """Disconnect from the current WiFi network.

        Returns:
            True if successfully disconnected.
        """
        self._require_api()

        try:
            # Termux doesn't have a direct disconnect command,
            # use Android settings approach
            subprocess.run(
                ["am", "broadcast", "-a", "android.net.wifi.WIFI_STATE_CHANGED"],
                capture_output=True, text=True, timeout=10,
            )

            # Try svc command (requires root)
            result = subprocess.run(
                ["svc", "wifi", "disable"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Fallback: attempt via Android intent
        try:
            subprocess.run(
                [
                    "am", "start",
                    "-a", "android.settings.WIFI_SETTINGS",
                ],
                capture_output=True, text=True, timeout=10,
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def enable_wifi(self) -> bool:
        """Enable WiFi on the Android device.

        Returns:
            True if successful.
        """
        try:
            result = subprocess.run(
                ["svc", "wifi", "enable"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Try Termux API
            try:
                subprocess.run(
                    ["termux-wifi-enable", "true"],
                    capture_output=True, text=True, timeout=10,
                )
                return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False

    def disable_wifi(self) -> bool:
        """Disable WiFi on the Android device.

        Returns:
            True if successful.
        """
        try:
            result = subprocess.run(
                ["svc", "wifi", "disable"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    # ------------------------------------------------------------------
    # WiFi Hotspot
    # ------------------------------------------------------------------

    def start_hotspot(
        self,
        ssid: str = "WiFiAIO-Hotspot",
        password: Optional[str] = None,
        band: str = "2.4GHz",
    ) -> Dict:
        """Start a WiFi hotspot.

        Args:
            ssid: Hotspot SSID.
            password: Hotspot password (None for open).
            band: Frequency band ('2.4GHz' or '5GHz').

        Returns:
            Dict with hotspot details.
        """
        # Android hotspot requires settings or root access
        try:
            # Try using settings command (root)
            cmd = [
                "am", "broadcast",
                "-a", "android.net.wifi.WIFI_AP_STATE_CHANGED",
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Use Android's settings database approach (requires root)
        if os.geteuid() == 0:
            return self._start_hotspot_root(ssid, password, band)

        return {
            "started": False,
            "message": "Hotspot start requires root access or manual configuration",
            "ssid": ssid,
        }

    def _start_hotspot_root(
        self,
        ssid: str,
        password: Optional[str],
        band: str,
    ) -> Dict:
        """Start hotspot with root access."""
        try:
            # Configure hotspot via settings provider
            subprocess.run(
                [
                    "settings", "put", "global",
                    "wifi_ap_state", "13",  # WIFI_AP_STATE_ENABLED
                ],
                capture_output=True, text=True, timeout=10,
            )

            # Set SSID and password
            subprocess.run(
                ["settings", "put", "global", "wifi_ap_ssid", ssid],
                capture_output=True, text=True, timeout=10,
            )
            if password:
                subprocess.run(
                    ["settings", "put", "global", "wifi_ap_password", password],
                    capture_output=True, text=True, timeout=10,
                )

            # Set band
            band_val = "1" if band == "5GHz" else "0"
            subprocess.run(
                ["settings", "put", "global", "wifi_ap_band", band_val],
                capture_output=True, text=True, timeout=10,
            )

            # Start AP via service call
            subprocess.run(
                ["service", "call", "wifi", "53"],  # setWifiApEnabled
                capture_output=True, text=True, timeout=10,
            )

            return {
                "started": True,
                "ssid": ssid,
                "band": band,
            }
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {
                "started": False,
                "message": str(exc),
            }

    def stop_hotspot(self) -> bool:
        """Stop the WiFi hotspot.

        Returns:
            True if successful.
        """
        try:
            subprocess.run(
                ["service", "call", "wifi", "53"],
                capture_output=True, text=True, timeout=10,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    # ------------------------------------------------------------------
    # Device Information
    # ------------------------------------------------------------------

    def get_device_info(self) -> Dict:
        """Get Android device information.

        Returns:
            Dict with device details.
        """
        info: Dict = {
            "is_termux": self._is_termux,
            "api_available": self._api_available,
            "android_version": "",
            "device_model": "",
            "sdk_version": "",
            "rooted": False,
        }

        try:
            result = subprocess.run(
                ["getprop", "ro.build.version.release"],
                capture_output=True, text=True, timeout=5,
            )
            info["android_version"] = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        try:
            result = subprocess.run(
                ["getprop", "ro.product.model"],
                capture_output=True, text=True, timeout=5,
            )
            info["device_model"] = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        try:
            result = subprocess.run(
                ["getprop", "ro.build.version.sdk"],
                capture_output=True, text=True, timeout=5,
            )
            info["sdk_version"] = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check root
        info["rooted"] = os.geteuid() == 0 or shutil.which("su") is not None

        # Battery info
        try:
            result = subprocess.run(
                ["termux-battery-status"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                battery = json.loads(result.stdout)
                info["battery"] = battery
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass

        return info

    # ------------------------------------------------------------------
    # Location
    # ------------------------------------------------------------------

    def get_location(self) -> Dict:
        """Get device GPS location.

        Returns:
            Dict with latitude, longitude, altitude, accuracy.
        """
        try:
            result = subprocess.run(
                ["termux-location"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return {
                    "latitude": data.get("latitude", 0.0),
                    "longitude": data.get("longitude", 0.0),
                    "altitude": data.get("altitude", 0.0),
                    "accuracy": data.get("accuracy", 0.0),
                    "provider": data.get("provider", "unknown"),
                    "timestamp": data.get("elapsedRealtimeNanos", 0),
                }
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass

        return {"latitude": 0.0, "longitude": 0.0, "provider": "unavailable"}

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------

    def send_notification(
        self,
        title: str,
        message: str,
        notification_id: int = 1,
    ) -> bool:
        """Send an Android notification.

        Args:
            title: Notification title.
            message: Notification message.
            notification_id: Notification ID.

        Returns:
            True if successful.
        """
        try:
            result = subprocess.run(
                [
                    "termux-notification",
                    "--title", title,
                    "--content", message,
                    "--id", str(notification_id),
                ],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    # ------------------------------------------------------------------
    # Clipboard
    # ------------------------------------------------------------------

    def get_clipboard(self) -> str:
        """Get clipboard content.

        Returns:
            Clipboard text.
        """
        try:
            result = subprocess.run(
                ["termux-clipboard-get"],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ""

    def set_clipboard(self, text: str) -> bool:
        """Set clipboard content.

        Returns:
            True if successful.
        """
        try:
            result = subprocess.run(
                ["termux-clipboard-set"],
                input=text,
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    # ------------------------------------------------------------------
    # Network utilities
    # ------------------------------------------------------------------

    def get_network_interfaces(self) -> List[Dict[str, str]]:
        """Get network interfaces on Android.

        Returns:
            List of interface dicts.
        """
        interfaces = []
        try:
            result = subprocess.run(
                ["ip", "addr", "show"],
                capture_output=True, text=True, timeout=10,
            )
            current = {}
            for line in result.stdout.splitlines():
                match = re.match(r"^\d+:\s+(\S+):", line)
                if match:
                    if current:
                        interfaces.append(current)
                    name = match.group(1).rstrip("@")
                    current = {"name": name, "ip": "", "mac": "", "state": "unknown"}
                elif current:
                    if "link/ether" in line:
                        current["mac"] = line.split()[1]
                    elif "inet " in line:
                        current["ip"] = line.split()[1].split("/")[0]
                    elif "state UP" in line:
                        current["state"] = "up"
                    elif "state DOWN" in line:
                        current["state"] = "down"
            if current:
                interfaces.append(current)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return interfaces

    def ping(self, host: str, count: int = 3) -> Dict:
        """Ping a host from the Android device.

        Returns:
            Dict with ping results.
        """
        try:
            result = subprocess.run(
                ["ping", "-c", str(count), host],
                capture_output=True, text=True, timeout=count * 5 + 5,
            )
            latencies = re.findall(r"time=([\d.]+)\s*ms", result.stdout)
            packet_loss = 0.0
            match = re.search(r"(\d+)% packet loss", result.stdout)
            if match:
                packet_loss = float(match.group(1))

            return {
                "success": result.returncode == 0,
                "latencies_ms": [float(l) for l in latencies],
                "packet_loss_percent": packet_loss,
                "output": result.stdout,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "latencies_ms": [], "packet_loss_percent": 100.0}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_security(capabilities: str) -> str:
        """Parse WiFi security from capabilities string."""
        if not capabilities:
            return "Open"
        caps = capabilities.upper()
        if "WPA3" in caps:
            return "WPA3"
        elif "WPA2" in caps:
            if "SAE" in caps:
                return "WPA3"
            return "WPA2"
        elif "WPA" in caps:
            return "WPA"
        elif "WEP" in caps:
            return "WEP"
        return "Open"

    @staticmethod
    def _freq_to_channel(frequency: int) -> int:
        """Convert frequency (MHz) to channel number."""
        if 2412 <= frequency <= 2484:
            if frequency == 2484:
                return 14
            return (frequency - 2407) // 5
        elif 5170 <= frequency <= 5885:
            return (frequency - 5000) // 5
        elif 5955 <= frequency <= 7115:
            return (frequency - 5950) // 5
        return 0
