"""Bluetooth scanning and device discovery.

Supports Classic Bluetooth and BLE (Bluetooth Low Energy) scanning,
service enumeration, and RSSI signal strength tracking.
"""

import asyncio
import json
import logging
import re
import subprocess
import time
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


class BluetoothScanner:
    """Scan and interact with Bluetooth Classic and BLE devices."""

    def __init__(self, timeout: int = 10):
        self.scan_timeout = timeout
        self._discovered_devices: Dict[str, Dict] = {}
        self._rssi_history: Dict[str, List[Tuple[float, int]]] = {}

    # ------------------------------------------------------------------
    # Classic Bluetooth scanning
    # ------------------------------------------------------------------

    def scan_classic(self, timeout: Optional[int] = None) -> List[Dict[str, str]]:
        """Scan for Classic Bluetooth devices.

        Args:
            timeout: Scan duration in seconds.

        Returns:
            List of dicts with keys: address, name, class, rssi.
        """
        scan_time = timeout or self.scan_timeout
        devices: List[Dict[str, str]] = []
        seen_addresses: set = set()

        try:
            result = subprocess.run(
                ["hcitool", "scan", "--flush"],
                capture_output=True, text=True, timeout=scan_time + 10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines()[1:]:
                    parts = line.strip().split("\t")
                    if len(parts) >= 2:
                        address = parts[0].strip()
                        name = parts[1].strip() if len(parts) > 1 else "Unknown"
                        if address not in seen_addresses:
                            device = {
                                "address": address,
                                "name": name,
                                "class": self._get_device_class(address),
                                "type": "classic",
                            }
                            devices.append(device)
                            seen_addresses.add(address)
                            self._discovered_devices[address] = device
        except FileNotFoundError:
            logger.warning("hcitool not found. Install bluez package.")
        except subprocess.TimeoutExpired:
            logger.warning("Classic Bluetooth scan timed out")

        # Also try to get RSSI for each found device
        for device in devices:
            rssi = self._get_rssi_classic(device["address"])
            device["rssi"] = str(rssi) if rssi is not None else "N/A"
            if rssi is not None:
                self._record_rssi(device["address"], rssi)

        return devices

    def scan_classic_inquiry(self, timeout: Optional[int] = None) -> List[Dict[str, str]]:
        """Perform an inquiry scan for Classic Bluetooth devices (no name resolution).

        Faster than regular scan but returns only addresses and device classes.

        Args:
            timeout: Scan duration in seconds.

        Returns:
            List of dicts with keys: address, class, clock_offset, rssi.
        """
        scan_time = timeout or self.scan_timeout
        devices: List[Dict[str, str]] = []

        try:
            result = subprocess.run(
                ["hcitool", "inq"],
                capture_output=True, text=True, timeout=scan_time + 10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    match = re.match(
                        r"\s*([0-9A-Fa-f:]{17})\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)",
                        line,
                    )
                    if match:
                        device = {
                            "address": match.group(1),
                            "class": match.group(2),
                            "clock_offset": match.group(3),
                            "type": "classic",
                        }
                        devices.append(device)
        except FileNotFoundError:
            logger.warning("hcitool not found")
        except subprocess.TimeoutExpired:
            pass

        return devices

    # ------------------------------------------------------------------
    # BLE scanning
    # ------------------------------------------------------------------

    def scan_ble(self, timeout: Optional[int] = None) -> List[Dict[str, str]]:
        """Scan for Bluetooth Low Energy (BLE) devices.

        Args:
            timeout: Scan duration in seconds.

        Returns:
            List of dicts with keys: address, name, rssi, type, services.
        """
        scan_time = timeout or self.scan_timeout
        devices: List[Dict[str, str]] = []
        seen_addresses: set = set()

        try:
            result = subprocess.run(
                ["hcitool", "lescan", "--duplicates"],
                capture_output=True, text=True, timeout=scan_time + 5,
            )
            # hcitool lescan outputs continuously; parse what we get
            for line in result.stdout.splitlines():
                match = re.match(r"([0-9A-Fa-f:]{17})\s+(.+)", line.strip())
                if match:
                    address = match.group(1)
                    name = match.group(2).strip()
                    if address not in seen_addresses and not name.startswith("(unknown)"):
                        device = {
                            "address": address,
                            "name": name if name != "(unknown)" else "Unknown",
                            "type": "ble",
                            "rssi": "N/A",
                        }
                        devices.append(device)
                        seen_addresses.add(address)
                        self._discovered_devices[address] = device
        except FileNotFoundError:
            logger.warning("hcitool not found. Install bluez package.")
        except subprocess.TimeoutExpired:
            pass

        # Try to get RSSI using hcitool
        for device in devices:
            rssi = self._get_rssi_ble(device["address"])
            device["rssi"] = str(rssi) if rssi is not None else "N/A"
            if rssi is not None:
                self._record_rssi(device["address"], rssi)

        return devices

    def scan_ble_with_timeout(self, timeout: Optional[int] = None) -> List[Dict[str, str]]:
        """Scan for BLE devices with explicit timeout management.

        Uses btmon or hcitool with a fixed scan window.
        """
        scan_time = timeout or self.scan_timeout
        devices: Dict[str, Dict[str, str]] = {}

        try:
            # Use hcitool lescan with a background process
            proc = subprocess.Popen(
                ["hcitool", "lescan"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            start = time.time()
            while time.time() - start < scan_time:
                line = proc.stdout.readline()
                if not line:
                    break
                match = re.match(r"([0-9A-Fa-f:]{17})\s+(.+)", line.strip())
                if match:
                    address = match.group(1)
                    name = match.group(2).strip()
                    if address not in devices and not name.startswith("(unknown)"):
                        devices[address] = {
                            "address": address,
                            "name": name,
                            "type": "ble",
                            "rssi": "N/A",
                        }
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except FileNotFoundError:
            logger.warning("hcitool not found")
        except Exception as exc:
            logger.warning("BLE scan error: %s", exc)

        device_list = list(devices.values())
        for dev in device_list:
            self._discovered_devices[dev["address"]] = dev

        return device_list

    # ------------------------------------------------------------------
    # Service enumeration
    # ------------------------------------------------------------------

    def get_services(self, address: str) -> List[Dict[str, str]]:
        """Enumerate services on a Bluetooth device.

        Args:
            address: Bluetooth device address.

        Returns:
            List of dicts with service information.
        """
        services: List[Dict[str, str]] = []

        # Try sdptool for Classic Bluetooth
        try:
            result = subprocess.run(
                ["sdptool", "records", address],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                current_service: Dict[str, str] = {}
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("Service Name:"):
                        if current_service:
                            services.append(current_service)
                        current_service = {"name": line.split(":", 1)[1].strip()}
                    elif line.startswith("Service RecHandle:"):
                        current_service["record_handle"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Protocol Descriptor List:"):
                        current_service["has_protocol_descriptor"] = "true"
                    elif "UUID:" in line:
                        uuid_match = re.search(r"UUID:\s*(\S+)", line)
                        if uuid_match:
                            current_service.setdefault("uuids", "")
                            if current_service["uuids"]:
                                current_service["uuids"] += ", "
                            current_service["uuids"] += uuid_match.group(1)
                if current_service:
                    services.append(current_service)
        except FileNotFoundError:
            logger.warning("sdptool not found")
        except subprocess.TimeoutExpired:
            logger.warning("sdptool timed out for %s", address)

        # Try gatttool for BLE services
        ble_services = self._get_ble_services(address)
        services.extend(ble_services)

        return services

    def _get_ble_services(self, address: str) -> List[Dict[str, str]]:
        """Get BLE GATT services using gatttool or btgatt-client."""
        services: List[Dict[str, str]] = []

        try:
            result = subprocess.run(
                [
                    "gatttool", "-b", address, "--characteristics",
                ],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    match = re.search(
                        r"handle = (0x[0-9a-fA-F]+), char properties = (0x[0-9a-fA-F]+), "
                        r"char value handle = (0x[0-9a-fA-F]+), uuid = ([0-9a-f-]+)",
                        line,
                    )
                    if match:
                        services.append({
                            "type": "ble_gatt",
                            "handle": match.group(1),
                            "properties": match.group(2),
                            "value_handle": match.group(3),
                            "uuid": match.group(4),
                        })
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            pass

        return services

    def read_characteristic(self, address: str, handle: str) -> Optional[str]:
        """Read a BLE GATT characteristic value.

        Args:
            address: BLE device address.
            handle: Characteristic handle (e.g., '0x0011').

        Returns:
            Characteristic value as hex string, or None.
        """
        try:
            result = subprocess.run(
                ["gatttool", "-b", address, "--char-read", "-a", handle],
                capture_output=True, text=True, timeout=15,
            )
            match = re.search(r"value: ([0-9a-fA-F ]+)", result.stdout)
            if match:
                return match.group(1).strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    # ------------------------------------------------------------------
    # RSSI tracking
    # ------------------------------------------------------------------

    def _get_rssi_classic(self, address: str) -> Optional[int]:
        """Get RSSI for a Classic Bluetooth device."""
        try:
            result = subprocess.run(
                ["hcitool", "rssi", address],
                capture_output=True, text=True, timeout=10,
            )
            match = re.search(r"RSSI return value: (-?\d+)", result.stdout)
            if match:
                return int(match.group(1))
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
        return None

    def _get_rssi_ble(self, address: str) -> Optional[int]:
        """Get RSSI for a BLE device."""
        try:
            result = subprocess.run(
                ["hcitool", "lescan", "--duplicates"],
                capture_output=True, text=True, timeout=5,
            )
            # Parse output for RSSI info
            for line in result.stdout.splitlines():
                if address in line:
                    match = re.search(r"(-\d+)", line)
                    if match:
                        return int(match.group(1))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Alternative: use btmgmt
        try:
            result = subprocess.run(
                ["btmgmt", "find"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if address in line:
                    match = re.search(r"rssi (-?\d+)", line)
                    if match:
                        return int(match.group(1))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return None

    def _record_rssi(self, address: str, rssi: int) -> None:
        """Record RSSI measurement with timestamp."""
        if address not in self._rssi_history:
            self._rssi_history[address] = []
        self._rssi_history[address].append((time.time(), rssi))

    def get_rssi_history(self, address: str) -> List[Tuple[float, int]]:
        """Get RSSI measurement history for a device.

        Returns:
            List of (timestamp, rssi) tuples.
        """
        return self._rssi_history.get(address, [])

    def get_rssi_average(self, address: str) -> Optional[float]:
        """Calculate average RSSI for a device.

        Returns:
            Average RSSI or None if no measurements.
        """
        history = self._rssi_history.get(address, [])
        if not history:
            return None
        return sum(rssi for _, rssi in history) / len(history)

    def estimate_distance(self, address: str) -> Optional[float]:
        """Estimate distance to device based on RSSI.

        Uses the log-distance path loss model.

        Returns:
            Estimated distance in meters, or None.
        """
        avg_rssi = self.get_rssi_average(address)
        if avg_rssi is None:
            return None

        # Reference values for BLE at 1 meter
        measured_power = -59  # Typical RSSI at 1 meter
        n = 2.0  # Path loss exponent (2.0 = free space)

        try:
            distance = 10 ** ((measured_power - avg_rssi) / (10 * n))
            return round(distance, 2)
        except (ValueError, ZeroDivisionError):
            return None

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    @staticmethod
    def _get_device_class(address: str) -> str:
        """Get the device class for a Bluetooth device."""
        try:
            result = subprocess.run(
                ["hcitool", "class", address],
                capture_output=True, text=True, timeout=5,
            )
            match = re.search(r"Device Class: ([0-9a-fA-Fx]+)", result.stdout)
            if match:
                return match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return "unknown"

    def get_device_info(self, address: str) -> Dict[str, str]:
        """Get detailed information about a discovered device.

        Args:
            address: Bluetooth device address.

        Returns:
            Dict with device information.
        """
        info = self._discovered_devices.get(address, {"address": address})

        # Get name
        try:
            result = subprocess.run(
                ["hcitool", "name", address],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout.strip():
                info["name"] = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Get device class
        info["class"] = self._get_device_class(address)

        # Get LMP version
        try:
            result = subprocess.run(
                ["hcitool", "info", address],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if "LMP Version" in line:
                    info["lmp_version"] = line.strip()
                elif "LMP Subversion" in line:
                    info["lmp_subversion"] = line.strip()
                elif "Manufacturer" in line:
                    info["manufacturer"] = line.strip()
                elif "Features" in line:
                    info["features"] = line.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # RSSI
        rssi = self._get_rssi_classic(address) or self._get_rssi_ble(address)
        info["rssi"] = str(rssi) if rssi is not None else "N/A"
        if rssi is not None:
            self._record_rssi(address, rssi)

        info["distance_estimate"] = str(self.estimate_distance(address))

        return info

    def is_bluetooth_available(self) -> bool:
        """Check if Bluetooth hardware is available."""
        try:
            result = subprocess.run(
                ["hcitool", "dev"],
                capture_output=True, text=True, timeout=5,
            )
            # Output lists devices; if there's at least one address, BT is available
            for line in result.stdout.splitlines():
                if re.match(r"\s+[0-9A-Fa-f:]{17}", line):
                    return True
        except FileNotFoundError:
            pass
        return False

    def get_adapter_info(self) -> Dict[str, str]:
        """Get information about the local Bluetooth adapter.

        Returns:
            Dict with adapter details.
        """
        info: Dict[str, str] = {}
        try:
            result = subprocess.run(
                ["hcitool", "dev"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                match = re.match(r"\s+(\S+)\s+([0-9A-Fa-f:]{17})", line)
                if match:
                    info["name"] = match.group(1)
                    info["address"] = match.group(2)
        except FileNotFoundError:
            pass

        try:
            result = subprocess.run(
                ["hciconfig", "hci0"],
                capture_output=True, text=True, timeout=5,
            )
            info["raw_config"] = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return info

    def reset_adapter(self) -> bool:
        """Reset the Bluetooth adapter.

        Returns:
            True if successful.
        """
        try:
            subprocess.run(
                ["hciconfig", "hci0", "reset"],
                capture_output=True, text=True, timeout=10,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return False
