"""MAC address spoofing wrapper for macchanger.

Provides a Python API for viewing and changing MAC addresses
on network interfaces using the macchanger tool.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Optional

from wifi_aio.exceptions import (
    InterfaceError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


@dataclass
class MACInfo:
    """MAC address information for an interface.

    Attributes:
        interface: Network interface name.
        permanent_mac: Hardware (permanent) MAC address.
        current_mac: Current (possibly spoofed) MAC address.
        vendor: OUI vendor string.
    """

    interface: str = ""
    permanent_mac: str = ""
    current_mac: str = ""
    vendor: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "interface": self.interface,
            "permanent_mac": self.permanent_mac,
            "current_mac": self.current_mac,
            "vendor": self.vendor,
        }

    @property
    def is_spoofed(self) -> bool:
        """Return True if the current MAC differs from the permanent one."""
        return self.current_mac.lower() != self.permanent_mac.lower()


class MacchangerWrapper:
    """MAC address spoofing with macchanger.

    Supports viewing, randomising, and setting specific MAC addresses.

    Example::

        mc = MacchangerWrapper()
        info = mc.show("wlan0")
        print(f"Current: {info.current_mac}, Permanent: {info.permanent_mac}")

        mc.randomize("wlan0")
        mc.set_mac("wlan0", "AA:BB:CC:DD:EE:FF")
        mc.reset("wlan0")
    """

    def __init__(
        self,
        macchanger_path: str = "macchanger",
        timeout: int = 15,
    ) -> None:
        self.macchanger_path = macchanger_path
        self.timeout = timeout

    def _check_root(self) -> None:
        if os.geteuid() != 0:
            raise WiFiPermissionError("MAC address changes require root privileges")

    def _run(self, args: list[str]) -> str:
        """Run macchanger with the given arguments and return stdout."""
        cmd = [self.macchanger_path] + args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout,
            )
            return result.stdout + result.stderr
        except FileNotFoundError:
            raise InterfaceError("macchanger not found. Install macchanger.")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("macchanger timed out")

    @staticmethod
    def _set_interface_state(interface: str, up: bool) -> None:
        """Bring an interface up or down."""
        state = "up" if up else "down"
        try:
            subprocess.run(
                ["ip", "link", "set", interface, state],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"Timeout setting {interface} {state}")

    # ── Operations ─────────────────────────────────────────────────────

    def show(self, interface: str) -> MACInfo:
        """Show MAC address information for an interface.

        Args:
            interface: Network interface name.

        Returns:
            MACInfo with current and permanent MAC addresses.
        """
        output = self._run(["-s", interface])

        permanent_mac = ""
        current_mac = ""
        vendor = ""

        # Parse output
        perm_match = re.search(r"Permanent MAC:\s+([0-9a-fA-F:]+)", output)
        if perm_match:
            permanent_mac = perm_match.group(1).lower()

        curr_match = re.search(r"Current MAC:\s+([0-9a-fA-F:]+)", output)
        if curr_match:
            current_mac = curr_match.group(1).lower()

        vendor_match = re.search(r"\(.*?\)", output)
        if vendor_match:
            vendor = vendor_match.group(0).strip("()")

        return MACInfo(
            interface=interface,
            permanent_mac=permanent_mac,
            current_mac=current_mac,
            vendor=vendor,
        )

    def randomize(self, interface: str) -> MACInfo:
        """Randomize the MAC address of an interface.

        The interface is briefly brought down and back up.

        Args:
            interface: Network interface name.

        Returns:
            Updated MACInfo.
        """
        self._check_root()
        self._set_interface_state(interface, up=False)

        try:
            output = self._run(["-r", interface])
            logger.info("Randomized MAC on %s", interface)
        finally:
            self._set_interface_state(interface, up=True)

        return self.show(interface)

    def set_mac(self, interface: str, mac: str) -> MACInfo:
        """Set a specific MAC address on an interface.

        Args:
            interface: Network interface name.
            mac: MAC address to set (e.g. ``"AA:BB:CC:DD:EE:FF"``).

        Returns:
            Updated MACInfo.

        Raises:
            InterfaceError: If the MAC format is invalid.
        """
        self._check_root()

        # Validate MAC format
        if not re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac):
            raise InterfaceError(f"Invalid MAC address format: {mac}")

        # Ensure unicast (second char must be even)
        first_octet = int(mac[0:2], 16)
        if first_octet & 0x01:
            logger.warning(
                "MAC %s is multicast; setting least-significant bit to 0", mac,
            )
            first_octet &= 0xFE
            mac = f"{first_octet:02X}{mac[2:]}"

        self._set_interface_state(interface, up=False)
        try:
            self._run(["-m", mac, interface])
            logger.info("Set MAC on %s to %s", interface, mac)
        finally:
            self._set_interface_state(interface, up=True)

        return self.show(interface)

    def reset(self, interface: str) -> MACInfo:
        """Reset the MAC address to the permanent (hardware) address.

        Args:
            interface: Network interface name.

        Returns:
            Updated MACInfo.
        """
        self._check_root()
        self._set_interface_state(interface, up=False)
        try:
            self._run(["-p", interface])
            logger.info("Reset MAC on %s to permanent", interface)
        finally:
            self._set_interface_state(interface, up=True)

        return self.show(interface)

    def set_vendor_mac(self, interface: str, vendor_prefix: str) -> MACInfo:
        """Set a MAC address with a specific OUI vendor prefix.

        The last three octets are randomised.

        Args:
            interface: Network interface name.
            vendor_prefix: OUI prefix (e.g. ``"AA:BB:CC"``).

        Returns:
            Updated MACInfo.
        """
        import random

        if not re.match(r"^([0-9a-fA-F]{2}:){2}[0-9a-fA-F]{2}$", vendor_prefix):
            raise InterfaceError(f"Invalid vendor prefix: {vendor_prefix}")

        suffix = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
        mac = f"{vendor_prefix}:{suffix}"

        return self.set_mac(interface, mac)

    def list_available_vendors(self) -> list[str]:
        """List available vendor OUI prefixes from macchanger's built-in list.

        Returns:
            List of vendor prefix strings.
        """
        output = self._run(["-l"])
        vendors: list[str] = []
        for line in output.splitlines():
            line = line.strip()
            if re.match(r"^([0-9a-fA-F]{2}:){2}[0-9a-fA-F]{2}", line):
                parts = line.split(None, 1)
                vendors.append(parts[0] if parts else line)
        return vendors

    def __repr__(self) -> str:
        return f"MacchangerWrapper(path={self.macchanger_path!r})"
