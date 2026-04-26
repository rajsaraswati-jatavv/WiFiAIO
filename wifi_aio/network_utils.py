"""WiFiAIO network interface utilities.

Functions for querying and controlling wireless network interfaces:
listing interfaces, switching between monitor / managed mode, channel
hopping and reading the current channel.
"""

import logging
import os
import re
import subprocess
import time
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import InterfaceError, MonitorModeError, WiFiPermissionError, WiFiTimeoutError
from wifi_aio.utils import run_command

logger = logging.getLogger(__name__)


# ── Interface discovery ──────────────────────────────────────────────

def get_interfaces(wireless_only: bool = True) -> List[Dict[str, str]]:
    """Return a list of network interface info dicts.

    Each dict has keys ``name``, ``type``, ``state``, ``driver``.

    Parameters
    ----------
    wireless_only:
        If ``True`` (default), only 802.11 interfaces are returned.
    """
    interfaces: List[Dict[str, str]] = []

    # Strategy 1: /sys/class/net (always available on Linux)
    net_dir = "/sys/class/net"
    if os.path.isdir(net_dir):
        for iface_name in sorted(os.listdir(net_dir)):
            iface_path = os.path.join(net_dir, iface_name)
            if not os.path.isdir(iface_path):
                continue

            is_wireless = os.path.isdir(os.path.join(iface_path, "wireless"))
            if wireless_only and not is_wireless:
                continue

            info: Dict[str, str] = {
                "name": iface_name,
                "type": "wireless" if is_wireless else "wired",
                "state": _read_sysfs(iface_path, "operstate"),
                "driver": _get_driver(iface_name),
            }

            # Check if in monitor mode
            mode_path = os.path.join(iface_path, "device", "mode")
            type_path = os.path.join(iface_path, "type")
            if is_wireless:
                info["mode"] = _detect_mode(iface_name)

            interfaces.append(info)

    # Strategy 2: iwconfig fallback
    if not interfaces:
        try:
            rc, out, err = run_command(["iwconfig"], timeout=10)
            if rc == 0:
                for match in re.finditer(
                    r"^(\S+)\s+.*?(?:ESSID|IEEE\s*802\.11)", out, re.MULTILINE | re.DOTALL
                ):
                    name = match.group(1)
                    interfaces.append({
                        "name": name,
                        "type": "wireless",
                        "state": "unknown",
                        "driver": _get_driver(name),
                        "mode": _detect_mode(name),
                    })
        except Exception:
            pass

    # Strategy 3: ip link fallback (at least list names)
    if not interfaces:
        try:
            rc, out, err = run_command(["ip", "-o", "link", "show"], timeout=10)
            if rc == 0:
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[1].rstrip(":")
                        if name == "lo":
                            continue
                        interfaces.append({
                            "name": name,
                            "type": "unknown",
                            "state": parts.get(parts.index("state") + 1) if "state" in parts else "unknown",
                            "driver": "",
                        })
        except Exception:
            pass

    return interfaces


def _read_sysfs(iface_path: str, attr: str) -> str:
    """Read a single-line sysfs attribute."""
    path = os.path.join(iface_path, attr)
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return "unknown"


def _get_driver(iface_name: str) -> str:
    """Determine the kernel driver for *iface_name*."""
    driver_link = f"/sys/class/net/{iface_name}/device/driver"
    try:
        target = os.path.realpath(driver_link)
        return os.path.basename(target)
    except OSError:
        return "unknown"


def _detect_mode(iface_name: str) -> str:
    """Detect whether an interface is in monitor or managed mode."""
    # Check via iw
    try:
        rc, out, err = run_command(["iw", "dev", iface_name, "info"], timeout=5)
        if rc == 0:
            for line in out.splitlines():
                if "type" in line.lower() and "monitor" in line.lower():
                    return "monitor"
            return "managed"
    except Exception:
        pass

    # Check via /sys/class/net/<iface>/type (803 = monitor)
    type_path = f"/sys/class/net/{iface_name}/type"
    try:
        with open(type_path, "r") as fh:
            if fh.read().strip() == "803":
                return "monitor"
    except OSError:
        pass

    # Check via iwconfig
    try:
        rc, out, err = run_command(["iwconfig", iface_name], timeout=5)
        if rc == 0 and "Mode:Monitor" in out:
            return "monitor"
    except Exception:
        pass

    return "managed"


# ── Monitor / managed mode ───────────────────────────────────────────

def set_monitor_mode(interface: str) -> None:
    """Switch *interface* to monitor mode.

    Raises :class:`MonitorModeError` on failure and
    :class:`WiFiPermissionError` if not running as root.
    """
    if os.geteuid() != 0:
        raise WiFiPermissionError("Root privileges required to set monitor mode")

    logger.info("Setting %s to monitor mode", interface)

    # Method 1: ip link + iw
    try:
        run_command(["ip", "link", "set", interface, "down"], timeout=10, sudo=True)
        run_command(["iw", "dev", interface, "set", "type", "monitor"], timeout=10, sudo=True)
        run_command(["ip", "link", "set", interface, "up"], timeout=10, sudo=True)
    except Exception as exc:
        logger.debug("iw method failed (%s), trying airmon-ng", exc)
        # Method 2: airmon-ng
        try:
            run_command(["airmon-ng", "start", interface], timeout=30, sudo=True)
        except Exception as airmon_exc:
            raise MonitorModeError(
                f"Cannot set {interface} to monitor mode: {exc} / {airmon_exc}"
            ) from airmon_exc

    # Verify
    if _detect_mode(interface) != "monitor":
        raise MonitorModeError(f"{interface} did not switch to monitor mode")

    logger.info("%s is now in monitor mode", interface)


def set_managed_mode(interface: str) -> None:
    """Switch *interface* back to managed (station) mode.

    Raises :class:`MonitorModeError` on failure.
    """
    if os.geteuid() != 0:
        raise WiFiPermissionError("Root privileges required to set managed mode")

    logger.info("Setting %s to managed mode", interface)

    # Kill any monitor-mode processes first
    try:
        run_command(["airmon-ng", "stop", interface], timeout=30, sudo=True)
    except Exception:
        pass

    try:
        run_command(["ip", "link", "set", interface, "down"], timeout=10, sudo=True)
        run_command(["iw", "dev", interface, "set", "type", "managed"], timeout=10, sudo=True)
        run_command(["ip", "link", "set", interface, "up"], timeout=10, sudo=True)
    except Exception as exc:
        raise MonitorModeError(
            f"Cannot set {interface} to managed mode: {exc}"
        ) from exc

    if _detect_mode(interface) != "managed":
        logger.warning("%s may not have fully switched to managed mode", interface)

    logger.info("%s is now in managed mode", interface)


# ── Channel control ─────────────────────────────────────────────────

def set_channel(interface: str, channel: int) -> None:
    """Set *interface* to a specific *channel*.

    Requires the interface to be in monitor mode.
    """
    logger.debug("Setting %s to channel %d", interface, channel)
    try:
        run_command(
            ["iw", "dev", interface, "set", "channel", str(channel)],
            timeout=10,
            sudo=True,
        )
    except Exception as exc:
        raise InterfaceError(f"Cannot set channel {channel} on {interface}: {exc}") from exc


def channel_hop(
    interface: str,
    channels: Optional[List[int]] = None,
    delay: float = 0.5,
    count: int = 1,
) -> None:
    """Hop through WiFi channels on *interface*.

    Parameters
    ----------
    interface:
        Monitor-mode interface.
    channels:
        List of channel numbers.  Defaults to 2.4 GHz channels 1–11.
    delay:
        Seconds to wait on each channel.
    count:
        Number of full cycles (0 = infinite until interrupted).
    """
    if channels is None:
        channels = list(range(1, 12))

    cycle = 0
    while count == 0 or cycle < count:
        for ch in channels:
            try:
                set_channel(interface, ch)
            except InterfaceError:
                pass
            time.sleep(delay)
        cycle += 1


def get_current_channel(interface: str) -> int:
    """Return the current channel of *interface*, or 0 on failure."""
    try:
        rc, out, err = run_command(["iw", "dev", interface, "info"], timeout=5)
        if rc == 0:
            for line in out.splitlines():
                if "channel" in line.lower():
                    # e.g. "channel 6 (2437 MHz)"
                    match = re.search(r"channel\s+(\d+)", line)
                    if match:
                        return int(match.group(1))
    except Exception:
        pass

    # Fallback: /sys/class/net/<iface>/channel (not standard, but some drivers)
    try:
        with open(f"/sys/class/net/{interface}/channel", "r") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        pass

    return 0
