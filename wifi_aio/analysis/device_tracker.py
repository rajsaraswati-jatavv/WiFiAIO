"""DeviceTracker – track devices by MAC, probe requests, and association changes.

Maintains a registry of discovered wireless devices, tracking their
probe requests, signal strengths, and association/disassociation events
over time.
"""

import time
from collections import defaultdict
from typing import Dict, List, Optional, Set

from wifi_aio.exceptions import WiFiConnectionError
from wifi_aio.logger import get_logger

logger = get_logger("analysis.device_tracker")


class DeviceRecord:
    """Represents a single tracked wireless device.

    Attributes
    ----------
    mac:
        Device MAC address.
    first_seen:
        Epoch timestamp of first detection.
    last_seen:
        Epoch timestamp of most recent detection.
    probe_ssids:
        Set of SSIDs the device has probed for.
    signal_history:
        List of (timestamp, signal_dbm) tuples.
    associated_bssid:
        BSSID the device is currently associated with (empty if none).
    association_history:
        List of (timestamp, bssid, event) association events.
    oui:
        Organizationally Unique Identifier (vendor) derived from MAC.
    """

    __slots__ = (
        "mac", "first_seen", "last_seen", "probe_ssids",
        "signal_history", "associated_bssid", "association_history", "oui",
    )

    def __init__(self, mac: str) -> None:
        self.mac = mac
        self.first_seen: float = time.time()
        self.last_seen: float = self.first_seen
        self.probe_ssids: Set[str] = set()
        self.signal_history: List[tuple] = []
        self.associated_bssid: str = ""
        self.association_history: List[tuple] = []
        self.oui: str = self._derive_oui()

    def _derive_oui(self) -> str:
        """Derive the OUI (first 3 octets) from the MAC address."""
        parts = self.mac.replace(":", "-").lower().split("-")
        if len(parts) >= 3:
            return ":".join(parts[:3]).upper()
        return ""

    def to_dict(self) -> Dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "mac": self.mac,
            "oui": self.oui,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "probe_ssids": sorted(self.probe_ssids),
            "signal_count": len(self.signal_history),
            "latest_signal": self.signal_history[-1][1] if self.signal_history else None,
            "associated_bssid": self.associated_bssid,
            "association_count": len(self.association_history),
        }


class DeviceTracker:
    """Track wireless devices across scans and captures.

    Parameters
    ----------
    max_signal_history:
        Maximum number of signal-strength samples kept per device.
    stale_timeout:
        Seconds after which a device not seen is considered stale.
    """

    def __init__(
        self,
        max_signal_history: int = 1000,
        stale_timeout: float = 600.0,
    ) -> None:
        self.max_signal_history = max_signal_history
        self.stale_timeout = stale_timeout
        self._devices: Dict[str, DeviceRecord] = {}

    # ── Device registration ────────────────────────────────────────────

    def register_probe(
        self,
        mac: str,
        ssid: str = "",
        signal_dbm: Optional[int] = None,
    ) -> DeviceRecord:
        """Register a probe request from a device.

        Parameters
        ----------
        mac:
            Source MAC of the probe request.
        ssid:
            SSID being probed (empty for broadcast probe).
        signal_dbm:
            Signal strength of the probe frame.

        Returns the updated :class:`DeviceRecord`.
        """
        mac = mac.lower()
        now = time.time()
        device = self._get_or_create(mac)

        device.last_seen = now
        if ssid:
            device.probe_ssids.add(ssid)
        if signal_dbm is not None:
            device.signal_history.append((now, signal_dbm))
            self._trim_signal_history(device)

        return device

    def register_association(
        self,
        mac: str,
        bssid: str,
        signal_dbm: Optional[int] = None,
    ) -> DeviceRecord:
        """Register an association event.

        Parameters
        ----------
        mac:
            Device MAC address.
        bssid:
            BSSID of the AP the device associated with.
        signal_dbm:
            Signal strength at association time.
        """
        mac = mac.lower()
        bssid = bssid.lower()
        now = time.time()
        device = self._get_or_create(mac)

        device.last_seen = now
        device.associated_bssid = bssid
        device.association_history.append((now, bssid, "associate"))
        if signal_dbm is not None:
            device.signal_history.append((now, signal_dbm))
            self._trim_signal_history(device)

        return device

    def register_disassociation(
        self,
        mac: str,
        bssid: str = "",
    ) -> DeviceRecord:
        """Register a disassociation event."""
        mac = mac.lower()
        now = time.time()
        device = self._get_or_create(mac)

        device.last_seen = now
        device.associated_bssid = ""
        device.association_history.append((now, bssid.lower(), "disassociate"))

        return device

    def register_signal(self, mac: str, signal_dbm: int) -> DeviceRecord:
        """Record a signal-strength observation for a device."""
        mac = mac.lower()
        now = time.time()
        device = self._get_or_create(mac)
        device.last_seen = now
        device.signal_history.append((now, signal_dbm))
        self._trim_signal_history(device)
        return device

    # ── Queries ────────────────────────────────────────────────────────

    def get_device(self, mac: str) -> Optional[DeviceRecord]:
        """Look up a device by MAC address."""
        return self._devices.get(mac.lower())

    def get_all_devices(self) -> List[DeviceRecord]:
        """Return all tracked devices."""
        return list(self._devices.values())

    def get_active_devices(self) -> List[DeviceRecord]:
        """Return devices seen within the stale timeout."""
        cutoff = time.time() - self.stale_timeout
        return [d for d in self._devices.values() if d.last_seen >= cutoff]

    def get_stale_devices(self) -> List[DeviceRecord]:
        """Return devices not seen for longer than the stale timeout."""
        cutoff = time.time() - self.stale_timeout
        return [d for d in self._devices.values() if d.last_seen < cutoff]

    def get_devices_by_ssid(self, ssid: str) -> List[DeviceRecord]:
        """Return all devices that have probed for the given SSID."""
        return [d for d in self._devices.values() if ssid in d.probe_ssids]

    def get_devices_by_bssid(self, bssid: str) -> List[DeviceRecord]:
        """Return devices currently associated with the given BSSID."""
        bssid = bssid.lower()
        return [d for d in self._devices.values() if d.associated_bssid == bssid]

    def get_probe_map(self) -> Dict[str, List[str]]:
        """Return a mapping of SSID → list of MACs that probed for it."""
        mapping: Dict[str, List[str]] = defaultdict(list)
        for device in self._devices.values():
            for ssid in device.probe_ssids:
                mapping[ssid].append(device.mac)
        return dict(mapping)

    def device_count(self) -> int:
        """Total number of tracked devices."""
        return len(self._devices)

    def active_count(self) -> int:
        """Number of devices seen within the stale timeout."""
        return len(self.get_active_devices())

    # ── Maintenance ────────────────────────────────────────────────────

    def remove_stale(self) -> int:
        """Remove devices that have exceeded the stale timeout.

        Returns the number of removed devices.
        """
        cutoff = time.time() - self.stale_timeout
        stale_macs = [mac for mac, d in self._devices.items() if d.last_seen < cutoff]
        for mac in stale_macs:
            del self._devices[mac]
        if stale_macs:
            logger.info("Removed %d stale devices", len(stale_macs))
        return len(stale_macs)

    def clear(self) -> None:
        """Remove all device records."""
        self._devices.clear()

    def to_dict_list(self) -> List[Dict[str, object]]:
        """Return all devices as a list of plain dictionaries."""
        return [d.to_dict() for d in self._devices.values()]

    def summary(self) -> Dict[str, object]:
        """Return a summary of the tracked device population."""
        active = self.get_active_devices()
        probed_ssids: Set[str] = set()
        for d in self._devices.values():
            probed_ssids.update(d.probe_ssids)

        return {
            "total_devices": len(self._devices),
            "active_devices": len(active),
            "stale_devices": len(self._devices) - len(active),
            "unique_probed_ssids": len(probed_ssids),
            "probed_ssids": sorted(probed_ssids),
        }

    # ── Internals ──────────────────────────────────────────────────────

    def _get_or_create(self, mac: str) -> DeviceRecord:
        """Return an existing device or create a new one."""
        if mac not in self._devices:
            self._devices[mac] = DeviceRecord(mac)
        return self._devices[mac]

    def _trim_signal_history(self, device: DeviceRecord) -> None:
        """Trim signal history to max_signal_history entries."""
        if len(device.signal_history) > self.max_signal_history:
            device.signal_history = device.signal_history[-self.max_signal_history:]
