"""ClientMonitor – track connected clients via DHCP leases and ARP.

Monitors which stations are associated with the rogue AP by reading
DHCP lease files and the kernel ARP table.
"""

import os
import re
import subprocess
import threading
import time
from typing import Dict, List, Optional

from wifi_aio.exceptions import WiFiPermissionError, WiFiTimeoutError
from wifi_aio.logger import get_logger

logger = get_logger("rogue.client_monitor")


class ClientInfo:
    """Data class representing a connected client.

    Attributes
    ----------
    mac:
        Client MAC address.
    ip:
        Assigned IP address (may be empty before DHCP lease).
    hostname:
        Hostname reported by the client.
    first_seen:
        Epoch timestamp when the client was first detected.
    last_seen:
        Epoch timestamp of the most recent detection.
    lease_time:
        DHCP lease duration string (e.g. ``"12h"``).
    """

    __slots__ = ("mac", "ip", "hostname", "first_seen", "last_seen", "lease_time")

    def __init__(self, mac: str, ip: str = "", hostname: str = "") -> None:
        self.mac = mac
        self.ip = ip
        self.hostname = hostname
        self.first_seen: float = time.time()
        self.last_seen: float = self.first_seen
        self.lease_time: str = ""

    def to_dict(self) -> Dict[str, object]:
        """Serialise to a plain dictionary."""
        return {
            "mac": self.mac,
            "ip": self.ip,
            "hostname": self.hostname,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "lease_time": self.lease_time,
        }


class ClientMonitor:
    """Track clients connected to the rogue AP.

    Combines data from the dnsmasq lease file and the kernel ARP table
    to maintain a real-time view of associated stations.

    Parameters
    ----------
    interface:
        The AP interface name.
    lease_file:
        Path to the dnsmasq lease file.
    ap_ip:
        IP address of the AP (used to filter ARP entries).
    poll_interval:
        Seconds between automatic refresh cycles when using ``start()``.
    """

    def __init__(
        self,
        interface: str = "wlan0",
        lease_file: str = "/tmp/wifiaio/rogue/dnsmasq.leases",
        ap_ip: str = "10.0.0.1",
        poll_interval: float = 5.0,
    ) -> None:
        self.interface = interface
        self.lease_file = lease_file
        self.ap_ip = ap_ip
        self.poll_interval = poll_interval
        self._clients: Dict[str, ClientInfo] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── One-shot data collection ───────────────────────────────────────

    def refresh(self) -> List[ClientInfo]:
        """Refresh the client list from DHCP leases and ARP, then return it."""
        self._read_leases()
        self._read_arp()
        return self.get_clients()

    def _read_leases(self) -> None:
        """Parse the dnsmasq lease file and update the client list.

        Lease file format (per dnsmasq man page):
        ``<timestamp> <mac> <ip> <hostname> <client_id>``
        """
        if not os.path.isfile(self.lease_file):
            return

        with self._lock:
            with open(self.lease_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) < 4:
                        continue
                    _timestamp, mac, ip, hostname = parts[0], parts[1], parts[2], parts[3]
                    mac_lower = mac.lower()
                    now = time.time()

                    if mac_lower in self._clients:
                        client = self._clients[mac_lower]
                        client.ip = ip
                        client.hostname = hostname if hostname != "*" else client.hostname
                        client.last_seen = now
                    else:
                        client = ClientInfo(mac_lower, ip, hostname if hostname != "*" else "")
                        client.first_seen = now
                        client.last_seen = now
                        self._clients[mac_lower] = client

    def _read_arp(self) -> None:
        """Read the kernel ARP table (``ip neigh``) and update clients.

        Only entries on the same subnet as the AP IP are considered.
        """
        try:
            result = subprocess.run(
                ["ip", "neigh", "show", "dev", self.interface],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("Could not read ARP table for %s", self.interface)
            return

        now = time.time()
        # Parse lines like: 10.0.0.15 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        arp_pattern = re.compile(r"(\S+)\s+lladdr\s+(\S+)")

        with self._lock:
            for line in result.stdout.splitlines():
                match = arp_pattern.search(line)
                if not match:
                    continue
                ip, mac = match.group(1), match.group(2).lower()

                if mac in self._clients:
                    self._clients[mac].ip = ip
                    self._clients[mac].last_seen = now
                else:
                    # Seen in ARP but not in DHCP – might be a static-IP client
                    client = ClientInfo(mac, ip)
                    client.last_seen = now
                    self._clients[mac] = client

    # ── Continuous monitoring ──────────────────────────────────────────

    def start(self) -> None:
        """Start a background thread that periodically refreshes the client list."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("ClientMonitor already running")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="client-monitor")
        self._thread.start()
        logger.info("ClientMonitor started (interval %.1fs)", self.poll_interval)

    def stop(self) -> None:
        """Stop the background monitoring thread."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None
        logger.info("ClientMonitor stopped")

    def is_running(self) -> bool:
        """Return ``True`` if the monitor thread is active."""
        return self._thread is not None and self._thread.is_alive()

    def _monitor_loop(self) -> None:
        """Background loop that calls :meth:`refresh` at the configured interval."""
        while not self._stop_event.is_set():
            try:
                self.refresh()
            except Exception as exc:
                logger.error("ClientMonitor refresh error: %s", exc)
            self._stop_event.wait(self.poll_interval)

    # ── Queries ────────────────────────────────────────────────────────

    def get_clients(self) -> List[ClientInfo]:
        """Return a snapshot of all known clients."""
        with self._lock:
            return list(self._clients.values())

    def get_client(self, mac: str) -> Optional[ClientInfo]:
        """Look up a client by MAC address."""
        with self._lock:
            return self._clients.get(mac.lower())

    def client_count(self) -> int:
        """Return the number of known clients."""
        with self._lock:
            return len(self._clients)

    def remove_stale(self, max_age: float = 3600.0) -> int:
        """Remove clients not seen for more than *max_age* seconds.

        Returns the number of removed entries.
        """
        now = time.time()
        stale_macs: List[str] = []
        with self._lock:
            for mac, client in self._clients.items():
                if now - client.last_seen > max_age:
                    stale_macs.append(mac)
            for mac in stale_macs:
                del self._clients[mac]
        if stale_macs:
            logger.info("Removed %d stale clients", len(stale_macs))
        return len(stale_macs)

    def clear(self) -> None:
        """Remove all client records."""
        with self._lock:
            self._clients.clear()

    def status(self) -> Dict[str, object]:
        """Return a status summary."""
        return {
            "running": self.is_running(),
            "client_count": self.client_count(),
            "interface": self.interface,
            "lease_file": self.lease_file,
        }

    def to_dict_list(self) -> List[Dict[str, object]]:
        """Return all clients as a list of plain dictionaries."""
        return [c.to_dict() for c in self.get_clients()]
