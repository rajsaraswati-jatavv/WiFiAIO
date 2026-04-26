"""DHCPServer – dnsmasq-based DHCP server for rogue access points.

Generates a dnsmasq configuration file that provides DHCP leases and
DNS redirection (all queries → AP IP) suitable for captive-portal
setups.
"""

import os
import subprocess
import time
from typing import Dict, List, Optional

from wifi_aio.exceptions import (
    DHCPError,
    WiFiPermissionError,
    WiFiTimeoutError,
)
from wifi_aio.logger import get_logger

logger = get_logger("rogue.dhcp_server")


class DHCPServer:
    """Manage a dnsmasq-based DHCP server for a rogue AP.

    Parameters
    ----------
    interface:
        Network interface to listen on (e.g. ``wlan0``).
    ap_ip:
        IP address assigned to the AP interface.
    subnet_mask:
        Subnet mask for the DHCP range.
    dhcp_range_start:
        Start of the DHCP lease range.
    dhcp_range_end:
        End of the DHCP lease range.
    lease_time:
        DHCP lease duration (e.g. ``"12h"``).
    dns_server:
        Upstream DNS server to forward to; defaults to *ap_ip* so all
        queries are redirected to the local DNS.
    config_dir:
        Directory for generated configuration files.
    dnsmasq_bin:
        Path to the ``dnsmasq`` binary.
    """

    def __init__(
        self,
        interface: str = "wlan0",
        ap_ip: str = "10.0.0.1",
        subnet_mask: str = "255.255.255.0",
        dhcp_range_start: str = "10.0.0.10",
        dhcp_range_end: str = "10.0.0.50",
        lease_time: str = "12h",
        dns_server: Optional[str] = None,
        config_dir: str = "/tmp/wifiaio/rogue",
        dnsmasq_bin: str = "dnsmasq",
    ) -> None:
        self.interface = interface
        self.ap_ip = ap_ip
        self.subnet_mask = subnet_mask
        self.dhcp_range_start = dhcp_range_start
        self.dhcp_range_end = dhcp_range_end
        self.lease_time = lease_time
        self.dns_server = dns_server or ap_ip
        self.config_dir = config_dir
        self.dnsmasq_bin = dnsmasq_bin
        self._process: Optional[subprocess.Popen] = None
        self._config_path: Optional[str] = None

    # ── Config generation ──────────────────────────────────────────────

    def generate_config(self) -> str:
        """Generate a dnsmasq configuration file with DHCP and DNS redirect.

        The key directive ``address=/#/<ap_ip>`` causes dnsmasq to resolve
        **all** DNS queries to the AP's IP address, which is essential for
        captive-portal redirection.

        Returns the path to the written configuration file.
        """
        params: List[str] = [
            f"interface={self.interface}",
            f"listen-address={self.ap_ip}",
            f"bind-interfaces",
            f"dhcp-range={self.dhcp_range_start},{self.dhcp_range_end},{self.subnet_mask},{self.lease_time}",
            f"dhcp-option=3,{self.ap_ip}",          # default gateway
            f"dhcp-option=6,{self.dns_server}",      # DNS server
            f"address=/#/{self.ap_ip}",               # redirect ALL DNS to AP
            f"log-queries",                           # log DNS queries
            f"log-facility={os.path.join(self.config_dir, 'dnsmasq.log')}",
            f"conf-dir={self.config_dir}/dnsmasq.d",  # include extra configs
        ]

        os.makedirs(os.path.join(self.config_dir, "dnsmasq.d"), exist_ok=True)
        config_path = os.path.join(self.config_dir, "dnsmasq.conf")
        with open(config_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(params) + "\n")

        self._config_path = config_path
        logger.debug("Wrote dnsmasq config to %s", config_path)
        return config_path

    # ── Interface configuration ────────────────────────────────────────

    def configure_interface(self) -> None:
        """Assign the AP IP address to the interface and bring it up.

        Requires root privileges.
        """
        if os.geteuid() != 0:
            raise WiFiPermissionError("Configuring network interfaces requires root")

        logger.info("Configuring %s with IP %s", self.interface, self.ap_ip)

        # Flush existing addresses
        subprocess.run(
            ["ip", "addr", "flush", "dev", self.interface],
            capture_output=True,
            text=True,
        )

        # Add new address
        rc, _, stderr = subprocess.run(
            ["ip", "addr", "add", f"{self.ap_ip}/24", "dev", self.interface],
            capture_output=True,
            text=True,
        )
        if rc != 0:
            raise DHCPError(f"Failed to set IP on {self.interface}: {stderr.strip()}")

        # Bring interface up
        subprocess.run(
            ["ip", "link", "set", self.interface, "up"],
            capture_output=True,
            text=True,
        )

        logger.info("Interface %s configured with %s/24", self.interface, self.ap_ip)

    # ── Process management ─────────────────────────────────────────────

    def start(self, timeout: float = 5.0) -> None:
        """Start the dnsmasq DHCP server.

        Generates a configuration file if one has not been generated yet.

        Raises
        ------
        DHCPError
            If dnsmasq fails to start.
        WiFiPermissionError
            If not running as root.
        """
        if os.geteuid() != 0:
            raise WiFiPermissionError("dnsmasq requires root privileges")

        if self._config_path is None:
            self.generate_config()

        if self.is_running():
            logger.warning("dnsmasq already running (pid %s)", self._process.pid)
            return

        cmd = [self.dnsmasq_bin, "-C", self._config_path, "--no-daemon"]
        logger.info("Starting dnsmasq: %s", " ".join(cmd))

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise DHCPError(
                f"dnsmasq binary not found: {self.dnsmasq_bin}"
            ) from exc

        # Brief wait to confirm it stays alive
        time.sleep(0.5)
        if self._process.poll() is not None:
            stderr = self._process.stderr.read() if self._process.stderr else ""
            raise DHCPError(f"dnsmasq exited immediately: {stderr.strip()}")

        logger.info("dnsmasq started (pid %d)", self._process.pid)

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the running dnsmasq process gracefully."""
        if self._process is None or self._process.poll() is not None:
            logger.debug("dnsmasq not running – nothing to stop")
            self._process = None
            return

        pid = self._process.pid
        logger.info("Stopping dnsmasq (pid %d)", pid)
        self._process.terminate()

        try:
            self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.warning("dnsmasq did not terminate – sending SIGKILL")
            self._process.kill()
            self._process.wait(timeout=2)

        logger.info("dnsmasq stopped (pid %d)", pid)
        self._process = None

    def is_running(self) -> bool:
        """Return ``True`` if the dnsmasq process is alive."""
        return self._process is not None and self._process.poll() is None

    def status(self) -> Dict[str, object]:
        """Return a status dictionary for the DHCP server."""
        return {
            "running": self.is_running(),
            "pid": self._process.pid if self.is_running() else None,
            "interface": self.interface,
            "ap_ip": self.ap_ip,
            "dhcp_range": f"{self.dhcp_range_start}-{self.dhcp_range_end}",
            "config_path": self._config_path,
        }

    def get_leases(self) -> List[Dict[str, str]]:
        """Parse the dnsmasq lease file and return active DHCP leases.

        Each entry is a dict with keys: ``timestamp``, ``mac``, ``ip``,
        ``hostname``, ``client_id``.
        """
        lease_file = os.path.join(self.config_dir, "dnsmasq.leases")
        if not os.path.isfile(lease_file):
            return []

        leases: List[Dict[str, str]] = []
        with open(lease_file, "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.strip().split()
                if len(parts) >= 5:
                    leases.append({
                        "timestamp": parts[0],
                        "mac": parts[1],
                        "ip": parts[2],
                        "hostname": parts[3],
                        "client_id": parts[4],
                    })
        return leases
