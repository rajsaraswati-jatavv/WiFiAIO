"""DNSServer – DNS redirect and query logging using dnsmasq.

Wraps dnsmasq in DNS-only mode (no DHCP) to redirect all queries to
the AP IP and optionally log every query for analysis.
"""

import os
import re
import subprocess
import time
from typing import Dict, List, Optional

from wifi_aio.exceptions import (
    WiFiPermissionError,
    WiFiTimeoutError,
)
from wifi_aio.logger import get_logger

logger = get_logger("rogue.dns_server")


class DNSServer:
    """DNS redirect and query-logging server powered by dnsmasq.

    Parameters
    ----------
    interface:
        Interface to listen on.
    listen_ip:
        IP address dnsmasq should bind to.
    redirect_ip:
        IP address to resolve **all** DNS queries to.
    upstream_dns:
        Optional upstream DNS server for non-redirected queries.
    log_queries:
        Whether to enable dnsmasq query logging.
    config_dir:
        Directory for configuration and log files.
    dnsmasq_bin:
        Path to the ``dnsmasq`` binary.
    """

    def __init__(
        self,
        interface: str = "wlan0",
        listen_ip: str = "10.0.0.1",
        redirect_ip: str = "10.0.0.1",
        upstream_dns: Optional[str] = None,
        log_queries: bool = True,
        config_dir: str = "/tmp/wifiaio/rogue",
        dnsmasq_bin: str = "dnsmasq",
    ) -> None:
        self.interface = interface
        self.listen_ip = listen_ip
        self.redirect_ip = redirect_ip
        self.upstream_dns = upstream_dns
        self.log_queries = log_queries
        self.config_dir = config_dir
        self.dnsmasq_bin = dnsmasq_bin
        self._process: Optional[subprocess.Popen] = None
        self._config_path: Optional[str] = None
        self._log_path: str = os.path.join(config_dir, "dns_queries.log")

    # ── Config generation ──────────────────────────────────────────────

    def generate_config(self) -> str:
        """Generate a dnsmasq config for DNS-only mode with redirection.

        The directive ``address=/#/<redirect_ip>`` causes all DNS lookups
        to resolve to *redirect_ip*, which is typically the AP's own IP
        for captive-portal redirection.

        Returns the path to the written configuration file.
        """
        lines: List[str] = [
            f"interface={self.interface}",
            f"listen-address={self.listen_ip}",
            "bind-interfaces",
            "port=53",
            "no-dhcp-interface=",  # disable DHCP in this instance
            f"address=/#/{self.redirect_ip}",  # redirect all domains
        ]

        if self.upstream_dns:
            lines.append(f"server={self.upstream_dns}")

        if self.log_queries:
            lines.append("log-queries")
            lines.append(f"log-facility={self._log_path}")

        os.makedirs(self.config_dir, exist_ok=True)
        config_path = os.path.join(self.config_dir, "dns_dnsmasq.conf")
        with open(config_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

        self._config_path = config_path
        logger.debug("Wrote DNS dnsmasq config to %s", config_path)
        return config_path

    # ── Process management ─────────────────────────────────────────────

    def start(self, timeout: float = 5.0) -> None:
        """Start the DNS server.

        Raises
        ------
        WiFiPermissionError
            If not running as root.
        """
        if os.geteuid() != 0:
            raise WiFiPermissionError("dnsmasq requires root privileges")

        if self._config_path is None:
            self.generate_config()

        if self.is_running():
            logger.warning("DNS server already running (pid %s)", self._process.pid)
            return

        cmd = [self.dnsmasq_bin, "-C", self._config_path, "--no-daemon"]
        logger.info("Starting DNS server: %s", " ".join(cmd))

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise WiFiPermissionError(
                f"dnsmasq binary not found: {self.dnsmasq_bin}"
            ) from exc

        time.sleep(0.5)
        if self._process.poll() is not None:
            stderr = self._process.stderr.read() if self._process.stderr else ""
            raise WiFiPermissionError(f"dnsmasq DNS exited immediately: {stderr.strip()}")

        logger.info("DNS server started (pid %d)", self._process.pid)

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the DNS server."""
        if self._process is None or self._process.poll() is not None:
            logger.debug("DNS server not running")
            self._process = None
            return

        pid = self._process.pid
        logger.info("Stopping DNS server (pid %d)", pid)
        self._process.terminate()

        try:
            self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=2)

        logger.info("DNS server stopped (pid %d)", pid)
        self._process = None

    def is_running(self) -> bool:
        """Return ``True`` if the DNS server process is alive."""
        return self._process is not None and self._process.poll() is None

    def status(self) -> Dict[str, object]:
        """Return a status dictionary for the DNS server."""
        return {
            "running": self.is_running(),
            "pid": self._process.pid if self.is_running() else None,
            "listen_ip": self.listen_ip,
            "redirect_ip": self.redirect_ip,
            "config_path": self._config_path,
        }

    # ── Query log parsing ──────────────────────────────────────────────

    def get_query_log(self) -> List[Dict[str, str]]:
        """Parse the DNS query log and return a list of recorded queries.

        Each entry has keys: ``timestamp``, ``type``, ``domain``,
        ``result``.
        """
        if not os.path.isfile(self._log_path):
            return []

        queries: List[Dict[str, str]] = []
        # dnsmasq log line example:
        # dnsmasq[1234]: query[A] example.com from 10.0.0.15
        pattern = re.compile(
            r"dnsmasq\[\d+\]:\s+(query|forwarded|cached|reply)\[(\w+)\]\s+(\S+)\s+from\s+(\S+)"
        )

        with open(self._log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                match = pattern.search(line)
                if match:
                    queries.append({
                        "action": match.group(1),
                        "type": match.group(2),
                        "domain": match.group(3),
                        "source": match.group(4),
                    })
        return queries

    def clear_query_log(self) -> None:
        """Truncate the DNS query log file."""
        if os.path.isfile(self._log_path):
            with open(self._log_path, "w", encoding="utf-8") as fh:
                fh.truncate(0)
            logger.debug("DNS query log cleared")
