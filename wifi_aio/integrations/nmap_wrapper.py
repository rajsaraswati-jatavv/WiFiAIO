"""Nmap wrapper for network scanning and service enumeration.

Provides a Python API for nmap with common scan profiles,
output parsing, and structured results.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Optional

from wifi_aio.exceptions import (
    AutomationError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


@dataclass
class NmapPort:
    """A single port result from an nmap scan."""

    port: int = 0
    protocol: str = ""
    state: str = ""
    service: str = ""
    version: str = ""
    banner: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
        }


@dataclass
class NmapHost:
    """A single host result from an nmap scan."""

    address: str = ""
    hostname: str = ""
    state: str = ""
    ports: list[NmapPort] = field(default_factory=list)
    os_guess: str = ""
    mac: str = ""
    vendor: str = ""
    uptime_seconds: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "hostname": self.hostname,
            "state": self.state,
            "ports": [p.to_dict() for p in self.ports],
            "os_guess": self.os_guess,
            "mac": self.mac,
            "vendor": self.vendor,
        }

    @property
    def open_ports(self) -> list[NmapPort]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class NmapResult:
    """Complete result of an nmap scan."""

    hosts: list[NmapHost] = field(default_factory=list)
    scan_type: str = ""
    elapsed: float = 0.0
    command: str = ""
    raw_output: str = ""
    xml_output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hosts": [h.to_dict() for h in self.hosts],
            "scan_type": self.scan_type,
            "elapsed": self.elapsed,
            "command": self.command,
        }

    @property
    def live_hosts(self) -> list[NmapHost]:
        return [h for h in self.hosts if h.state == "up"]


class NmapWrapper:
    """Network scanning with nmap.

    Supports common scan profiles, custom arguments, and
    structured output parsing from XML.

    Example::

        nmap = NmapWrapper()
        result = nmap.scan("192.168.1.0/24", scan_type="quick")
        for host in result.live_hosts:
            print(f"{host.address} ({host.hostname}): {len(host.open_ports)} ports")
    """

    SCAN_PROFILES: dict[str, list[str]] = {
        "quick": ["-T4", "-F"],
        "intense": ["-T4", "-A", "-v"],
        "intense_udp": ["-sU", "-T4", "-A", "-v"],
        "stealth": ["-sS", "-T3"],
        "comprehensive": ["-sS", "-sU", "-T4", "-A", "-p-", "-v"],
        "vuln": ["--script=vuln", "-T4"],
        "service": ["-sV", "-T4"],
        "os_detect": ["-O", "-T4"],
    }

    def __init__(
        self,
        nmap_path: str = "nmap",
        timeout: int = 300,
        sudo: bool = False,
    ) -> None:
        self.nmap_path = nmap_path
        self.timeout = timeout
        self.sudo = sudo
        self._process: Optional[subprocess.Popen] = None

    def _build_cmd(
        self,
        target: str,
        scan_type: str = "quick",
        ports: Optional[str] = None,
        interface: Optional[str] = None,
        extra_args: Optional[list[str]] = None,
        output_xml: Optional[str] = None,
    ) -> list[str]:
        """Build the nmap command list."""
        cmd = []
        if self.sudo and os.geteuid() != 0:
            cmd.append("sudo")

        cmd.append(self.nmap_path)

        # Add scan profile
        profile = self.SCAN_PROFILES.get(scan_type, [])
        cmd.extend(profile)

        # Additional options
        if ports:
            cmd.extend(["-p", ports])
        if interface:
            cmd.extend(["-e", interface])
        if output_xml:
            cmd.extend(["-oX", output_xml])

        if extra_args:
            cmd.extend(extra_args)

        cmd.append(target)
        return cmd

    def scan(
        self,
        target: str,
        scan_type: str = "quick",
        ports: Optional[str] = None,
        interface: Optional[str] = None,
        extra_args: Optional[list[str]] = None,
        timeout: Optional[int] = None,
    ) -> NmapResult:
        """Run an nmap scan.

        Args:
            target: Target specification (IP, range, CIDR).
            scan_type: Scan profile name (see SCAN_PROFILES).
            ports: Port specification (e.g. ``"1-1000"``, ``"80,443"``).
            interface: Network interface to use.
            extra_args: Additional nmap arguments.
            timeout: Maximum seconds (default: instance timeout).

        Returns:
            NmapResult with parsed hosts and ports.
        """
        import tempfile

        effective_timeout = timeout or self.timeout

        # Use a temp file for XML output
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_file = tmp.name

        cmd = self._build_cmd(
            target, scan_type, ports, interface, extra_args, xml_file,
        )
        cmd_str = " ".join(cmd)
        logger.info("Running nmap: %s", cmd_str)

        start = __import__("time").time()
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=effective_timeout,
            )
            raw_output = result.stdout + result.stderr
        except FileNotFoundError:
            raise AutomationError("nmap not found. Install nmap.")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"nmap scan timed out after {effective_timeout}s")
        finally:
            pass

        elapsed = __import__("time").time() - start

        # Parse XML output
        nmap_result = NmapResult(
            scan_type=scan_type,
            elapsed=elapsed,
            command=cmd_str,
            raw_output=raw_output,
        )

        if os.path.isfile(xml_file):
            try:
                with open(xml_file, "r") as f:
                    nmap_result.xml_output = f.read()
                nmap_result.hosts = self._parse_xml(xml_file)
            except (OSError, ET.ParseError) as exc:
                logger.warning("Failed to parse nmap XML: %s", exc)
                nmap_result.hosts = self._parse_text(raw_output)
            finally:
                try:
                    os.unlink(xml_file)
                except OSError:
                    pass
        else:
            nmap_result.hosts = self._parse_text(raw_output)

        logger.info(
            "nmap scan complete: %d hosts found in %.1fs",
            len(nmap_result.live_hosts), elapsed,
        )
        return nmap_result

    # ── Convenience methods ────────────────────────────────────────────

    def ping_scan(self, target: str) -> NmapResult:
        """Host discovery only (no port scan)."""
        return self.scan(target, extra_args=["-sn"])

    def port_scan(self, target: str, ports: str = "1-1000") -> NmapResult:
        """Port scan with specific port range."""
        return self.scan(target, scan_type="quick", ports=ports)

    def vulnerability_scan(self, target: str) -> NmapResult:
        """Run nmap vulnerability scripts."""
        return self.scan(target, scan_type="vuln")

    def service_scan(self, target: str) -> NmapResult:
        """Service version detection scan."""
        return self.scan(target, scan_type="service")

    def os_scan(self, target: str) -> NmapResult:
        """OS detection scan (requires root/sudo)."""
        return self.scan(target, scan_type="os_detect", extra_args=["-O"])

    # ── Parsing ────────────────────────────────────────────────────────

    @staticmethod
    def _parse_xml(xml_file: str) -> list[NmapHost]:
        """Parse nmap XML output into NmapHost objects."""
        hosts: list[NmapHost] = []
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError:
            return hosts

        for host_elem in root.findall(".//host"):
            host = NmapHost()

            # Status
            status = host_elem.find("status")
            if status is not None:
                host.state = status.get("state", "")

            # Address
            for addr in host_elem.findall("address"):
                addr_type = addr.get("addrtype", "")
                if addr_type == "ipv4":
                    host.address = addr.get("addr", "")
                elif addr_type == "mac":
                    host.mac = addr.get("addr", "")
                    host.vendor = addr.get("vendor", "")

            # Hostname
            hostnames = host_elem.find("hostnames")
            if hostnames is not None:
                hostname = hostnames.find("hostname")
                if hostname is not None:
                    host.hostname = hostname.get("name", "")

            # Ports
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port = NmapPort(
                        port=int(port_elem.get("portid", 0)),
                        protocol=port_elem.get("protocol", ""),
                    )
                    state = port_elem.find("state")
                    if state is not None:
                        port.state = state.get("state", "")
                    service = port_elem.find("service")
                    if service is not None:
                        port.service = service.get("name", "")
                        port.version = service.get("version", "")
                        port.banner = service.get("extrainfo", "")
                    host.ports.append(port)

            # OS
            os_elem = host_elem.find("os")
            if os_elem is not None:
                os_match = os_elem.find("osmatch")
                if os_match is not None:
                    host.os_guess = os_match.get("name", "")

            # Uptime
            uptime = host_elem.find("uptime")
            if uptime is not None:
                try:
                    host.uptime_seconds = int(uptime.get("seconds", 0))
                except (ValueError, TypeError):
                    pass

            hosts.append(host)

        return hosts

    @staticmethod
    def _parse_text(output: str) -> list[NmapHost]:
        """Fallback text-mode parsing of nmap output."""
        hosts: list[NmapHost] = []
        current_host: Optional[NmapHost] = None

        for line in output.splitlines():
            line = line.strip()

            # New host line
            host_match = re.match(r"Nmap scan report for\s+(?:\S+\s+\()?([\d.]+)\)?", line)
            if host_match:
                if current_host:
                    hosts.append(current_host)
                current_host = NmapHost(address=host_match.group(1))
                continue

            # Host is up
            if current_host and "Host is up" in line:
                current_host.state = "up"

            # Port line
            if current_host:
                port_match = re.match(r"(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)", line)
                if port_match:
                    current_host.ports.append(NmapPort(
                        port=int(port_match.group(1)),
                        protocol=port_match.group(2),
                        state=port_match.group(3),
                        service=port_match.group(4),
                    ))

        if current_host:
            hosts.append(current_host)

        return hosts

    def __repr__(self) -> str:
        return f"NmapWrapper(path={self.nmap_path!r})"
