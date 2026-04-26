"""
WiFiAIO Network Scanner Module

Provides active and passive WiFi network scanning capabilities using
iw, airodump-ng, and direct interface manipulation.
"""

import os
import re
import json
import time
import logging
import subprocess
from typing import List, Dict, Optional, Any, Generator
from dataclasses import dataclass, field, asdict
from enum import Enum

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    WiFiScanError,
    WiFiInterfaceError,
)

logger = logging.getLogger(__name__)


class ScanMode(Enum):
    """Scanning mode."""
    ACTIVE = "active"
    PASSIVE = "passive"


class SecurityType(Enum):
    """WiFi security protocol types."""
    OPEN = "OPEN"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    WPA_WPA2 = "WPA/WPA2"
    WPA2_WPA3 = "WPA2/WPA3"


@dataclass
class AccessPoint:
    """Represents a discovered access point."""
    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    frequency: int = 0
    signal_dbm: int = 0
    noise_dbm: int = 0
    security: str = ""
    security_type: SecurityType = SecurityType.OPEN
    cipher: str = ""
    authentication: str = ""
    bandwidth: str = ""
    encryption: str = ""
    beacon_interval: int = 0
    wps: bool = False
    wps_version: str = ""
    wps_locked: bool = False
    first_seen: float = 0.0
    last_seen: float = 0.0
    packets: int = 0
    clients: List[str] = field(default_factory=list)
    vendor: str = ""
    lat: float = 0.0
    lon: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        d = asdict(self)
        d["security_type"] = self.security_type.value
        return d


@dataclass
class ClientStation:
    """Represents a connected client station."""
    mac: str = ""
    bssid: str = ""
    ssid: str = ""
    signal_dbm: int = 0
    channel: int = 0
    packets: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    probed_ssids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class NetworkScanner:
    """
    WiFi network scanner supporting active and passive scanning modes.

    Uses iw and airodump-ng as backends for network discovery.
    """

    def __init__(self, interface: str = "wlan0", scan_mode: ScanMode = ScanMode.ACTIVE):
        """
        Initialize NetworkScanner.

        Args:
            interface: Wireless interface name.
            scan_mode: Active or passive scanning mode.
        """
        self.interface = interface
        self.scan_mode = scan_mode
        self._access_points: Dict[str, AccessPoint] = {}
        self._clients: Dict[str, ClientStation] = {}
        self._scanning = False
        self._airodump_process: Optional[subprocess.Popen] = None
        self._vendor_db: Dict[str, str] = {}
        self._load_vendor_db()

    def _load_vendor_db(self) -> None:
        """Load OUI vendor database from IEEE data."""
        oui_paths = [
            "/usr/share/wireshark/manuf",
            "/usr/share/ieee-data/oui.txt",
            "/etc/manuf",
        ]
        for path in oui_paths:
            if os.path.isfile(path):
                try:
                    with open(path, "r") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            parts = line.split()
                            if len(parts) >= 2:
                                mac_prefix = parts[0].lower().replace(":", "")[:6]
                                vendor = parts[1]
                                self._vendor_db[mac_prefix] = vendor
                    logger.debug("Loaded vendor DB from %s (%d entries)", path, len(self._vendor_db))
                    break
                except OSError as e:
                    logger.warning("Failed to load vendor DB from %s: %s", path, e)

    def _lookup_vendor(self, mac: str) -> str:
        """Look up vendor from MAC address OUI prefix."""
        prefix = mac.replace(":", "").lower()[:6]
        return self._vendor_db.get(prefix, "Unknown")

    def _check_root(self) -> None:
        """Verify running as root for scanning operations."""
        if os.geteuid() != 0:
            raise WiFiPermissionError("Network scanning requires root privileges")

    def _set_interface_mode(self, mode: str) -> None:
        """Set wireless interface mode (managed, monitor, etc.)."""
        try:
            subprocess.run(
                ["ip", "link", "set", self.interface, "down"],
                check=True, capture_output=True, timeout=10
            )
            subprocess.run(
                ["iw", self.interface, "set", "type", mode],
                check=True, capture_output=True, timeout=10
            )
            subprocess.run(
                ["ip", "link", "set", self.interface, "up"],
                check=True, capture_output=True, timeout=10
            )
            logger.info("Set interface %s to %s mode", self.interface, mode)
        except subprocess.CalledProcessError as e:
            raise WiFiInterfaceError(
                f"Failed to set {self.interface} to {mode} mode: {e.stderr.decode() if e.stderr else e}"
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"Timeout setting {self.interface} to {mode} mode")

    def _detect_security_type(self, security_str: str) -> SecurityType:
        """
        Detect security type from scan result string.

        WPA2 must be detected before WPA to avoid false matches.
        Since "WPA2" contains "WPA" as substring, we must be careful
        to distinguish standalone WPA from WPA2.
        """
        sec = security_str.upper()

        # Check for WPA3 first (highest priority)
        if "WPA3" in sec:
            if "WPA2" in sec:
                return SecurityType.WPA2_WPA3
            return SecurityType.WPA3

        # Check for WPA2 (must check before WPA since "WPA2" contains "WPA")
        if "WPA2" in sec:
            # Check if there's also a standalone WPA (not part of WPA2/WPA3)
            # Mixed mode strings look like "WPA/WPA2" or "WPA WPA2"
            # Remove all WPA2/WPA3 occurrences and check if WPA still remains
            stripped = sec.replace("WPA2", "").replace("WPA3", "")
            if "WPA" in stripped:
                return SecurityType.WPA_WPA2
            return SecurityType.WPA2

        # Check for standalone WPA (not WPA2 or WPA3)
        if "WPA" in sec:
            return SecurityType.WPA

        if "WEP" in sec:
            return SecurityType.WEP

        return SecurityType.OPEN

    def scan_iw(self, timeout: int = 30) -> List[AccessPoint]:
        """
        Perform scan using iw dev scan.

        Args:
            timeout: Scan timeout in seconds.

        Returns:
            List of discovered AccessPoint objects.
        """
        self._check_root()
        self._access_points.clear()
        now = time.time()

        try:
            result = subprocess.run(
                ["iw", "dev", self.interface, "scan"],
                capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"iw scan timed out after {timeout}s")
        except subprocess.CalledProcessError as e:
            raise WiFiScanError(f"iw scan failed: {e.stderr if e.stderr else e}")

        if result.returncode != 0:
            raise WiFiScanError(f"iw scan error: {result.stderr}")

        current_ap: Optional[AccessPoint] = None

        for line in result.stdout.splitlines():
            line = line.strip()

            # BSSID line
            bssid_match = re.match(r"^BSSID\s+([0-9a-fA-F:]+)\s*\(on\s+\S+\)", line)
            if bssid_match:
                if current_ap and current_ap.bssid:
                    self._access_points[current_ap.bssid] = current_ap
                current_ap = AccessPoint(
                    bssid=bssid_match.group(1).lower(),
                    first_seen=now,
                    last_seen=now,
                )
                continue

            # Also handle "BSSID xx:xx:xx:xx:xx:xx" format
            bssid_match2 = re.match(r"^BSSID\s+([0-9a-fA-F:]+)", line)
            if bssid_match2 and current_ap is None:
                current_ap = AccessPoint(
                    bssid=bssid_match2.group(1).lower(),
                    first_seen=now,
                    last_seen=now,
                )
                continue

            if current_ap is None:
                continue

            # SSID
            ssid_match = re.match(r"^SSID:\s*(.*)", line)
            if ssid_match:
                current_ap.ssid = ssid_match.group(1).strip()
                continue

            # Frequency
            freq_match = re.match(r"^freq:\s*(\d+)", line)
            if freq_match:
                current_ap.frequency = int(freq_match.group(1))
                # Calculate channel from frequency
                freq = current_ap.frequency
                if 2412 <= freq <= 2484:
                    current_ap.channel = (freq - 2407) // 5
                    if freq == 2484:
                        current_ap.channel = 14
                elif 5170 <= freq <= 5885:
                    current_ap.channel = (freq - 5000) // 5
                elif 5955 <= freq <= 7115:
                    current_ap.channel = (freq - 5950) // 5
                continue

            # Signal
            signal_match = re.match(r"^signal:\s*(-?\d+\.\d+)\s*dBm", line)
            if signal_match:
                current_ap.signal_dbm = int(float(signal_match.group(1)))
                continue

            # Capability / Security
            if "capability:" in line.lower() or "RSN:" in line or "WPA:" in line:
                sec_parts = []
                if "WPA2" in line or "RSN" in line:
                    sec_parts.append("WPA2")
                elif "WPA" in line:
                    sec_parts.append("WPA")
                if "Privacy" in line and not sec_parts:
                    sec_parts.append("WEP")
                if sec_parts:
                    current_ap.security = " ".join(sec_parts)
                    current_ap.security_type = self._detect_security_type(current_ap.security)
                continue

            # RSN/WPA detail block (multi-line)
            if line.startswith("RSN:"):
                current_ap.security = "WPA2"
                current_ap.security_type = SecurityType.WPA2
                continue

            if line.startswith("WPA:"):
                if current_ap.security_type != SecurityType.WPA2:
                    if current_ap.security_type == SecurityType.WPA2:
                        current_ap.security = "WPA/WPA2"
                        current_ap.security_type = SecurityType.WPA_WPA2
                    else:
                        current_ap.security = "WPA"
                        current_ap.security_type = SecurityType.WPA
                continue

            # WPS
            if "WPS" in line:
                current_ap.wps = True
                continue

        # Don't forget the last AP
        if current_ap and current_ap.bssid:
            self._access_points[current_ap.bssid] = current_ap

        # Enrich with vendor data
        for ap in self._access_points.values():
            ap.vendor = self._lookup_vendor(ap.bssid)

        return list(self._access_points.values())

    def scan_airodump(self, channel: Optional[int] = None, timeout: int = 30,
                      output_prefix: str = "/tmp/wifiaio_scan") -> List[AccessPoint]:
        """
        Perform scan using airodump-ng.

        Args:
            channel: Optional specific channel to scan.
            timeout: Scan duration in seconds.
            output_prefix: File prefix for airodump output files.

        Returns:
            List of discovered AccessPoint objects.
        """
        self._check_root()
        self._access_points.clear()

        cmd = [
            "airodump-ng",
            self.interface,
            "-w", output_prefix,
            "--output-format", "csv",
        ]
        if channel is not None:
            cmd.extend(["-c", str(channel)])

        try:
            self._airodump_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            logger.info("Started airodump-ng scan for %d seconds", timeout)
            time.sleep(timeout)
            self._airodump_process.terminate()
            self._airodump_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._airodump_process.kill()
            self._airodump_process.wait()
        except FileNotFoundError:
            raise WiFiScanError("airodump-ng not found. Install aircrack-ng suite.")
        finally:
            self._airodump_process = None

        # Parse the CSV output
        csv_file = output_prefix + "-01.csv"
        if os.path.isfile(csv_file):
            return self._parse_airodump_csv(csv_file)
        else:
            logger.warning("airodump-ng CSV output not found at %s", csv_file)
            return []

    def _parse_airodump_csv(self, csv_path: str) -> List[AccessPoint]:
        """Parse airodump-ng CSV output file."""
        now = time.time()
        aps: List[AccessPoint] = []
        clients: List[ClientStation] = []

        try:
            with open(csv_path, "r") as f:
                content = f.read()
        except OSError as e:
            raise WiFiScanError(f"Failed to read airodump CSV: {e}")

        # Split into AP and client sections
        sections = content.split("\r\n\r\n") if "\r\n\r\n" in content else content.split("\n\n")

        for section in sections:
            lines = section.strip().splitlines()
            if not lines:
                continue

            header = lines[0].lower()
            if "bssid" in header and "station" not in header:
                # AP section
                for line in lines[1:]:
                    line = line.strip()
                    if not line:
                        continue
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) < 14:
                        continue

                    ap = AccessPoint(
                        bssid=parts[0].strip().lower(),
                        channel=int(parts[3].strip()) if parts[3].strip() else 0,
                        signal_dbm=int(parts[8].strip()) if parts[8].strip() else 0,
                        security=parts[5].strip(),
                        cipher=parts[6].strip() if len(parts) > 6 else "",
                        authentication=parts[7].strip() if len(parts) > 7 else "",
                        ssid=parts[13].strip() if len(parts) > 13 else "",
                        first_seen=now,
                        last_seen=now,
                        packets=int(parts[10].strip()) if parts[10].strip() else 0,
                    )
                    ap.security_type = self._detect_security_type(ap.security)
                    ap.vendor = self._lookup_vendor(ap.bssid)

                    # WPS detection from authentication field
                    if "WPS" in ap.authentication.upper():
                        ap.wps = True

                    aps.append(ap)
                    self._access_points[ap.bssid] = ap

            elif "station" in header:
                # Client section
                for line in lines[1:]:
                    line = line.strip()
                    if not line:
                        continue
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) < 6:
                        continue

                    client = ClientStation(
                        mac=parts[0].strip().lower(),
                        bssid=parts[5].strip().lower() if len(parts) > 5 else "",
                        signal_dbm=int(parts[3].strip()) if parts[3].strip() else 0,
                        packets=int(parts[4].strip()) if parts[4].strip() else 0,
                        first_seen=now,
                        last_seen=now,
                        probed_ssids=[p.strip() for p in parts[6].split()] if len(parts) > 6 else [],
                    )
                    clients.append(client)
                    self._clients[client.mac] = client

        # Associate clients with their APs
        for client in clients:
            if client.bssid in self._access_points:
                self._access_points[client.bssid].clients.append(client.mac)

        return aps

    def scan(self, mode: Optional[ScanMode] = None, channel: Optional[int] = None,
             timeout: int = 30, backend: str = "iw") -> List[AccessPoint]:
        """
        Perform a network scan.

        Args:
            mode: Scan mode (active/passive). Defaults to instance mode.
            channel: Specific channel to scan.
            timeout: Scan timeout in seconds.
            backend: Scanning backend ('iw' or 'airodump').

        Returns:
            List of discovered AccessPoint objects.
        """
        scan_mode = mode or self.scan_mode

        if scan_mode == ScanMode.PASSIVE:
            # Passive: set to monitor mode, listen without probe requests
            self._set_interface_mode("monitor")
            if channel is not None:
                try:
                    subprocess.run(
                        ["iw", "dev", self.interface, "set", "channel", str(channel)],
                        check=True, capture_output=True, timeout=10
                    )
                except subprocess.CalledProcessError as e:
                    raise WiFiScanError(f"Failed to set channel: {e}")

        if backend == "airodump":
            results = self.scan_airodump(channel=channel, timeout=timeout)
        else:
            results = self.scan_iw(timeout=timeout)

        if scan_mode == ScanMode.PASSIVE:
            self._set_interface_mode("managed")

        return results

    def get_access_points(self) -> List[AccessPoint]:
        """Get all discovered access points."""
        return list(self._access_points.values())

    def get_clients(self) -> List[ClientStation]:
        """Get all discovered client stations."""
        return list(self._clients.values())

    def get_access_point(self, bssid: str) -> Optional[AccessPoint]:
        """Get a specific access point by BSSID."""
        return self._access_points.get(bssid.lower())

    def sort_results(self, results: Optional[List[AccessPoint]] = None,
                     sort_by: str = "signal", reverse: bool = True) -> List[AccessPoint]:
        """
        Sort scan results.

        Args:
            results: List of APs to sort (defaults to all discovered).
            sort_by: Field to sort by ('signal', 'channel', 'ssid', 'security', 'bssid').
            reverse: Reverse sort order.

        Returns:
            Sorted list of AccessPoint objects.
        """
        aps = results or list(self._access_points.values())
        sort_key_map = {
            "signal": lambda ap: ap.signal_dbm,
            "channel": lambda ap: ap.channel,
            "ssid": lambda ap: ap.ssid.lower(),
            "security": lambda ap: ap.security_type.value,
            "bssid": lambda ap: ap.bssid,
        }
        key_func = sort_key_map.get(sort_by, lambda ap: ap.signal_dbm)
        return sorted(aps, key=key_func, reverse=reverse)

    def filter_results(self, results: Optional[List[AccessPoint]] = None,
                       security: Optional[SecurityType] = None,
                       channel: Optional[int] = None,
                       min_signal: Optional[int] = None,
                       wps_only: bool = False,
                       ssid_pattern: Optional[str] = None) -> List[AccessPoint]:
        """
        Filter scan results by criteria.

        Args:
            results: List of APs to filter (defaults to all discovered).
            security: Filter by security type.
            channel: Filter by channel.
            min_signal: Minimum signal strength in dBm.
            wps_only: Only show WPS-enabled APs.
            ssid_pattern: Regex pattern to match SSID.

        Returns:
            Filtered list of AccessPoint objects.
        """
        aps = results or list(self._access_points.values())

        filtered = aps
        if security is not None:
            filtered = [ap for ap in filtered if ap.security_type == security]
        if channel is not None:
            filtered = [ap for ap in filtered if ap.channel == channel]
        if min_signal is not None:
            filtered = [ap for ap in filtered if ap.signal_dbm >= min_signal]
        if wps_only:
            filtered = [ap for ap in filtered if ap.wps]
        if ssid_pattern is not None:
            regex = re.compile(ssid_pattern, re.IGNORECASE)
            filtered = [ap for ap in filtered if regex.search(ap.ssid)]

        return filtered

    def export_json(self, filepath: str, results: Optional[List[AccessPoint]] = None) -> None:
        """
        Export scan results to JSON file.

        Args:
            filepath: Output file path.
            results: APs to export (defaults to all discovered).
        """
        aps = results or list(self._access_points.values())
        data = [ap.to_dict() for ap in aps]
        try:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2, default=str)
            logger.info("Exported %d APs to %s", len(aps), filepath)
        except OSError as e:
            raise WiFiScanError(f"Failed to export JSON: {e}")

    def export_csv(self, filepath: str, results: Optional[List[AccessPoint]] = None) -> None:
        """
        Export scan results to CSV file.

        Args:
            filepath: Output file path.
            results: APs to export (defaults to all discovered).
        """
        aps = results or list(self._access_points.values())
        try:
            with open(filepath, "w") as f:
                headers = [
                    "bssid", "ssid", "channel", "frequency", "signal_dbm",
                    "security", "security_type", "cipher", "authentication",
                    "wps", "vendor", "clients_count", "packets"
                ]
                f.write(",".join(headers) + "\n")
                for ap in aps:
                    row = [
                        ap.bssid,
                        f'"{ap.ssid}"',
                        str(ap.channel),
                        str(ap.frequency),
                        str(ap.signal_dbm),
                        ap.security,
                        ap.security_type.value,
                        ap.cipher,
                        ap.authentication,
                        str(ap.wps),
                        ap.vendor,
                        str(len(ap.clients)),
                        str(ap.packets),
                    ]
                    f.write(",".join(row) + "\n")
            logger.info("Exported %d APs to %s", len(aps), filepath)
        except OSError as e:
            raise WiFiScanError(f"Failed to export CSV: {e}")

    def export_kml(self, filepath: str, results: Optional[List[AccessPoint]] = None) -> None:
        """
        Export scan results to KML format for Google Earth.

        Args:
            filepath: Output file path.
            results: APs to export (defaults to all discovered).
        """
        aps = results or list(self._access_points.values())
        try:
            with open(filepath, "w") as f:
                f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                f.write('<kml xmlns="http://www.opengis.net/kml/2.2">\n')
                f.write('<Document>\n')
                f.write('<name>WiFiAIO Scan Results</name>\n')
                for ap in aps:
                    if ap.lat != 0.0 and ap.lon != 0.0:
                        f.write('  <Placemark>\n')
                        f.write(f'    <name>{ap.ssid} ({ap.bssid})</name>\n')
                        f.write(f'    <description>Channel: {ap.channel}, '
                                f'Signal: {ap.signal_dbm} dBm, '
                                f'Security: {ap.security_type.value}</description>\n')
                        f.write('    <Point>\n')
                        f.write(f'      <coordinates>{ap.lon},{ap.lat},0</coordinates>\n')
                        f.write('    </Point>\n')
                        f.write('  </Placemark>\n')
                f.write('</Document>\n')
                f.write('</kml>\n')
            logger.info("Exported %d APs to KML %s", len(aps), filepath)
        except OSError as e:
            raise WiFiScanError(f"Failed to export KML: {e}")

    def stop(self) -> None:
        """Stop any running scan process."""
        if self._airodump_process and self._airodump_process.poll() is None:
            self._airodump_process.terminate()
            try:
                self._airodump_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._airodump_process.kill()
                self._airodump_process.wait()
            self._airodump_process = None
        self._scanning = False
        logger.info("Scanner stopped")
