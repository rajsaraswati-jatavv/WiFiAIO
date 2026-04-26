"""Integration with external security tools.

Provides unified interface to aircrack-ng suite, hashcat, john the ripper,
reaver, bettercap, kismet, nmap, and wireshark/tshark.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


class ToolIntegration:
    """Integrate with external WiFi security tools.

    Provides a unified Python interface to common security tools,
    handling path discovery, execution, and output parsing.
    """

    def __init__(self):
        self._tool_paths: Dict[str, str] = {}
        self._discover_tools()

    def _discover_tools(self) -> None:
        """Auto-discover available tools in PATH."""
        tools = [
            "aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng",
            "hashcat", "john", "reaver", "wash",
            "bettercap", "kismet",
            "nmap", "tshark", "wireshark",
            "hostapd", "dnsmasq", "dhcpd",
            "hcxdumptool", "hcxtools",
            "bully", "cowpatty",
            "pyrit", "coWPAtty",
        ]
        for tool in tools:
            path = shutil.which(tool)
            if path:
                self._tool_paths[tool] = path

    def get_available_tools(self) -> Dict[str, Optional[str]]:
        """Get list of available tools and their paths.

        Returns:
            Dict mapping tool name -> path (or None if not found).
        """
        all_tools = {
            "aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng",
            "hashcat", "john", "reaver", "wash",
            "bettercap", "kismet",
            "nmap", "tshark", "wireshark",
            "hostapd", "dnsmasq",
        }
        return {tool: self._tool_paths.get(tool) for tool in all_tools}

    def get_tool_path(self, tool: str) -> str:
        """Get the path to a tool, raising if not found.

        Raises:
            WiFiConnectionError: If the tool is not installed.
        """
        if tool in self._tool_paths:
            return self._tool_paths[tool]
        path = shutil.which(tool)
        if path:
            self._tool_paths[tool] = path
            return path
        raise WiFiConnectionError(f"Tool not found: {tool}")

    def is_available(self, tool: str) -> bool:
        """Check if a tool is available."""
        return tool in self._tool_paths or shutil.which(tool) is not None

    # ------------------------------------------------------------------
    # Aircrack-ng Suite
    # ------------------------------------------------------------------

    def aircrack_scan(
        self,
        interface: str,
        duration: int = 30,
        channel: Optional[int] = None,
        bssid: Optional[str] = None,
        output_prefix: str = "/tmp/wifiaio_scan",
    ) -> Dict:
        """Run airodump-ng to scan for WiFi networks.

        Args:
            interface: Wireless interface in monitor mode.
            duration: Scan duration in seconds.
            channel: Specific channel to scan.
            bssid: Specific BSSID to target.
            output_prefix: Output file prefix.

        Returns:
            Dict with scan results and output files.
        """
        self.get_tool_path("airodump-ng")

        cmd = [
            "airodump-ng", interface,
            "-w", output_prefix,
            "--output-format", "csv,pcap",
        ]
        if channel:
            cmd.extend(["-c", str(channel)])
        if bssid:
            cmd.extend(["--bssid", bssid])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(duration)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except FileNotFoundError:
            raise WiFiConnectionError("airodump-ng not found")

        # Parse CSV output
        networks = self._parse_airodump_csv(f"{output_prefix}-01.csv")

        return {
            "networks": networks,
            "pcap_file": f"{output_prefix}-01.cap",
            "csv_file": f"{output_prefix}-01.csv",
        }

    @staticmethod
    def _parse_airodump_csv(csv_path: str) -> List[Dict]:
        """Parse airodump-ng CSV output."""
        networks = []
        try:
            with open(csv_path, "r", errors="ignore") as fh:
                in_sta_section = False
                for line in fh:
                    line = line.strip()
                    if line.startswith("Station"):
                        in_sta_section = True
                        continue
                    if in_sta_section or not line:
                        continue
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 14 and re.match(r"([0-9A-Fa-f:]{17})", parts[0]):
                        networks.append({
                            "bssid": parts[0],
                            "first_seen": parts[1],
                            "channel": parts[3],
                            "speed": parts[4],
                            "privacy": parts[5],
                            "cipher": parts[6],
                            "auth": parts[7],
                            "power": parts[8],
                            "beacons": parts[9],
                            "essid": parts[13],
                        })
        except OSError:
            pass
        return networks

    def aircrack_crack(
        self,
        capture_file: str,
        wordlist: str,
        bssid: Optional[str] = None,
    ) -> Dict:
        """Attempt to crack a WPA handshake using aircrack-ng.

        Args:
            capture_file: Path to capture file (.cap/.pcap).
            wordlist: Path to wordlist file.
            bssid: Target BSSID (auto-detect if None).

        Returns:
            Dict with: cracked, key, output.
        """
        self.get_tool_path("aircrack-ng")

        cmd = ["aircrack-ng", "-w", wordlist]
        if bssid:
            cmd.extend(["-b", bssid])
        cmd.append(capture_file)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=3600,
            )
            output = result.stdout

            if "KEY FOUND" in output:
                match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output)
                key = match.group(1) if match else "found"
                return {"cracked": True, "key": key, "output": output}
            return {"cracked": False, "key": None, "output": output}

        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("aircrack-ng timed out")

    def aireplay_deauth(
        self,
        interface: str,
        bssid: str,
        client: Optional[str] = None,
        count: int = 5,
    ) -> Dict:
        """Send deauthentication packets.

        Args:
            interface: Monitor mode interface.
            bssid: Target AP BSSID.
            client: Target client MAC (broadcast if None).
            count: Number of deauth packets.

        Returns:
            Dict with: sent_count.
        """
        self.get_tool_path("aireplay-ng")

        cmd = [
            "aireplay-ng",
            "-0", str(count),
            "-a", bssid,
        ]
        if client:
            cmd.extend(["-c", client])
        cmd.append(interface)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            sent = 0
            match = re.search(r"Sent (\d+) packets", result.stdout)
            if match:
                sent = int(match.group(1))
            return {"sent_count": sent, "output": result.stdout}
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("aireplay-ng deauth timed out")

    def airmon_start(self, interface: str) -> Dict:
        """Start monitor mode using airmon-ng.

        Returns:
            Dict with: monitor_interface.
        """
        self.get_tool_path("airmon-ng")

        try:
            # Kill interfering processes
            subprocess.run(
                ["airmon-ng", "check", "kill"],
                capture_output=True, text=True, timeout=30,
            )
            result = subprocess.run(
                ["airmon-ng", "start", interface],
                capture_output=True, text=True, timeout=30,
            )
            # Parse monitor interface name
            match = re.search(r"monitor mode enabled on (\S+)", result.stdout)
            mon_if = match.group(1) if match else f"{interface}mon"
            return {"monitor_interface": mon_if, "output": result.stdout}
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("airmon-ng start timed out")

    def airmon_stop(self, interface: str) -> Dict:
        """Stop monitor mode using airmon-ng.

        Returns:
            Dict with result.
        """
        self.get_tool_path("airmon-ng")

        try:
            result = subprocess.run(
                ["airmon-ng", "stop", interface],
                capture_output=True, text=True, timeout=30,
            )
            return {"output": result.stdout}
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("airmon-ng stop timed out")

    # ------------------------------------------------------------------
    # Hashcat
    # ------------------------------------------------------------------

    def hashcat_crack(
        self,
        hash_file: str,
        wordlist: Optional[str] = None,
        mask: Optional[str] = None,
        hash_type: int = 22000,
        attack_mode: int = 0,
        extra_args: Optional[List[str]] = None,
    ) -> Dict:
        """Crack hashes using hashcat.

        Args:
            hash_file: Path to hash file.
            wordlist: Path to wordlist (for dictionary attack).
            mask: Mask pattern (for mask attack).
            hash_type: Hash type (22000=WPA-PBKDF2, 22001=WPA-PMK).
            attack_mode: Attack mode (0=dict, 3=mask, 6=hybrid).
            extra_args: Additional hashcat arguments.

        Returns:
            Dict with: cracked, results, cracked_count.
        """
        self.get_tool_path("hashcat")

        cmd = [
            "hashcat",
            "-m", str(hash_type),
            "-a", str(attack_mode),
            "--force",
            "--potfile-disable",
            hash_file,
        ]

        if attack_mode == 0 and wordlist:
            cmd.append(wordlist)
        elif attack_mode == 3 and mask:
            cmd.append(mask)
        elif attack_mode == 6 and wordlist and mask:
            cmd.extend([wordlist, mask])

        if extra_args:
            cmd.extend(extra_args)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=7200,
            )
            output = result.stdout + result.stderr
            cracked = "Cracked" in output or result.returncode == 0

            # Parse cracked passwords
            cracked_passwords = []
            for line in output.splitlines():
                if ":" in line and not line.startswith("$"):
                    parts = line.rsplit(":", 1)
                    if len(parts) == 2 and len(parts[1]) > 0:
                        cracked_passwords.append({
                            "hash": parts[0].strip(),
                            "password": parts[1].strip(),
                        })

            return {
                "cracked": cracked,
                "results": cracked_passwords,
                "cracked_count": len(cracked_passwords),
                "output": output,
            }
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("hashcat timed out")

    def hashcat_convert_pcap(
        self,
        pcap_file: str,
        output_file: Optional[str] = None,
        bssid: Optional[str] = None,
    ) -> str:
        """Convert PCAP to hashcat format using hcxpcapngtool.

        Returns:
            Path to the converted hash file.
        """
        tool = "hcxpcapngtool"
        if not self.is_available(tool):
            # Try hcxpcap2tool
            tool = "hcxpcap2tool"
        self.get_tool_path(tool)

        out = output_file or pcap_file.rsplit(".", 1)[0] + ".hc22000"
        cmd = [tool, "-o", out]
        if bssid:
            cmd.extend(["-b", bssid])
        cmd.append(pcap_file)

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("PCAP conversion timed out")

        return out

    # ------------------------------------------------------------------
    # John the Ripper
    # ------------------------------------------------------------------

    def john_crack(
        self,
        hash_file: str,
        wordlist: Optional[str] = None,
        format_type: Optional[str] = None,
        rules: bool = True,
    ) -> Dict:
        """Crack hashes using John the Ripper.

        Args:
            hash_file: Path to hash file.
            wordlist: Path to wordlist.
            format_type: Hash format (e.g., 'wpapsk').
            rules: Enable wordlist rules.

        Returns:
            Dict with: cracked, results.
        """
        self.get_tool_path("john")

        cmd = ["john"]
        if wordlist:
            cmd.extend(["--wordlist", wordlist])
        if rules and wordlist:
            cmd.append("--rules")
        if format_type:
            cmd.extend(["--format", format_type])
        cmd.append(hash_file)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=7200,
            )
            output = result.stdout + result.stderr

            # Get cracked passwords
            cracked = self._john_show_passwords(hash_file, format_type)

            return {
                "cracked": len(cracked) > 0,
                "results": cracked,
                "output": output,
            }
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("john timed out")

    @staticmethod
    def _john_show_passwords(hash_file: str, format_type: Optional[str] = None) -> List[Dict]:
        """Show cracked passwords from john session."""
        cmd = ["john", "--show"]
        if format_type:
            cmd.extend(["--format", format_type])
        cmd.append(hash_file)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            passwords = []
            for line in result.stdout.splitlines():
                if ":" in line and not line.startswith("0 password"):
                    parts = line.split(":")
                    if len(parts) >= 2:
                        passwords.append({
                            "username": parts[0],
                            "password": parts[1],
                        })
            return passwords
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    # ------------------------------------------------------------------
    # Reaver / WPS
    # ------------------------------------------------------------------

    def reaver_attack(
        self,
        interface: str,
        bssid: str,
        channel: Optional[int] = None,
        timeout: int = 600,
        pixie_dust: bool = True,
    ) -> Dict:
        """Run reaver WPS attack.

        Args:
            interface: Monitor mode interface.
            bssid: Target BSSID.
            channel: Target channel.
            timeout: Attack timeout in seconds.
            pixie_dust: Use Pixie Dust attack.

        Returns:
            Dict with results.
        """
        self.get_tool_path("reaver")

        cmd = [
            "reaver",
            "-i", interface,
            "-b", bssid,
            "-vv",
        ]
        if channel:
            cmd.extend(["-c", str(channel)])
        if pixie_dust:
            cmd.extend(["-K", "1"])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            output = result.stdout + result.stderr

            wps_pin = None
            wpa_key = None

            pin_match = re.search(r"WPS PIN:\s*['\"]?(\d{8})['\"]?", output)
            if pin_match:
                wps_pin = pin_match.group(1)

            key_match = re.search(r"WPA PSK:\s*['\"](.+?)['\"]", output)
            if key_match:
                wpa_key = key_match.group(1)

            return {
                "success": wps_pin is not None or wpa_key is not None,
                "wps_pin": wps_pin,
                "wpa_key": wpa_key,
                "output": output,
            }
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("reaver timed out")

    def wash_scan(
        self,
        interface: str,
        channel: Optional[int] = None,
    ) -> List[Dict]:
        """Scan for WPS-enabled access points using wash.

        Returns:
            List of WPS AP dicts.
        """
        self.get_tool_path("wash")

        cmd = ["wash", "-i", interface]
        if channel:
            cmd.extend(["-c", str(channel)])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
            )
            aps = []
            for line in result.stdout.splitlines()[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 7 and re.match(r"[0-9A-Fa-f:]{17}", parts[0]):
                    aps.append({
                        "bssid": parts[0],
                        "channel": parts[1],
                        "dbm": parts[2] if len(parts) > 2 else "",
                        "wps_locked": parts[3] if len(parts) > 3 else "",
                        "essid": " ".join(parts[6:]) if len(parts) > 6 else "",
                    })
            return aps
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("wash scan timed out")

    # ------------------------------------------------------------------
    # Bettercap
    # ------------------------------------------------------------------

    def bettercap_run(
        self,
        interface: str,
        commands: List[str],
        timeout: int = 300,
    ) -> Dict:
        """Run bettercap with specified commands.

        Args:
            interface: Network interface.
            commands: List of bettercap commands to execute.
            timeout: Execution timeout.

        Returns:
            Dict with output.
        """
        self.get_tool_path("bettercap")

        cmd_str = "; ".join(commands)
        cmd = [
            "bettercap",
            "-iface", interface,
            "-eval", cmd_str,
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            return {
                "output": result.stdout,
                "errors": result.stderr,
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("bettercap timed out")

    # ------------------------------------------------------------------
    # Kismet
    # ------------------------------------------------------------------

    def kismet_start(
        self,
        interface: str,
        output_prefix: str = "/tmp/wifiaio_kismet",
        duration: int = 60,
    ) -> Dict:
        """Run Kismet for passive WiFi monitoring.

        Args:
            interface: Wireless interface.
            output_prefix: Output file prefix.
            duration: Capture duration in seconds.

        Returns:
            Dict with output files.
        """
        self.get_tool_path("kismet")

        cmd = [
            "kismet",
            "-c", interface,
            "--daemonize",
            "-o", f"{output_prefix}.kismet",
            "-t", output_prefix,
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
            )
            time.sleep(duration)

            # Stop kismet
            subprocess.run(
                ["pkill", "kismet"],
                capture_output=True, text=True, timeout=10,
            )

            return {
                "output_files": [f"{output_prefix}.kismet"],
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("kismet timed out")

    # ------------------------------------------------------------------
    # Nmap
    # ------------------------------------------------------------------

    def nmap_scan(
        self,
        target: str,
        scan_type: str = "syn",
        ports: Optional[str] = None,
        interface: Optional[str] = None,
        timeout: int = 300,
    ) -> Dict:
        """Run nmap scan.

        Args:
            target: Target IP/range.
            scan_type: Scan type (syn, connect, udp, aggressive).
            ports: Port specification (e.g., '1-1000').
            interface: Source interface.
            timeout: Scan timeout.

        Returns:
            Dict with parsed scan results.
        """
        self.get_tool_path("nmap")

        type_flags = {
            "syn": "-sS",
            "connect": "-sT",
            "udp": "-sU",
            "aggressive": "-A",
            "quick": "-T4 -F",
            "stealth": "-sS -T2",
        }

        cmd = ["nmap"]
        cmd.extend(type_flags.get(scan_type, "-sS").split())
        if ports:
            cmd.extend(["-p", ports])
        if interface:
            cmd.extend(["-e", interface])
        cmd.extend(["-oX", "-", target])  # XML output to stdout

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            # Parse XML (simplified)
            hosts = self._parse_nmap_xml(result.stdout)
            return {
                "hosts": hosts,
                "raw_output": result.stdout,
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("nmap scan timed out")

    @staticmethod
    def _parse_nmap_xml(xml_output: str) -> List[Dict]:
        """Parse nmap XML output (simplified)."""
        hosts = []
        # Simple regex-based parsing for key fields
        for match in re.finditer(
            r'<host[^>]*>.*?<address addr="([^"]+)"[^>]*/>.*?<hostnames>.*?<hostname name="([^"]*)"',
            xml_output, re.DOTALL,
        ):
            hosts.append({
                "ip": match.group(1),
                "hostname": match.group(2),
            })

        # If regex fails, try simpler IP extraction
        if not hosts:
            for match in re.finditer(r'addr="(\d+\.\d+\.\d+\.\d+)"', xml_output):
                ip = match.group(1)
                if not any(h["ip"] == ip for h in hosts):
                    hosts.append({"ip": ip, "hostname": ""})

        return hosts

    # ------------------------------------------------------------------
    # Wireshark / Tshark
    # ------------------------------------------------------------------

    def tshark_capture(
        self,
        interface: str,
        output_file: str,
        duration: int = 60,
        display_filter: Optional[str] = None,
        capture_filter: Optional[str] = None,
    ) -> Dict:
        """Capture packets using tshark.

        Args:
            interface: Capture interface.
            output_file: Output PCAP file.
            duration: Capture duration in seconds.
            display_filter: Wireshark display filter.
            capture_filter: BPF capture filter.

        Returns:
            Dict with capture results.
        """
        self.get_tool_path("tshark")

        cmd = [
            "tshark",
            "-i", interface,
            "-w", output_file,
            "-a", f"duration:{duration}",
        ]
        if display_filter:
            cmd.extend(["-Y", display_filter])
        if capture_filter:
            cmd.extend(["-f", capture_filter])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=duration + 30,
            )
            file_size = os.path.getsize(output_file) if os.path.isfile(output_file) else 0
            return {
                "output_file": output_file,
                "file_size": file_size,
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("tshark capture timed out")

    def tshark_analyze(
        self,
        pcap_file: str,
        display_filter: Optional[str] = None,
        fields: Optional[List[str]] = None,
        max_packets: int = 10000,
    ) -> Dict:
        """Analyze a PCAP file using tshark.

        Args:
            pcap_file: Path to PCAP file.
            display_filter: Display filter.
            fields: List of fields to extract.
            max_packets: Maximum packets to process.

        Returns:
            Dict with analysis results.
        """
        self.get_tool_path("tshark")

        cmd = [
            "tshark",
            "-r", pcap_file,
            "-c", str(max_packets),
        ]

        if display_filter:
            cmd.extend(["-Y", display_filter])

        if fields:
            cmd.extend(["-T", "fields"])
            for field in fields:
                cmd.extend(["-e", field])
        else:
            cmd.extend(["-T", "json"])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
            )
            if fields:
                # Parse tab-separated fields
                records = []
                for line in result.stdout.splitlines():
                    parts = line.split("\t")
                    record = {}
                    for i, field in enumerate(fields):
                        record[field] = parts[i] if i < len(parts) else ""
                    records.append(record)
                return {"records": records, "count": len(records)}
            else:
                try:
                    data = json.loads(result.stdout)
                    return {"packets": data, "count": len(data)}
                except json.JSONDecodeError:
                    return {"raw_output": result.stdout}
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("tshark analysis timed out")

    # ------------------------------------------------------------------
    # Hcxdumptool / Hcxtools
    # ------------------------------------------------------------------

    def hcxdumptool_capture(
        self,
        interface: str,
        output_file: str,
        duration: int = 60,
        filter_list: Optional[str] = None,
    ) -> Dict:
        """Capture WPA handshakes using hcxdumptool.

        Returns:
            Dict with capture results.
        """
        self.get_tool_path("hcxdumptool")

        cmd = [
            "hcxdumptool",
            "-i", interface,
            "-o", output_file,
            "-t", str(duration),
        ]
        if filter_list:
            cmd.extend(["--filterlist_ap", filter_list])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=duration + 30,
            )
            file_size = os.path.getsize(output_file) if os.path.isfile(output_file) else 0
            return {
                "output_file": output_file,
                "file_size": file_size,
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("hcxdumptool timed out")
