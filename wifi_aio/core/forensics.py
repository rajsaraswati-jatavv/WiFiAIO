"""PCAP and network forensics analysis.

Provides PCAP file analysis, timeline reconstruction, credential extraction,
and DNS query analysis with support for large files via chunked reading.
"""

import json
import logging
import os
import re
import struct
import subprocess
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)

# PCAP file format constants
PCAP_MAGIC = 0xA1B2C3D4
PCAPNG_MAGIC = 0x0A0D0D0A
PCAP_HEADER_SIZE = 24
PCAP_RECORD_HEADER_SIZE = 16
CHUNK_SIZE = 1024 * 1024  # 1MB chunks for large file reading


class Forensics:
    """Analyze PCAP files and reconstruct network activity timelines.

    Supports:
    - PCAP/PCAPNG file analysis
    - Timeline reconstruction
    - Credential extraction
    - DNS query analysis
    """

    def __init__(self, tshark_path: Optional[str] = None):
        self.tshark_path = tshark_path or self._find_tshark()
        self._analysis_cache: Dict[str, Dict] = {}

    # ------------------------------------------------------------------
    # PCAP Analysis
    # ------------------------------------------------------------------

    def analyze_pcap(
        self,
        filepath: str,
        display_filter: Optional[str] = None,
        max_packets: int = 100000,
    ) -> Dict:
        """Analyze a PCAP file and extract summary information.

        Uses tshark for detailed analysis if available, falls back to
        raw PCAP parsing for basic statistics.

        Args:
            filepath: Path to the PCAP file.
            display_filter: Wireshark display filter string.
            max_packets: Maximum number of packets to analyze.

        Returns:
            Dict with analysis results.
        """
        if not os.path.isfile(filepath):
            raise WiFiConnectionError(f"PCAP file not found: {filepath}")

        if self.tshark_path:
            return self._analyze_pcap_tshark(filepath, display_filter, max_packets)
        else:
            return self._analyze_pcap_raw(filepath, max_packets)

    def _analyze_pcap_tshark(
        self,
        filepath: str,
        display_filter: Optional[str],
        max_packets: int,
    ) -> Dict:
        """Analyze PCAP using tshark for detailed results."""
        result: Dict = {
            "filepath": filepath,
            "file_size": os.path.getsize(filepath),
            "packets": [],
            "summary": {},
            "protocols": defaultdict(int),
            "conversations": [],
            "errors": [],
        }

        cmd = [
            self.tshark_path,
            "-r", filepath,
            "-T", "json",
            "-c", str(max_packets),
        ]
        if display_filter:
            cmd.extend(["-Y", display_filter])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("tshark analysis timed out")
        except FileNotFoundError:
            return self._analyze_pcap_raw(filepath, max_packets)

        if proc.returncode != 0:
            result["errors"].append(proc.stderr.strip())
            return result

        try:
            packets = json.loads(proc.stdout)
        except json.JSONDecodeError:
            result["errors"].append("Failed to parse tshark JSON output")
            return result

        if not isinstance(packets, list):
            packets = [packets]

        total_packets = len(packets)
        src_ips: Dict[str, int] = defaultdict(int)
        dst_ips: Dict[str, int] = defaultdict(int)

        for pkt in packets:
            layers = pkt.get("_source", {}).get("layers", {})

            # Protocol counts
            for layer_name in layers:
                result["protocols"][layer_name] += 1

            # Extract IP info
            ip_layer = layers.get("ip", {})
            if ip_layer:
                src = self._tshark_json_value(ip_layer.get("ip.src", ""))
                dst = self._tshark_json_value(ip_layer.get("ip.dst", ""))
                if src:
                    src_ips[src] += 1
                if dst:
                    dst_ips[dst] += 1

            result["packets"].append(layers)

        result["summary"] = {
            "total_packets": total_packets,
            "unique_source_ips": len(src_ips),
            "unique_dest_ips": len(dst_ips),
            "top_source_ips": dict(sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            "top_dest_ips": dict(sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            "protocols": dict(result["protocols"]),
        }

        return result

    def _analyze_pcap_raw(self, filepath: str, max_packets: int) -> Dict:
        """Analyze PCAP using raw binary parsing (chunked for large files).

        Provides basic statistics without requiring tshark.
        """
        result: Dict = {
            "filepath": filepath,
            "file_size": os.path.getsize(filepath),
            "packets": [],
            "summary": {},
            "protocols": defaultdict(int),
            "errors": [],
        }

        packet_count = 0
        total_bytes = 0
        timestamps: List[float] = []

        with open(filepath, "rb") as fh:
            # Read global header
            header = fh.read(PCAP_HEADER_SIZE)
            if len(header) < PCAP_HEADER_SIZE:
                result["errors"].append("Invalid PCAP header")
                return result

            magic = struct.unpack("<I", header[:4])[0]
            if magic == PCAP_MAGIC:
                byte_order = "<"
            elif magic == struct.unpack(">I", header[:4])[0] and struct.unpack(">I", header[:4])[0] == PCAP_MAGIC:
                byte_order = ">"
            else:
                result["errors"].append(f"Not a valid PCAP file (magic: 0x{magic:08X})")
                return result

            # Parse version info from header
            ver_major, ver_minor = struct.unpack(f"{byte_order}HH", header[4:8])
            snap_len = struct.unpack(f"{byte_order}I", header[16:20])[0]
            link_type = struct.unpack(f"{byte_order}I", header[20:24])[0]

            result["pcap_version"] = f"{ver_major}.{ver_minor}"
            result["link_type"] = link_type

            # Read packets using chunked approach
            while packet_count < max_packets:
                rec_header = fh.read(PCAP_RECORD_HEADER_SIZE)
                if len(rec_header) < PCAP_RECORD_HEADER_SIZE:
                    break  # End of file

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    f"{byte_order}IIII", rec_header
                )

                timestamp = ts_sec + ts_usec / 1_000_000
                timestamps.append(timestamp)

                # Read packet data in chunks if large
                packet_data = self._read_chunked(fh, incl_len)
                if len(packet_data) < incl_len:
                    break

                total_bytes += orig_len
                packet_count += 1

                # Basic protocol detection
                protocol = self._detect_protocol(packet_data, link_type)
                result["protocols"][protocol] += 1

        # Build summary
        if timestamps:
            duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
        else:
            duration = 0

        result["summary"] = {
            "total_packets": packet_count,
            "total_bytes": total_bytes,
            "duration_seconds": round(duration, 3),
            "avg_packets_per_second": round(packet_count / duration, 2) if duration > 0 else 0,
            "avg_packet_size": round(total_bytes / packet_count, 2) if packet_count > 0 else 0,
            "protocols": dict(result["protocols"]),
        }

        return result

    @staticmethod
    def _read_chunked(fh, length: int) -> bytes:
        """Read data from file in chunks to handle large records.

        Args:
            fh: File handle.
            length: Number of bytes to read.

        Returns:
            Bytes read.
        """
        data = b""
        remaining = length
        while remaining > 0:
            chunk = fh.read(min(remaining, CHUNK_SIZE))
            if not chunk:
                break
            data += chunk
            remaining -= len(chunk)
        return data

    @staticmethod
    def _detect_protocol(data: bytes, link_type: int) -> str:
        """Basic protocol detection from raw packet data."""
        try:
            if link_type == 1:  # Ethernet
                if len(data) < 14:
                    return "unknown"
                ethertype = struct.unpack("!H", data[12:14])[0]
                if ethertype == 0x0800:
                    return "ip"
                elif ethertype == 0x0806:
                    return "arp"
                elif ethertype == 0x86DD:
                    return "ipv6"
                elif ethertype == 0x888E:
                    return "eap"
                return f"eth_0x{ethertype:04X}"
            elif link_type == 105:  # IEEE 802.11
                return "wifi"
            elif link_type == 113:  # Linux cooked capture
                if len(data) < 2:
                    return "unknown"
                proto = struct.unpack("!H", data[2:4])[0]
                if proto == 0x0800:
                    return "ip"
                elif proto == 0x0806:
                    return "arp"
                return f"cooked_0x{proto:04X}"
            elif link_type == 127:  # IEEE 802.11 radiotap
                return "wifi_radiotap"
        except (struct.error, IndexError):
            pass
        return "unknown"

    # ------------------------------------------------------------------
    # Timeline Reconstruction
    # ------------------------------------------------------------------

    def reconstruct_timeline(
        self,
        filepath: str,
        group_by: str = "protocol",
        max_packets: int = 50000,
    ) -> Dict:
        """Reconstruct a network activity timeline from a PCAP file.

        Args:
            filepath: Path to PCAP file.
            group_by: Grouping method ('protocol', 'ip', 'port', 'conversation').
            max_packets: Maximum packets to process.

        Returns:
            Dict with timeline entries grouped as requested.
        """
        if not self.tshark_path:
            raise WiFiConnectionError("tshark required for timeline reconstruction")

        fields = "-e frame.time_relative -e frame.number -e ip.src -e ip.dst"
        fields += " -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport"
        fields += " -e _ws.col.Protocol -e frame.len"

        cmd = [
            self.tshark_path,
            "-r", filepath,
            "-T", "fields",
            fields.split(),
            "-c", str(max_packets),
        ]
        # Flatten the list
        flat_cmd = []
        for item in cmd:
            if isinstance(item, list):
                flat_cmd.extend(item)
            else:
                flat_cmd.append(item)

        try:
            proc = subprocess.run(
                flat_cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("Timeline reconstruction timed out")

        if proc.returncode != 0:
            raise WiFiConnectionError(f"tshark failed: {proc.stderr.strip()}")

        timeline: Dict[str, List[Dict]] = defaultdict(list)

        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 9:
                continue

            entry = {
                "time_relative": self._safe_float(parts[0]),
                "frame_number": self._safe_int(parts[1]),
                "src_ip": self._tshark_val(parts[2]),
                "dst_ip": self._tshark_val(parts[3]),
                "src_port": self._safe_int(parts[4] or parts[6]),
                "dst_port": self._safe_int(parts[5] or parts[7]),
                "protocol": self._tshark_val(parts[8]),
                "frame_len": self._safe_int(parts[9]) if len(parts) > 9 else 0,
            }

            if group_by == "protocol":
                key = entry["protocol"]
            elif group_by == "ip":
                key = entry["src_ip"] or "unknown"
            elif group_by == "port":
                key = str(entry["dst_port"]) if entry["dst_port"] else "unknown"
            elif group_by == "conversation":
                src = entry["src_ip"]
                dst = entry["dst_ip"]
                key = f"{src} -> {dst}" if src and dst else "unknown"
            else:
                key = "all"

            timeline[key].append(entry)

        return dict(timeline)

    # ------------------------------------------------------------------
    # Credential Extraction
    # ------------------------------------------------------------------

    def extract_credentials(
        self,
        filepath: str,
        max_packets: int = 100000,
    ) -> List[Dict]:
        """Extract potential credentials from a PCAP file.

        Looks for HTTP Basic Auth, FTP, SMTP, IMAP, POP3, and Telnet
        credentials in plaintext.

        Args:
            filepath: Path to PCAP file.
            max_packets: Maximum packets to process.

        Returns:
            List of credential dicts.
        """
        credentials: List[Dict] = []

        if self.tshark_path:
            credentials = self._extract_creds_tshark(filepath, max_packets)
        else:
            credentials = self._extract_creds_raw(filepath)

        return credentials

    def _extract_creds_tshark(self, filepath: str, max_packets: int) -> List[Dict]:
        """Extract credentials using tshark display filters."""
        credentials: List[Dict] = []
        filters = [
            ("http.authorization", "http.authorization"),
            ("ftp.request.command", "ftp"),
            ("imap.request", "imap"),
            ("pop.request", "pop"),
            ("smtp.request.command", "smtp"),
            ("telnet.data", "telnet"),
        ]

        for name, filt in filters:
            try:
                cmd = [
                    self.tshark_path,
                    "-r", filepath,
                    "-Y", filt,
                    "-T", "fields",
                    "-e", "ip.src",
                    "-e", "ip.dst",
                    "-e", f"{filt}",
                    "-c", str(max_packets),
                ]
                # For http.authorization, use different field extraction
                if name == "http.authorization":
                    cmd = [
                        self.tshark_path,
                        "-r", filepath,
                        "-Y", "http.authorization",
                        "-T", "fields",
                        "-e", "ip.src",
                        "-e", "ip.dst",
                        "-e", "http.authorization",
                        "-c", str(max_packets),
                    ]

                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if proc.returncode != 0:
                    continue

                for line in proc.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        cred = {
                            "source": name,
                            "src_ip": self._tshark_val(parts[0]),
                            "dst_ip": self._tshark_val(parts[1]),
                            "data": self._tshark_val(parts[2]),
                        }

                        # Decode HTTP Basic Auth
                        if name == "http.authorization" and "Basic" in cred["data"]:
                            try:
                                import base64
                                b64_part = cred["data"].split("Basic")[-1].strip()
                                decoded = base64.b64decode(b64_part).decode("utf-8", errors="replace")
                                if ":" in decoded:
                                    username, password = decoded.split(":", 1)
                                    cred["username"] = username
                                    cred["password"] = password
                            except Exception:
                                pass

                        # Parse FTP USER/PASS
                        if name == "ftp.request.command":
                            data = cred["data"]
                            if isinstance(data, str):
                                if "USER" in data.upper():
                                    cred["username"] = data.split()[-1] if data.split() else ""
                                elif "PASS" in data.upper():
                                    cred["password"] = data.split()[-1] if data.split() else ""

                        credentials.append(cred)
            except subprocess.TimeoutExpired:
                continue

        return credentials

    def _extract_creds_raw(self, filepath: str) -> List[Dict]:
        """Extract credentials from PCAP using raw string search (fallback)."""
        credentials: List[Dict] = []
        patterns = [
            (b"Authorization: Basic ", "http_basic_auth"),
            (b"USER ", "ftp_user"),
            (b"PASS ", "ftp_pass"),
            (b"LOGIN ", "imap_login"),
            (b"EHLO ", "smtp_ehlo"),
            (b"APOP ", "pop_apop"),
        ]

        try:
            with open(filepath, "rb") as fh:
                buffer = b""
                offset = 0
                while True:
                    chunk = fh.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    buffer += chunk

                    for pattern, source in patterns:
                        pos = 0
                        while True:
                            idx = buffer.find(pattern, pos)
                            if idx == -1:
                                break
                            # Extract the line
                            line_end = buffer.find(b"\r\n", idx)
                            if line_end == -1:
                                line_end = min(idx + 256, len(buffer))
                            line = buffer[idx:line_end].decode("utf-8", errors="replace").strip()
                            cred = {
                                "source": source,
                                "offset": offset + idx,
                                "data": line,
                            }

                            # Decode basic auth
                            if source == "http_basic_auth" and "Basic" in line:
                                try:
                                    import base64
                                    b64_part = line.split("Basic")[-1].strip()
                                    decoded = base64.b64decode(b64_part).decode("utf-8", errors="replace")
                                    if ":" in decoded:
                                        username, password = decoded.split(":", 1)
                                        cred["username"] = username
                                        cred["password"] = password
                                except Exception:
                                    pass

                            credentials.append(cred)
                            pos = idx + len(pattern)

                    # Keep last portion of buffer for cross-chunk matches
                    keep = max(len(max(p for p, _ in patterns)), 4096)
                    offset += len(buffer) - keep
                    buffer = buffer[-keep:]

        except OSError as exc:
            logger.error("Failed to read PCAP for credential extraction: %s", exc)

        return credentials

    # ------------------------------------------------------------------
    # DNS Query Analysis
    # ------------------------------------------------------------------

    def analyze_dns_queries(
        self,
        filepath: str,
        max_packets: int = 100000,
    ) -> Dict:
        """Analyze DNS queries in a PCAP file.

        Args:
            filepath: Path to PCAP file.
            max_packets: Maximum packets to process.

        Returns:
            Dict with DNS analysis results.
        """
        if not self.tshark_path:
            return self._analyze_dns_raw(filepath)

        result: Dict = {
            "total_queries": 0,
            "domains": defaultdict(int),
            "query_types": defaultdict(int),
            "suspicious_domains": [],
            "dns_servers": defaultdict(int),
            "queries": [],
            "entropy_analysis": {},
        }

        cmd = [
            self.tshark_path,
            "-r", filepath,
            "-Y", "dns.qry.name",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "dns.qry.name",
            "-e", "dns.qry.type",
            "-e", "dns.flags.response",
            "-c", str(max_packets),
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("DNS analysis timed out")

        if proc.returncode != 0:
            return result

        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue

            src_ip = self._tshark_val(parts[0])
            dst_ip = self._tshark_val(parts[1])
            domain = self._tshark_val(parts[2])
            query_type = self._tshark_val(parts[3]) if len(parts) > 3 else "A"
            is_response = self._tshark_val(parts[4]) if len(parts) > 4 else ""

            # Build a structured query dict using "domain" as key (not "query")
            query = {
                "domain": domain,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "query_type": query_type,
                "is_response": is_response == "1",
            }

            # Only count queries (not responses)
            if query.get("is_response"):
                continue

            # Use query.get("domain") to access the domain field
            query_domain = query.get("domain", "")
            if not query_domain:
                continue

            result["total_queries"] += 1
            result["domains"][query_domain] += 1
            if query.get("query_type"):
                result["query_types"][query.get("query_type", "A")] += 1
            if query.get("dst_ip"):
                result["dns_servers"][query.get("dst_ip", "")] += 1

            # Store individual query records (limited)
            if len(result["queries"]) < 1000:
                result["queries"].append(query)

        # Identify suspicious domains
        result["suspicious_domains"] = self._identify_suspicious_domains(
            dict(result["domains"])
        )

        # Convert defaultdicts to regular dicts
        result["domains"] = dict(result["domains"])
        result["query_types"] = dict(result["query_types"])
        result["dns_servers"] = dict(result["dns_servers"])

        return result

    def _analyze_dns_raw(self, filepath: str) -> Dict:
        """Analyze DNS queries from raw PCAP data (fallback)."""
        result: Dict = {
            "total_queries": 0,
            "domains": defaultdict(int),
            "query_types": defaultdict(int),
            "suspicious_domains": [],
            "dns_servers": defaultdict(int),
        }

        try:
            with open(filepath, "rb") as fh:
                buffer = b""
                while True:
                    chunk = fh.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    buffer += chunk

                    # Look for DNS query patterns
                    # DNS queries typically have a domain name in label format
                    # followed by query type bytes
                    pos = 0
                    while pos < len(buffer) - 12:
                        # Look for DNS header pattern (transaction ID + flags)
                        # Standard DNS query: flags byte 2 = 0x01 (recursion desired)
                        if buffer[pos:pos+2] != b'\x00\x00' and len(buffer) > pos + 12:
                            # Try to extract domain from DNS question section
                            domain = self._extract_dns_domain(buffer, pos)
                            if domain and "." in domain:
                                result["total_queries"] += 1
                                result["domains"][domain] += 1
                        pos += 1

                    # Keep last portion
                    buffer = buffer[-8192:]

        except OSError as exc:
            logger.error("DNS raw analysis failed: %s", exc)

        result["suspicious_domains"] = self._identify_suspicious_domains(
            dict(result["domains"])
        )
        result["domains"] = dict(result["domains"])
        result["query_types"] = dict(result["query_types"])
        result["dns_servers"] = dict(result["dns_servers"])
        return result

    @staticmethod
    def _extract_dns_domain(data: bytes, offset: int) -> Optional[str]:
        """Extract a DNS domain name from raw packet data."""
        try:
            labels = []
            pos = offset
            while pos < len(data) and pos < offset + 256:
                length = data[pos]
                if length == 0:
                    break
                if length >= 0xC0:
                    # Compressed pointer - skip
                    break
                pos += 1
                if pos + length > len(data):
                    break
                label = data[pos:pos + length].decode("utf-8", errors="replace")
                if label and all(c.isalnum() or c in "-_" for c in label):
                    labels.append(label)
                else:
                    break
                pos += length
            if labels:
                return ".".join(labels)
        except (IndexError, UnicodeDecodeError):
            pass
        return None

    @staticmethod
    def _identify_suspicious_domains(domains: Dict[str, int]) -> List[Dict]:
        """Identify potentially suspicious domains from DNS queries."""
        suspicious = []
        suspicious_patterns = [
            (r".*\.tk$", "Free .tk domain - often used for malicious purposes"),
            (r".*\.ml$", "Free .ml domain - often used for malicious purposes"),
            (r".*\.ga$", "Free .ga domain - often used for malicious purposes"),
            (r".*\.cf$", "Free .cf domain - often used for malicious purposes"),
            (r"^[a-z0-9]{8,}\.", "Long random subdomain - possible DGA"),
            (r".*-[a-f0-9]{8,}\.", "Hex subdomain - possible DGA"),
            (r"^data\.", "Data exfiltration domain pattern"),
            (r".*\.onion\.", "Tor-related domain"),
            (r".*dyn[dD]ns.*", "Dynamic DNS - often used for C2"),
            (r".*duckdns.*", "DuckDNS - often used for C2"),
        ]

        for domain, count in domains.items():
            for pattern, reason in suspicious_patterns:
                if re.match(pattern, domain, re.IGNORECASE):
                    suspicious.append({
                        "domain": domain,
                        "reason": reason,
                        "query_count": count,
                    })
                    break

        return suspicious

    # ------------------------------------------------------------------
    # WiFi-specific forensics
    # ------------------------------------------------------------------

    def extract_handshakes(
        self,
        filepath: str,
    ) -> List[Dict]:
        """Extract WiFi handshake information from a PCAP file.

        Args:
            filepath: Path to PCAP file.

        Returns:
            List of handshake dicts with BSSID, client, and frame info.
        """
        handshakes: List[Dict] = []

        if not self.tshark_path:
            raise WiFiConnectionError("tshark required for handshake extraction")

        # EAPOL frames
        cmd = [
            self.tshark_path,
            "-r", filepath,
            "-Y", "eapol",
            "-T", "fields",
            "-e", "wlan.bssid",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "eapol.type",
            "-e", "frame.number",
            "-e", "frame.time_relative",
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("Handshake extraction timed out")

        current_handshake: Dict = {}

        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 5:
                continue

            bssid = self._tshark_val(parts[0])
            sa = self._tshark_val(parts[1])
            da = self._tshark_val(parts[2])
            eapol_type = self._tshark_val(parts[3])
            frame_num = self._safe_int(parts[4])
            time_rel = self._safe_float(parts[5]) if len(parts) > 5 else 0.0

            if eapol_type == "0":  # EAPOL-Start / M1
                current_handshake = {
                    "bssid": bssid,
                    "client": sa if sa != bssid else da,
                    "ap": bssid,
                    "frame_numbers": [frame_num],
                    "timestamp": time_rel,
                    "complete": False,
                }
            elif current_handshake:
                current_handshake["frame_numbers"].append(frame_num)
                if len(current_handshake["frame_numbers"]) >= 4:
                    current_handshake["complete"] = True
                    handshakes.append(dict(current_handshake))
                    current_handshake = {}

        # Partial handshakes
        if current_handshake and current_handshake.get("frame_numbers"):
            handshakes.append(current_handshake)

        return handshakes

    def extract_probe_requests(
        self,
        filepath: str,
    ) -> List[Dict]:
        """Extract WiFi probe requests from a PCAP file.

        Returns:
            List of probe request dicts.
        """
        probes: List[Dict] = []
        if not self.tshark_path:
            raise WiFiConnectionError("tshark required for probe request extraction")

        cmd = [
            self.tshark_path,
            "-r", filepath,
            "-Y", "wlan.fc.type_subtype == 4",
            "-T", "fields",
            "-e", "wlan.sa",
            "-e", "wlan_mgt.ssid",
            "-e", "wlan_mgt.supported_rates",
            "-e", "frame.number",
            "-e", "frame.time_relative",
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("Probe request extraction timed out")

        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue

            probe = {
                "client_mac": self._tshark_val(parts[0]),
                "ssid": self._tshark_val(parts[1]),
                "frame_number": self._safe_int(parts[3]) if len(parts) > 3 else 0,
                "timestamp": self._safe_float(parts[4]) if len(parts) > 4 else 0.0,
            }
            probes.append(probe)

        return probes

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_tshark() -> Optional[str]:
        """Find tshark binary in common locations."""
        common_paths = [
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/usr/sbin/tshark",
            "/snap/bin/tshark",
        ]
        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path

        # Try which
        import shutil
        tshark = shutil.which("tshark")
        return tshark

    @staticmethod
    def _tshark_json_value(value) -> str:
        """Extract a string value from tshark JSON output.

        tshark JSON can return values as either a string or a list.
        Handle both cases by taking the first element if it's a list.
        """
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value) if value else ""

    @staticmethod
    def _tshark_val(value: str) -> str:
        """Clean a tshark field value."""
        if not value:
            return ""
        return value.strip()

    @staticmethod
    def _safe_int(value: str) -> int:
        """Safely convert to int."""
        try:
            return int(value.strip())
        except (ValueError, AttributeError):
            return 0

    @staticmethod
    def _safe_float(value: str) -> float:
        """Safely convert to float."""
        try:
            return float(value.strip())
        except (ValueError, AttributeError):
            return 0.0
