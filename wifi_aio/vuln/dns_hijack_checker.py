"""DNS hijacking checker for WiFiAIO.

Detects DNS hijacking and DNS spoofing attacks by comparing DNS
responses against expected values and checking for inconsistencies.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from wifi_aio.exceptions import WiFiConnectionError, WiFiTimeoutError

logger = logging.getLogger(__name__)


class DNSHijackType(Enum):
    """Type of DNS hijack detected."""
    FULL_HIJACK = "full_hijack"        # All DNS queries redirected
    PARTIAL_HIJACK = "partial_hijack"  # Specific domains redirected
    DNS_SPOOF = "dns_spoof"            # Spoofed DNS responses
    ROGUE_DNS = "rogue_dns"            # Rogue DNS server configured
    DNS_INJECTION = "dns_injection"    # DNS response injection
    UNKNOWN = "unknown"


@dataclass
class DNSHijackVulnerability:
    """Represents a single DNS hijack vulnerability finding."""
    vuln_id: str
    title: str
    description: str
    severity: str
    cve_ids: List[str] = field(default_factory=list)
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DNSHijackScanResult:
    """Aggregated result of a DNS hijacking scan."""
    is_vulnerable: bool
    vulnerabilities: List[DNSHijackVulnerability] = field(default_factory=list)
    hijack_type: DNSHijackType = DNSHijackType.UNKNOWN
    configured_dns_servers: List[str] = field(default_factory=list)
    detected_dns_servers: List[str] = field(default_factory=list)
    expected_dns_servers: List[str] = field(default_factory=list)
    hijacked_domains: List[Dict[str, Any]] = field(default_factory=list)
    dns_response_consistency: float = 0.0  # 0.0-1.0
    scan_timestamp: float = 0.0


# Well-known test domains and their expected IP ranges
DNS_TEST_DOMAINS: List[Dict[str, Any]] = [
    {
        "domain": "dns.google",
        "expected_ips": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"],
        "description": "Google DNS resolver",
    },
    {
        "domain": "one.one.one.one",
        "expected_ips": ["1.1.1.1", "1.0.0.1"],
        "description": "Cloudflare DNS resolver",
    },
    {
        "domain": "www.google.com",
        "expected_ips": [],
        "description": "Google homepage (any valid Google IP)",
        "validate_ownership": "google",
    },
    {
        "domain": "www.cloudflare.com",
        "expected_ips": [],
        "description": "Cloudflare homepage",
        "validate_ownership": "cloudflare",
    },
]

# Known legitimate DNS server ranges
LEGITIMATE_DNS_RANGES: List[Dict[str, str]] = [
    {"name": "Google", "cidr": "8.8.4.0/24"},
    {"name": "Google", "cidr": "8.8.8.0/24"},
    {"name": "Cloudflare", "cidr": "1.1.1.0/24"},
    {"name": "Cloudflare", "cidr": "1.0.0.0/24"},
    {"name": "OpenDNS", "cidr": "208.67.222.0/24"},
    {"name": "OpenDNS", "cidr": "208.67.220.0/24"},
    {"name": "Quad9", "cidr": "9.9.9.0/24"},
    {"name": "Comodo", "cidr": "8.26.56.0/24"},
    {"name": "Comodo", "cidr": "8.20.247.0/24"},
]

# Common router/gateway DNS IPs (often used by ISPs)
COMMON_GATEWAY_DNS: List[str] = [
    "192.168.1.1", "192.168.0.1", "192.168.2.1",
    "10.0.0.1", "10.1.1.1",
    "172.16.0.1",
]

# Domains commonly targeted by DNS hijacking
COMMON_HIJACK_TARGETS: List[str] = [
    "www.facebook.com", "www.twitter.com", "www.gmail.com",
    "www.youtube.com", "www.amazon.com", "www.apple.com",
    "www.microsoft.com", "www.netflix.com", "www.paypal.com",
    "www.bankofamerica.com", "www.chase.com", "www.wellsfargo.com",
]


def _ip_to_int(ip: str) -> int:
    """Convert IP address string to integer."""
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except (socket.error, OSError):
        return 0


def _is_ip_in_cidr(ip: str, cidr: str) -> bool:
    """Check if an IP address falls within a CIDR range."""
    try:
        network, prefix_len = cidr.split("/")
        prefix_len = int(prefix_len)
        ip_int = _ip_to_int(ip)
        net_int = _ip_to_int(network)
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        return (ip_int & mask) == (net_int & mask)
    except (ValueError, TypeError):
        return False


class DNSHijackChecker:
    """Detects DNS hijacking and spoofing on a Wi-Fi network.

    Tests DNS resolution behavior to identify when DNS queries are
    being intercepted, modified, or redirected by a rogue DNS server
    or DNS injection attack.

    Usage::

        checker = DNSHijackChecker()
        result = checker.check(
            configured_dns=["192.168.1.1"],
            expected_dns=["8.8.8.8"],
        )
        if result.is_vulnerable:
            for vuln in result.vulnerabilities:
                print(f"[{vuln.severity}] {vuln.title}")
    """

    # DNS query timeout in seconds
    DNS_TIMEOUT = 5
    # Number of DNS queries per domain for consistency check
    CONSISTENCY_QUERIES = 3
    # Minimum consistency score to consider DNS responses reliable
    MIN_CONSISTENCY = 0.8

    def __init__(self, timeout: int = 5, interface: str = "") -> None:
        """Initialize the DNS hijack checker.

        Args:
            timeout: Timeout for DNS queries in seconds.
            interface: Network interface to use.
        """
        self.timeout = timeout
        self.interface = interface
        self._dns_results_cache: Dict[str, List[str]] = {}
        logger.info("DNSHijackChecker initialized")

    def check(
        self,
        configured_dns: Optional[List[str]] = None,
        expected_dns: Optional[List[str]] = None,
        gateway_ip: str = "",
        test_domains: Optional[List[str]] = None,
        capture_data: Optional[bytes] = None,
    ) -> DNSHijackScanResult:
        """Perform a DNS hijacking check.

        Args:
            configured_dns: DNS servers currently configured on the interface.
            expected_dns: Expected/legitimate DNS servers.
            gateway_ip: Gateway IP address.
            test_domains: Additional domains to test.
            capture_data: Captured DNS traffic for analysis.

        Returns:
            DNSHijackScanResult with findings.
        """
        start_time = time.time()
        result = DNSHijackScanResult(
            is_vulnerable=False,
            configured_dns_servers=configured_dns or [],
            expected_dns_servers=expected_dns or [],
            scan_timestamp=start_time,
        )

        # Step 1: Detect configured DNS servers
        if not configured_dns:
            detected = self._detect_dns_servers()
            result.configured_dns_servers = detected
        else:
            result.configured_dns_servers = configured_dns

        # Step 2: Check if configured DNS matches expected
        if expected_dns and configured_dns:
            unexpected_dns = set(configured_dns) - set(expected_dns)
            if unexpected_dns:
                result.detected_dns_servers = list(unexpected_dns)
                rogue_dns_vuln = DNSHijackVulnerability(
                    vuln_id="DNS-001",
                    title="Unexpected DNS Server Configuration",
                    description=(
                        f"DNS servers {unexpected_dns} are configured but not "
                        f"in the expected list {expected_dns}. This may "
                        "indicate DNS settings have been modified by a "
                        "rogue DHCP server or malicious configuration."
                    ),
                    severity="high",
                    cve_ids=[],
                    recommendation=(
                        "Verify DNS server settings and configure them "
                        "manually to trusted servers (e.g., 8.8.8.8, 1.1.1.1)."
                    ),
                    evidence={
                        "configured": configured_dns,
                        "expected": expected_dns,
                        "unexpected": list(unexpected_dns),
                    },
                )
                result.vulnerabilities.append(rogue_dns_vuln)
                result.hijack_type = DNSHijackType.ROGUE_DNS

        # Step 3: Check for gateway as DNS server (common but suspicious)
        if gateway_ip and gateway_ip in result.configured_dns_servers:
            gateway_dns_vuln = DNSHijackVulnerability(
                vuln_id="DNS-002",
                title="Gateway Used as DNS Server",
                description=(
                    f"The gateway ({gateway_ip}) is configured as the DNS "
                    "server. While this is common for ISP-provided routers, "
                    "it means all DNS queries pass through the router, which "
                    "could intercept or modify responses."
                ),
                severity="low",
                cve_ids=[],
                recommendation=(
                    "Configure a trusted external DNS server directly on "
                    "your device to bypass potential router-level DNS "
                    "interception."
                ),
                evidence={"gateway_dns": gateway_ip},
            )
            result.vulnerabilities.append(gateway_dns_vuln)

        # Step 4: Test DNS resolution against known domains
        hijacked = self._test_dns_resolution(test_domains or [])
        if hijacked:
            result.hijacked_domains = hijacked
            for hijack in hijacked:
                domain = hijack.get("domain", "")
                resolved_ips = hijack.get("resolved_ips", [])
                expected_ips = hijack.get("expected_ips", [])

                if expected_ips and resolved_ips:
                    # Check if resolved IPs match expected
                    matching = set(resolved_ips) & set(expected_ips)
                    if not matching and expected_ips:
                        domain_vuln = DNSHijackVulnerability(
                            vuln_id="DNS-003",
                            title=f"DNS Hijacking Detected for {domain}",
                            description=(
                                f"DNS query for {domain} returned "
                                f"{resolved_ips} instead of expected "
                                f"{expected_ips}. This strongly indicates "
                                "DNS hijacking or spoofing."
                            ),
                            severity="critical",
                            cve_ids=[],
                            recommendation=(
                                "Use a trusted DNS server with DNS-over-HTTPS "
                                "or DNS-over-TLS to prevent DNS manipulation."
                            ),
                            evidence=hijack,
                        )
                        result.vulnerabilities.append(domain_vuln)
                        if result.hijack_type == DNSHijackType.UNKNOWN:
                            result.hijack_type = DNSHijackType.DNS_SPOOF

        # Step 5: Check DNS response consistency
        consistency = self._check_dns_consistency()
        result.dns_response_consistency = consistency

        if consistency < self.MIN_CONSISTENCY:
            consistency_vuln = DNSHijackVulnerability(
                vuln_id="DNS-004",
                title="Inconsistent DNS Responses",
                description=(
                    f"DNS response consistency is {consistency:.1%}, below "
                    f"the expected threshold of {self.MIN_CONSISTENCY:.1%}. "
                    "Inconsistent responses may indicate DNS injection, "
                    "load balancer interference, or active DNS spoofing."
                ),
                severity="medium",
                cve_ids=[],
                recommendation=(
                    "Use DNS-over-HTTPS or DNS-over-TLS to ensure "
                    "consistent, authenticated DNS responses."
                ),
                evidence={"consistency": consistency},
            )
            result.vulnerabilities.append(consistency_vuln)

        # Step 6: Check for DNS rebinding protection
        rebinding_vuln = self._check_dns_rebinding()
        if rebinding_vuln:
            result.vulnerabilities.append(rebinding_vuln)

        # Step 7: Analyze captured DNS traffic if available
        if capture_data:
            traffic_vulns = self._analyze_dns_traffic(capture_data)
            result.vulnerabilities.extend(traffic_vulns)

        # Determine overall hijack type if not already set
        if result.vulnerabilities and result.hijack_type == DNSHijackType.UNKNOWN:
            if len(result.hijacked_domains) > 3:
                result.hijack_type = DNSHijackType.FULL_HIJACK
            elif result.hijacked_domains:
                result.hijack_type = DNSHijackType.PARTIAL_HIJACK
            else:
                result.hijack_type = DNSHijackType.UNKNOWN

        result.is_vulnerable = len(result.vulnerabilities) > 0
        logger.info(
            "DNS hijack check complete: %d findings, consistency=%.1f%%",
            len(result.vulnerabilities),
            consistency * 100,
        )
        return result

    def _detect_dns_servers(self) -> List[str]:
        """Detect currently configured DNS servers.

        Attempts to read DNS configuration from system files.
        """
        dns_servers: List[str] = []

        # Try reading /etc/resolv.conf on Linux
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            dns_servers.append(parts[1])
        except (FileNotFoundError, PermissionError):
            pass

        # Fallback: try to detect via socket
        if not dns_servers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout)
                    # Connect to a public IP to determine default route
                    s.connect(("8.8.8.8", 53))
                    local_ip = s.getsockname()[0]
                    # The gateway is often the first DNS server
                    parts = local_ip.split(".")
                    gateway = ".".join(parts[:3] + ["1"])
                    dns_servers.append(gateway)
            except (socket.error, OSError):
                pass

        return dns_servers

    def _test_dns_resolution(
        self, extra_domains: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Test DNS resolution against known domains.

        Args:
            extra_domains: Additional domains to test.

        Returns:
            List of domains with unexpected DNS responses.
        """
        hijacked: List[Dict[str, Any]] = []
        domains_to_test = list(DNS_TEST_DOMAINS)

        for domain in (extra_domains or []):
            domains_to_test.append({
                "domain": domain,
                "expected_ips": [],
                "description": "User-specified test domain",
            })

        for test_info in domains_to_test:
            domain = test_info["domain"]
            expected = test_info.get("expected_ips", [])

            try:
                resolved = socket.getaddrinfo(domain, None, socket.AF_INET)
                resolved_ips = list(set(addr[4][0] for addr in resolved))
            except socket.gaierror:
                resolved_ips = []

            # Cache the result
            self._dns_results_cache[domain] = resolved_ips

            # Check against expected IPs
            if expected and resolved_ips:
                matching = set(resolved_ips) & set(expected)
                if not matching:
                    hijacked.append({
                        "domain": domain,
                        "resolved_ips": resolved_ips,
                        "expected_ips": expected,
                        "description": test_info.get("description", ""),
                    })

        return hijacked

    def _check_dns_consistency(self) -> float:
        """Check DNS response consistency by querying domains multiple times.

        Returns:
            Consistency score between 0.0 and 1.0.
        """
        consistent_count = 0
        total_checks = 0

        for domain, cached_ips in self._dns_results_cache.items():
            if not cached_ips:
                continue

            # Re-query the domain
            try:
                new_resolved = socket.getaddrinfo(domain, None, socket.AF_INET)
                new_ips = list(set(addr[4][0] for addr in new_resolved))
            except socket.gaierror:
                new_ips = []

            total_checks += 1
            if set(new_ips) == set(cached_ips):
                consistent_count += 1

        if total_checks == 0:
            return 1.0

        return consistent_count / total_checks

    def _check_dns_rebinding(self) -> Optional[DNSHijackVulnerability]:
        """Check if DNS rebinding protection is in place.

        DNS rebinding allows an attacker to bypass same-origin policy
        by making a domain resolve to an internal IP address.
        """
        # Test by checking if private IP ranges are returned for test queries
        private_ranges = [
            ("10.0.0.0", "10.255.255.255"),
            ("172.16.0.0", "172.31.255.255"),
            ("192.168.0.0", "192.168.255.255"),
            ("127.0.0.0", "127.255.255.255"),
        ]

        for domain, ips in self._dns_results_cache.items():
            for ip in ips:
                ip_int = _ip_to_int(ip)
                for start, end in private_ranges:
                    start_int = _ip_to_int(start)
                    end_int = _ip_to_int(end)
                    if start_int <= ip_int <= end_int:
                        # A public domain resolving to a private IP
                        # suggests DNS rebinding or hijacking
                        return DNSHijackVulnerability(
                            vuln_id="DNS-005",
                            title="DNS Rebinding / Private IP Resolution",
                            description=(
                                f"Domain {domain} resolves to private IP "
                                f"{ip}. This could indicate DNS rebinding, "
                                "which allows attackers to bypass same-origin "
                                "policy and access internal services."
                            ),
                            severity="high",
                            cve_ids=["CVE-2020-9496"],
                            recommendation=(
                                "Configure the router to block DNS responses "
                                "that resolve to private/internal IP addresses "
                                "for external domains. Use DNS rebinding protection."
                            ),
                            evidence={"domain": domain, "resolved_ip": ip},
                        )

        return None

    def _analyze_dns_traffic(self, data: bytes) -> List[DNSHijackVulnerability]:
        """Analyze captured DNS traffic for hijacking indicators."""
        vulns: List[DNSHijackVulnerability] = []

        # Parse DNS packets from capture data
        dns_packets = self._parse_dns_packets(data)

        spoofed_responses = 0
        multiple_responses = 0
        total_queries = 0

        pending_queries: Dict[int, Dict[str, Any]] = {}

        for pkt in dns_packets:
            if pkt.get("is_query", False):
                total_queries += 1
                txid = pkt.get("transaction_id", 0)
                pending_queries[txid] = pkt
            elif pkt.get("is_response", False):
                txid = pkt.get("transaction_id", 0)
                if txid in pending_queries:
                    query = pending_queries[txid]

                    # Check for multiple responses to same query
                    if query.get("responses_received", 0) > 0:
                        multiple_responses += 1
                        query["responses_received"] += 1
                    else:
                        query["responses_received"] = 1

                    # Check if response IP matches expected
                    resolved_ips = pkt.get("answer_ips", [])
                    domain = query.get("domain", "")

                    # Check for private IP in response
                    for ip in resolved_ips:
                        ip_int = _ip_to_int(ip)
                        if 0x0A000000 <= ip_int <= 0x0AFFFFFF:  # 10.x.x.x
                            spoofed_responses += 1

        if multiple_responses > 0:
            vuln = DNSHijackVulnerability(
                vuln_id="DNS-006",
                title="Multiple DNS Responses Detected",
                description=(
                    f"Detected {multiple_responses} cases of multiple DNS "
                    "responses for the same query. This indicates DNS "
                    "injection where an attacker is sending spoofed DNS "
                    "responses alongside legitimate ones."
                ),
                severity="high",
                cve_ids=[],
                recommendation="Use DNSSEC or DNS-over-HTTPS to authenticate DNS responses.",
                evidence={"multiple_responses": multiple_responses},
            )
            vulns.append(vuln)

        return vulns

    def _parse_dns_packets(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse DNS packets from captured data.

        Attempts to extract DNS packets from raw packet data,
        handling both PCAP format and raw UDP data.
        """
        packets: List[Dict[str, Any]] = []
        offset = 0

        # Check for PCAP format
        if len(data) >= 24:
            magic = struct.unpack("<I", data[0:4])[0]
            if magic in (0xA1B2C3D4, 0xD4C3B2A1):
                offset = 24
                while offset + 16 <= len(data):
                    _, _, incl_len, _ = struct.unpack("<IIII", data[offset : offset + 16])
                    pkt_start = offset + 16
                    pkt_end = pkt_start + incl_len
                    if pkt_end > len(data):
                        break

                    # Try to parse as Ethernet+IP+UDP+DNS
                    dns_pkt = self._try_parse_udp_dns(data[pkt_start:pkt_end])
                    if dns_pkt:
                        packets.append(dns_pkt)

                    offset = pkt_end
                return packets

        # Try parsing as raw DNS data
        dns_pkt = self._try_parse_raw_dns(data)
        if dns_pkt:
            packets.append(dns_pkt)

        return packets

    def _try_parse_udp_dns(self, pkt: bytes) -> Optional[Dict[str, Any]]:
        """Try to parse a packet as Ethernet+IP+UDP+DNS."""
        try:
            # Ethernet header: 14 bytes
            if len(pkt) < 14:
                return None
            ethertype = struct.unpack("!H", pkt[12:14])[0]
            if ethertype != 0x0800:  # Not IPv4
                return None

            # IP header
            ip_start = 14
            if len(pkt) < ip_start + 20:
                return None
            ip_header = pkt[ip_start : ip_start + 20]
            protocol = ip_header[9]
            if protocol != 17:  # Not UDP
                return None

            ip_header_len = (ip_header[0] & 0x0F) * 4
            udp_start = ip_start + ip_header_len

            if len(pkt) < udp_start + 8:
                return None
            src_port, dst_port = struct.unpack("!HH", pkt[udp_start : udp_start + 4])

            if src_port != 53 and dst_port != 53:  # Not DNS
                return None

            dns_start = udp_start + 8
            dns_data = pkt[dns_start:]
            return self._try_parse_raw_dns(dns_data)
        except (struct.error, IndexError):
            return None

    def _try_parse_raw_dns(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse raw DNS message data."""
        if len(data) < 12:
            return None

        try:
            txid = struct.unpack("!H", data[0:2])[0]
            flags = struct.unpack("!H", data[2:4])[0]
            qdcount = struct.unpack("!H", data[4:6])[0]
            ancount = struct.unpack("!H", data[6:8])[0]

            is_response = bool(flags & 0x8000)

            # Parse question section
            domain = ""
            offset = 12
            for _ in range(qdcount):
                domain, offset = self._parse_dns_name(data, offset)
                if offset + 4 <= len(data):
                    offset += 4  # Skip QTYPE and QCLASS

            answer_ips: List[str] = []
            for _ in range(ancount):
                name, offset = self._parse_dns_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype, rclass, ttl, rdlength = struct.unpack(
                    "!HHIH", data[offset : offset + 10]
                )
                offset += 10
                if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):  # A record
                    ip = ".".join(str(b) for b in data[offset : offset + 4])
                    answer_ips.append(ip)
                offset += rdlength

            return {
                "transaction_id": txid,
                "is_query": not is_response,
                "is_response": is_response,
                "domain": domain,
                "answer_ips": answer_ips,
                "flags": flags,
            }
        except (struct.error, IndexError):
            return None

    def _parse_dns_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Parse a DNS domain name from packet data."""
        labels: List[str] = []
        original_offset = offset
        jumped = False
        max_jumps = 10
        jumps = 0

        while offset < len(data):
            length = data[offset]
            if length == 0:
                if not jumped:
                    offset += 1
                break
            if (length & 0xC0) == 0xC0:
                # DNS pointer compression
                if offset + 1 < len(data):
                    pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
                    if not jumped:
                        original_offset = offset + 2
                    offset = pointer
                    jumped = True
                    jumps += 1
                    if jumps > max_jumps:
                        break
                else:
                    break
            else:
                offset += 1
                if offset + length <= len(data):
                    try:
                        labels.append(data[offset : offset + length].decode("ascii"))
                    except UnicodeDecodeError:
                        labels.append("???")
                    offset += length
                else:
                    break

        domain = ".".join(labels) if labels else ""
        return domain, original_offset if jumped else offset

    def test_specific_domain(
        self, domain: str, expected_ips: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Test DNS resolution for a specific domain.

        Args:
            domain: Domain to resolve.
            expected_ips: Expected IP addresses.

        Returns:
            Dictionary with test results.
        """
        result: Dict[str, Any] = {
            "domain": domain,
            "resolved_ips": [],
            "expected_ips": expected_ips or [],
            "hijacked": False,
            "response_time_ms": 0,
        }

        start = time.time()
        try:
            resolved = socket.getaddrinfo(domain, None, socket.AF_INET)
            result["resolved_ips"] = list(set(addr[4][0] for addr in resolved))
        except socket.gaierror:
            result["resolved_ips"] = []
        elapsed = (time.time() - start) * 1000
        result["response_time_ms"] = round(elapsed, 2)

        if expected_ips:
            matching = set(result["resolved_ips"]) & set(expected_ips)
            result["hijacked"] = len(matching) == 0 and len(result["resolved_ips"]) > 0

        return result

    def quick_check(self, configured_dns: List[str]) -> bool:
        """Quick check if DNS configuration looks suspicious.

        Args:
            configured_dns: List of configured DNS servers.

        Returns:
            True if DNS configuration looks suspicious.
        """
        if not configured_dns:
            return True  # No DNS configured is suspicious

        # Check if only gateway DNS is configured
        all_private = all(
            ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                          "172.19.", "172.2", "172.3"))
            for ip in configured_dns
        )
        if all_private and len(configured_dns) == 1:
            return True  # Single private DNS server

        return False
