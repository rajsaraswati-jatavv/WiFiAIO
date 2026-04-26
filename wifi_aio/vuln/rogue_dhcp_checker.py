"""Rogue DHCP server checker for WiFiAIO.

Detects rogue DHCP servers on the network that may be distributing
malicious DNS settings, gateways, or other network configuration.
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from wifi_aio.exceptions import WiFiConnectionError, WiFiTimeoutError

logger = logging.getLogger(__name__)


class DHCPMessageType(Enum):
    """DHCP message types."""
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8


class RogueDHCPSeverity(Enum):
    """Severity of rogue DHCP detection."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RogueDHCPVulnerability:
    """Represents a single rogue DHCP vulnerability finding."""
    vuln_id: str
    title: str
    description: str
    severity: str
    cve_ids: List[str] = field(default_factory=list)
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DHCPServerInfo:
    """Information about a discovered DHCP server."""
    ip: str
    mac: str = ""
    offered_ip: str = ""
    subnet_mask: str = ""
    gateway: str = ""
    dns_servers: List[str] = field(default_factory=list)
    lease_time: int = 0
    domain_name: str = ""
    is_rogue: bool = False
    is_legitimate: bool = False
    confidence: str = "low"  # "low", "medium", "high"


@dataclass
class RogueDHCPScanResult:
    """Aggregated result of a rogue DHCP scan."""
    is_vulnerable: bool
    vulnerabilities: List[RogueDHCPVulnerability] = field(default_factory=list)
    legitimate_dhcp_servers: List[DHCPServerInfo] = field(default_factory=list)
    rogue_dhcp_servers: List[DHCPServerInfo] = field(default_factory=list)
    total_dhcp_servers: int = 0
    gateway_ip: str = ""
    expected_gateway: str = ""
    scan_timestamp: float = 0.0


# DHCP option codes
DHCP_OPTIONS = {
    1: "Subnet Mask",
    3: "Router/Gateway",
    6: "DNS Server",
    12: "Host Name",
    15: "Domain Name",
    28: "Broadcast Address",
    42: "NTP Server",
    44: "NetBIOS Name Server",
    51: "Lease Time",
    53: "DHCP Message Type",
    54: "Server Identifier",
    58: "Renewal Time (T1)",
    59: "Rebinding Time (T2)",
    119: "Domain Search",
    252: "WPAD URL",
}

# DHCP magic cookie
DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"

# Known legitimate DHCP server IP patterns
LEGITIMATE_GATEWAY_PATTERNS = [
    "192.168.1.1", "192.168.0.1", "192.168.2.1",
    "10.0.0.1", "10.1.1.1", "10.0.1.1",
]


def _build_dhcp_discover(
    mac_address: str = "00:00:00:00:00:00",
    transaction_id: int = 0,
) -> bytes:
    """Build a DHCPDISCOVER packet.

    Args:
        mac_address: Client MAC address.
        transaction_id: Transaction ID for the DHCP exchange.

    Returns:
        Raw DHCP discover packet bytes.
    """
    # Convert MAC to bytes
    mac_bytes = bytes(int(o, 16) for o in mac_address.split(":"))

    # Build DHCP packet
    packet = bytearray(240)  # Minimum DHCP packet size

    # Op: 1 = BOOTREQUEST
    packet[0] = 1
    # Hardware type: 1 = Ethernet
    packet[1] = 1
    # Hardware address length
    packet[2] = 6
    # Hops
    packet[3] = 0
    # Transaction ID
    struct.pack_into("!I", packet, 4, transaction_id)
    # Seconds elapsed
    struct.pack_into("!H", packet, 8, 0)
    # Flags (broadcast flag)
    struct.pack_into("!H", packet, 10, 0x8000)
    # Client IP: 0.0.0.0
    struct.pack_into("!I", packet, 12, 0)
    # Your IP: 0.0.0.0
    struct.pack_into("!I", packet, 16, 0)
    # Server IP: 0.0.0.0
    struct.pack_into("!I", packet, 20, 0)
    # Relay IP: 0.0.0.0
    struct.pack_into("!I", packet, 24, 0)
    # Client MAC
    packet[28:34] = mac_bytes

    # Magic cookie
    packet[236:240] = DHCP_MAGIC_COOKIE

    # DHCP options
    options = bytearray()
    # Option 53: DHCP Message Type = DISCOVER (1)
    options += bytes([53, 1, DHCPMessageType.DISCOVER.value])
    # Option 55: Parameter Request List
    options += bytes([55, 4, 1, 3, 6, 51])  # Subnet, Router, DNS, Lease
    # End option
    options += bytes([255])

    return bytes(packet[:236]) + DHCP_MAGIC_COOKIE + bytes(options)


def _parse_dhcp_response(data: bytes) -> Dict[str, Any]:
    """Parse a DHCP response packet (DHCPOFFER or DHCPACK).

    Args:
        data: Raw DHCP response packet bytes.

    Returns:
        Dictionary with parsed DHCP fields.
    """
    result: Dict[str, Any] = {
        "op": data[0] if len(data) > 0 else 0,
        "transaction_id": struct.unpack("!I", data[4:8])[0] if len(data) >= 8 else 0,
        "offered_ip": socket.inet_ntoa(data[16:20]) if len(data) >= 20 else "",
        "server_ip": socket.inet_ntoa(data[20:24]) if len(data) >= 24 else "",
        "client_mac": ":".join(f"{b:02x}" for b in data[28:34]) if len(data) >= 34 else "",
        "options": {},
    }

    # Parse options (starting after magic cookie at offset 236)
    if len(data) < 240:
        return result

    magic = data[236:240]
    if magic != DHCP_MAGIC_COOKIE:
        return result

    offset = 240
    while offset < len(data):
        opt_code = data[offset]
        if opt_code == 255:  # End
            break
        if opt_code == 0:  # Padding
            offset += 1
            continue

        if offset + 1 >= len(data):
            break
        opt_len = data[offset + 1]

        if offset + 2 + opt_len > len(data):
            break

        opt_data = data[offset + 2 : offset + 2 + opt_len]

        if opt_code == 53:  # Message Type
            result["message_type"] = opt_data[0] if opt_data else 0
        elif opt_code == 54:  # Server Identifier
            result["options"]["server_id"] = socket.inet_ntoa(opt_data[:4]) if len(opt_data) >= 4 else ""
        elif opt_code == 1:  # Subnet Mask
            result["options"]["subnet_mask"] = socket.inet_ntoa(opt_data[:4]) if len(opt_data) >= 4 else ""
        elif opt_code == 3:  # Router/Gateway
            gateways = []
            for i in range(0, len(opt_data) - 3, 4):
                gateways.append(socket.inet_ntoa(opt_data[i : i + 4]))
            result["options"]["gateway"] = gateways
        elif opt_code == 6:  # DNS Server
            dns_servers = []
            for i in range(0, len(opt_data) - 3, 4):
                dns_servers.append(socket.inet_ntoa(opt_data[i : i + 4]))
            result["options"]["dns_servers"] = dns_servers
        elif opt_code == 51:  # Lease Time
            result["options"]["lease_time"] = struct.unpack("!I", opt_data[:4])[0] if len(opt_data) >= 4 else 0
        elif opt_code == 15:  # Domain Name
            try:
                result["options"]["domain_name"] = opt_data.decode("ascii").strip("\x00")
            except UnicodeDecodeError:
                pass
        elif opt_code == 252:  # WPAD URL
            try:
                result["options"]["wpad_url"] = opt_data.decode("ascii").strip("\x00")
            except UnicodeDecodeError:
                pass

        offset += 2 + opt_len

    return result


class RogueDHCPChecker:
    """Detects rogue DHCP servers on the network.

    Sends DHCP discover messages and analyzes responses to identify
    unauthorized DHCP servers that may be distributing malicious
    network configuration.

    Usage::

        checker = RogueDHCPChecker(interface="eth0")
        result = checker.check(expected_gateway="192.168.1.1")
        if result.is_vulnerable:
            for server in result.rogue_dhcp_servers:
                print(f"Rogue DHCP: {server.ip} offering gateway {server.gateway}")
    """

    # Number of DHCP discover attempts
    DISCOVER_ATTEMPTS = 3
    # Timeout per discover attempt in seconds
    DISCOVER_TIMEOUT = 5
    # DHCP server port
    DHCP_SERVER_PORT = 67
    DHCP_CLIENT_PORT = 68

    def __init__(
        self,
        interface: str = "eth0",
        timeout: int = 5,
        expected_gateway: str = "",
        expected_dns: Optional[List[str]] = None,
    ) -> None:
        """Initialize the rogue DHCP checker.

        Args:
            interface: Network interface to send DHCP discovers on.
            timeout: Timeout for DHCP response in seconds.
            expected_gateway: Expected legitimate gateway IP.
            expected_dns: Expected legitimate DNS servers.
        """
        self.interface = interface
        self.timeout = timeout
        self.expected_gateway = expected_gateway
        self.expected_dns = expected_dns or []
        self._discovered_servers: List[DHCPServerInfo] = []
        logger.info("RogueDHCPChecker initialized on interface %s", interface)

    def check(
        self,
        expected_gateway: str = "",
        expected_dns: Optional[List[str]] = None,
        expected_dhcp_servers: Optional[List[str]] = None,
        capture_data: Optional[bytes] = None,
    ) -> RogueDHCPScanResult:
        """Perform a rogue DHCP server check.

        Args:
            expected_gateway: Expected legitimate gateway IP.
            expected_dns: Expected legitimate DNS servers.
            expected_dhcp_servers: Expected legitimate DHCP server IPs.
            capture_data: Pre-captured DHCP traffic for analysis.

        Returns:
            RogueDHCPScanResult with findings.
        """
        start_time = time.time()
        result = RogueDHCPScanResult(
            is_vulnerable=False,
            expected_gateway=expected_gateway or self.expected_gateway,
            scan_timestamp=start_time,
        )

        gateway = expected_gateway or self.expected_gateway
        dns_list = expected_dns or self.expected_dns
        expected_servers = expected_dhcp_servers or []

        # Step 1: Send DHCP discovers and collect responses
        discovered = self._send_dhcp_discovers()
        result.total_dhcp_servers = len(discovered)

        for server in discovered:
            server_info = DHCPServerInfo(
                ip=server.get("server_ip", ""),
                mac=server.get("client_mac", ""),
                offered_ip=server.get("offered_ip", ""),
                subnet_mask=server.get("options", {}).get("subnet_mask", ""),
                gateway=server.get("options", {}).get("gateway", [""])[0] if server.get("options", {}).get("gateway") else "",
                dns_servers=server.get("options", {}).get("dns_servers", []),
                lease_time=server.get("options", {}).get("lease_time", 0),
                domain_name=server.get("options", {}).get("domain_name", ""),
            )

            # Classify the server
            is_legitimate = self._classify_server(
                server_info, gateway, dns_list, expected_servers
            )
            server_info.is_legitimate = is_legitimate
            server_info.is_rogue = not is_legitimate

            if is_legitimate:
                result.legitimate_dhcp_servers.append(server_info)
            else:
                result.rogue_dhcp_servers.append(server_info)

        # Step 2: Analyze captured data if provided
        if capture_data:
            captured_servers = self._analyze_capture_data(capture_data)
            for server in captured_servers:
                is_legitimate = self._classify_server(
                    server, gateway, dns_list, expected_servers
                )
                server.is_legitimate = is_legitimate
                server.is_rogue = not is_legitimate

                # Check if already discovered
                already_known = any(
                    s.ip == server.ip and s.mac == server.mac
                    for s in result.legitimate_dhcp_servers + result.rogue_dhcp_servers
                )
                if not already_known:
                    result.total_dhcp_servers += 1
                    if is_legitimate:
                        result.legitimate_dhcp_servers.append(server)
                    else:
                        result.rogue_dhcp_servers.append(server)

        # Step 3: Generate vulnerabilities based on findings
        if result.rogue_dhcp_servers:
            for rogue in result.rogue_dhcp_servers:
                # Rogue DHCP server detected
                rogue_vuln = RogueDHCPVulnerability(
                    vuln_id="RDHCP-001",
                    title="Rogue DHCP Server Detected",
                    description=(
                        f"A rogue DHCP server at {rogue.ip} (MAC: {rogue.mac}) "
                        f"is offering IP {rogue.offered_ip} with gateway "
                        f"{rogue.gateway} and DNS servers {rogue.dns_servers}. "
                        "This allows the attacker to perform man-in-the-middle "
                        "attacks by controlling the default gateway and DNS "
                        "resolution for clients."
                    ),
                    severity="critical",
                    cve_ids=[],
                    recommendation=(
                        "Enable DHCP snooping on network switches to block "
                        "unauthorized DHCP responses. Identify and remove the "
                        "rogue device. Configure DHCP server authentication."
                    ),
                    evidence={
                        "rogue_ip": rogue.ip,
                        "rogue_mac": rogue.mac,
                        "offered_gateway": rogue.gateway,
                        "offered_dns": rogue.dns_servers,
                    },
                )
                result.vulnerabilities.append(rogue_vuln)

                # Check for suspicious gateway
                if gateway and rogue.gateway and rogue.gateway != gateway:
                    gw_vuln = RogueDHCPVulnerability(
                        vuln_id="RDHCP-002",
                        title="Rogue DHCP Offering Malicious Gateway",
                        description=(
                            f"Rogue DHCP server is offering gateway {rogue.gateway} "
                            f"instead of the legitimate gateway {gateway}. This "
                            "routes all traffic through the attacker's machine."
                        ),
                        severity="critical",
                        cve_ids=[],
                        recommendation=(
                            "Block the rogue DHCP server and configure static "
                            "gateway settings on critical devices."
                        ),
                        evidence={
                            "offered_gateway": rogue.gateway,
                            "legitimate_gateway": gateway,
                        },
                    )
                    result.vulnerabilities.append(gw_vuln)

                # Check for suspicious DNS
                if dns_list and rogue.dns_servers:
                    suspicious_dns = set(rogue.dns_servers) - set(dns_list)
                    if suspicious_dns:
                        dns_vuln = RogueDHCPVulnerability(
                            vuln_id="RDHCP-003",
                            title="Rogue DHCP Offering Malicious DNS Servers",
                            description=(
                                f"Rogue DHCP server is offering DNS servers "
                                f"{list(suspicious_dns)} instead of legitimate "
                                f"servers {dns_list}. This enables DNS "
                                "hijacking and traffic interception."
                            ),
                            severity="critical",
                            cve_ids=[],
                            recommendation="Configure DNS manually on all devices.",
                            evidence={
                                "offered_dns": rogue.dns_servers,
                                "legitimate_dns": dns_list,
                                "suspicious_dns": list(suspicious_dns),
                            },
                        )
                        result.vulnerabilities.append(dns_vuln)

                # Check for WPAD URL injection
                wpad_url = getattr(rogue, "wpad_url", "")
                if wpad_url:
                    wpad_vuln = RogueDHCPVulnerability(
                        vuln_id="RDHCP-004",
                        title="WPAD URL Injection via DHCP",
                        description=(
                            f"Rogue DHCP server is offering WPAD URL: {wpad_url}. "
                            "This can force clients to use a malicious proxy "
                            "server for all web traffic."
                        ),
                        severity="critical",
                        cve_ids=["CVE-2016-1010"],
                        recommendation="Disable WPAD on all devices and browsers.",
                        evidence={"wpad_url": wpad_url},
                    )
                    result.vulnerabilities.append(wpad_vuln)

        # Step 4: Check for DHCP starvation attack indicators
        if result.total_dhcp_servers > 3:
            starvation_vuln = RogueDHCPVulnerability(
                vuln_id="RDHCP-005",
                title="Multiple DHCP Servers - Possible Starvation Attack",
                description=(
                    f"Detected {result.total_dhcp_servers} DHCP servers on the "
                    "network. Multiple DHCP servers may indicate a DHCP "
                    "starvation attack where an attacker exhausts the address "
                    "pool of the legitimate server."
                ),
                severity="medium",
                cve_ids=[],
                recommendation=(
                    "Enable DHCP snooping and port security on switches. "
                    "Monitor DHCP pool utilization."
                ),
                evidence={"total_servers": result.total_dhcp_servers},
            )
            result.vulnerabilities.append(starvation_vuln)

        result.is_vulnerable = len(result.vulnerabilities) > 0
        logger.info(
            "Rogue DHCP check complete: %d servers found (%d rogue), %d vulnerabilities",
            result.total_dhcp_servers,
            len(result.rogue_dhcp_servers),
            len(result.vulnerabilities),
        )
        return result

    def _send_dhcp_discovers(self) -> List[Dict[str, Any]]:
        """Send DHCP discover messages and collect responses.

        Returns:
            List of DHCP response dictionaries.
        """
        responses: List[Dict[str, Any]] = []
        seen_servers: set = set()

        for attempt in range(self.DISCOVER_ATTEMPTS):
            tx_id = int(time.time()) + attempt * 1000

            try:
                discover = _build_dhcp_discover(
                    mac_address="00:00:00:00:00:00",
                    transaction_id=tx_id,
                )

                # Create broadcast socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(self.DISCOVER_TIMEOUT)

                try:
                    sock.bind(("0.0.0.0", self.DHCP_CLIENT_PORT))
                except (OSError, PermissionError):
                    # If we can't bind to port 68, try a high port
                    try:
                        sock.bind(("0.0.0.0", 0))
                    except (OSError, PermissionError):
                        sock.close()
                        continue

                # Send discover
                try:
                    sock.sendto(discover, ("<broadcast>", self.DHCP_SERVER_PORT))
                except (OSError, PermissionError):
                    sock.close()
                    continue

                # Wait for responses
                start = time.time()
                while time.time() - start < self.DISCOVER_TIMEOUT:
                    try:
                        data, addr = sock.recvfrom(4096)
                        parsed = _parse_dhcp_response(data)

                        if parsed.get("message_type") in (
                            DHCPMessageType.OFFER.value,
                            DHCPMessageType.ACK.value,
                        ):
                            server_ip = parsed.get("server_ip", "") or addr[0]
                            if server_ip and server_ip not in seen_servers:
                                seen_servers.add(server_ip)
                                responses.append(parsed)
                    except socket.timeout:
                        break
                    except (OSError, socket.error):
                        break

                sock.close()

            except (OSError, PermissionError) as e:
                logger.debug("DHCP discover attempt %d failed: %s", attempt, e)
                continue

        return responses

    def _analyze_capture_data(self, data: bytes) -> List[DHCPServerInfo]:
        """Analyze captured DHCP traffic for rogue servers."""
        servers: List[DHCPServerInfo] = []

        # Parse packets looking for DHCP OFFER/ACK
        offset = 0
        while offset < len(data):
            # Look for DHCP magic cookie to find DHCP packets
            idx = data.find(DHCP_MAGIC_COOKIE, offset)
            if idx == -1:
                break

            # The DHCP packet starts 4 bytes before the magic cookie
            pkt_start = max(0, idx - 236)
            pkt_end = min(len(data), idx + 300)  # Reasonable DHCP packet size

            parsed = _parse_dhcp_response(data[pkt_start:pkt_end])
            if parsed.get("message_type") in (
                DHCPMessageType.OFFER.value,
                DHCPMessageType.ACK.value,
            ):
                server_info = DHCPServerInfo(
                    ip=parsed.get("server_ip", ""),
                    offered_ip=parsed.get("offered_ip", ""),
                    gateway=parsed.get("options", {}).get("gateway", [""])[0] if parsed.get("options", {}).get("gateway") else "",
                    dns_servers=parsed.get("options", {}).get("dns_servers", []),
                    lease_time=parsed.get("options", {}).get("lease_time", 0),
                    domain_name=parsed.get("options", {}).get("domain_name", ""),
                )
                servers.append(server_info)

            offset = idx + 4

        return servers

    def _classify_server(
        self,
        server: DHCPServerInfo,
        expected_gateway: str,
        expected_dns: List[str],
        expected_servers: List[str],
    ) -> bool:
        """Classify a DHCP server as legitimate or rogue.

        Args:
            server: DHCP server info to classify.
            expected_gateway: Expected legitimate gateway.
            expected_dns: Expected legitimate DNS servers.
            expected_servers: Expected legitimate DHCP server IPs.

        Returns:
            True if the server appears legitimate.
        """
        # If we have a list of expected servers, check against it
        if expected_servers:
            return server.ip in expected_servers

        # Check gateway
        if expected_gateway and server.gateway:
            if server.gateway != expected_gateway:
                return False

        # Check DNS
        if expected_dns and server.dns_servers:
            for dns in server.dns_servers:
                if dns not in expected_dns:
                    # Allow ISP DNS servers (not in our expected list but not necessarily rogue)
                    # Only flag if the DNS points to a private IP that isn't the gateway
                    if dns.startswith(("10.", "192.168.")):
                        if dns != expected_gateway:
                            return False

        # Check for suspicious configuration patterns
        # Very short lease time may indicate a rogue server
        if server.lease_time > 0 and server.lease_time < 60:
            return False

        # If the server IP is in a completely different subnet from the offered IP
        if server.ip and server.offered_ip:
            server_prefix = ".".join(server.ip.split(".")[:3])
            offered_prefix = ".".join(server.offered_ip.split(".")[:3])
            if server_prefix != offered_prefix:
                # Server and offered IP in different subnets - suspicious
                pass  # Could be legitimate for relay agents

        return True  # Default to legitimate if no clear signs of being rogue

    def monitor_dhcp(
        self,
        duration: int = 60,
        expected_gateway: str = "",
    ) -> Dict[str, Any]:
        """Monitor for rogue DHCP servers over a time period.

        Args:
            duration: Duration to monitor in seconds.
            expected_gateway: Expected legitimate gateway IP.

        Returns:
            Dictionary with monitoring results.
        """
        result: Dict[str, Any] = {
            "monitored_duration": duration,
            "dhcp_servers_seen": [],
            "rogue_servers": [],
            "total_offers": 0,
        }

        start_time = time.time()
        seen_servers: Dict[str, Dict[str, Any]] = {}

        while time.time() - start_time < duration:
            tx_id = int(time.time())
            try:
                discover = _build_dhcp_discover(transaction_id=tx_id)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(self.DISCOVER_TIMEOUT)

                try:
                    sock.bind(("0.0.0.0", 0))
                    sock.sendto(discover, ("<broadcast>", self.DHCP_SERVER_PORT))

                    data, addr = sock.recvfrom(4096)
                    parsed = _parse_dhcp_response(data)
                    server_ip = parsed.get("server_ip", "") or addr[0]

                    if server_ip and server_ip not in seen_servers:
                        seen_servers[server_ip] = {
                            "ip": server_ip,
                            "gateway": parsed.get("options", {}).get("gateway", []),
                            "dns": parsed.get("options", {}).get("dns_servers", []),
                            "first_seen": time.time(),
                        }
                        result["total_offers"] += 1

                except (socket.timeout, OSError, PermissionError):
                    pass
                finally:
                    sock.close()

            except (OSError, PermissionError):
                pass

            # Wait before next discover
            time.sleep(min(10, duration / 6))

        result["dhcp_servers_seen"] = list(seen_servers.values())

        # Classify servers
        for server in seen_servers.values():
            gateway_list = server.get("gateway", [])
            if expected_gateway and gateway_list and gateway_list[0] != expected_gateway:
                result["rogue_servers"].append(server)

        return result

    def quick_check(self, expected_gateway: str = "") -> bool:
        """Quick check for any rogue DHCP servers.

        Args:
            expected_gateway: Expected legitimate gateway IP.

        Returns:
            True if a rogue DHCP server is detected.
        """
        result = self.check(expected_gateway=expected_gateway)
        return len(result.rogue_dhcp_servers) > 0
