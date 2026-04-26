"""WiFiAIO rogue access point sub-package.

Provides all components needed to create and manage a rogue AP:
hostapd management, DHCP/DNS services, HTTP/HTTPS captive portals,
credential logging, client monitoring, and SSL certificate generation.
"""

from wifi_aio.rogue.hostapd_manager import HostapdManager
from wifi_aio.rogue.dhcp_server import DHCPServer
from wifi_aio.rogue.dns_server import DNSServer
from wifi_aio.rogue.http_server import HTTPServer
from wifi_aio.rogue.https_server import HTTPSServer
from wifi_aio.rogue.captive_portal import CaptivePortal
from wifi_aio.rogue.credential_logger import CredentialLogger
from wifi_aio.rogue.client_monitor import ClientMonitor, ClientInfo
from wifi_aio.rogue.ssl_cert_gen import SSLCertGenerator

__all__ = [
    "HostapdManager",
    "DHCPServer",
    "DNSServer",
    "HTTPServer",
    "HTTPSServer",
    "CaptivePortal",
    "CredentialLogger",
    "ClientMonitor",
    "ClientInfo",
    "SSLCertGenerator",
]
