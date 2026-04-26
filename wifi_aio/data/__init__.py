"""WiFiAIO data sub-package.

Provides reference data modules for WiFi security assessments
including OUI databases, password lists, channel tables,
encryption definitions, and CVE databases.
"""

from wifi_aio.data.oui_database import OUIDatabase
from wifi_aio.data.common_passwords import COMMON_PASSWORDS, get_common_passwords
from wifi_aio.data.wps_pins import WPS_PINS, generate_wps_pin, validate_wps_pin
from wifi_aio.data.router_defaults import ROUTER_DEFAULTS, get_router_defaults
from wifi_aio.data.wifi_channels import WIFI_CHANNELS_2GHZ, WIFI_CHANNELS_5GHZ, channel_to_frequency, frequency_to_channel
from wifi_aio.data.wifi6e_channels import WIFI6E_CHANNELS, WIFI6E_PSC_CHANNELS
from wifi_aio.data.wifi7_features import WIFI7_FEATURES, WiFi7FeatureSet
from wifi_aio.data.encryption_suites import ENCRYPTION_SUITES, get_encryption_suite
from wifi_aio.data.cve_database import CVE_DATABASE, search_cves
from wifi_aio.data.wordlist_rules import WORDLIST_RULES, apply_rule
from wifi_aio.data.port_services import PORT_SERVICES, get_service_by_port
from wifi_aio.data.reason_codes import REASON_CODES, STATUS_CODES, get_reason_code, get_status_code

__all__ = [
    "OUIDatabase",
    "COMMON_PASSWORDS",
    "get_common_passwords",
    "WPS_PINS",
    "generate_wps_pin",
    "validate_wps_pin",
    "ROUTER_DEFAULTS",
    "get_router_defaults",
    "WIFI_CHANNELS_2GHZ",
    "WIFI_CHANNELS_5GHZ",
    "channel_to_frequency",
    "frequency_to_channel",
    "WIFI6E_CHANNELS",
    "WIFI6E_PSC_CHANNELS",
    "WIFI7_FEATURES",
    "WiFi7FeatureSet",
    "ENCRYPTION_SUITES",
    "get_encryption_suite",
    "CVE_DATABASE",
    "search_cves",
    "WORDLIST_RULES",
    "apply_rule",
    "PORT_SERVICES",
    "get_service_by_port",
    "REASON_CODES",
    "STATUS_CODES",
    "get_reason_code",
    "get_status_code",
]
