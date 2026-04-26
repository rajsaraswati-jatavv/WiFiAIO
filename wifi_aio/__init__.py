"""WiFiAIO - All-in-One WiFi Security Toolkit."""

__version__ = "3.0.0"
__author__ = "WiFiAIO Contributors"
__license__ = "MIT"
__description__ = "Comprehensive WiFi security auditing and analysis toolkit"

from wifi_aio.exceptions import (
    WiFiAIOError,
    ScanError,
    NoNetworksFoundError,
    DeauthError,
    PMFBlockedError,
    FrameInjectionError,
    RogueAPError,
    HostAPDError,
    DHCPError,
    CrackingError,
    WordlistNotFoundError,
    HashExtractionError,
    WPSError,
    WPSLockoutError,
    WPSPinError,
    CaptureError,
    PCAPError,
    InterfaceError,
    MonitorModeError,
    OSINTError,
    GeolocationError,
    ForensicsError,
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    ConfigurationError,
    DatabaseError,
    PluginError,
    AutomationError,
    VulnerabilityError,
    ComplianceError,
    UpdateError,
)

try:
    from wifi_aio.constants import (
        __version__ as constants_version,
        SecurityType,
        Severity,
        FrameType,
        FrameSubtype,
        CipherSuite,
        AKMType,
        CHANNEL_2GHZ,
        CHANNEL_5GHZ,
        FREQ_TO_CHANNEL,
        ALL_CHANNELS,
        WIFI_STANDARDS,
        RSSI_EXCELLENT,
        RSSI_GOOD,
        RSSI_FAIR,
        RSSI_POOR,
        RSSI_UNUSABLE,
        rssi_quality,
        SECURITY_RISK,
        REASON_CODES,
        COMMON_OUI,
    )
except ImportError:
    pass

from wifi_aio.config import ConfigManager
from wifi_aio.logger import get_logger
try:
    from wifi_aio.logger import setup_logger
except ImportError:
    setup_logger = None  # type: ignore[assignment]
from wifi_aio.database import Database
try:
    from wifi_aio.validators import (
        validate_mac,
        validate_ssid,
        validate_channel,
        validate_ip,
        validate_bssid,
        validate_wps_pin,
        validate_filepath,
    )
except ImportError:
    pass
try:
    from wifi_aio.utils import (
        random_mac,
        random_hex,
        mac_format,
        channel_to_freq,
        freq_to_channel,
        run_command,
        read_file_lines,
        sanitize_filename,
        is_root,
        which_tool,
    )
except ImportError:
    pass
try:
    from wifi_aio.crypto_utils import (
        pbkdf2_sha1,
        derive_ptk,
        verify_mic,
        prf_80211,
        aes_unwrap,
        hmac_sha1,
        hmac_sha256,
    )
except ImportError:
    pass
try:
    from wifi_aio.network_utils import (
        get_interfaces,
        set_monitor_mode,
        set_managed_mode,
        channel_hop,
        get_current_channel,
    )
except ImportError:
    pass
try:
    from wifi_aio.platform_detect import detect_platform, Platform
except ImportError:
    pass
try:
    from wifi_aio.plugin_manager import PluginManager
except ImportError:
    pass
try:
    from wifi_aio.update_checker import check_for_updates
except ImportError:
    pass
try:
    from wifi_aio.auto_installer import auto_install
except ImportError:
    pass
try:
    from wifi_aio.dependency_checker import check_dependencies
except ImportError:
    pass
try:
    from wifi_aio.i18n import I18n
except ImportError:
    pass
try:
    from wifi_aio.theme import ThemeManager
except ImportError:
    pass
try:
    from wifi_aio.export_engine import ExportEngine
except ImportError:
    pass
try:
    from wifi_aio.report_engine import ReportEngine
except ImportError:
    pass
try:
    from wifi_aio.notification import NotificationManager
except ImportError:
    pass
try:
    from wifi_aio.scheduler import TaskScheduler
except ImportError:
    pass
try:
    from wifi_aio.session import SessionManager
except ImportError:
    pass
try:
    from wifi_aio.auto_updater import AutoUpdater
except ImportError:
    pass

__all__ = [
    # Version / metadata
    "__version__",
    "__author__",
    "__license__",
    "__description__",
    # Exceptions
    "WiFiAIOError",
    "ScanError",
    "NoNetworksFoundError",
    "DeauthError",
    "PMFBlockedError",
    "FrameInjectionError",
    "RogueAPError",
    "HostAPDError",
    "DHCPError",
    "CrackingError",
    "WordlistNotFoundError",
    "HashExtractionError",
    "WPSError",
    "WPSLockoutError",
    "WPSPinError",
    "CaptureError",
    "PCAPError",
    "InterfaceError",
    "MonitorModeError",
    "OSINTError",
    "GeolocationError",
    "ForensicsError",
    "WiFiConnectionError",
    "WiFiPermissionError",
    "WiFiTimeoutError",
    "ConfigurationError",
    "DatabaseError",
    "PluginError",
    "AutomationError",
    "VulnerabilityError",
    "ComplianceError",
    "UpdateError",
    # Constants / Enums
    "SecurityType",
    "Severity",
    "FrameType",
    "FrameSubtype",
    "CipherSuite",
    "AKMType",
    "CHANNEL_2GHZ",
    "CHANNEL_5GHZ",
    "FREQ_TO_CHANNEL",
    "ALL_CHANNELS",
    "WIFI_STANDARDS",
    "RSSI_EXCELLENT",
    "RSSI_GOOD",
    "RSSI_FAIR",
    "RSSI_POOR",
    "RSSI_UNUSABLE",
    "rssi_quality",
    "SECURITY_RISK",
    "REASON_CODES",
    "COMMON_OUI",
    # Config / Logging / Database
    "ConfigManager",
    "setup_logger",
    "get_logger",
    "Database",
    # Validators
    "validate_mac",
    "validate_ssid",
    "validate_channel",
    "validate_ip",
    "validate_bssid",
    "validate_wps_pin",
    "validate_filepath",
    # Utilities
    "random_mac",
    "random_hex",
    "mac_format",
    "channel_to_freq",
    "freq_to_channel",
    "run_command",
    "read_file_lines",
    "sanitize_filename",
    "is_root",
    "which_tool",
    # Crypto
    "pbkdf2_sha1",
    "derive_ptk",
    "verify_mic",
    "prf_80211",
    "aes_unwrap",
    "hmac_sha1",
    "hmac_sha256",
    # Network
    "get_interfaces",
    "set_monitor_mode",
    "set_managed_mode",
    "channel_hop",
    "get_current_channel",
    # Platform
    "detect_platform",
    "Platform",
    # Plugin / Update / Install / Deps
    "PluginManager",
    "check_for_updates",
    "auto_install",
    "check_dependencies",
    # i18n / Theme
    "I18n",
    "ThemeManager",
    # Export / Report / Notification
    "ExportEngine",
    "ReportEngine",
    "NotificationManager",
    # Scheduler / Session / AutoUpdater
    "TaskScheduler",
    "SessionManager",
    "AutoUpdater",
]
