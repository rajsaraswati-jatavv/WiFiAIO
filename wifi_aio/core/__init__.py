"""
WiFiAIO Core Module

Provides the core WiFi security auditing components:
- NetworkScanner: WiFi network scanning and discovery
- DeauthEngine: Deauthentication/disassociation frame injection
- EvilTwin: Rogue access point with captive portal
- PasswordCracker: WiFi password cracking (dictionary, brute-force, mask, hybrid, rule)
- WPSEngine: WPS Pixie Dust and PIN brute-force attacks
- FrameInjector: Custom 802.11 frame crafting and injection
- VulnScanner: Comprehensive vulnerability assessment
- SignalAnalyzer: Channel survey, signal measurement, heatmap
- HandshakeCapture: WPA/WPA2 handshake and PMKID capture
- PacketSniffer: Real-time packet capture with tshark/scapy
- Jammer: Channel jamming, deauth jamming, noise generation
- InterfaceManager: WiFi interface management (monitor/managed mode, channel, MAC)
- NetworkConnector: WiFi network connection (wpa_supplicant/nmcli)
- BluetoothScanner: Classic/BLE Bluetooth scanning and device discovery
- SpeedTester: Network speed, latency, and jitter testing
- Geolocation: WiFi AP geolocation (WiGLE, Google) and KML export
- Osint: Open Source Intelligence for WiFi networks
- Forensics: PCAP analysis, timeline reconstruction, credential extraction
- PasswordTools: Password generation, analysis, mutation, WPA passphrase
- WorkflowEngine: Automated security testing workflows
- Reporting: Scan, vulnerability, and compliance report generation
- SystemUtils: System utilities (root check, CPU/mem info, process management)
- ToolIntegration: External security tool integration
- TermuxModule: Android/Termux WiFi operations
- WiFi6E7: WiFi 6E/7 (6 GHz) support with HE/EHT capabilities
- ComplianceChecker: PCI-DSS, NIST, CIS, ISO 27001 compliance checks
"""

from wifi_aio.core.network_scanner import (
    NetworkScanner,
    ScanMode,
    SecurityType,
    AccessPoint,
    ClientStation,
)
from wifi_aio.core.deauth_engine import (
    DeauthEngine,
    FrameType as DeauthFrameType,
    ReasonCode,
    InjectionStats as DeauthInjectionStats,
)
from wifi_aio.core.evil_twin import (
    EvilTwin,
    CapturedCredential,
    CaptivePortalHandler,
)
from wifi_aio.core.password_cracker import (
    PasswordCracker,
    AttackMode,
    HashType,
    CrackResult,
    HandshakeData,
)
from wifi_aio.core.wps_engine import (
    WPSEngine,
    WPSMethod,
    WPSResult,
    WPSNetworkInfo,
)
from wifi_aio.core.frame_injector import (
    FrameInjector,
    IEBuilder,
    FrameCategory,
    ManagementSubtype,
    ControlSubtype,
    DataSubtype,
    InjectionResult,
    FuzzConfig,
)
from wifi_aio.core.vuln_scanner import (
    VulnScanner,
    Severity,
    VulnCategory,
    Vulnerability,
    AuditResult,
    _normalize_severity,
)
from wifi_aio.core.signal_analyzer import (
    SignalAnalyzer,
    SignalMeasurement,
    ChannelInfo,
    HeatmapPoint,
)
from wifi_aio.core.handshake_capture import (
    HandshakeCapture,
    CaptureState,
    HandshakeInfo,
)
from wifi_aio.core.packet_sniffer import (
    PacketSniffer,
    CaptureBackend,
    PacketInfo,
    CaptureStats,
)
from wifi_aio.core.jammer import (
    Jammer,
    JammerMode,
    JammerStats,
)
from wifi_aio.core.interface_manager import InterfaceManager
from wifi_aio.core.network_connector import NetworkConnector
from wifi_aio.core.bluetooth_scanner import BluetoothScanner
from wifi_aio.core.speed_tester import SpeedTester
from wifi_aio.core.geolocation import Geolocation
from wifi_aio.core.osint import Osint
from wifi_aio.core.forensics import Forensics
from wifi_aio.core.password_tools import PasswordTools
from wifi_aio.core.automation import (
    WorkflowEngine,
    WorkflowStep,
    WorkflowState,
)
from wifi_aio.core.reporting import Reporting
from wifi_aio.core.system_utils import SystemUtils
from wifi_aio.core.tool_integration import ToolIntegration
from wifi_aio.core.termux_module import TermuxModule
from wifi_aio.core.wifi_6e7 import WiFi6E7
from wifi_aio.core.compliance_checker import (
    ComplianceChecker,
    ComplianceStatus,
    ComplianceStandard,
)

__all__ = [
    # Network Scanner
    "NetworkScanner",
    "ScanMode",
    "SecurityType",
    "AccessPoint",
    "ClientStation",
    # Deauth Engine
    "DeauthEngine",
    "DeauthFrameType",
    "ReasonCode",
    "DeauthInjectionStats",
    # Evil Twin
    "EvilTwin",
    "CapturedCredential",
    "CaptivePortalHandler",
    # Password Cracker
    "PasswordCracker",
    "AttackMode",
    "HashType",
    "CrackResult",
    "HandshakeData",
    # WPS Engine
    "WPSEngine",
    "WPSMethod",
    "WPSResult",
    "WPSNetworkInfo",
    # Frame Injector
    "FrameInjector",
    "IEBuilder",
    "FrameCategory",
    "ManagementSubtype",
    "ControlSubtype",
    "DataSubtype",
    "InjectionResult",
    "FuzzConfig",
    # Vulnerability Scanner
    "VulnScanner",
    "Severity",
    "VulnCategory",
    "Vulnerability",
    "AuditResult",
    "_normalize_severity",
    # Signal Analyzer
    "SignalAnalyzer",
    "SignalMeasurement",
    "ChannelInfo",
    "HeatmapPoint",
    # Handshake Capture
    "HandshakeCapture",
    "CaptureState",
    "HandshakeInfo",
    # Packet Sniffer
    "PacketSniffer",
    "CaptureBackend",
    "PacketInfo",
    "CaptureStats",
    # Jammer
    "Jammer",
    "JammerMode",
    "JammerStats",
    # Interface Manager
    "InterfaceManager",
    # Network Connector
    "NetworkConnector",
    # Bluetooth Scanner
    "BluetoothScanner",
    # Speed Tester
    "SpeedTester",
    # Geolocation
    "Geolocation",
    # OSINT
    "Osint",
    # Forensics
    "Forensics",
    # Password Tools
    "PasswordTools",
    # Automation
    "WorkflowEngine",
    "WorkflowStep",
    "WorkflowState",
    # Reporting
    "Reporting",
    # System Utils
    "SystemUtils",
    # Tool Integration
    "ToolIntegration",
    # Termux
    "TermuxModule",
    # WiFi 6E/7
    "WiFi6E7",
    # Compliance Checker
    "ComplianceChecker",
    "ComplianceStatus",
    "ComplianceStandard",
]
