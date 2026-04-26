"""Pydantic request/response models for WiFiAIO REST API.

Defines typed models for all API endpoints ensuring request validation,
response serialization, and automatic OpenAPI documentation generation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Authentication ──────────────────────────────────────────────────────

class APIKeyAuth(BaseModel):
    """API key authentication model."""
    api_key: str = Field(..., description="API key for authentication")


# ── Scan ────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Network scan request."""
    interface: str = Field(default="wlan0", description="Wireless interface to use")
    scan_type: str = Field(default="active", description="Scan type: active or passive")
    band: str = Field(default="both", description="Band to scan: 2.4GHz, 5GHz, 6GHz, or both")
    channel: Optional[int] = Field(default=None, description="Specific channel to scan")
    duration: int = Field(default=30, description="Scan duration in seconds")


class ScanResponse(BaseModel):
    """Network scan response."""
    scan_id: str
    status: str
    access_points: List[Dict[str, Any]] = Field(default_factory=list)
    total_found: int = 0
    duration_seconds: float = 0.0
    timestamp: str = ""


# ── Capture ─────────────────────────────────────────────────────────────

class CaptureRequest(BaseModel):
    """Packet/handshake capture request."""
    interface: str = Field(default="wlan0", description="Capture interface in monitor mode")
    bssid: str = Field(..., description="Target AP BSSID")
    channel: int = Field(..., description="Target channel")
    capture_type: str = Field(default="handshake", description="Capture type: handshake, pmkid, raw")
    timeout: int = Field(default=300, description="Capture timeout in seconds")
    output_file: Optional[str] = Field(default=None, description="Output PCAP file path")


class CaptureResponse(BaseModel):
    """Capture operation response."""
    capture_id: str
    status: str
    capture_type: str = ""
    output_file: str = ""
    file_size: int = 0
    handshake_captured: bool = False
    pmkid_captured: bool = False
    packets_captured: int = 0
    duration_seconds: float = 0.0


# ── Crack ───────────────────────────────────────────────────────────────

class CrackRequest(BaseModel):
    """Password cracking request."""
    capture_file: str = Field(..., description="Path to capture file (PCAP/PCAPNG)")
    method: str = Field(default="dictionary", description="Method: dictionary, brute_force, mask, rule, hybrid")
    wordlist: Optional[str] = Field(default=None, description="Path to wordlist file")
    mask: Optional[str] = Field(default=None, description="Hashcat mask for mask attack")
    rules: Optional[str] = Field(default=None, description="Rule file or rule name")
    tool: str = Field(default="auto", description="Cracking tool: hashcat, john, aircrack, cowpatty, auto")
    gpu: bool = Field(default=True, description="Use GPU acceleration if available")


class CrackResponse(BaseModel):
    """Password cracking response."""
    session_id: str
    status: str
    method: str = ""
    tool: str = ""
    progress: float = 0.0
    speed: int = 0
    tried: int = 0
    total: int = 0
    cracked: bool = False
    password: str = ""
    duration_seconds: float = 0.0


# ── Deauth ──────────────────────────────────────────────────────────────

class DeauthRequest(BaseModel):
    """Deauthentication attack request."""
    interface: str = Field(default="wlan0", description="Interface in monitor mode")
    bssid: str = Field(..., description="Target AP BSSID")
    client: str = Field(default="FF:FF:FF:FF:FF:FF", description="Target client MAC (broadcast for all)")
    count: int = Field(default=10, description="Number of deauth frames to send")
    channel: int = Field(..., description="Target channel")
    reason_code: int = Field(default=7, description="802.11 reason code")


class DeauthResponse(BaseModel):
    """Deauthentication response."""
    status: str
    frames_sent: int = 0
    bssid: str = ""
    client: str = ""
    channel: int = 0
    pmf_blocked: bool = False


# ── Evil Twin ───────────────────────────────────────────────────────────

class EvilTwinRequest(BaseModel):
    """Evil Twin AP request."""
    interface: str = Field(..., description="Interface for rogue AP")
    ssid: str = Field(..., description="SSID to clone")
    channel: int = Field(default=1, description="Channel for rogue AP")
    encryption: str = Field(default="open", description="AP encryption: open, wep, wpa2")
    captive_portal: bool = Field(default=True, description="Enable captive portal")
    dhcp_range_start: str = Field(default="10.0.0.100", description="DHCP range start")
    dhcp_range_end: str = Field(default="10.0.0.200", description="DHCP range end")
    dns_redirect: bool = Field(default=True, description="Redirect DNS to captive portal")


class EvilTwinResponse(BaseModel):
    """Evil Twin AP response."""
    status: str
    ap_running: bool = False
    ssid: str = ""
    channel: int = 0
    connected_clients: int = 0
    captured_credentials: List[Dict[str, str]] = Field(default_factory=list)
    dhcp_server_running: bool = False
    dns_server_running: bool = False
    captive_portal_running: bool = False


# ── WPS ─────────────────────────────────────────────────────────────────

class WPSRequest(BaseModel):
    """WPS attack request."""
    interface: str = Field(default="wlan0", description="Interface in monitor mode")
    bssid: str = Field(..., description="Target AP BSSID")
    method: str = Field(default="pixie_dust", description="Attack method: pixie_dust, pin_brute, null_pin")
    pin: Optional[str] = Field(default=None, description="Specific WPS PIN to try")
    timeout: int = Field(default=300, description="Timeout in seconds")
    max_attempts: int = Field(default=10000, description="Max PIN attempts for brute force")


class WPSResponse(BaseModel):
    """WPS attack response."""
    status: str
    method: str = ""
    pin_found: bool = False
    wps_pin: str = ""
    password: str = ""
    attempts: int = 0
    locked: bool = False
    duration_seconds: float = 0.0


# ── Sniff ───────────────────────────────────────────────────────────────

class SniffRequest(BaseModel):
    """Packet sniffing request."""
    interface: str = Field(default="wlan0", description="Interface in monitor mode")
    channel: Optional[int] = Field(default=None, description="Channel to sniff on")
    bssid: Optional[str] = Field(default=None, description="Filter by BSSID")
    filter: Optional[str] = Field(default=None, description="BPF filter expression")
    duration: int = Field(default=60, description="Sniff duration in seconds")
    output_file: Optional[str] = Field(default=None, description="Output PCAP file path")
    decode: bool = Field(default=False, description="Decode EAPOL/DNS/HTTP frames")


class SniffResponse(BaseModel):
    """Packet sniffing response."""
    status: str
    output_file: str = ""
    packets_captured: int = 0
    file_size: int = 0
    duration_seconds: float = 0.0
    protocols_seen: List[str] = Field(default_factory=list)


# ── Signal ──────────────────────────────────────────────────────────────

class SignalRequest(BaseModel):
    """Signal analysis request."""
    interface: str = Field(default="wlan0", description="Wireless interface")
    bssid: str = Field(..., description="Target AP BSSID")
    channel: int = Field(..., description="Target channel")
    duration: int = Field(default=30, description="Analysis duration in seconds")
    samples: int = Field(default=100, description="Number of signal samples")


class SignalResponse(BaseModel):
    """Signal analysis response."""
    bssid: str = ""
    channel: int = 0
    avg_signal_dbm: float = 0.0
    min_signal_dbm: int = 0
    max_signal_dbm: int = 0
    noise_dbm: int = 0
    snr_db: float = 0.0
    signal_quality: int = 0
    samples_collected: int = 0
    signal_history: List[Dict[str, Any]] = Field(default_factory=list)


# ── Vulnerability ───────────────────────────────────────────────────────

class VulnRequest(BaseModel):
    """Vulnerability scan request."""
    bssid: str = Field(..., description="Target AP BSSID")
    ssid: str = Field(default="", description="Target SSID")
    checks: List[str] = Field(
        default=["wep", "wps", "krack", "pmf", "default_creds", "dns_hijack", "rogue_dhcp"],
        description="Vulnerability checks to perform",
    )
    channel: int = Field(default=0, description="Target channel")


class VulnResponse(BaseModel):
    """Vulnerability scan response."""
    bssid: str = ""
    ssid: str = ""
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    total_vulns: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    security_score: int = 100


# ── OSINT ───────────────────────────────────────────────────────────────

class OSINTRequest(BaseModel):
    """OSINT lookup request."""
    bssid: str = Field(..., description="Target BSSID")
    ssid: str = Field(default="", description="Target SSID")
    sources: List[str] = Field(
        default=["wigle", "google_locate", "openwifi", "isp", "router_fingerprint"],
        description="OSINT sources to query",
    )
    include_cves: bool = Field(default=True, description="Include CVE lookups")


class OSINTResponse(BaseModel):
    """OSINT lookup response."""
    bssid: str = ""
    ssid: str = ""
    isp_info: Dict[str, Any] = Field(default_factory=dict)
    router_fingerprint: Dict[str, Any] = Field(default_factory=dict)
    geolocation: Dict[str, Any] = Field(default_factory=dict)
    wigle_data: Dict[str, Any] = Field(default_factory=dict)
    openwifi_data: Dict[str, Any] = Field(default_factory=dict)
    ssid_intel: Dict[str, Any] = Field(default_factory=dict)
    cve_matches: List[Dict[str, Any]] = Field(default_factory=list)
    default_credentials: Dict[str, str] = Field(default_factory=dict)
    report_path: str = ""


# ── Forensics ───────────────────────────────────────────────────────────

class ForensicsRequest(BaseModel):
    """Forensics analysis request."""
    capture_file: str = Field(..., description="Path to PCAP/PCAPNG file")
    analysis_type: str = Field(default="full", description="Analysis type: full, handshake, devices, traffic")
    output_format: str = Field(default="json", description="Output format: json, text, html")


class ForensicsResponse(BaseModel):
    """Forensics analysis response."""
    status: str
    capture_file: str = ""
    access_points: List[Dict[str, Any]] = Field(default_factory=list)
    clients: List[Dict[str, Any]] = Field(default_factory=list)
    handshakes: List[Dict[str, Any]] = Field(default_factory=list)
    eapol_frames: int = 0
    total_packets: int = 0
    file_size: int = 0
    analysis_time_seconds: float = 0.0


# ── Bluetooth ───────────────────────────────────────────────────────────

class BluetoothRequest(BaseModel):
    """Bluetooth scan request."""
    duration: int = Field(default=15, description="Scan duration in seconds")
    scan_type: str = Field(default="classic", description="Scan type: classic, ble, both")
    filter_name: Optional[str] = Field(default=None, description="Filter by device name")


class BluetoothResponse(BaseModel):
    """Bluetooth scan response."""
    devices: List[Dict[str, Any]] = Field(default_factory=list)
    total_found: int = 0
    classic_count: int = 0
    ble_count: int = 0
    duration_seconds: float = 0.0


# ── Geolocation ─────────────────────────────────────────────────────────

class GeoRequest(BaseModel):
    """Geolocation request."""
    bssid: str = Field(..., description="Target BSSID for geolocation")
    api_key: Optional[str] = Field(default=None, description="Google Geolocation API key")
    method: str = Field(default="google", description="Method: google, wigle, mosetsk")


class GeoResponse(BaseModel):
    """Geolocation response."""
    bssid: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    accuracy_meters: int = 0
    address: str = ""
    method: str = ""
    confidence: float = 0.0


# ── Speed Test ──────────────────────────────────────────────────────────

class SpeedRequest(BaseModel):
    """Speed test request."""
    interface: str = Field(default="wlan0", description="WiFi interface")
    ssid: str = Field(..., description="Network SSID")
    password: str = Field(default="", description="Network password")
    test_type: str = Field(default="both", description="Test type: download, upload, both")
    server: Optional[str] = Field(default=None, description="Speed test server URL")


class SpeedResponse(BaseModel):
    """Speed test response."""
    download_mbps: float = 0.0
    upload_mbps: float = 0.0
    latency_ms: float = 0.0
    jitter_ms: float = 0.0
    packet_loss: float = 0.0
    server: str = ""
    interface: str = ""


# ── Password Tools ──────────────────────────────────────────────────────

class PasswordRequest(BaseModel):
    """Password analysis request."""
    password: str = Field(..., description="Password to analyze")
    check_breach: bool = Field(default=True, description="Check against breach databases")
    generate_mutations: bool = Field(default=False, description="Generate password mutations")


class PasswordResponse(BaseModel):
    """Password analysis response."""
    password: str = ""
    strength_score: int = 0
    strength_label: str = ""
    crack_time: str = ""
    entropy_bits: float = 0.0
    breach_found: bool = False
    breach_count: int = 0
    mutations: List[str] = Field(default_factory=list)
    issues: List[str] = Field(default_factory=list)


# ── Compliance ──────────────────────────────────────────────────────────

class ComplianceRequest(BaseModel):
    """Compliance check request."""
    bssid: str = Field(..., description="Target BSSID")
    ssid: str = Field(default="", description="Target SSID")
    standards: List[str] = Field(
        default=["pci_dss", "nist", "cis", "iso_27001"],
        description="Compliance standards to check against",
    )


class ComplianceResponse(BaseModel):
    """Compliance check response."""
    bssid: str = ""
    ssid: str = ""
    overall_compliant: bool = False
    compliance_score: float = 0.0
    checks: List[Dict[str, Any]] = Field(default_factory=list)
    passed: int = 0
    failed: int = 0
    warnings: int = 0


# ── Topology ────────────────────────────────────────────────────────────

class TopologyRequest(BaseModel):
    """Network topology mapping request."""
    interface: str = Field(default="wlan0", description="Wireless interface")
    scan_duration: int = Field(default=60, description="Scan duration in seconds")
    include_clients: bool = Field(default=True, description="Include client devices")
    include_wired: bool = Field(default=False, description="Include wired network discovery")


class TopologyResponse(BaseModel):
    """Network topology response."""
    access_points: List[Dict[str, Any]] = Field(default_factory=list)
    clients: List[Dict[str, Any]] = Field(default_factory=list)
    connections: List[Dict[str, Any]] = Field(default_factory=list)
    network_graph: Dict[str, Any] = Field(default_factory=dict)


# ── Connect ─────────────────────────────────────────────────────────────

class ConnectRequest(BaseModel):
    """WiFi connection request."""
    interface: str = Field(default="wlan0", description="Wireless interface")
    ssid: str = Field(..., description="Network SSID")
    password: str = Field(default="", description="Network password")
    bssid: Optional[str] = Field(default=None, description="Specific BSSID to connect to")
    hidden: bool = Field(default=False, description="Network is hidden")
    timeout: int = Field(default=30, description="Connection timeout in seconds")


class ConnectResponse(BaseModel):
    """WiFi connection response."""
    status: str
    connected: bool = False
    ssid: str = ""
    bssid: str = ""
    ip_address: str = ""
    gateway: str = ""
    dns: str = ""
    signal_dbm: int = 0


# ── Jammer ──────────────────────────────────────────────────────────────

class JammerRequest(BaseModel):
    """WiFi jammer request."""
    interface: str = Field(default="wlan0", description="Interface in monitor mode")
    channel: int = Field(..., description="Channel to jam")
    bandwidth: str = Field(default="20", description="Jam bandwidth: 20, 40, 80")
    duration: int = Field(default=60, description="Duration in seconds")
    power: int = Field(default=20, description="TX power in dBm")


class JammerResponse(BaseModel):
    """WiFi jammer response."""
    status: str
    channel: int = 0
    duration_seconds: float = 0.0
    frames_sent: int = 0


# ── Frame Injection ─────────────────────────────────────────────────────

class InjectRequest(BaseModel):
    """Frame injection request."""
    interface: str = Field(default="wlan0", description="Interface in monitor mode")
    frame_type: str = Field(..., description="Frame type: beacon, probe, deauth, auth, association")
    bssid: str = Field(..., description="Source BSSID")
    destination: str = Field(default="FF:FF:FF:FF:FF:FF", description="Destination MAC")
    channel: int = Field(..., description="Channel to inject on")
    count: int = Field(default=1, description="Number of frames to inject")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Frame-specific parameters")


class InjectResponse(BaseModel):
    """Frame injection response."""
    status: str
    frames_injected: int = 0
    frame_type: str = ""
    channel: int = 0


# ── System ──────────────────────────────────────────────────────────────

class SystemStatusResponse(BaseModel):
    """System status response."""
    version: str = ""
    uptime_seconds: float = 0.0
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0
    interfaces: List[Dict[str, Any]] = Field(default_factory=list)
    active_tasks: List[Dict[str, Any]] = Field(default_factory=list)
    database_path: str = ""
    database_size_mb: float = 0.0
    active_sessions: int = 0


# ── Config ──────────────────────────────────────────────────────────────

class ConfigRequest(BaseModel):
    """Configuration update request."""
    key: str = Field(..., description="Configuration key")
    value: str = Field(..., description="Configuration value")
    category: str = Field(default="general", description="Configuration category")
    description: str = Field(default="", description="Configuration description")


class ConfigResponse(BaseModel):
    """Configuration response."""
    key: str = ""
    value: str = ""
    category: str = ""
    description: str = ""
    updated_at: str = ""


# ── Sessions ────────────────────────────────────────────────────────────

class SessionResponse(BaseModel):
    """Session information response."""
    session_id: str = ""
    task_type: str = ""
    status: str = ""
    progress: float = 0.0
    created_at: str = ""
    result: Dict[str, Any] = Field(default_factory=dict)
    error: str = ""


# ── Plugins ─────────────────────────────────────────────────────────────

class PluginResponse(BaseModel):
    """Plugin information response."""
    name: str = ""
    version: str = ""
    description: str = ""
    enabled: bool = False
    author: str = ""


# ── Reports ─────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    """Report generation request."""
    report_type: str = Field(default="full", description="Report type: full, vuln, osint, compliance, summary")
    format: str = Field(default="html", description="Output format: html, json, text, pdf")
    scan_ids: List[str] = Field(default_factory=list, description="Scan IDs to include")
    include_evidence: bool = Field(default=True, description="Include evidence data")


class ReportResponse(BaseModel):
    """Report generation response."""
    report_id: str = ""
    status: str = ""
    report_type: str = ""
    format: str = ""
    file_path: str = ""
    file_size: int = 0
    generated_at: str = ""


# ── Export ──────────────────────────────────────────────────────────────

class ExportRequest(BaseModel):
    """Data export request."""
    data_type: str = Field(..., description="Data type: scans, credentials, vulnerabilities, all")
    format: str = Field(default="json", description="Export format: json, csv, xml")
    filters: Dict[str, Any] = Field(default_factory=dict, description="Data filters")


class ExportResponse(BaseModel):
    """Data export response."""
    status: str = ""
    file_path: str = ""
    file_size: int = 0
    record_count: int = 0
    format: str = ""


# ── Workflows ───────────────────────────────────────────────────────────

class WorkflowRequest(BaseModel):
    """Workflow execution request."""
    workflow: str = Field(..., description="Workflow name or ID")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Workflow parameters")
    async_exec: bool = Field(default=True, description="Execute asynchronously")


class WorkflowResponse(BaseModel):
    """Workflow execution response."""
    workflow_id: str = ""
    workflow_name: str = ""
    status: str = ""
    steps_total: int = 0
    steps_completed: int = 0
    current_step: str = ""
    result: Dict[str, Any] = Field(default_factory=dict)
    error: str = ""


# ── Generic ─────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    """Error response model."""
    error: str
    detail: str = ""
    code: int = 400


class SuccessResponse(BaseModel):
    """Generic success response."""
    success: bool = True
    message: str = ""
