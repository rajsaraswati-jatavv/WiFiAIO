"""WiFiAIO custom exception hierarchy.

All WiFiAIO-specific exceptions inherit from WiFiAIOError, making it easy
to catch any package-level error with a single except clause.
"""


class WiFiAIOError(Exception):
    """Base exception for all WiFiAIO errors."""

    def __init__(self, message: str = "", *, details: str = ""):
        self.details = details
        super().__init__(message)


# ── Scanning & Network Errors ────────────────────────────────────────

class ScanError(WiFiAIOError):
    """Raised when a wireless scan operation fails."""


class NoNetworksFoundError(ScanError):
    """Raised when a scan completes but finds zero networks."""


# ── Deauthentication & Frame Errors ──────────────────────────────────

class DeauthError(WiFiAIOError):
    """Raised when sending a deauthentication frame fails."""


class PMFBlockedError(DeauthError):
    """Raised when deauth is blocked by Protected Management Frames."""


class FrameInjectionError(WiFiAIOError):
    """Raised when raw frame injection fails (e.g. missing monitor mode)."""


# ── Rogue AP & HostAPD Errors ────────────────────────────────────────

class RogueAPError(WiFiAIOError):
    """Raised when creating or managing a rogue access point fails."""


class HostAPDError(RogueAPError):
    """Raised when the hostapd daemon encounters an error."""


class DHCPError(RogueAPError):
    """Raised when the DHCP server (dnsmasq/isc-dhcp) fails."""


# ── Cracking & Wordlist Errors ───────────────────────────────────────

class CrackingError(WiFiAIOError):
    """Raised when a password-cracking operation fails."""


class WordlistNotFoundError(CrackingError):
    """Raised when the specified wordlist file does not exist."""


class HashExtractionError(CrackingError):
    """Raised when extracting a hash from a capture file fails."""


# ── WPS Errors ────────────────────────────────────────────────────────

class WPSError(WiFiAIOError):
    """Raised when a WPS operation fails."""


class WPSLockoutError(WPSError):
    """Raised when the AP has locked WPS after too many attempts."""


class WPSPinError(WPSError):
    """Raised when an invalid WPS PIN is used."""


# ── Capture & PCAP Errors ────────────────────────────────────────────

class CaptureError(WiFiAIOError):
    """Raised when packet capture fails."""


class PCAPError(CaptureError):
    """Raised when reading or writing a PCAP/PCAPNG file fails."""


# ── Interface Errors ──────────────────────────────────────────────────

class InterfaceError(WiFiAIOError):
    """Raised when a wireless interface operation fails."""


class MonitorModeError(InterfaceError):
    """Raised when enabling or disabling monitor mode fails."""


# ── OSINT & Geolocation Errors ────────────────────────────────────────

class OSINTError(WiFiAIOError):
    """Raised when an OSINT lookup fails."""


class GeolocationError(OSINTError):
    """Raised when a geolocation lookup fails."""


# ── Forensics Errors ──────────────────────────────────────────────────

class ForensicsError(CaptureError):
    """Raised when a forensics analysis operation fails."""


# ── Connection Errors ────────────────────────────────────────────────

class WiFiConnectionError(WiFiAIOError):
    """Raised when a WiFi connection attempt fails."""


class AuthenticationError(WiFiConnectionError):
    """Raised when authentication with an AP fails."""


class AssociationError(WiFiConnectionError):
    """Raised when association with an AP fails."""


# ── Permission & Timeout Errors ──────────────────────────────────────

class WiFiPermissionError(WiFiAIOError):
    """Raised when the user lacks required privileges (e.g. not root)."""


class WiFiTimeoutError(WiFiAIOError):
    """Raised when a WiFi operation times out."""


# ── Configuration & Database Errors ──────────────────────────────────

class ConfigurationError(WiFiAIOError):
    """Raised when a configuration value is invalid or missing."""


class DatabaseError(WiFiAIOError):
    """Raised when a database operation fails."""


# ── Plugin & Automation Errors ───────────────────────────────────────

class PluginError(WiFiAIOError):
    """Raised when loading or executing a plugin fails."""


class AutomationError(WiFiAIOError):
    """Raised when an automation / scripting operation fails."""


# ── Security & Compliance Errors ─────────────────────────────────────

class VulnerabilityError(WiFiAIOError):
    """Raised when a vulnerability assessment encounters an error."""


class ComplianceError(WiFiAIOError):
    """Raised when a compliance check fails."""


# ── Update Errors ────────────────────────────────────────────────────

class UpdateError(WiFiAIOError):
    """Raised when checking for or applying updates fails."""


# ── Backward-Compatible Aliases ────────────────────────────────────────
# These aliases ensure that code using older exception names continues
# to work.  They map the legacy names to the current canonical class.

WiFiScanError = ScanError
WiFiInterfaceError = InterfaceError
WiFiInjectionError = FrameInjectionError
EvilTwinError = RogueAPError
HandshakeError = CaptureError
WiFiDeauthError = DeauthError
