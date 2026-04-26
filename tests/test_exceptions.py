"""Tests for wifi_aio.exceptions – exception hierarchy and aliases.

Covers the full exception tree, backward-compatible aliases, and the
``details`` keyword attribute.
"""

import pytest

from wifi_aio.exceptions import (
    AuthenticationError,
    AutomationError,
    CaptureError,
    ComplianceError,
    ConfigurationError,
    CrackingError,
    DatabaseError,
    DeauthError,
    DHCPError,
    EvilTwinError,
    ForensicsError,
    FrameInjectionError,
    GeolocationError,
    HandshakeError,
    HashExtractionError,
    HostAPDError,
    InterfaceError,
    MonitorModeError,
    NoNetworksFoundError,
    OSINTError,
    PCAPError,
    PluginError,
    PMFBlockedError,
    RogueAPError,
    ScanError,
    UpdateError,
    VulnerabilityError,
    WiFiAIOError,
    WiFiConnectionError,
    WiFiDeauthError,
    WiFiInjectionError,
    WiFiInterfaceError,
    WiFiPermissionError,
    WiFiScanError,
    WiFiTimeoutError,
    WordlistNotFoundError,
    WPSLockoutError,
    WPSPinError,
    WPSError,
)


# ── Base exception ──────────────────────────────────────────────────────

class TestWiFiAIOError:
    """Root exception class."""

    def test_inherits_from_exception(self) -> None:
        assert issubclass(WiFiAIOError, Exception)

    def test_message(self) -> None:
        exc = WiFiAIOError("something broke")
        assert str(exc) == "something broke"

    def test_details_attribute(self) -> None:
        exc = WiFiAIOError("oops", details="extra info")
        assert exc.details == "extra info"

    def test_details_defaults_empty(self) -> None:
        exc = WiFiAIOError("oops")
        assert exc.details == ""


# ── Exception hierarchy ──────────────────────────────────────────────────

class TestHierarchy:
    """Every specific exception should inherit from WiFiAIOError."""

    @pytest.mark.parametrize("exc_cls", [
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
        AuthenticationError,
        ConfigurationError,
        DatabaseError,
        PluginError,
        AutomationError,
        VulnerabilityError,
        ComplianceError,
        UpdateError,
        WiFiPermissionError,
        WiFiTimeoutError,
    ])
    def test_inherits_wifaio_error(self, exc_cls: type) -> None:
        assert issubclass(exc_cls, WiFiAIOError)

    def test_scan_error_hierarchy(self) -> None:
        """NoNetworksFoundError → ScanError → WiFiAIOError."""
        assert issubclass(NoNetworksFoundError, ScanError)
        assert issubclass(ScanError, WiFiAIOError)

    def test_deauth_error_hierarchy(self) -> None:
        """PMFBlockedError → DeauthError → WiFiAIOError."""
        assert issubclass(PMFBlockedError, DeauthError)

    def test_rogue_ap_hierarchy(self) -> None:
        """HostAPDError → RogueAPError → WiFiAIOError."""
        assert issubclass(HostAPDError, RogueAPError)
        assert issubclass(DHCPError, RogueAPError)

    def test_cracking_hierarchy(self) -> None:
        assert issubclass(WordlistNotFoundError, CrackingError)
        assert issubclass(HashExtractionError, CrackingError)

    def test_wps_hierarchy(self) -> None:
        assert issubclass(WPSLockoutError, WPSError)
        assert issubclass(WPSPinError, WPSError)

    def test_capture_hierarchy(self) -> None:
        assert issubclass(PCAPError, CaptureError)
        assert issubclass(ForensicsError, CaptureError)

    def test_interface_hierarchy(self) -> None:
        assert issubclass(MonitorModeError, InterfaceError)

    def test_osint_hierarchy(self) -> None:
        assert issubclass(GeolocationError, OSINTError)

    def test_connection_hierarchy(self) -> None:
        assert issubclass(AuthenticationError, WiFiConnectionError)


# ── Backward-compatible aliases ──────────────────────────────────────────

class TestAliases:
    """Legacy exception names should still work."""

    def test_wifi_scan_error_is_scan_error(self) -> None:
        assert WiFiScanError is ScanError

    def test_wifi_interface_error_is_interface_error(self) -> None:
        assert WiFiInterfaceError is InterfaceError

    def test_wifi_injection_error_is_frame_injection_error(self) -> None:
        assert WiFiInjectionError is FrameInjectionError

    def test_evil_twin_error_is_rogue_ap_error(self) -> None:
        assert EvilTwinError is RogueAPError

    def test_handshake_error_is_capture_error(self) -> None:
        assert HandshakeError is CaptureError

    def test_wifi_deauth_error_is_deauth_error(self) -> None:
        assert WiFiDeauthError is DeauthError

    def test_alias_catches_subclass(self) -> None:
        """Catching with an alias should also catch derived exceptions."""
        with pytest.raises(WiFiScanError):
            raise NoNetworksFoundError("none found")


# ── Details attribute propagation ────────────────────────────────────────

class TestDetails:
    """The ``details`` kwarg should be available on all subclasses."""

    def test_details_on_scan_error(self) -> None:
        exc = ScanError("scan failed", details="interface wlan0 not found")
        assert exc.details == "interface wlan0 not found"

    def test_details_on_database_error(self) -> None:
        exc = DatabaseError("query failed", details="SQL error near SELECT")
        assert exc.details == "SQL error near SELECT"
