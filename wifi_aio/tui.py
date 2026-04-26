"""Textual TUI interface for WiFiAIO."""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal, Vertical, VerticalScroll
    from textual.widgets import (
        Button,
        DataTable,
        Footer,
        Header,
        Input,
        Label,
        ListView,
        ListItem,
        Static,
        TabbedContent,
        TabPane,
        Tree,
    )
    from textual.reactive import reactive
    from textual import work
    _HAS_TEXTUAL = True
except ImportError:
    _HAS_TEXTUAL = False

from wifi_aio.config import ConfigManager
from wifi_aio.database import Database
from wifi_aio.theme import ThemeManager
from wifi_aio.i18n import I18n
from wifi_aio.constants import RSSI_GOOD, RSSI_FAIR, RSSI_POOR, RSSI_UNUSABLE

logger = logging.getLogger(__name__)


class NetworkInfoWidget(Static):
    """Widget displaying information about a scanned network."""

    def __init__(self, network: Dict, **kwargs):
        self.network = network
        super().__init__(**kwargs)
        self._build_content()

    def _build_content(self) -> None:
        n = self.network
        ssid = n.get("ssid", "<hidden>")
        bssid = n.get("bssid", "Unknown")
        channel = n.get("channel", "?")
        signal = n.get("signal_dbm", -100)
        security = n.get("security", "Unknown")
        vendor = n.get("vendor", "Unknown")

        # Signal quality label
        if signal >= RSSI_GOOD:
            quality = "Excellent"
        elif signal >= RSSI_FAIR:
            quality = "Good"
        elif signal >= RSSI_POOR:
            quality = "Fair"
        elif signal >= RSSI_UNUSABLE:
            quality = "Poor"
        else:
            quality = "Unusable"

        self.update(
            f"[bold]{ssid}[/bold]\n"
            f"  BSSID: {bssid}  CH: {channel}  Signal: {signal} dBm ({quality})\n"
            f"  Security: {security}  Vendor: {vendor}"
        )


class ScanPanel(Vertical):
    """Panel for network scanning."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Label("[bold]Network Scanner[/bold]")
        yield Horizontal(
            Input(placeholder="Interface (e.g. wlan0)", id="scan-interface"),
            Button("Scan", variant="primary", id="scan-btn"),
            Button("Stop", variant="error", id="scan-stop-btn"),
        )
        yield DataTable(id="scan-results")

    def on_mount(self) -> None:
        table = self.query_one("#scan-results", DataTable)
        table.add_columns("SSID", "BSSID", "Channel", "Signal", "Security", "Vendor")


class CapturePanel(Vertical):
    """Panel for packet capture."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Label("[bold]Packet Capture[/bold]")
        yield Horizontal(
            Input(placeholder="Interface", id="capture-interface"),
            Input(placeholder="BSSID", id="capture-bssid"),
            Input(placeholder="Channel", id="capture-channel"),
            Button("Start Capture", variant="primary", id="capture-start-btn"),
            Button("Stop", variant="error", id="capture-stop-btn"),
        )
        yield Static("Capture status: Idle", id="capture-status")


class CrackPanel(Vertical):
    """Panel for password cracking."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Label("[bold]Password Cracking[/bold]")
        yield Horizontal(
            Input(placeholder="Capture file path", id="crack-capture"),
            Input(placeholder="Wordlist path", id="crack-wordlist"),
            Button("Crack", variant="primary", id="crack-btn"),
        )
        yield Static("Crack status: Idle", id="crack-status")


class DeauthPanel(Vertical):
    """Panel for deauthentication attacks."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Label("[bold]Deauthentication[/bold]")
        yield Horizontal(
            Input(placeholder="Interface", id="deauth-interface"),
            Input(placeholder="Target BSSID", id="deauth-bssid"),
            Input(placeholder="Client (blank = broadcast)", id="deauth-client"),
            Input(placeholder="Count (default 5)", id="deauth-count"),
            Button("Send Deauth", variant="warning", id="deauth-btn"),
        )
        yield Static("Deauth status: Idle", id="deauth-status")


class EvilTwinPanel(Vertical):
    """Panel for Evil Twin AP."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Label("[bold]Evil Twin Access Point[/bold]")
        yield Horizontal(
            Input(placeholder="Interface", id="et-interface"),
            Input(placeholder="SSID to clone", id="et-ssid"),
            Input(placeholder="Channel", id="et-channel"),
            Button("Start", variant="primary", id="et-start-btn"),
            Button("Stop", variant="error", id="et-stop-btn"),
        )
        yield Static("Evil Twin status: Idle", id="et-status")


class WPSPanel(Vertical):
    """Panel for WPS attacks."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Label("[bold]WPS Attack[/bold]")
        yield Horizontal(
            Input(placeholder="Interface", id="wps-interface"),
            Input(placeholder="Target BSSID", id="wps-bssid"),
            Button("Start Pixie Dust", variant="primary", id="wps-pixie-btn"),
            Button("Start PIN Attack", variant="warning", id="wps-pin-btn"),
        )
        yield Static("WPS status: Idle", id="wps-status")


class LogPanel(VerticalScroll):
    """Panel showing live log output."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Label("[bold]Activity Log[/bold]")
        yield Static("", id="log-content")

    def add_log(self, message: str, level: str = "INFO") -> None:
        """Add a log message to the panel."""
        try:
            log_widget = self.query_one("#log-content", Static)
            current = log_widget.renderable or ""
            timestamp = datetime.now().strftime("%H:%M:%S")
            color_map = {
                "DEBUG": "dim",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "bold red",
            }
            color = color_map.get(level, "white")
            new_line = f"[{color}]{timestamp} [{level}] {message}[/{color}]"
            lines = current.split("\n") if current else []
            lines.append(new_line)
            # Keep last 200 lines
            if len(lines) > 200:
                lines = lines[-200:]
            log_widget.update("\n".join(lines))
        except Exception:
            pass


class StatsPanel(Vertical):
    """Panel showing session statistics."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Label("[bold]Session Statistics[/bold]")
        yield DataTable(id="stats-table")

    def on_mount(self) -> None:
        table = self.query_one("#stats-table", DataTable)
        table.add_columns("Metric", "Value")
        table.add_row("Networks Scanned", "0")
        table.add_row("Handshakes Captured", "0")
        table.add_row("Passwords Cracked", "0")
        table.add_row("Deauth Frames Sent", "0")
        table.add_row("Session Duration", "0:00:00")


if _HAS_TEXTUAL:
    class WiFiAIOApp(App):
        """WiFiAIO Textual TUI Application.

        Provides a full-featured tabbed interface for WiFi security
        auditing operations: scanning, capture, cracking, deauth,
        Evil Twin, and WPS attacks.  Each panel's buttons are wired
        to the corresponding core engine via ``on_button_pressed``.
        Long-running operations use ``@work(exclusive=True)`` to run
        in a background worker without blocking the UI.
        """

        TITLE = "WiFiAIO"
        SUB_TITLE = "All-in-One WiFi Security Toolkit"

        CSS = """
        Screen {
            layout: vertical;
        }
        #main-container {
            height: 1fr;
        }
        .panel {
            border: round $primary;
            padding: 1;
            margin: 0 1;
        }
        #log-panel {
            height: 12;
            border: round $secondary;
        }
        #stats-panel {
            height: 8;
            border: round $accent;
        }
        Button {
            margin: 0 1;
        }
        Input {
            width: 20;
            margin: 0 1;
        }
        """

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("s", "scan", "Scan"),
            Binding("c", "capture", "Capture"),
            Binding("d", "deauth", "Deauth"),
            Binding("t", "toggle_theme", "Theme"),
        ]

        networks: reactive[List[Dict]] = reactive([])
        scan_active: reactive[bool] = reactive(False)

        # ── Engine references (lazily initialised) ─────────────────────
        _scanner: Optional[object] = None
        _capturer: Optional[object] = None
        _cracker: Optional[object] = None
        _deauth_engine: Optional[object] = None
        _evil_twin: Optional[object] = None
        _wps_engine: Optional[object] = None

        # Session counters for the stats panel
        _networks_scanned: int = 0
        _handshakes_captured: int = 0
        _passwords_cracked: int = 0
        _deauth_frames_sent: int = 0

        def __init__(self, config: Optional[ConfigManager] = None, **kwargs):
            super().__init__(**kwargs)
            self.config = config or ConfigManager()
            self.database = Database(self.config.get("database.path"))
            self.theme_manager = ThemeManager(current=self.config.get("general.theme", "dark"))
            self.i18n = I18n(language=self.config.get("general.language", "en"))

        # ── Layout ─────────────────────────────────────────────────────

        def compose(self) -> ComposeResult:
            yield Header()
            with TabbedContent():
                with TabPane("Scan"):
                    yield ScanPanel(classes="panel")
                with TabPane("Capture"):
                    yield CapturePanel(classes="panel")
                with TabPane("Crack"):
                    yield CrackPanel(classes="panel")
                with TabPane("Deauth"):
                    yield DeauthPanel(classes="panel")
                with TabPane("Evil Twin"):
                    yield EvilTwinPanel(classes="panel")
                with TabPane("WPS"):
                    yield WPSPanel(classes="panel")
            yield LogPanel(id="log-panel")
            yield StatsPanel(id="stats-panel", classes="panel")
            yield Footer()

        def on_mount(self) -> None:
            self._apply_theme()
            self._log("WiFiAIO TUI started")

        # ── Central button dispatcher ──────────────────────────────────

        def on_button_pressed(self, event: Button.Pressed) -> None:
            """Dispatch button press to the appropriate handler based on button ID."""
            button_id = event.button.id
            dispatch = {
                "scan-btn": self._handle_scan,
                "scan-stop-btn": self._handle_scan_stop,
                "capture-start-btn": self._handle_capture_start,
                "capture-stop-btn": self._handle_capture_stop,
                "crack-btn": self._handle_crack,
                "deauth-btn": self._handle_deauth,
                "et-start-btn": self._handle_et_start,
                "et-stop-btn": self._handle_et_stop,
                "wps-pixie-btn": self._handle_wps_pixie,
                "wps-pin-btn": self._handle_wps_pin,
            }
            handler = dispatch.get(button_id)
            if handler:
                handler()
            else:
                self._log(f"Unhandled button: {button_id}", level="WARNING")

        # ── Scan handlers ──────────────────────────────────────────────

        def _handle_scan(self) -> None:
            """Handle scan-btn press – start a network scan."""
            interface = self._get_input_value("scan-interface") or \
                self.config.get("general.interface", "wlan0")
            self._log(f"Starting network scan on {interface}...")
            self.scan_active = True
            self._run_scan(interface)

        def _handle_scan_stop(self) -> None:
            """Handle scan-stop-btn press – stop an active scan."""
            if self._scanner is not None:
                try:
                    self._scanner.stop()
                    self._log("Scan stopped by user")
                except Exception as exc:
                    self._log(f"Error stopping scan: {exc}", level="ERROR")
            else:
                self._log("No active scan to stop", level="WARNING")
            self.scan_active = False

        @work(exclusive=True)
        async def _run_scan(self, interface: str) -> None:
            """Run a network scan in a background worker.

            Uses :class:`NetworkScanner` to perform an active scan,
            then populates the scan-results DataTable with discovered
            networks.

            Args:
                interface: Wireless interface to scan on.
            """
            try:
                from wifi_aio.core.network_scanner import NetworkScanner

                timeout = self.config.get("scan.timeout", 30)
                self._scanner = NetworkScanner(interface=interface)
                self._log(f"Scanning on {interface} for {timeout}s...")

                results = self._scanner.scan(timeout=timeout)
                self.networks = [ap.to_dict() for ap in results]
                self._networks_scanned = len(self.networks)
                self._log(f"Scan complete – {self._networks_scanned} network(s) found")

                # Populate the DataTable
                try:
                    table = self.query_one("#scan-results", DataTable)
                    table.clear()
                    for ap in results:
                        table.add_row(
                            ap.ssid or "<hidden>",
                            ap.bssid,
                            str(ap.channel),
                            str(ap.signal_dbm),
                            ap.security or "Unknown",
                            ap.vendor or "Unknown",
                        )
                except Exception as exc:
                    self._log(f"Error updating scan table: {exc}", level="WARNING")

                self._update_stats()

            except Exception as exc:
                self._log(f"Scan error: {exc}", level="ERROR")
            finally:
                self.scan_active = False
                self._scanner = None

        # ── Capture handlers ───────────────────────────────────────────

        def _handle_capture_start(self) -> None:
            """Handle capture-start-btn – begin handshake capture."""
            interface = self._get_input_value("capture-interface") or \
                self.config.get("general.interface", "wlan0mon")
            bssid = self._get_input_value("capture-bssid")
            channel_str = self._get_input_value("capture-channel")

            if not bssid:
                self._log("Capture requires a target BSSID", level="WARNING")
                return

            try:
                channel = int(channel_str) if channel_str else 1
            except ValueError:
                channel = 1

            self._log(f"Starting handshake capture for {bssid} on channel {channel}...")
            self._run_capture(interface, bssid, channel)

        def _handle_capture_stop(self) -> None:
            """Handle capture-stop-btn – stop active capture."""
            if self._capturer is not None:
                try:
                    self._capturer.stop()
                    self._log("Capture stopped by user")
                except Exception as exc:
                    self._log(f"Error stopping capture: {exc}", level="ERROR")
            else:
                self._log("No active capture to stop", level="WARNING")

        @work(exclusive=True)
        async def _run_capture(self, interface: str, bssid: str, channel: int) -> None:
            """Run a handshake capture in a background worker.

            Args:
                interface: Monitor-mode interface.
                bssid: Target AP BSSID.
                channel: Target channel number.
            """
            try:
                from wifi_aio.core.handshake_capture import HandshakeCapture

                timeout = self.config.get("capture.timeout", 120)
                self._capturer = HandshakeCapture(interface=interface)

                self._set_status("capture-status", "Capturing...")
                info = self._capturer.capture_handshake(
                    bssid=bssid,
                    channel=channel,
                    timeout=timeout,
                    deauth=True,
                )

                if info.is_complete:
                    self._handshakes_captured += 1
                    status = "Handshake captured!"
                    if info.has_pmkid:
                        status = "PMKID captured!"
                    self._log(f"{status} for {bssid}")
                    self._set_status("capture-status", f"Capture status: {status}")
                else:
                    self._log(f"Capture failed or timed out for {bssid}", level="WARNING")
                    self._set_status("capture-status", "Capture status: Failed / Timeout")

                self._update_stats()

            except Exception as exc:
                self._log(f"Capture error: {exc}", level="ERROR")
                self._set_status("capture-status", f"Capture status: Error – {exc}")
            finally:
                self._capturer = None

        # ── Crack handler ──────────────────────────────────────────────

        def _handle_crack(self) -> None:
            """Handle crack-btn – start password cracking."""
            capture_file = self._get_input_value("crack-capture")
            wordlist = self._get_input_value("crack-wordlist")

            if not capture_file:
                self._log("Crack requires a capture file path", level="WARNING")
                return

            self._log(f"Starting dictionary crack against {capture_file}...")
            self._run_crack(capture_file, wordlist)

        @work(exclusive=True)
        async def _run_crack(self, capture_file: str, wordlist: Optional[str] = None) -> None:
            """Run a password cracking attempt in a background worker.

            Args:
                capture_file: Path to the capture / hash file.
                wordlist: Optional path to a wordlist file.
            """
            try:
                from wifi_aio.core.password_cracker import PasswordCracker

                self._cracker = PasswordCracker()
                self._set_status("crack-status", "Cracking...")

                if not wordlist:
                    wordlist = self.config.get("cracking.wordlist",
                                               "/usr/share/wordlists/rockyou.txt")

                result = self._cracker.dictionary_attack(
                    hash_file=capture_file,
                    wordlist=wordlist,
                )

                if result.found:
                    self._passwords_cracked += 1
                    self._log(f"Password found: {result.password}")
                    self._set_status("crack-status",
                                     f"Crack status: FOUND – {result.password}")
                else:
                    self._log("Password not found in wordlist")
                    self._set_status("crack-status", "Crack status: Not found")

                self._update_stats()

            except Exception as exc:
                self._log(f"Crack error: {exc}", level="ERROR")
                self._set_status("crack-status", f"Crack status: Error – {exc}")
            finally:
                self._cracker = None

        # ── Deauth handler ─────────────────────────────────────────────

        def _handle_deauth(self) -> None:
            """Handle deauth-btn – send deauthentication frames."""
            interface = self._get_input_value("deauth-interface") or \
                self.config.get("general.interface", "wlan0mon")
            bssid = self._get_input_value("deauth-bssid")
            client = self._get_input_value("deauth-client") or "FF:FF:FF:FF:FF:FF"
            count_str = self._get_input_value("deauth-count")

            if not bssid:
                self._log("Deauth requires a target BSSID", level="WARNING")
                return

            try:
                count = int(count_str) if count_str else 5
            except ValueError:
                count = 5

            self._log(f"Sending {count} deauth frame(s) to {bssid}...")
            self._run_deauth(interface, bssid, client, count)

        @work(exclusive=True)
        async def _run_deauth(self, interface: str, bssid: str,
                              client: str, count: int) -> None:
            """Run a deauthentication attack in a background worker.

            Args:
                interface: Monitor-mode interface.
                bssid: Target AP BSSID.
                client: Client MAC address (broadcast if FF:FF:FF:FF:FF:FF).
                count: Number of deauth frames to send.
            """
            try:
                from wifi_aio.core.deauth_engine import DeauthEngine

                self._deauth_engine = DeauthEngine(interface=interface)
                self._set_status("deauth-status", "Sending deauth frames...")

                stats = self._deauth_engine.inject_deauth(
                    target_bssid=bssid,
                    client_mac=client,
                    count=count,
                )

                self._deauth_frames_sent += stats.frames_sent
                self._log(f"Sent {stats.frames_sent} deauth frame(s) "
                          f"({stats.rate_per_second:.1f}/s)")
                self._set_status("deauth-status",
                                 f"Deauth status: {stats.frames_sent} frames sent")
                self._update_stats()

            except Exception as exc:
                self._log(f"Deauth error: {exc}", level="ERROR")
                self._set_status("deauth-status", f"Deauth status: Error – {exc}")
            finally:
                self._deauth_engine = None

        # ── Evil Twin handlers ─────────────────────────────────────────

        def _handle_et_start(self) -> None:
            """Handle et-start-btn – start Evil Twin AP."""
            interface = self._get_input_value("et-interface") or \
                self.config.get("general.interface", "wlan0")
            ssid = self._get_input_value("et-ssid") or "FreeWiFi"
            channel_str = self._get_input_value("et-channel")

            try:
                channel = int(channel_str) if channel_str else 6
            except ValueError:
                channel = 6

            self._log(f"Starting Evil Twin '{ssid}' on channel {channel}...")
            self._run_et_start(interface, ssid, channel)

        def _handle_et_stop(self) -> None:
            """Handle et-stop-btn – stop Evil Twin AP."""
            if self._evil_twin is not None:
                try:
                    self._evil_twin.stop()
                    self._log("Evil Twin stopped")
                    self._set_status("et-status", "Evil Twin status: Stopped")
                except Exception as exc:
                    self._log(f"Error stopping Evil Twin: {exc}", level="ERROR")
            else:
                self._log("No Evil Twin running", level="WARNING")
            self._evil_twin = None

        @work(exclusive=True)
        async def _run_et_start(self, interface: str, ssid: str, channel: int) -> None:
            """Start the Evil Twin AP in a background worker.

            Args:
                interface: Wireless interface for the rogue AP.
                ssid: SSID for the rogue AP.
                channel: Channel for the rogue AP.
            """
            try:
                from wifi_aio.core.evil_twin import EvilTwin

                self._evil_twin = EvilTwin(
                    interface=interface,
                    ssid=ssid,
                    channel=channel,
                )
                self._set_status("et-status", "Evil Twin status: Starting...")
                self._evil_twin.start()
                self._log(f"Evil Twin '{ssid}' is running on channel {channel}")
                self._set_status("et-status",
                                 f"Evil Twin status: Running ({ssid} ch {channel})")

            except Exception as exc:
                self._log(f"Evil Twin error: {exc}", level="ERROR")
                self._set_status("et-status", f"Evil Twin status: Error – {exc}")
                self._evil_twin = None

        # ── WPS handlers ───────────────────────────────────────────────

        def _handle_wps_pixie(self) -> None:
            """Handle wps-pixie-btn – start WPS Pixie Dust attack."""
            interface = self._get_input_value("wps-interface") or \
                self.config.get("general.interface", "wlan0mon")
            bssid = self._get_input_value("wps-bssid")

            if not bssid:
                self._log("WPS Pixie Dust requires a target BSSID", level="WARNING")
                return

            self._log(f"Starting Pixie Dust attack on {bssid}...")
            self._run_wps_pixie(interface, bssid)

        def _handle_wps_pin(self) -> None:
            """Handle wps-pin-btn – start WPS PIN brute-force."""
            interface = self._get_input_value("wps-interface") or \
                self.config.get("general.interface", "wlan0mon")
            bssid = self._get_input_value("wps-bssid")

            if not bssid:
                self._log("WPS PIN attack requires a target BSSID", level="WARNING")
                return

            self._log(f"Starting WPS PIN brute-force on {bssid}...")
            self._run_wps_pin(interface, bssid)

        @work(exclusive=True)
        async def _run_wps_pixie(self, interface: str, bssid: str) -> None:
            """Run WPS Pixie Dust attack in a background worker.

            Args:
                interface: Monitor-mode interface.
                bssid: Target AP BSSID.
            """
            try:
                from wifi_aio.core.wps_engine import WPSEngine

                self._wps_engine = WPSEngine(interface=interface)
                self._set_status("wps-status", "WPS status: Pixie Dust running...")

                result = self._wps_engine.pixie_dust_attack(
                    bssid=bssid,
                    channel=1,
                    timeout=300,
                )

                if result.success:
                    msg = f"PIN: {result.pin}"
                    if result.psk:
                        msg += f"  PSK: {result.psk}"
                    self._log(f"Pixie Dust success – {msg}")
                    self._set_status("wps-status", f"WPS status: {msg}")
                else:
                    self._log("Pixie Dust attack failed", level="WARNING")
                    self._set_status("wps-status", "WPS status: Pixie Dust failed")

            except Exception as exc:
                self._log(f"Pixie Dust error: {exc}", level="ERROR")
                self._set_status("wps-status", f"WPS status: Error – {exc}")
            finally:
                self._wps_engine = None

        @work(exclusive=True)
        async def _run_wps_pin(self, interface: str, bssid: str) -> None:
            """Run WPS PIN brute-force attack in a background worker.

            Args:
                interface: Monitor-mode interface.
                bssid: Target AP BSSID.
            """
            try:
                from wifi_aio.core.wps_engine import WPSEngine

                self._wps_engine = WPSEngine(interface=interface)
                self._set_status("wps-status", "WPS status: PIN brute-force running...")

                result = self._wps_engine.pin_bruteforce(
                    bssid=bssid,
                    channel=1,
                )

                if result.success:
                    msg = f"PIN: {result.pin}"
                    if result.psk:
                        msg += f"  PSK: {result.psk}"
                    self._log(f"PIN brute-force success – {msg}")
                    self._set_status("wps-status", f"WPS status: {msg}")
                else:
                    self._log("PIN brute-force failed", level="WARNING")
                    self._set_status("wps-status",
                                     f"WPS status: PIN failed ({result.pins_tried} tried)")

            except Exception as exc:
                self._log(f"PIN brute-force error: {exc}", level="ERROR")
                self._set_status("wps-status", f"WPS status: Error – {exc}")
            finally:
                self._wps_engine = None

        # ── Keyboard shortcut actions ──────────────────────────────────

        def action_scan(self) -> None:
            """Start a network scan via keyboard shortcut."""
            self._handle_scan()

        def action_capture(self) -> None:
            """Start packet capture via keyboard shortcut."""
            self._handle_capture_start()

        def action_deauth(self) -> None:
            """Send deauth via keyboard shortcut."""
            self._handle_deauth()

        def action_toggle_theme(self) -> None:
            """Cycle through available themes."""
            themes = self.theme_manager.list_themes()
            current = self.theme_manager.current_name
            idx = themes.index(current) if current in themes else -1
            next_idx = (idx + 1) % len(themes)
            self.theme_manager.set_theme(themes[next_idx])
            self._apply_theme()
            self._log(f"Theme changed to {themes[next_idx]}")

        # ── UI helpers ─────────────────────────────────────────────────

        def _get_input_value(self, input_id: str) -> str:
            """Return the current text value of an Input widget, or ''."""
            try:
                widget = self.query_one(f"#{input_id}", Input)
                return str(widget.value).strip()
            except Exception:
                return ""

        def _set_status(self, widget_id: str, text: str) -> None:
            """Update a Static widget's display text."""
            try:
                widget = self.query_one(f"#{widget_id}", Static)
                widget.update(text)
            except Exception:
                pass

        def _update_stats(self) -> None:
            """Refresh the session statistics table."""
            try:
                table = self.query_one("#stats-table", DataTable)
                table.clear()
                table.add_row("Networks Scanned", str(self._networks_scanned))
                table.add_row("Handshakes Captured", str(self._handshakes_captured))
                table.add_row("Passwords Cracked", str(self._passwords_cracked))
                table.add_row("Deauth Frames Sent", str(self._deauth_frames_sent))
                table.add_row("Session Duration", "0:00:00")
            except Exception:
                pass

        def _apply_theme(self) -> None:
            """Apply the current theme colors to the TUI."""
            theme = self.theme_manager.current
            # Set Textual's dark mode based on theme brightness
            bg = theme.get("background", "#1e1e2e")
            # Simple heuristic: if background is dark, use dark mode
            r = int(bg[1:3], 16)
            g = int(bg[3:5], 16)
            b = int(bg[5:7], 16)
            brightness = (r * 299 + g * 587 + b * 114) / 1000
            self.dark = brightness < 128

        def _log(self, message: str, level: str = "INFO") -> None:
            """Add a message to the log panel."""
            try:
                log_panel = self.query_one("#log-panel", LogPanel)
                log_panel.add_log(message, level)
            except Exception:
                logger.log(getattr(logging, level, logging.INFO), message)


def run_tui(config: Optional[ConfigManager] = None) -> None:
    """Launch the WiFiAIO TUI application.

    Args:
        config: Optional ConfigManager instance.

    Raises:
        RuntimeError: If the textual package is not installed.
    """
    if not _HAS_TEXTUAL:
        raise RuntimeError(
            "The 'textual' package is required for the TUI. "
            "Install it with: pip install textual"
        )
    app = WiFiAIOApp(config=config)
    app.run()
