"""ASCII art for WiFiAIO branding.

Provides ASCII art logos and branding elements for terminal display.
"""

from __future__ import annotations

from typing import Dict, List


WIFI_AIO_LOGO: str = r"""
 ██╗    ██╗ █████╗ ██╗     ██╗     ███╗   ███╗ █████╗ ██╗███╗   ██╗
 ██║    ██║██╔══██╗██║     ██║     ████╗ ████║██╔══██╗██║████╗  ██║
 ██║ █╗ ██║███████║██║     ██║     ██╔████╔██║███████║██║██╔██╗ ██║
 ██║███╗██║██╔══██║██║     ██║     ██║╚██╔╝██║██╔══██║██║██║╚██╗██║
 ╚███╔███╔╝██║  ██║███████╗███████╗██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
          WiFi Security Assessment & Auditing Framework
"""

WIFI_AIO_SMALL: str = r"""
  ╦ ╦╔═╗╔╗ ╔═╗╦ ╦╔═╗╦  ╦
  ║║║║╣ ╠╩╗╚═╗╠═╣║╣ ║  ║
  ╚╩╝╚═╝╚═╝╚═╝╩ ╩╚═╝╩═╝╩═╝
"""

WIFI_AIO_COMPACT: str = "█▓▓▓ WiFiAIO ▓▓▓█"

# Module icons for menu display
MODULE_ICONS: Dict[str, str] = {
    "scanner":        "📡",
    "deauth":         "⚡",
    "handshake":      "🤝",
    "cracking":       "🔓",
    "wps":            "🔘",
    "evil_twin":      "👥",
    "sniffer":        "🕵",
    "forensics":      "🔬",
    "osint":          "🔍",
    "report":         "📊",
    "bluetooth":      "📶",
    "speed_test":     "⏱",
    "signal":         "📈",
    "geolocation":    "📍",
    "vuln_scan":      "🛡",
    "compliance":     "✅",
    "password_tools": "🔑",
    "automation":     "🤖",
    "settings":       "⚙",
    "update":         "🔄",
    "help":           "❓",
    "quit":           "🚪",
}

# Status ASCII art
STATUS_ART: Dict[str, List[str]] = {
    "scanning": [
        "  Scanning...",
        "  ╔══════════╗",
        "  ║  📡 >>>> ║",
        "  ╚══════════╝",
    ],
    "capturing": [
        "  Capturing...",
        "  ╔══════════╗",
        "  ║  🤝 <<<< ║",
        "  ╚══════════╝",
    ],
    "cracking": [
        "  Cracking...",
        "  ╔══════════╗",
        "  ║  🔓 xxxx ║",
        "  ╚══════════╝",
    ],
    "success": [
        "  ╔════════════════════╗",
        "  ║   ✓ SUCCESS!      ║",
        "  ╚════════════════════╝",
    ],
    "failed": [
        "  ╔════════════════════╗",
        "  ║   ✗ FAILED        ║",
        "  ╚════════════════════╝",
    ],
    "warning": [
        "  ╔════════════════════╗",
        "  ║   ⚠ WARNING       ║",
        "  ╚════════════════════╝",
    ],
    "error": [
        "  ╔════════════════════╗",
        "  ║   ✗ ERROR         ║",
        "  ╚════════════════════╝",
    ],
}

# WiFi signal strength ASCII indicators
SIGNAL_BARS: Dict[str, str] = {
    "excellent": "▓▓▓▓▓",
    "good":      "▓▓▓▓░",
    "fair":      "▓▓▓░░",
    "weak":      "▓▓░░░",
    "very_weak": "▓░░░░",
    "none":      "░░░░░",
}

# Security level ASCII indicators
SECURITY_BADGES: Dict[str, str] = {
    "wpa3":     "█████",
    "wpa2":     "████░",
    "wpa":      "███░░",
    "wep":      "██░░░",
    "open":     "░░░░░",
}


class ASCIIArt:
    """Utility class for ASCII art generation and display."""

    @staticmethod
    def get_logo(small: bool = False) -> str:
        """Get the WiFiAIO logo.

        Args:
            small: If True, return the compact version.

        Returns:
            ASCII art logo string.
        """
        return WIFI_AIO_SMALL if small else WIFI_AIO_LOGO

    @staticmethod
    def get_module_icon(module: str) -> str:
        """Get the icon for a module name.

        Args:
            module: Module name.

        Returns:
            Icon string, or a default bullet if not found.
        """
        return MODULE_ICONS.get(module, "►")

    @staticmethod
    def get_status_art(status: str) -> str:
        """Get ASCII art for a status indicator.

        Args:
            status: Status key (scanning, capturing, cracking, etc.).

        Returns:
            ASCII art string, or empty string if not found.
        """
        lines = STATUS_ART.get(status, [])
        return "\n".join(lines)

    @staticmethod
    def get_signal_bar(signal_level: str) -> str:
        """Get ASCII signal strength bar.

        Args:
            signal_level: Signal level key (excellent, good, fair, weak, etc.).

        Returns:
            Signal bar string.
        """
        return SIGNAL_BARS.get(signal_level, "░░░░░")

    @staticmethod
    def get_security_badge(security: str) -> str:
        """Get ASCII security level badge.

        Args:
            security: Security type key (wpa3, wpa2, wpa, wep, open).

        Returns:
            Security badge string.
        """
        return SECURITY_BADGES.get(security.lower(), "░░░░░")

    @staticmethod
    def text_box(text: str, width: int = 50, style: str = "single") -> str:
        """Create an ASCII text box around text.

        Args:
            text: Text content for the box.
            width: Box width in characters.
            style: Box style ("single", "double", "round").

        Returns:
            Boxed text string.
        """
        chars = {
            "single": {"tl": "┌", "tr": "┐", "bl": "└", "br": "┘", "h": "─", "v": "│"},
            "double": {"tl": "╔", "tr": "╗", "bl": "╚", "br": "╝", "h": "═", "v": "║"},
            "round":  {"tl": "╭", "tr": "╮", "bl": "╰", "br": "╯", "h": "─", "v": "│"},
        }
        c = chars.get(style, chars["single"])
        inner_width = width - 2

        lines = []
        lines.append(f"{c['tl']}{c['h'] * inner_width}{c['tr']}")
        for line in text.split("\n"):
            lines.append(f"{c['v']} {line.ljust(inner_width - 1)}{c['v']}")
        lines.append(f"{c['bl']}{c['h'] * inner_width}{c['br']}")
        return "\n".join(lines)

    @staticmethod
    def progress_bar_frame(frame: int, width: int = 20) -> str:
        """Generate an animated progress bar frame.

        Args:
            frame: Current animation frame number.
            width: Bar width.

        Returns:
            Animated progress bar string.
        """
        patterns = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = frame % len(patterns)
        spinner = patterns[idx]
        dots = "." * ((frame % 3) + 1)
        return f"  {spinner} Processing{dots}"
