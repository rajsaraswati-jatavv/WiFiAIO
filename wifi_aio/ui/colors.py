"""Color definitions for terminal output.

Provides ANSI color codes, 8 built-in themes, and utility functions
for styled terminal output across different environments.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Dict, Optional


class Colors:
    """ANSI color code constants for terminal output."""

    # Reset
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"
    HIDDEN = "\033[8m"
    STRIKETHROUGH = "\033[9m"

    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright foreground colors
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Background colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"

    # Bright background colors
    BG_BRIGHT_BLACK = "\033[100m"
    BG_BRIGHT_RED = "\033[101m"
    BG_BRIGHT_GREEN = "\033[102m"
    BG_BRIGHT_YELLOW = "\033[103m"
    BG_BRIGHT_BLUE = "\033[104m"
    BG_BRIGHT_MAGENTA = "\033[105m"
    BG_BRIGHT_CYAN = "\033[106m"
    BG_BRIGHT_WHITE = "\033[107m"

    @staticmethod
    def rgb(r: int, g: int, b: int) -> str:
        """Return ANSI 24-bit color escape sequence.

        Args:
            r: Red component (0-255).
            g: Green component (0-255).
            b: Blue component (0-255).

        Returns:
            ANSI escape string for the specified color.
        """
        return f"\033[38;2;{r};{g};{b}m"

    @staticmethod
    def bg_rgb(r: int, g: int, b: int) -> str:
        """Return ANSI 24-bit background color escape sequence."""
        return f"\033[48;2;{r};{g};{b}m"

    @staticmethod
    def supports_color() -> bool:
        """Check if the terminal supports color output."""
        if os.getenv("NO_COLOR") is not None:
            return False
        if os.getenv("TERM") == "dumb":
            return False
        if not hasattr(sys.stdout, "isatty"):
            return False
        if not sys.stdout.isatty():
            return False
        if os.name == "nt":
            return os.getenv("ANSICON") is not None or os.getenv("WT_SESSION") is not None
        return True


@dataclass
class Theme:
    """Color theme definition for terminal UI elements."""
    name: str
    description: str
    primary: str
    secondary: str
    success: str
    warning: str
    error: str
    info: str
    accent: str
    muted: str
    highlight: str = ""
    bg_primary: str = ""
    bg_secondary: str = ""

    def style(self, text: str, style_type: str) -> str:
        """Apply a themed style to text.

        Args:
            text: Text to style.
            style_type: Style type key (primary, secondary, success, etc.).

        Returns:
            Styled text string.
        """
        if not Colors.supports_color():
            return text
        color = getattr(self, style_type, "")
        if not color:
            return text
        return f"{color}{text}{Colors.RESET}"


# ── Built-in Themes ─────────────────────────────────────────────────────

THEMES: Dict[str, Theme] = {
    "default": Theme(
        name="default",
        description="Default dark theme with cyan accents",
        primary=Colors.CYAN,
        secondary=Colors.BRIGHT_CYAN,
        success=Colors.GREEN,
        warning=Colors.YELLOW,
        error=Colors.RED,
        info=Colors.BLUE,
        accent=Colors.BRIGHT_MAGENTA,
        muted=Colors.BRIGHT_BLACK,
        highlight=Colors.BRIGHT_WHITE,
    ),
    "hacker": Theme(
        name="hacker",
        description="Classic green-on-black hacker theme",
        primary=Colors.GREEN,
        secondary=Colors.BRIGHT_GREEN,
        success=Colors.BRIGHT_GREEN,
        warning=Colors.BRIGHT_YELLOW,
        error=Colors.BRIGHT_RED,
        info=Colors.GREEN,
        accent=Colors.BRIGHT_GREEN,
        muted=Colors.DIM + Colors.GREEN,
        highlight=Colors.BOLD + Colors.BRIGHT_GREEN,
    ),
    "ocean": Theme(
        name="ocean",
        description="Deep blue ocean theme",
        primary=Colors.BLUE,
        secondary=Colors.BRIGHT_BLUE,
        success=Colors.CYAN,
        warning=Colors.BRIGHT_YELLOW,
        error=Colors.BRIGHT_RED,
        info=Colors.BRIGHT_BLUE,
        accent=Colors.BRIGHT_CYAN,
        muted=Colors.BRIGHT_BLACK,
        highlight=Colors.BRIGHT_WHITE,
    ),
    "sunset": Theme(
        name="sunset",
        description="Warm sunset gradient theme",
        primary=Colors.rgb(255, 154, 0),
        secondary=Colors.rgb(255, 206, 0),
        success=Colors.rgb(255, 184, 0),
        warning=Colors.rgb(255, 111, 0),
        error=Colors.rgb(255, 61, 0),
        info=Colors.rgb(255, 167, 38),
        accent=Colors.rgb(255, 82, 82),
        muted=Colors.rgb(180, 120, 60),
        highlight=Colors.rgb(255, 235, 59),
    ),
    "cyberpunk": Theme(
        name="cyberpunk",
        description="Neon cyberpunk aesthetic",
        primary=Colors.rgb(0, 255, 255),
        secondary=Colors.rgb(255, 0, 255),
        success=Colors.rgb(0, 255, 128),
        warning=Colors.rgb(255, 255, 0),
        error=Colors.rgb(255, 0, 64),
        info=Colors.rgb(128, 0, 255),
        accent=Colors.rgb(255, 0, 255),
        muted=Colors.rgb(128, 128, 128),
        highlight=Colors.rgb(255, 255, 255),
    ),
    "monochrome": Theme(
        name="monochrome",
        description="Clean monochrome with bold emphasis",
        primary=Colors.WHITE,
        secondary=Colors.BRIGHT_WHITE,
        success=Colors.BRIGHT_WHITE,
        warning=Colors.BOLD + Colors.WHITE,
        error=Colors.BOLD + Colors.WHITE,
        info=Colors.BRIGHT_BLACK,
        accent=Colors.BOLD + Colors.WHITE,
        muted=Colors.BRIGHT_BLACK,
        highlight=Colors.BOLD + Colors.WHITE,
    ),
    "dracula": Theme(
        name="dracula",
        description="Dracula color scheme inspired theme",
        primary=Colors.rgb(189, 147, 249),
        secondary=Colors.rgb(80, 250, 123),
        success=Colors.rgb(80, 250, 123),
        warning=Colors.rgb(241, 250, 140),
        error=Colors.rgb(255, 85, 85),
        info=Colors.rgb(139, 233, 253),
        accent=Colors.rgb(255, 121, 198),
        muted=Colors.rgb(98, 114, 164),
        highlight=Colors.rgb(248, 248, 242),
    ),
    "nord": Theme(
        name="nord",
        description="Nord color palette theme",
        primary=Colors.rgb(136, 192, 208),
        secondary=Colors.rgb(129, 161, 193),
        success=Colors.rgb(163, 190, 140),
        warning=Colors.rgb(235, 203, 139),
        error=Colors.rgb(191, 97, 106),
        info=Colors.rgb(94, 129, 172),
        accent=Colors.rgb(180, 142, 173),
        muted=Colors.rgb(76, 86, 106),
        highlight=Colors.rgb(236, 239, 244),
    ),
}

# Active theme (default)
_active_theme: Optional[Theme] = THEMES["default"]


def get_theme() -> Theme:
    """Get the currently active theme.

    Returns:
        The active Theme object.
    """
    return _active_theme


def set_theme(name: str) -> None:
    """Set the active theme by name.

    Args:
        name: Theme name (must exist in THEMES dict).

    Raises:
        KeyError: If the theme name is not found.
    """
    global _active_theme
    if name not in THEMES:
        raise KeyError(f"Theme '{name}' not found. Available: {list(THEMES.keys())}")
    _active_theme = THEMES[name]


def styled(text: str, style_type: str, theme: Optional[Theme] = None) -> str:
    """Apply a themed style to text.

    Args:
        text: Text to style.
        style_type: Style type key (primary, success, warning, error, etc.).
        theme: Optional theme override; uses active theme if None.

    Returns:
        Styled text string.
    """
    t = theme or _active_theme
    if t is None:
        t = THEMES["default"]
    return t.style(text, style_type)


def colorize(text: str, color: str) -> str:
    """Apply a raw color code to text.

    Args:
        text: Text to colorize.
        color: ANSI color escape sequence.

    Returns:
        Colorized text string.
    """
    if not Colors.supports_color():
        return text
    return f"{color}{text}{Colors.RESET}"
