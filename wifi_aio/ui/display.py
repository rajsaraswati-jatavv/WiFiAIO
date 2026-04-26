"""Display helpers for terminal output.

Provides banners, headers, section dividers, formatted output,
and key-value list display utilities.
"""

from __future__ import annotations

import shutil
import textwrap
from typing import Any, Dict, List, Optional, Tuple

from wifi_aio.ui.colors import Colors, get_theme, styled


class Banner:
    """Application banner display component."""

    def __init__(self, title: str, subtitle: str = "", version: str = ""):
        self.title = title
        self.subtitle = subtitle
        self.version = version

    def render(self) -> str:
        """Render the banner as a formatted string."""
        theme = get_theme()
        width = min(70, shutil.get_terminal_size().columns - 4)
        lines: List[str] = []
        lines.append(styled("=" * width, "muted", theme))
        lines.append("")
        lines.append(styled(self.title.center(width), "primary", theme))
        if self.subtitle:
            lines.append(styled(self.subtitle.center(width), "secondary", theme))
        if self.version:
            lines.append(styled(f"v{self.version}".center(width), "muted", theme))
        lines.append("")
        lines.append(styled("=" * width, "muted", theme))
        return "\n".join(lines)

    def print(self) -> None:
        """Print the banner to stdout."""
        print(self.render())


class Header:
    """Section header display component."""

    def __init__(self, text: str, level: int = 1):
        self.text = text
        self.level = level

    def render(self) -> str:
        """Render the header as a formatted string."""
        theme = get_theme()
        width = min(60, shutil.get_terminal_size().columns - 4)

        if self.level == 1:
            return "\n".join([
                "",
                styled(f"  {self.text}", "primary", theme),
                styled(f"  {'═' * min(len(self.text), width)}", "primary", theme),
            ])
        elif self.level == 2:
            return "\n".join([
                "",
                styled(f"  {self.text}", "secondary", theme),
                styled(f"  {'─' * min(len(self.text), width)}", "muted", theme),
            ])
        else:
            return styled(f"  ▸ {self.text}", "accent", theme)

    def print(self) -> None:
        """Print the header to stdout."""
        print(self.render())


class Section:
    """Content section with title and body text."""

    def __init__(self, title: str, content: str = "", collapsed: bool = False):
        self.title = title
        self.content = content
        self.collapsed = collapsed

    def render(self) -> str:
        """Render the section as a formatted string."""
        theme = get_theme()
        lines: List[str] = []
        marker = "▶" if self.collapsed else "▼"
        lines.append(styled(f"  {marker} {self.title}", "primary", theme))

        if not self.collapsed and self.content:
            for line in self.content.split("\n"):
                wrapped = textwrap.wrap(line, width=70, initial_indent="    ", subsequent_indent="    ")
                lines.extend(wrapped)

        return "\n".join(lines)

    def print(self) -> None:
        """Print the section to stdout."""
        print(self.render())


class FormattedOutput:
    """Utilities for formatted terminal output."""

    @staticmethod
    def info(message: str) -> str:
        """Format an info message."""
        theme = get_theme()
        return styled(f"  ℹ {message}", "info", theme)

    @staticmethod
    def success(message: str) -> str:
        """Format a success message."""
        theme = get_theme()
        return styled(f"  ✓ {message}", "success", theme)

    @staticmethod
    def warning(message: str) -> str:
        """Format a warning message."""
        theme = get_theme()
        return styled(f"  ⚠ {message}", "warning", theme)

    @staticmethod
    def error(message: str) -> str:
        """Format an error message."""
        theme = get_theme()
        return styled(f"  ✗ {message}", "error", theme)

    @staticmethod
    def debug(message: str) -> str:
        """Format a debug message."""
        theme = get_theme()
        return styled(f"  ⚙ {message}", "muted", theme)

    @staticmethod
    def item(label: str, value: Any, label_width: int = 20) -> str:
        """Format a labeled item for display.

        Args:
            label: Item label.
            value: Item value.
            label_width: Width to pad the label.

        Returns:
            Formatted string.
        """
        theme = get_theme()
        lbl = styled(f"  {label}:".ljust(label_width + 2), "accent", theme)
        val = str(value)
        return f"{lbl} {val}"

    @staticmethod
    def bullet(text: str, bullet_char: str = "•") -> str:
        """Format a bulleted item."""
        theme = get_theme()
        return f"  {styled(bullet_char, 'accent', theme)} {text}"

    @staticmethod
    def separator(char: str = "─", width: Optional[int] = None) -> str:
        """Format a visual separator line."""
        theme = get_theme()
        if width is None:
            width = min(60, shutil.get_terminal_size().columns - 4)
        return styled(f"  {char * width}", "muted", theme)


class KeyValueList:
    """Display a list of key-value pairs in a formatted layout."""

    def __init__(self, title: Optional[str] = None, key_width: int = 22):
        self.title = title
        self.key_width = key_width
        self.items: List[Tuple[str, Any]] = []

    def add(self, key: str, value: Any) -> "KeyValueList":
        """Add a key-value pair.

        Args:
            key: Label string.
            value: Value to display.

        Returns:
            Self for method chaining.
        """
        self.items.append((key, value))
        return self

    def render(self) -> str:
        """Render the key-value list as a formatted string."""
        theme = get_theme()
        lines: List[str] = []

        if self.title:
            lines.append(styled(f"  {self.title}", "primary", theme))
            lines.append(styled(f"  {'─' * len(self.title)}", "muted", theme))

        for key, value in self.items:
            lbl = styled(f"  {key}:".ljust(self.key_width + 2), "accent", theme)
            lines.append(f"{lbl} {value}")

        return "\n".join(lines)

    def print(self) -> None:
        """Print the key-value list to stdout."""
        print(self.render())


def print_info(msg: str) -> None:
    """Print an info message."""
    print(FormattedOutput.info(msg))


def print_success(msg: str) -> None:
    """Print a success message."""
    print(FormattedOutput.success(msg))


def print_warning(msg: str) -> None:
    """Print a warning message."""
    print(FormattedOutput.warning(msg))


def print_error(msg: str) -> None:
    """Print an error message."""
    print(FormattedOutput.error(msg))


def print_debug(msg: str) -> None:
    """Print a debug message."""
    print(FormattedOutput.debug(msg))
