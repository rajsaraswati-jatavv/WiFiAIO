"""Input handling for terminal user interaction.

Provides prompts, confirmations, selections, and multi-select
utilities for interactive CLI applications.
"""

from __future__ import annotations

import getpass
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from wifi_aio.ui.colors import Colors, get_theme, styled
from wifi_aio.exceptions import WiFiTimeoutError


class InputHandler:
    """Centralized input handling with validation, timeout, and history."""

    def __init__(self, history_size: int = 100):
        self.history_size = history_size
        self._history: List[str] = []

    def prompt(
        self,
        message: str,
        default: Optional[str] = None,
        validator: Optional[Callable[[str], bool]] = None,
        error_message: str = "Invalid input. Please try again.",
        hidden: bool = False,
        max_attempts: int = 3,
    ) -> Optional[str]:
        """Prompt the user for text input.

        Args:
            message: Prompt message to display.
            default: Default value if user enters nothing.
            validator: Optional validation function.
            error_message: Message to show on validation failure.
            hidden: If True, input is hidden (password mode).
            max_attempts: Maximum number of retry attempts.

        Returns:
            User input string, or None if cancelled.
        """
        theme = get_theme()
        prompt_text = styled(f"  {message}", "primary", theme)
        if default:
            prompt_text += styled(f" [{default}]", "muted", theme)
        prompt_text += ": "

        for attempt in range(max_attempts):
            try:
                if hidden:
                    value = getpass.getpass(prompt_text)
                else:
                    value = input(prompt_text)
            except (EOFError, KeyboardInterrupt):
                print()
                return None

            value = value.strip()
            if not value and default:
                value = default
            if not value:
                continue
            if validator and not validator(value):
                print(styled(f"  {error_message}", "error", theme))
                continue

            self._add_history(value)
            return value

        print(styled("  Maximum attempts reached.", "error", theme))
        return None

    def confirm(
        self,
        message: str,
        default: bool = False,
    ) -> bool:
        """Prompt the user for a yes/no confirmation.

        Args:
            message: Confirmation message.
            default: Default value if user presses Enter.

        Returns:
            True for yes, False for no.
        """
        theme = get_theme()
        hint = "(Y/n)" if default else "(y/N)"
        prompt_text = styled(f"  {message} ", "warning", theme) + styled(f"{hint}: ", "muted", theme)

        try:
            value = input(prompt_text).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return default

        if not value:
            return default
        return value in ("y", "yes", "1", "true")

    def select(
        self,
        message: str,
        options: List[str],
        allow_cancel: bool = True,
    ) -> Optional[int]:
        """Prompt the user to select from a list of options.

        Args:
            message: Selection prompt message.
            options: List of option strings.
            allow_cancel: If True, allows cancellation.

        Returns:
            Selected option index (0-based), or None if cancelled.
        """
        theme = get_theme()
        print()
        print(styled(f"  {message}", "primary", theme))

        for i, option in enumerate(options):
            num = styled(f"  [{i + 1}]", "accent", theme)
            print(f"{num} {option}")

        if allow_cancel:
            print(styled(f"  [0]", "muted", theme) + " Cancel")

        while True:
            try:
                raw = input(styled("  Select> ", "accent", theme)).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return None

            if raw == "0" and allow_cancel:
                return None
            try:
                idx = int(raw) - 1
                if 0 <= idx < len(options):
                    return idx
            except ValueError:
                pass

            print(styled("  Invalid selection. Try again.", "error", theme))

    def multi_select(
        self,
        message: str,
        options: List[str],
        allow_empty: bool = False,
    ) -> List[int]:
        """Prompt the user to select multiple options.

        Args:
            message: Selection prompt message.
            options: List of option strings.
            allow_empty: If True, allows empty selection.

        Returns:
            List of selected indices (0-based).
        """
        theme = get_theme()
        print()
        print(styled(f"  {message}", "primary", theme))
        print(styled("  Enter comma-separated numbers (e.g., 1,3,5)", "muted", theme))

        for i, option in enumerate(options):
            num = styled(f"  [{i + 1}]", "accent", theme)
            print(f"{num} {option}")

        while True:
            try:
                raw = input(styled("  Select> ", "accent", theme)).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return []

            if not raw and allow_empty:
                return []
            try:
                indices = [int(x.strip()) - 1 for x in raw.split(",")]
                if all(0 <= idx < len(options) for idx in indices):
                    return indices
            except ValueError:
                pass

            print(styled("  Invalid selection. Try again.", "error", theme))

    def _add_history(self, value: str) -> None:
        """Add a value to input history."""
        self._history.append(value)
        if len(self._history) > self.history_size:
            self._history.pop(0)


# ── Module-level convenience functions ───────────────────────────────────

# Default input handler instance
_default_handler = InputHandler()


def prompt(
    message: str,
    default: Optional[str] = None,
    validator: Optional[Callable[[str], bool]] = None,
    hidden: bool = False,
) -> Optional[str]:
    """Prompt for user input using the default handler.

    Args:
        message: Prompt message.
        default: Default value.
        validator: Optional validation function.
        hidden: If True, input is hidden.

    Returns:
        User input string, or None if cancelled.
    """
    return _default_handler.prompt(message, default, validator, hidden=hidden)


def confirm(message: str, default: bool = False) -> bool:
    """Prompt for yes/no confirmation using the default handler.

    Args:
        message: Confirmation message.
        default: Default value.

    Returns:
        True for yes, False for no.
    """
    return _default_handler.confirm(message, default)


def select(message: str, options: List[str]) -> Optional[int]:
    """Prompt for option selection using the default handler.

    Args:
        message: Selection message.
        options: List of options.

    Returns:
        Selected index (0-based), or None if cancelled.
    """
    return _default_handler.select(message, options)


def multi_select(message: str, options: List[str]) -> List[int]:
    """Prompt for multi-option selection using the default handler.

    Args:
        message: Selection message.
        options: List of options.

    Returns:
        List of selected indices (0-based).
    """
    return _default_handler.multi_select(message, options)


# ── Common validators ────────────────────────────────────────────────────

def validate_mac_address(value: str) -> bool:
    """Validate a MAC address format."""
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, value))


def validate_ip_address(value: str) -> bool:
    """Validate an IPv4 address format."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, value):
        return False
    parts = value.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def validate_port(value: str) -> bool:
    """Validate a network port number."""
    try:
        port = int(value)
        return 1 <= port <= 65535
    except ValueError:
        return False


def validate_channel(value: str) -> bool:
    """Validate a WiFi channel number."""
    try:
        ch = int(value)
        return ch in list(range(1, 15)) or ch in [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
    except ValueError:
        return False


def validate_ssid(value: str) -> bool:
    """Validate an SSID (1-32 bytes)."""
    return 1 <= len(value.encode("utf-8")) <= 32


def validate_bssid(value: str) -> bool:
    """Validate a BSSID (MAC address format)."""
    return validate_mac_address(value)


def validate_wps_pin(value: str) -> bool:
    """Validate a WPS PIN (8 digits)."""
    return value.isdigit() and len(value) == 8
