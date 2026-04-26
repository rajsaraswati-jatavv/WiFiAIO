"""Theme management for WiFiAIO TUI."""

import json
import logging
import os
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ─── Built-in Themes ──────────────────────────────────────────────────

THEMES: Dict[str, Dict] = {
    "dark": {
        "name": "Dark",
        "background": "#1e1e2e",
        "surface": "#282840",
        "primary": "#89b4fa",
        "secondary": "#a6adc8",
        "accent": "#f5c2e7",
        "success": "#a6e3a1",
        "warning": "#f9e2af",
        "error": "#f38ba8",
        "info": "#89dceb",
        "text": "#cdd6f4",
        "text_muted": "#6c7086",
        "text_bold": "#cdd6f4",
        "border": "#45475a",
        "highlight": "#45475a",
        "scrollbar": "#585b70",
        "cursor": "#f5e0dc",
        "panel_header_bg": "#313244",
        "panel_header_fg": "#cdd6f4",
        "table_header_bg": "#313244",
        "table_header_fg": "#89b4fa",
        "table_row_even": "#1e1e2e",
        "table_row_odd": "#252540",
        "signal_excellent": "#a6e3a1",
        "signal_good": "#a6e3a1",
        "signal_fair": "#f9e2af",
        "signal_poor": "#fab387",
        "signal_unusable": "#f38ba8",
        "security_minimal": "#a6e3a1",
        "security_low": "#a6e3a1",
        "security_medium": "#f9e2af",
        "security_high": "#fab387",
        "security_critical": "#f38ba8",
    },
    "light": {
        "name": "Light",
        "background": "#eff1f5",
        "surface": "#e6e9ef",
        "primary": "#1e66f5",
        "secondary": "#6c6f85",
        "accent": "#ea76cb",
        "success": "#40a02b",
        "warning": "#df8e1d",
        "error": "#d20f39",
        "info": "#179299",
        "text": "#4c4f69",
        "text_muted": "#9ca0b0",
        "text_bold": "#4c4f69",
        "border": "#bcc0cc",
        "highlight": "#ccd0da",
        "scrollbar": "#acb0be",
        "cursor": "#dc8a78",
        "panel_header_bg": "#dce0e8",
        "panel_header_fg": "#4c4f69",
        "table_header_bg": "#dce0e8",
        "table_header_fg": "#1e66f5",
        "table_row_even": "#eff1f5",
        "table_row_odd": "#e6e9ef",
        "signal_excellent": "#40a02b",
        "signal_good": "#40a02b",
        "signal_fair": "#df8e1d",
        "signal_poor": "#fe640b",
        "signal_unusable": "#d20f39",
        "security_minimal": "#40a02b",
        "security_low": "#40a02b",
        "security_medium": "#df8e1d",
        "security_high": "#fe640b",
        "security_critical": "#d20f39",
    },
    "hacker": {
        "name": "Hacker",
        "background": "#0d0d0d",
        "surface": "#1a1a1a",
        "primary": "#00ff41",
        "secondary": "#008f11",
        "accent": "#39ff14",
        "success": "#00ff41",
        "warning": "#ffff00",
        "error": "#ff0000",
        "info": "#00cc00",
        "text": "#00ff41",
        "text_muted": "#006600",
        "text_bold": "#39ff14",
        "border": "#003300",
        "highlight": "#004400",
        "scrollbar": "#006600",
        "cursor": "#39ff14",
        "panel_header_bg": "#001a00",
        "panel_header_fg": "#00ff41",
        "table_header_bg": "#001a00",
        "table_header_fg": "#39ff14",
        "table_row_even": "#0d0d0d",
        "table_row_odd": "#0a0a0a",
        "signal_excellent": "#00ff41",
        "signal_good": "#00ff41",
        "signal_fair": "#ffff00",
        "signal_poor": "#ff8800",
        "signal_unusable": "#ff0000",
        "security_minimal": "#00ff41",
        "security_low": "#00ff41",
        "security_medium": "#ffff00",
        "security_high": "#ff8800",
        "security_critical": "#ff0000",
    },
    "nord": {
        "name": "Nord",
        "background": "#2e3440",
        "surface": "#3b4252",
        "primary": "#88c0d0",
        "secondary": "#d8dee9",
        "accent": "#b48ead",
        "success": "#a3be8c",
        "warning": "#ebcb8b",
        "error": "#bf616a",
        "info": "#81a1c1",
        "text": "#eceff4",
        "text_muted": "#4c566a",
        "text_bold": "#eceff4",
        "border": "#4c566a",
        "highlight": "#434c5e",
        "scrollbar": "#4c566a",
        "cursor": "#d08770",
        "panel_header_bg": "#434c5e",
        "panel_header_fg": "#eceff4",
        "table_header_bg": "#434c5e",
        "table_header_fg": "#88c0d0",
        "table_row_even": "#2e3440",
        "table_row_odd": "#3b4252",
        "signal_excellent": "#a3be8c",
        "signal_good": "#a3be8c",
        "signal_fair": "#ebcb8b",
        "signal_poor": "#d08770",
        "signal_unusable": "#bf616a",
        "security_minimal": "#a3be8c",
        "security_low": "#a3be8c",
        "security_medium": "#ebcb8b",
        "security_high": "#d08770",
        "security_critical": "#bf616a",
    },
    "solarized": {
        "name": "Solarized",
        "background": "#002b36",
        "surface": "#073642",
        "primary": "#268bd2",
        "secondary": "#839496",
        "accent": "#d33682",
        "success": "#859900",
        "warning": "#b58900",
        "error": "#dc322f",
        "info": "#2aa198",
        "text": "#93a1a1",
        "text_muted": "#586e75",
        "text_bold": "#eee8d5",
        "border": "#586e75",
        "highlight": "#073642",
        "scrollbar": "#586e75",
        "cursor": "#cb4b16",
        "panel_header_bg": "#073642",
        "panel_header_fg": "#eee8d5",
        "table_header_bg": "#073642",
        "table_header_fg": "#268bd2",
        "table_row_even": "#002b36",
        "table_row_odd": "#073642",
        "signal_excellent": "#859900",
        "signal_good": "#859900",
        "signal_fair": "#b58900",
        "signal_poor": "#cb4b16",
        "signal_unusable": "#dc322f",
        "security_minimal": "#859900",
        "security_low": "#859900",
        "security_medium": "#b58900",
        "security_high": "#cb4b16",
        "security_critical": "#dc322f",
    },
}


class ThemeManager:
    """Manage TUI themes for WiFiAIO."""

    def __init__(self, theme_dir: Optional[str] = None, current: str = "dark"):
        self.theme_dir = Path(
            os.path.expanduser(theme_dir or "~/.config/wifi_aio/themes")
        )
        self._current_name = current
        self._themes: Dict[str, Dict] = dict(THEMES)
        self._load_custom_themes()

    @property
    def current_name(self) -> str:
        """Name of the active theme."""
        return self._current_name

    @property
    def current(self) -> Dict:
        """The active theme dictionary."""
        return self._themes.get(self._current_name, self._themes["dark"])

    def set_theme(self, name: str) -> None:
        """Switch to a different theme.

        Args:
            name: Theme name (must exist in loaded themes).

        Raises:
            ValueError: If the theme name is not found.
        """
        if name not in self._themes:
            raise ValueError(f"Theme '{name}' not found. Available: {list(self._themes.keys())}")
        self._current_name = name

    def get_theme(self, name: str) -> Dict:
        """Get a theme dictionary by name."""
        return self._themes.get(name, {})

    def list_themes(self) -> list:
        """List all available theme names."""
        return sorted(self._themes.keys())

    def get_color(self, key: str, theme_name: Optional[str] = None) -> str:
        """Get a specific color value from a theme.

        Args:
            key: Color key (e.g. 'primary', 'background', 'signal_good').
            theme_name: Theme name (defaults to current theme).

        Returns:
            Hex color string (e.g. '#89b4fa').
        """
        theme = self._themes.get(theme_name or self._current_name, {})
        return theme.get(key, "#ffffff")

    def register_theme(self, name: str, theme: Dict) -> None:
        """Register a custom theme.

        Args:
            name: Theme name.
            theme: Dict of color key → hex value. Missing keys will
                inherit from the dark theme.
        """
        merged = dict(THEMES["dark"])
        merged.update(theme)
        merged["name"] = name
        self._themes[name] = merged

    def save_theme(self, name: str, filepath: Optional[str] = None) -> str:
        """Save a theme to a JSON file.

        Args:
            name: Theme name to save.
            filepath: Output path. Defaults to theme_dir/<name>.json.

        Returns:
            Path the file was saved to.
        """
        theme = self._themes.get(name)
        if theme is None:
            raise ValueError(f"Theme '{name}' not found")

        if filepath is None:
            self.theme_dir.mkdir(parents=True, exist_ok=True)
            filepath = str(self.theme_dir / f"{name}.json")

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(theme, fh, indent=2, sort_keys=True)

        return filepath

    def _load_custom_themes(self) -> None:
        """Load any custom theme JSON files from the theme directory."""
        if not self.theme_dir.exists():
            return

        for item in self.theme_dir.iterdir():
            if item.is_file() and item.suffix == ".json":
                try:
                    with open(item, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                    if isinstance(data, dict) and "name" in data:
                        name = item.stem
                        merged = dict(THEMES["dark"])
                        merged.update(data)
                        self._themes[name] = merged
                        logger.debug("Loaded custom theme: %s", name)
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning("Failed to load theme %s: %s", item, exc)

    def signal_color(self, rssi: int, theme_name: Optional[str] = None) -> str:
        """Get the appropriate signal color for an RSSI value.

        Args:
            rssi: Signal strength in dBm.
            theme_name: Theme name (defaults to current).

        Returns:
            Hex color string.
        """
        if rssi >= -50:
            key = "signal_excellent"
        elif rssi >= -60:
            key = "signal_good"
        elif rssi >= -70:
            key = "signal_fair"
        elif rssi >= -80:
            key = "signal_poor"
        else:
            key = "signal_unusable"
        return self.get_color(key, theme_name)

    def security_color(self, risk: str, theme_name: Optional[str] = None) -> str:
        """Get the appropriate security color for a risk level.

        Args:
            risk: Risk level string (critical, high, medium, low, minimal, info).
            theme_name: Theme name (defaults to current).

        Returns:
            Hex color string.
        """
        key = f"security_{risk}"
        return self.get_color(key, theme_name)
