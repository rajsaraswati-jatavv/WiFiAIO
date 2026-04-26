"""Example plugin implementation for WiFiAIO.

Demonstrates how to create a plugin by subclassing BasePlugin,
registering hooks, and handling events.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from wifi_aio.plugins.base_plugin import BasePlugin, PluginHook, PluginInfo

logger = logging.getLogger(__name__)


class ExamplePlugin(BasePlugin):
    """Sample plugin that logs scan results and filters weak signals.

    This plugin demonstrates:
      - Plugin metadata via the ``info`` property.
      - Lifecycle hooks (``on_load``, ``on_unload``).
      - Hook subscription and event handling.
      - Configuration management.

    Example::

        from wifi_aio.plugins import ExamplePlugin, PluginRegistry

        registry = PluginRegistry()
        plugin = ExamplePlugin()
        registry.register(plugin)
        registry.enable_plugin("example_plugin")
        registry.load_all()

        # Later, when a scan completes:
        filtered = registry.dispatch(PluginHook.POST_SCAN, scan_results)
    """

    def __init__(self, min_signal: int = -70, log_scans: bool = True) -> None:
        super().__init__()
        self._min_signal = min_signal
        self._log_scans = log_scans
        self._scan_count: int = 0
        self._start_time: float = 0.0

    # ── Plugin metadata ────────────────────────────────────────────────

    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            name="example_plugin",
            version="1.0.0",
            description="Example plugin: logs scans and filters weak signals",
            author="WiFiAIO Team",
            license="MIT",
            hooks=[
                PluginHook.PRE_SCAN.value,
                PluginHook.POST_SCAN.value,
                PluginHook.PASSWORD_FOUND.value,
            ],
            config_schema={
                "min_signal": {
                    "type": "int",
                    "default": -70,
                    "description": "Minimum signal strength (dBm) to keep in results",
                },
                "log_scans": {
                    "type": "bool",
                    "default": True,
                    "description": "Whether to log scan results to the plugin logger",
                },
            },
        )

    # ── Lifecycle ──────────────────────────────────────────────────────

    def on_load(self, context: dict[str, Any]) -> None:
        """Called when the plugin is loaded."""
        self._context = context
        self._start_time = time.time()
        self._config.setdefault("min_signal", self._min_signal)
        self._config.setdefault("log_scans", self._log_scans)

        # Register explicit hook handlers
        self.register_hook(PluginHook.PRE_SCAN.value, self._on_pre_scan)
        self.register_hook(PluginHook.POST_SCAN.value, self._on_post_scan)
        self.register_hook(PluginHook.PASSWORD_FOUND.value, self._on_password_found)

        self.log("info", "ExamplePlugin loaded and ready")

    def on_unload(self) -> None:
        """Called when the plugin is unloaded."""
        uptime = time.time() - self._start_time if self._start_time else 0
        self.log(
            "info",
            f"ExamplePlugin unloading – {self._scan_count} scans processed "
            f"in {uptime:.0f}s uptime",
        )

    # ── Hook handlers ──────────────────────────────────────────────────

    def _on_pre_scan(self, data: Any) -> Any:
        """Handle the pre-scan hook.

        Called before a network scan begins. *data* may contain scan
        parameters.
        """
        self.log("info", "Scan starting...")
        return data

    def _on_post_scan(self, data: Any) -> Any:
        """Handle the post-scan hook.

        Called after a network scan completes. *data* is expected to
        be a list of AP dicts. This handler filters out weak signals
        based on the ``min_signal`` configuration.
        """
        self._scan_count += 1

        if data is None:
            return data

        if not isinstance(data, list):
            if self._config.get("log_scans", True):
                self.log("info", f"Scan #{self._scan_count} completed (non-list data)")
            return data

        # Log scan summary
        if self._config.get("log_scans", True):
            self.log(
                "info",
                f"Scan #{self._scan_count} found {len(data)} access points",
            )

        # Filter by minimum signal strength
        min_signal = self._config.get("min_signal", -70)
        filtered = [
            ap for ap in data
            if isinstance(ap, dict) and ap.get("signal_dbm", -100) >= min_signal
        ]

        removed = len(data) - len(filtered)
        if removed > 0:
            self.log(
                "debug",
                f"Filtered {removed} APs below {min_signal} dBm "
                f"({len(filtered)} remaining)",
            )

        return filtered

    def _on_password_found(self, data: Any) -> Any:
        """Handle the password-found hook.

        Called when a password is successfully cracked.
        """
        if isinstance(data, dict):
            ssid = data.get("ssid", "unknown")
            password = data.get("password", "")
            self.log("info", f"Password found for '{ssid}': {password}")
        else:
            self.log("info", f"Password found: {data}")

        return data

    # ── Convenience naming convention handlers ─────────────────────────
    # These will also be discovered by the base class's handle() method
    # via the on_<hook> naming convention if not explicitly registered.

    def on_anomaly_detected(self, data: Any) -> Any:
        """Handle anomaly detection events."""
        self.log("info", f"Anomaly detected: {data}")
        return data

    def on_config_change(self, changed: dict[str, Any]) -> None:
        """React to configuration changes."""
        if "min_signal" in changed:
            self._min_signal = changed["min_signal"]
            self.log("info", f"Minimum signal threshold updated to {self._min_signal} dBm")

        if "log_scans" in changed:
            self._log_scans = changed["log_scans"]
            self.log("info", f"Scan logging {'enabled' if self._log_scans else 'disabled'}")

    # ── Custom plugin methods ──────────────────────────────────────────

    def get_scan_count(self) -> int:
        """Return the number of scans processed since loading."""
        return self._scan_count

    def get_uptime(self) -> float:
        """Return seconds since the plugin was loaded."""
        if not self._start_time:
            return 0.0
        return time.time() - self._start_time

    def get_stats(self) -> dict[str, Any]:
        """Return plugin statistics."""
        return {
            "scan_count": self._scan_count,
            "uptime": self.get_uptime(),
            "min_signal": self._config.get("min_signal", self._min_signal),
            "log_scans": self._config.get("log_scans", self._log_scans),
            "enabled": self.enabled,
        }
