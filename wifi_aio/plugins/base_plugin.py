"""Abstract base class for WiFiAIO plugins.

Defines the interface that all plugins must implement, including
lifecycle hooks, metadata, and configuration management.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from wifi_aio.exceptions import PluginError

logger = logging.getLogger(__name__)


class PluginHook(Enum):
    """Available hook points for plugins.

    Plugins can register callbacks at these hook points to extend
    WiFiAIO functionality at specific stages of operation.
    """

    # Scanning hooks
    PRE_SCAN = "pre_scan"
    POST_SCAN = "post_scan"
    SCAN_RESULT_FILTER = "scan_result_filter"

    # Capture hooks
    PRE_CAPTURE = "pre_capture"
    POST_CAPTURE = "post_capture"
    HANDSHAKE_CAPTURED = "handshake_captured"

    # Cracking hooks
    PRE_CRACK = "pre_crack"
    POST_CRACK = "post_crack"
    PASSWORD_FOUND = "password_found"

    # Attack hooks
    PRE_DEAUTH = "pre_deauth"
    POST_DEAUTH = "post_deauth"
    PRE_EVIL_TWIN = "pre_evil_twin"
    POST_EVIL_TWIN = "post_evil_twin"

    # Monitoring hooks
    MONITOR_TICK = "monitor_tick"
    ANOMALY_DETECTED = "anomaly_detected"

    # UI hooks
    MENU_REGISTER = "menu_register"
    TAB_REGISTER = "tab_register"

    # General hooks
    INIT = "init"
    SHUTDOWN = "shutdown"
    CONFIG_CHANGE = "config_change"


@dataclass
class PluginInfo:
    """Metadata about a plugin.

    Attributes:
        name: Unique plugin identifier.
        version: Plugin version string.
        description: Human-readable description.
        author: Plugin author name.
        url: Plugin homepage or repository URL.
        license: License identifier.
        min_app_version: Minimum WiFiAIO version required.
        hooks: List of hook names this plugin subscribes to.
        dependencies: List of other plugin names this plugin depends on.
        config_schema: Dict describing configurable parameters.
    """

    name: str = ""
    version: str = "0.1.0"
    description: str = ""
    author: str = ""
    url: str = ""
    license: str = "MIT"
    min_app_version: str = ""
    hooks: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    config_schema: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "url": self.url,
            "license": self.license,
            "min_app_version": self.min_app_version,
            "hooks": self.hooks,
            "dependencies": self.dependencies,
        }


class BasePlugin(ABC):
    """Abstract base class for WiFiAIO plugins.

    All plugins must inherit from this class and implement the
    ``info`` property and the ``on_load`` / ``on_unload`` methods.

    Lifecycle::

        plugin = MyPlugin()
        plugin.on_load(context)     # Called when the plugin is loaded
        plugin.handle(hook, data)   # Called for each subscribed hook
        plugin.on_unload()          # Called when the plugin is unloaded

    Example::

        class MyPlugin(BasePlugin):
            @property
            def info(self):
                return PluginInfo(name="my_plugin", version="1.0.0")

            def on_load(self, context):
                self._context = context
                logger.info("MyPlugin loaded")

            def on_unload(self):
                logger.info("MyPlugin unloaded")

            def on_post_scan(self, data):
                # Filter scan results
                return [ap for ap in data if ap.get("signal_dbm", -100) > -70]
    """

    def __init__(self) -> None:
        self._enabled: bool = False
        self._config: dict[str, Any] = {}
        self._context: dict[str, Any] = {}
        self._hook_handlers: dict[str, Callable[..., Any]] = {}

    # ── Abstract interface ─────────────────────────────────────────────

    @property
    @abstractmethod
    def info(self) -> PluginInfo:
        """Return plugin metadata. Must be implemented by subclasses."""
        ...

    @abstractmethod
    def on_load(self, context: dict[str, Any]) -> None:
        """Called when the plugin is loaded into the registry.

        Args:
            context: Shared context dict with application-wide state.
        """
        ...

    @abstractmethod
    def on_unload(self) -> None:
        """Called when the plugin is being unloaded.

        Perform cleanup (stop threads, close files, etc.).
        """
        ...

    # ── Lifecycle ──────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        """Whether the plugin is currently enabled."""
        return self._enabled

    def enable(self) -> None:
        """Enable the plugin."""
        if not self._enabled:
            self._enabled = True
            logger.debug("Plugin %s enabled", self.info.name)

    def disable(self) -> None:
        """Disable the plugin."""
        if self._enabled:
            self._enabled = False
            logger.debug("Plugin %s disabled", self.info.name)

    # ── Configuration ──────────────────────────────────────────────────

    @property
    def config(self) -> dict[str, Any]:
        """Current plugin configuration."""
        return self._config

    def configure(self, config: dict[str, Any]) -> None:
        """Update plugin configuration.

        Args:
            config: New configuration values (merged with existing).
        """
        self._config.update(config)
        self.on_config_change(config)

    def on_config_change(self, changed: dict[str, Any]) -> None:
        """Hook called when configuration changes.

        Override to react to config updates. Default is a no-op.
        """
        pass

    def get_config_value(self, key: str, default: Any = None) -> Any:
        """Get a single configuration value."""
        return self._config.get(key, default)

    def set_config_value(self, key: str, value: Any) -> None:
        """Set a single configuration value."""
        self._config[key] = value
        self.on_config_change({key: value})

    # ── Hook dispatch ──────────────────────────────────────────────────

    def register_hook(self, hook: str, handler: Callable[..., Any]) -> None:
        """Register a handler for a specific hook.

        Args:
            hook: Hook name (from PluginHook values or custom).
            handler: Callable to invoke when the hook fires.
        """
        self._hook_handlers[hook] = handler
        logger.debug("Plugin %s registered handler for hook %s", self.info.name, hook)

    def handle(self, hook: str, data: Any = None) -> Any:
        """Dispatch a hook event to the registered handler.

        Args:
            hook: Hook name that was triggered.
            data: Payload data for the hook.

        Returns:
            The handler's return value, or *data* unchanged if no handler.
        """
        if not self._enabled:
            return data

        handler = self._hook_handlers.get(hook)
        if handler is None:
            # Try naming convention: on_<hook>
            method_name = f"on_{hook}"
            method = getattr(self, method_name, None)
            if callable(method):
                handler = method
                self._hook_handlers[hook] = handler

        if handler is not None:
            try:
                return handler(data)
            except Exception as exc:
                raise PluginError(
                    f"Plugin {self.info.name} handler for {hook} failed: {exc}",
                    details=str(exc),
                )

        return data

    # ── Utility ────────────────────────────────────────────────────────

    def log(self, level: str, message: str) -> None:
        """Log a message with the plugin name as context."""
        log_func = getattr(logger, level, logger.info)
        log_func("[%s] %s", self.info.name, message)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(name={self.info.name!r}, "
            f"version={self.info.version!r}, enabled={self._enabled})"
        )
