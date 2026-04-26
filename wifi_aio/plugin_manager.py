"""Plugin manager for WiFiAIO."""

import importlib
import importlib.util
import inspect
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type

from wifi_aio.exceptions import PluginError

logger = logging.getLogger(__name__)


class Plugin:
    """Represents a loaded plugin."""

    def __init__(self, name: str, version: str, description: str,
                 author: str, module: Any, path: str,
                 enabled: bool = True):
        self.name = name
        self.version = version
        self.description = description
        self.author = author
        self.module = module
        self.path = path
        self.enabled = enabled
        self._hooks: Dict[str, Callable] = {}

    def register_hook(self, event: str, callback: Callable) -> None:
        """Register a callback for an event."""
        self._hooks[event] = callback

    def get_hook(self, event: str) -> Optional[Callable]:
        """Get the callback for an event."""
        return self._hooks.get(event)

    def call_hook(self, event: str, *args, **kwargs) -> Any:
        """Call the hook for an event if registered."""
        hook = self._hooks.get(event)
        if hook and self.enabled:
            try:
                return hook(*args, **kwargs)
            except Exception as exc:
                raise PluginError(f"Plugin '{self.name}' hook '{event}' failed: {exc}") from exc
        return None

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "path": self.path,
            "enabled": self.enabled,
        }


class PluginManager:
    """Load, register, and manage WiFiAIO plugins."""

    # Well-known hook events
    EVENTS = [
        "on_scan_result",
        "on_capture_start",
        "on_capture_stop",
        "on_handshake_captured",
        "on_crack_success",
        "on_crack_failure",
        "on_deauth_sent",
        "on_client_connected",
        "on_client_disconnected",
        "on_vulnerability_found",
        "on_session_start",
        "on_session_end",
        "on_report_generated",
        "on_error",
    ]

    def __init__(self, plugin_dir: Optional[str] = None):
        self.plugin_dir = Path(
            os.path.expanduser(plugin_dir or "~/.config/wifi_aio/plugins")
        )
        self._plugins: Dict[str, Plugin] = {}
        self._global_hooks: Dict[str, List[Callable]] = {}

    # ── Loading ───────────────────────────────────────────────────────

    def load_all(self) -> List[str]:
        """Load all plugins from the plugin directory.

        Returns:
            List of loaded plugin names.
        """
        loaded = []
        if not self.plugin_dir.exists():
            self.plugin_dir.mkdir(parents=True, exist_ok=True)
            return loaded

        for item in sorted(self.plugin_dir.iterdir()):
            if item.is_dir() and (item / "__init__.py").exists():
                try:
                    name = self.load_plugin(str(item))
                    loaded.append(name)
                except PluginError as exc:
                    logger.error("Failed to load plugin from %s: %s", item, exc)
            elif item.is_file() and item.suffix == ".py" and item.name != "__init__.py":
                try:
                    name = self.load_plugin(str(item))
                    loaded.append(name)
                except PluginError as exc:
                    logger.error("Failed to load plugin %s: %s", item, exc)

        logger.info("Loaded %d plugin(s): %s", len(loaded), loaded)
        return loaded

    def load_plugin(self, path: str) -> str:
        """Load a single plugin from a file or directory path.

        The plugin module must define a `PLUGIN_INFO` dict with at least 'name'.
        It may also define `register_hooks(manager)` to hook into events.

        Args:
            path: Path to the plugin (.py file or directory with __init__.py).

        Returns:
            Plugin name.

        Raises:
            PluginError: If the plugin cannot be loaded.
        """
        plugin_path = Path(os.path.expanduser(path))
        if not plugin_path.exists():
            raise PluginError(f"Plugin path not found: {path}")

        # Determine module name
        module_name = f"wifi_aio_plugin_{plugin_path.stem}"

        try:
            if plugin_path.is_dir():
                init_file = plugin_path / "__init__.py"
                if not init_file.exists():
                    raise PluginError(f"No __init__.py in plugin directory: {path}")
                spec = importlib.util.spec_from_file_location(module_name, str(init_file))
            else:
                spec = importlib.util.spec_from_file_location(module_name, str(plugin_path))

            if spec is None or spec.loader is None:
                raise PluginError(f"Cannot create module spec for plugin: {path}")

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module

            try:
                spec.loader.exec_module(module)
            except Exception as exc:
                sys.modules.pop(module_name, None)
                raise PluginError(f"Error executing plugin {path}: {exc}") from exc

        except PluginError:
            raise
        except Exception as exc:
            raise PluginError(f"Failed to load plugin {path}: {exc}") from exc

        # Extract plugin info
        info = getattr(module, "PLUGIN_INFO", {})
        name = info.get("name", plugin_path.stem)
        version = info.get("version", "0.0.0")
        description = info.get("description", "")
        author = info.get("author", "")

        if name in self._plugins:
            raise PluginError(f"Plugin '{name}' is already loaded")

        plugin = Plugin(
            name=name,
            version=version,
            description=description,
            author=author,
            module=module,
            path=str(plugin_path),
            enabled=True,
        )

        # Auto-discover hooks from the module
        for event in self.EVENTS:
            callback = getattr(module, event, None)
            if callback and callable(callback):
                plugin.register_hook(event, callback)

        # Call register_hooks if defined
        register_fn = getattr(module, "register_hooks", None)
        if register_fn and callable(register_fn):
            try:
                register_fn(self)
            except Exception as exc:
                raise PluginError(f"Plugin '{name}' register_hooks failed: {exc}") from exc

        self._plugins[name] = plugin
        logger.info("Plugin loaded: %s v%s", name, version)
        return name

    def unload_plugin(self, name: str) -> None:
        """Unload a plugin by name."""
        plugin = self._plugins.pop(name, None)
        if plugin is None:
            raise PluginError(f"Plugin '{name}' not found")
        module_name = f"wifi_aio_plugin_{Path(plugin.path).stem}"
        sys.modules.pop(module_name, None)
        logger.info("Plugin unloaded: %s", name)

    def reload_plugin(self, name: str) -> str:
        """Reload a plugin by name."""
        plugin = self._plugins.get(name)
        if plugin is None:
            raise PluginError(f"Plugin '{name}' not found")
        path = plugin.path
        self.unload_plugin(name)
        return self.load_plugin(path)

    # ── Registry / Query ──────────────────────────────────────────────

    def get_plugin(self, name: str) -> Optional[Plugin]:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def list_plugins(self) -> List[Dict]:
        """List all loaded plugins as dicts."""
        return [p.to_dict() for p in self._plugins.values()]

    def enable_plugin(self, name: str) -> None:
        """Enable a plugin."""
        plugin = self._plugins.get(name)
        if plugin is None:
            raise PluginError(f"Plugin '{name}' not found")
        plugin.enabled = True

    def disable_plugin(self, name: str) -> None:
        """Disable a plugin."""
        plugin = self._plugins.get(name)
        if plugin is None:
            raise PluginError(f"Plugin '{name}' not found")
        plugin.enabled = False

    # ── Event Dispatching ─────────────────────────────────────────────

    def register_hook(self, event: str, callback: Callable) -> None:
        """Register a global hook for an event (not tied to a specific plugin)."""
        if event not in self._global_hooks:
            self._global_hooks[event] = []
        self._global_hooks[event].append(callback)

    def dispatch(self, event: str, *args, **kwargs) -> List[Any]:
        """Dispatch an event to all registered hooks (plugin + global).

        Returns:
            List of results from all hook calls.
        """
        results = []
        # Plugin hooks
        for plugin in self._plugins.values():
            result = plugin.call_hook(event, *args, **kwargs)
            if result is not None:
                results.append(result)
        # Global hooks
        for callback in self._global_hooks.get(event, []):
            try:
                result = callback(*args, **kwargs)
                if result is not None:
                    results.append(result)
            except Exception as exc:
                logger.error("Global hook for '%s' failed: %s", event, exc)
        return results
