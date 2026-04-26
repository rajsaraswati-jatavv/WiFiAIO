"""Plugin registry for managing loaded plugins.

Maintains a central registry of plugins, their lifecycle,
hook subscriptions, and inter-plugin communication.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from wifi_aio.exceptions import PluginError
from wifi_aio.plugins.base_plugin import BasePlugin, PluginHook, PluginInfo

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Register and manage plugins.

    The registry is the central point for:
      - Registering/unregistering plugins.
      - Subscribing plugins to hook points.
      - Dispatching hook events to all subscribed plugins.
      - Managing plugin lifecycle (load, enable, disable, unload).
      - Querying registered plugins.

    Example::

        registry = PluginRegistry()
        registry.register(my_plugin)
        registry.enable_plugin("my_plugin")
        registry.dispatch(PluginHook.POST_SCAN, scan_results)
    """

    def __init__(self) -> None:
        self._plugins: dict[str, BasePlugin] = {}
        self._hooks: dict[str, list[str]] = {}  # hook_name → [plugin_name, ...]
        self._context: dict[str, Any] = {}

    # ── Registration ───────────────────────────────────────────────────

    def register(self, plugin: BasePlugin) -> None:
        """Register a plugin with the registry.

        Args:
            plugin: Instantiated BasePlugin subclass.

        Raises:
            PluginError: If a plugin with the same name is already registered.
        """
        info = plugin.info
        if not info.name:
            raise PluginError("Plugin must have a non-empty name")

        if info.name in self._plugins:
            raise PluginError(f"Plugin already registered: {info.name}")

        self._plugins[info.name] = plugin

        # Register hook subscriptions from plugin info
        for hook_name in info.hooks:
            self._subscribe(info.name, hook_name)

        # Auto-register any handlers already set on the plugin
        for hook_name in list(plugin._hook_handlers.keys()):
            if hook_name not in self._hooks or info.name not in self._hooks[hook_name]:
                self._subscribe(info.name, hook_name)

        logger.info(
            "Registered plugin %s v%s", info.name, info.version,
        )

    def unregister(self, name: str) -> None:
        """Unregister and unload a plugin.

        Args:
            name: Plugin name.

        Raises:
            PluginError: If the plugin is not registered.
        """
        plugin = self._plugins.get(name)
        if plugin is None:
            raise PluginError(f"Plugin not registered: {name}")

        # Disable and unload
        if plugin.enabled:
            plugin.disable()
        try:
            plugin.on_unload()
        except Exception as exc:
            logger.error("Error unloading plugin %s: %s", name, exc)

        # Remove from hooks
        for hook_name in list(self._hooks.keys()):
            if name in self._hooks[hook_name]:
                self._hooks[hook_name].remove(name)
            if not self._hooks[hook_name]:
                del self._hooks[hook_name]

        del self._plugins[name]
        logger.info("Unregistered plugin %s", name)

    # ── Hook subscriptions ─────────────────────────────────────────────

    def _subscribe(self, plugin_name: str, hook_name: str) -> None:
        """Subscribe a plugin to a hook."""
        if hook_name not in self._hooks:
            self._hooks[hook_name] = []
        if plugin_name not in self._hooks[hook_name]:
            self._hooks[hook_name].append(plugin_name)
            logger.debug("Plugin %s subscribed to hook %s", plugin_name, hook_name)

    def subscribe(self, plugin_name: str, hook_name: str) -> None:
        """Public API to subscribe a registered plugin to a hook.

        Args:
            plugin_name: Name of the registered plugin.
            hook_name: Hook to subscribe to.

        Raises:
            PluginError: If the plugin is not registered.
        """
        if plugin_name not in self._plugins:
            raise PluginError(f"Plugin not registered: {plugin_name}")
        self._subscribe(plugin_name, hook_name)

    def unsubscribe(self, plugin_name: str, hook_name: str) -> None:
        """Unsubscribe a plugin from a hook.

        Args:
            plugin_name: Plugin name.
            hook_name: Hook to unsubscribe from.
        """
        if hook_name in self._hooks and plugin_name in self._hooks[hook_name]:
            self._hooks[hook_name].remove(plugin_name)
            logger.debug("Plugin %s unsubscribed from hook %s", plugin_name, hook_name)

    # ── Hook dispatch ──────────────────────────────────────────────────

    def dispatch(self, hook: str, data: Any = None) -> Any:
        """Dispatch a hook event to all subscribed plugins.

        Plugins are called in registration order. Each handler receives
        the data from the previous handler (pipeline pattern).

        Args:
            hook: Hook name (use PluginHook values or custom strings).
            data: Payload to pass to hook handlers.

        Returns:
            The data after all handlers have processed it.
        """
        subscribers = self._hooks.get(hook, [])
        if not subscribers:
            return data

        current_data = data
        for plugin_name in subscribers:
            plugin = self._plugins.get(plugin_name)
            if plugin is None or not plugin.enabled:
                continue

            try:
                result = plugin.handle(hook, current_data)
                if result is not None:
                    current_data = result
            except PluginError as exc:
                logger.error(
                    "Hook %s handler failed in plugin %s: %s",
                    hook, plugin_name, exc,
                )
            except Exception as exc:
                logger.error(
                    "Unexpected error in hook %s handler (plugin %s): %s",
                    hook, plugin_name, exc,
                )

        return current_data

    # ── Lifecycle management ───────────────────────────────────────────

    def load_all(self, context: Optional[dict[str, Any]] = None) -> None:
        """Call on_load for all registered plugins.

        Args:
            context: Shared application context.
        """
        if context:
            self._context.update(context)

        for name, plugin in self._plugins.items():
            try:
                plugin.on_load(self._context)
                logger.debug("Loaded plugin %s", name)
            except Exception as exc:
                logger.error("Failed to load plugin %s: %s", name, exc)

    def unload_all(self) -> None:
        """Call on_unload for all registered plugins."""
        for name, plugin in list(self._plugins.items()):
            try:
                if plugin.enabled:
                    plugin.disable()
                plugin.on_unload()
                logger.debug("Unloaded plugin %s", name)
            except Exception as exc:
                logger.error("Failed to unload plugin %s: %s", name, exc)

    def enable_plugin(self, name: str) -> None:
        """Enable a registered plugin.

        Args:
            name: Plugin name.

        Raises:
            PluginError: If the plugin is not registered.
        """
        plugin = self._plugins.get(name)
        if plugin is None:
            raise PluginError(f"Plugin not registered: {name}")
        plugin.enable()

    def disable_plugin(self, name: str) -> None:
        """Disable a registered plugin.

        Args:
            name: Plugin name.

        Raises:
            PluginError: If the plugin is not registered.
        """
        plugin = self._plugins.get(name)
        if plugin is None:
            raise PluginError(f"Plugin not registered: {name}")
        plugin.disable()

    def enable_all(self) -> None:
        """Enable all registered plugins."""
        for plugin in self._plugins.values():
            plugin.enable()

    def disable_all(self) -> None:
        """Disable all registered plugins."""
        for plugin in self._plugins.values():
            plugin.disable()

    # ── Configuration ──────────────────────────────────────────────────

    def configure_plugin(self, name: str, config: dict[str, Any]) -> None:
        """Update a plugin's configuration.

        Args:
            name: Plugin name.
            config: New configuration values.

        Raises:
            PluginError: If the plugin is not registered.
        """
        plugin = self._plugins.get(name)
        if plugin is None:
            raise PluginError(f"Plugin not registered: {name}")
        plugin.configure(config)

    # ── Queries ────────────────────────────────────────────────────────

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Look up a plugin by name."""
        return self._plugins.get(name)

    def list_plugins(self) -> list[PluginInfo]:
        """Return metadata for all registered plugins."""
        return [p.info for p in self._plugins.values()]

    def list_enabled(self) -> list[PluginInfo]:
        """Return metadata for all enabled plugins."""
        return [p.info for p in self._plugins.values() if p.enabled]

    def list_disabled(self) -> list[PluginInfo]:
        """Return metadata for all disabled plugins."""
        return [p.info for p in self._plugins.values() if not p.enabled]

    def get_hooks(self) -> dict[str, list[str]]:
        """Return the current hook → plugins mapping."""
        return dict(self._hooks)

    def get_subscribers(self, hook: str) -> list[str]:
        """Return plugin names subscribed to a specific hook."""
        return list(self._hooks.get(hook, []))

    @property
    def plugin_count(self) -> int:
        """Total number of registered plugins."""
        return len(self._plugins)

    @property
    def enabled_count(self) -> int:
        """Number of currently enabled plugins."""
        return sum(1 for p in self._plugins.values() if p.enabled)

    def __repr__(self) -> str:
        return (
            f"PluginRegistry(plugins={self.plugin_count}, "
            f"enabled={self.enabled_count})"
        )
