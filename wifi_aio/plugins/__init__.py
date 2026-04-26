"""WiFiAIO plugins sub-package.

Provides the plugin system with base classes, loading, and registry.
"""

from wifi_aio.plugins.base_plugin import BasePlugin, PluginInfo, PluginHook
from wifi_aio.plugins.plugin_loader import PluginLoader
from wifi_aio.plugins.plugin_registry import PluginRegistry
from wifi_aio.plugins.example_plugin import ExamplePlugin

__all__ = [
    "BasePlugin",
    "PluginInfo",
    "PluginHook",
    "PluginLoader",
    "PluginRegistry",
    "ExamplePlugin",
]
