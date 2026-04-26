"""Plugin loader for discovering and loading plugins from directories.

Scans specified directories for Python modules that contain
BasePlugin subclasses, loads them safely, and returns instantiated
plugin objects.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

from wifi_aio.exceptions import PluginError
from wifi_aio.plugins.base_plugin import BasePlugin

logger = logging.getLogger(__name__)


class PluginLoader:
    """Discover and load plugins from directories.

    Searches for Python files and packages that contain subclasses of
    BasePlugin, imports them safely, and instantiates the plugin classes.

    Example::

        loader = PluginLoader()
        plugins = loader.load_from_directory("/path/to/plugins")
        for plugin in plugins:
            print(f"Loaded: {plugin.info.name} v{plugin.info.version}")

        # Also load a single file
        plugin = loader.load_file("/path/to/my_plugin.py")
    """

    def __init__(self, extra_paths: Optional[list[str]] = None) -> None:
        self._loaded_modules: dict[str, Any] = {}
        self._extra_paths = extra_paths or []

    # ── Directory scanning ─────────────────────────────────────────────

    def scan_directory(self, directory: str) -> list[str]:
        """Scan a directory for potential plugin files.

        Looks for ``.py`` files and packages (directories with ``__init__.py``).

        Args:
            directory: Path to scan.

        Returns:
            List of discovered file/package paths.
        """
        dir_path = Path(directory)
        if not dir_path.is_dir():
            logger.warning("Plugin directory does not exist: %s", directory)
            return []

        candidates: list[str] = []

        for entry in sorted(dir_path.iterdir()):
            # Skip hidden files and __pycache__
            if entry.name.startswith("_") or entry.name.startswith("."):
                continue

            if entry.is_file() and entry.suffix == ".py":
                candidates.append(str(entry))

            elif entry.is_dir() and (entry / "__init__.py").is_file():
                candidates.append(str(entry))

        return candidates

    def load_from_directory(self, directory: str) -> list[BasePlugin]:
        """Load all plugins from a directory.

        Args:
            directory: Path to the plugin directory.

        Returns:
            List of instantiated BasePlugin subclasses.
        """
        candidates = self.scan_directory(directory)
        plugins: list[BasePlugin] = []

        for path in candidates:
            try:
                found = self.load_file(path)
                plugins.extend(found)
            except PluginError as exc:
                logger.error("Failed to load plugin from %s: %s", path, exc)
            except Exception as exc:
                logger.error("Unexpected error loading %s: %s", path, exc)

        logger.info("Loaded %d plugins from %s", len(plugins), directory)
        return plugins

    def load_from_directories(self, directories: list[str]) -> list[BasePlugin]:
        """Load plugins from multiple directories.

        Args:
            directories: List of directory paths.

        Returns:
            Combined list of instantiated plugins.
        """
        all_plugins: list[BasePlugin] = []
        for directory in directories:
            all_plugins.extend(self.load_from_directory(directory))
        return all_plugins

    # ── File loading ───────────────────────────────────────────────────

    def load_file(self, filepath: str) -> list[BasePlugin]:
        """Load plugins from a single Python file.

        Args:
            filepath: Path to the .py file or package directory.

        Returns:
            List of instantiated BasePlugin subclasses found in the file.
        """
        path = Path(filepath)
        module_name = f"wifiaio_plugin_{path.stem}"

        if path.is_dir():
            # Package
            init_file = path / "__init__.py"
            if init_file.is_file():
                module = self._import_module(str(init_file), module_name)
            else:
                raise PluginError(f"No __init__.py in package: {path}")
        elif path.is_file() and path.suffix == ".py":
            module = self._import_module(str(path), module_name)
        else:
            raise PluginError(f"Not a valid plugin path: {filepath}")

        if module is None:
            return []

        self._loaded_modules[module_name] = module
        return self._extract_plugins(module)

    def _import_module(self, filepath: str, module_name: str) -> Any:
        """Import a Python module from a file path.

        Args:
            filepath: Path to the .py file.
            module_name: Name to assign to the module.

        Returns:
            The imported module object.
        """
        spec = importlib.util.spec_from_file_location(module_name, filepath)
        if spec is None:
            raise PluginError(f"Cannot create module spec for: {filepath}")

        if spec.loader is None:
            raise PluginError(f"No loader for module spec: {filepath}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module

        try:
            spec.loader.exec_module(module)
            logger.debug("Imported module %s from %s", module_name, filepath)
            return module
        except Exception as exc:
            # Clean up failed module
            sys.modules.pop(module_name, None)
            raise PluginError(
                f"Failed to import module {module_name}: {exc}",
                details=str(exc),
            )

    def _extract_plugins(self, module: Any) -> list[BasePlugin]:
        """Extract and instantiate BasePlugin subclasses from a module.

        Args:
            module: The imported module to scan.

        Returns:
            List of instantiated plugin objects.
        """
        plugins: list[BasePlugin] = []

        for name in dir(module):
            obj = getattr(module, name)

            # Must be a class, a subclass of BasePlugin, but not BasePlugin itself
            if (
                inspect.isclass(obj)
                and issubclass(obj, BasePlugin)
                and obj is not BasePlugin
                and not inspect.isabstract(obj)
            ):
                try:
                    instance = obj()
                    # Verify it has proper metadata
                    info = instance.info
                    if not info.name:
                        logger.warning(
                            "Plugin class %s has no name in PluginInfo – skipping", name
                        )
                        continue

                    plugins.append(instance)
                    logger.debug(
                        "Found plugin: %s v%s", info.name, info.version,
                    )
                except Exception as exc:
                    logger.error(
                        "Failed to instantiate plugin class %s: %s", name, exc,
                    )

        return plugins

    # ── Cleanup ────────────────────────────────────────────────────────

    def unload_all(self) -> None:
        """Unload all previously loaded plugin modules."""
        for module_name in list(self._loaded_modules.keys()):
            if module_name in sys.modules:
                del sys.modules[module_name]
        self._loaded_modules.clear()
        logger.info("Unloaded all plugin modules")

    @property
    def loaded_module_names(self) -> list[str]:
        """Names of currently loaded plugin modules."""
        return list(self._loaded_modules.keys())

    def __repr__(self) -> str:
        return f"PluginLoader(modules={len(self._loaded_modules)})"
