"""WiFiAIO configuration management.

Handles loading, saving, and validating JSON-based configuration files
with automatic backup on corruption and path sanitization.
"""

import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from wifi_aio.constants import DEFAULT_CONFIG
from wifi_aio.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manages the WiFiAIO JSON configuration file.

    Features:
      * Automatic creation of default config on first run
      * Backup & recovery when the config file is corrupted
      * Path sanitization for profile-related settings
      * Dot-notation access (e.g. cfg.get("scan.timeout", 30))
    """

    def __init__(self, config_path: Optional[str] = None):
        self._config_path = config_path or os.path.join(
            os.path.expanduser("~"), ".config", "wifiaio", "config.json"
        )
        self._data: Dict[str, Any] = {}
        self._load()

    # ── Public API ────────────────────────────────────────────────────

    @property
    def config_path(self) -> str:
        return self._config_path

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a value using dot-notation (e.g. ``"scan.timeout"``)."""
        keys = key.split(".")
        value: Any = self._data
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def set(self, key: str, value: Any) -> None:
        """Set a value using dot-notation."""
        keys = key.split(".")
        data = self._data
        for k in keys[:-1]:
            if k not in data or not isinstance(data[k], dict):
                data[k] = {}
            data = data[k]
        data[keys[-1]] = value

    def save(self) -> None:
        """Persist the current configuration to disk.

        Creates a ``.bak`` copy of the existing file before writing.  If
        writing fails the original file is restored and a
        :class:`ConfigurationError` is raised.
        """
        config_dir = os.path.dirname(self._config_path)
        try:
            os.makedirs(config_dir, exist_ok=True)
        except OSError as exc:
            raise ConfigurationError(
                f"Cannot create config directory {config_dir}: {exc}"
            ) from exc

        backup_path = self._config_path + ".bak"
        if os.path.isfile(self._config_path):
            try:
                shutil.copy2(self._config_path, backup_path)
            except OSError as exc:
                logger.warning("Could not create config backup: %s", exc)

        try:
            tmp_path = self._config_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, sort_keys=True)
                fh.write("\n")
            os.replace(tmp_path, self._config_path)
            logger.debug("Configuration saved to %s", self._config_path)
        except (OSError, TypeError) as exc:
            logger.error("Failed to save configuration: %s", exc)
            if os.path.isfile(backup_path):
                try:
                    shutil.copy2(backup_path, self._config_path)
                    logger.info("Restored configuration from backup")
                except OSError as restore_exc:
                    logger.error("Failed to restore backup: %s", restore_exc)
            raise ConfigurationError(
                f"Failed to save configuration: {exc}"
            ) from exc

    def reload(self) -> None:
        """Re-read the configuration from disk."""
        self._load()

    def reset_to_defaults(self) -> None:
        """Reset all settings to package defaults and save."""
        self._data = _deep_copy(DEFAULT_CONFIG)
        self.save()

    def all(self) -> Dict[str, Any]:
        """Return a shallow copy of the entire config dict."""
        return dict(self._data)

    def sanitize_path(self, key: str) -> str:
        """Sanitize a file-system path stored under *key*.

        Resolves ``..`` segments, removes null bytes, and makes the path
        absolute.  Returns the sanitized path.
        """
        raw = self.get(key, "")
        if not raw:
            return raw
        cleaned = raw.replace("\x00", "")
        resolved = os.path.realpath(os.path.expanduser(cleaned))
        self.set(key, resolved)
        return resolved

    def validate_profile_path(self, profile_name: str) -> str:
        """Return a safe, absolute directory path for *profile_name*.

        Raises :class:`ConfigurationError` if the profile name contains
        path traversal components or null bytes.
        """
        if "\x00" in profile_name:
            raise ConfigurationError("Profile name contains null bytes")
        if ".." in profile_name or profile_name.startswith("/"):
            raise ConfigurationError(
                f"Invalid profile name (path traversal): {profile_name}"
            )
        base_dir = self.get("output_dir", "/tmp/wifiaio/profiles")
        return os.path.realpath(os.path.join(base_dir, profile_name))

    # ── Private helpers ───────────────────────────────────────────────

    def _load(self) -> None:
        """Load configuration from disk, falling back to defaults."""
        if not os.path.isfile(self._config_path):
            logger.info("No config file found – using defaults")
            self._data = _deep_copy(DEFAULT_CONFIG)
            return

        try:
            with open(self._config_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if not isinstance(loaded, dict):
                raise ConfigurationError("Config file does not contain a JSON object")
            self._data = _merge(DEFAULT_CONFIG, loaded)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Config file corrupted (%s) – restoring from backup", exc)
            self._recover()
            if not self._data:
                self._data = _deep_copy(DEFAULT_CONFIG)

    def _recover(self) -> None:
        """Try to restore the config from the ``.bak`` file."""
        backup_path = self._config_path + ".bak"
        if os.path.isfile(backup_path):
            try:
                with open(backup_path, "r", encoding="utf-8") as fh:
                    self._data = json.load(fh)
                shutil.copy2(backup_path, self._config_path)
                logger.info("Configuration recovered from backup")
                return
            except (json.JSONDecodeError, OSError) as exc:
                logger.error("Backup also corrupted: %s", exc)
        self._data = _deep_copy(DEFAULT_CONFIG)
        logger.info("Using default configuration")


# ── Module-level helpers ─────────────────────────────────────────────

def _deep_copy(d: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deep copy of a dict composed only of JSON-safe types."""
    return json.loads(json.dumps(d))


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge *override* into a copy of *base*."""
    result = _deep_copy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result
