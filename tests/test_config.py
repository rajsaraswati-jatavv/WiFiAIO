"""Tests for wifi_aio.config – ConfigManager.

Covers loading, saving, getting, setting, resetting, backup/restore,
path-traversal protection, and default values.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest

from wifi_aio.config import ConfigManager, _deep_copy, _merge
from wifi_aio.constants import DEFAULT_CONFIG
from wifi_aio.exceptions import ConfigurationError


# ── Fixtures ────────────────────────────────────────────────────────────

@pytest.fixture
def config_path(tmp_path: Path) -> str:
    """Return a path to a non-existent config file inside tmp_path."""
    return str(tmp_path / "config.json")


@pytest.fixture
def cfg(config_path: str) -> ConfigManager:
    """Return a ConfigManager that reads/writes to a temp file."""
    return ConfigManager(config_path=config_path)


@pytest.fixture
def cfg_with_data(config_path: str) -> ConfigManager:
    """Return a ConfigManager pre-loaded with some custom values."""
    data = {**DEFAULT_CONFIG, "scan_timeout": 60, "interface": "wlan1"}
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as fh:
        json.dump(data, fh)
    return ConfigManager(config_path=config_path)


# ── Loading / defaults ──────────────────────────────────────────────────

class TestLoadDefaults:
    """ConfigManager should fall back to DEFAULT_CONFIG when no file exists."""

    def test_load_creates_defaults(self, cfg: ConfigManager) -> None:
        """When the config file doesn't exist, defaults are used."""
        for key, value in DEFAULT_CONFIG.items():
            assert cfg.get(key) == value

    def test_all_returns_copy(self, cfg: ConfigManager) -> None:
        """``all()`` returns a shallow copy, not a reference."""
        data = cfg.all()
        assert isinstance(data, dict)
        data["foo"] = "bar"
        assert cfg.get("foo") is None


# ── Get / Set ───────────────────────────────────────────────────────────

class TestGetSet:
    """Dot-notation get/set and nested key support."""

    def test_get_existing_key(self, cfg: ConfigManager) -> None:
        assert cfg.get("interface") == DEFAULT_CONFIG["interface"]

    def test_get_missing_key_returns_default(self, cfg: ConfigManager) -> None:
        assert cfg.get("nonexistent") is None
        assert cfg.get("nonexistent", 42) == 42

    def test_set_and_get(self, cfg: ConfigManager) -> None:
        cfg.set("interface", "wlan2")
        assert cfg.get("interface") == "wlan2"

    def test_set_nested_key(self, cfg: ConfigManager) -> None:
        """Setting 'scan.timeout' should create nested dict."""
        cfg.set("scan.timeout", 60)
        assert cfg.get("scan.timeout") == 60
        assert cfg.get("scan") == {"timeout": 60}

    def test_set_overwrite_nested(self, cfg: ConfigManager) -> None:
        cfg.set("scan.timeout", 30)
        cfg.set("scan.mode", "passive")
        assert cfg.get("scan.timeout") == 30
        assert cfg.get("scan.mode") == "passive"


# ── Save / Reload ───────────────────────────────────────────────────────

class TestSaveReload:
    """Persisting to disk and re-reading."""

    def test_save_and_reload(self, cfg: ConfigManager) -> None:
        cfg.set("interface", "wlan5")
        cfg.save()
        cfg2 = ConfigManager(config_path=cfg.config_path)
        assert cfg2.get("interface") == "wlan5"

    def test_save_creates_directory(self, tmp_path: Path) -> None:
        """The parent directory is created if it doesn't exist."""
        path = str(tmp_path / "nested" / "dir" / "config.json")
        c = ConfigManager(config_path=path)
        c.save()
        assert os.path.isfile(path)

    def test_backup_created_on_save(self, cfg: ConfigManager) -> None:
        # First save creates the file; backup is only created on *subsequent* saves
        cfg.save()  # initial save – no prior file to back up
        cfg.set("interface", "changed")
        cfg.save()  # second save – should now have a backup
        backup = cfg.config_path + ".bak"
        assert os.path.isfile(backup)


# ── Reset ────────────────────────────────────────────────────────────────

class TestReset:
    """reset_to_defaults() should restore DEFAULT_CONFIG."""

    def test_reset_restores_defaults(self, cfg: ConfigManager) -> None:
        cfg.set("interface", "modified")
        cfg.reset_to_defaults()
        assert cfg.get("interface") == DEFAULT_CONFIG["interface"]


# ── Backup / Restore ────────────────────────────────────────────────────

class TestBackupRestore:
    """Recovery from a corrupted config file."""

    def test_recover_from_corrupted_file(self, config_path: str) -> None:
        """If the config file is invalid JSON, recover from backup."""
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        # Write a valid config first
        with open(config_path, "w") as fh:
            json.dump(DEFAULT_CONFIG, fh)
        # Create a backup
        backup_path = config_path + ".bak"
        with open(backup_path, "w") as fh:
            json.dump({"interface": "from_backup"}, fh)
        # Corrupt the main file
        with open(config_path, "w") as fh:
            fh.write("{invalid json!!!")
        cfg = ConfigManager(config_path=config_path)
        assert cfg.get("interface") == "from_backup"


# ── Path-traversal protection ────────────────────────────────────────────

class TestPathTraversal:
    """Profile name and path sanitization."""

    def test_validate_profile_rejects_dotdot(self, cfg: ConfigManager) -> None:
        with pytest.raises(ConfigurationError, match="path traversal"):
            cfg.validate_profile_path("../../etc/passwd")

    def test_validate_profile_rejects_absolute(self, cfg: ConfigManager) -> None:
        with pytest.raises(ConfigurationError, match="path traversal"):
            cfg.validate_profile_path("/etc/shadow")

    def test_validate_profile_rejects_null_bytes(self, cfg: ConfigManager) -> None:
        with pytest.raises(ConfigurationError, match="null bytes"):
            cfg.validate_profile_path("safe\x00evil")

    def test_sanitize_path_resolves_dotdot(self, cfg: ConfigManager) -> None:
        cfg.set("output_dir", "/tmp/wifiaio")
        result = cfg.sanitize_path("output_dir")
        assert ".." not in result


# ── Deep copy / merge helpers ────────────────────────────────────────────

class TestHelpers:
    """Module-level _deep_copy and _merge functions."""

    def test_deep_copy_independence(self) -> None:
        original = {"a": [1, 2]}
        copy = _deep_copy(original)
        copy["a"].append(3)
        assert original["a"] == [1, 2]

    def test_merge_override(self) -> None:
        base = {"x": 1, "y": 2}
        override = {"y": 99, "z": 3}
        result = _merge(base, override)
        assert result == {"x": 1, "y": 99, "z": 3}

    def test_merge_nested(self) -> None:
        base = {"scan": {"timeout": 30, "mode": "active"}}
        override = {"scan": {"timeout": 60}}
        result = _merge(base, override)
        assert result["scan"] == {"timeout": 60, "mode": "active"}
