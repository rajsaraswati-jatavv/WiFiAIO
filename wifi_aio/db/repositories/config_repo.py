"""Configuration repository for CRUD operations on config entries.

Provides create, read, update, delete, and query operations
for application configuration key-value pairs.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

from wifi_aio.db.models import Config
from wifi_aio.exceptions import DatabaseError, ConfigurationError


class ConfigRepository:
    """Repository for Config model CRUD operations."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def create(self, config: Config) -> Config:
        """Create a new configuration entry.

        Args:
            config: Config model instance to persist.

        Returns:
            The created Config instance.

        Raises:
            DatabaseError: If the insert fails (e.g., duplicate key).
        """
        try:
            self.conn.execute(
                """INSERT INTO config
                   (id, key, value, category, description, created_at, updated_at, is_sensitive)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    config.id, config.key, config.value, config.category,
                    config.description,
                    config.created_at.isoformat() if config.created_at else None,
                    config.updated_at.isoformat() if config.updated_at else None,
                    int(config.is_sensitive),
                ),
            )
            self.conn.commit()
            return config
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to create config entry: {e}", details=str(e))

    def get_by_key(self, key: str) -> Optional[Config]:
        """Get a configuration entry by key.

        Args:
            key: Configuration key to look up.

        Returns:
            Config instance, or None if not found.
        """
        cursor = self.conn.execute("SELECT * FROM config WHERE key = ?", (key,))
        row = cursor.fetchone()
        return self._row_to_config(row) if row else None

    def get_value(self, key: str, default: str = "") -> str:
        """Get a configuration value by key with optional default.

        Args:
            key: Configuration key.
            default: Default value if key not found.

        Returns:
            Configuration value string.
        """
        config = self.get_by_key(key)
        if config is None:
            return default
        return config.value

    def get_int(self, key: str, default: int = 0) -> int:
        """Get a configuration value as an integer.

        Args:
            key: Configuration key.
            default: Default value if key not found or not parseable.

        Returns:
            Configuration value as integer.
        """
        value = self.get_value(key, str(default))
        try:
            return int(value)
        except ValueError:
            return default

    def get_float(self, key: str, default: float = 0.0) -> float:
        """Get a configuration value as a float.

        Args:
            key: Configuration key.
            default: Default value if key not found or not parseable.

        Returns:
            Configuration value as float.
        """
        value = self.get_value(key, str(default))
        try:
            return float(value)
        except ValueError:
            return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        """Get a configuration value as a boolean.

        Args:
            key: Configuration key.
            default: Default value if key not found.

        Returns:
            Configuration value as boolean.
        """
        value = self.get_value(key, str(default)).lower()
        return value in ("true", "1", "yes", "on", "enabled")

    def set_value(self, key: str, value: str, category: str = "general", description: str = "") -> Config:
        """Set a configuration value, creating or updating as needed.

        Args:
            key: Configuration key.
            value: Configuration value.
            category: Configuration category.
            description: Configuration description.

        Returns:
            The created or updated Config instance.

        Raises:
            DatabaseError: If the operation fails.
        """
        existing = self.get_by_key(key)
        if existing:
            existing.value = value
            existing.category = category
            existing.description = description
            existing.updated_at = datetime.utcnow()
            return self.update(existing)
        else:
            config = Config(
                key=key, value=value, category=category, description=description,
                created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
            )
            return self.create(config)

    def get_by_category(self, category: str) -> List[Config]:
        """Get all configuration entries in a category.

        Args:
            category: Category name.

        Returns:
            List of Config instances in the category.
        """
        cursor = self.conn.execute(
            "SELECT * FROM config WHERE category = ? ORDER BY key",
            (category,),
        )
        return [self._row_to_config(row) for row in cursor.fetchall()]

    def get_all(self) -> List[Config]:
        """Get all configuration entries."""
        cursor = self.conn.execute("SELECT * FROM config ORDER BY category, key")
        return [self._row_to_config(row) for row in cursor.fetchall()]

    def get_categories(self) -> List[str]:
        """Get all configuration categories."""
        cursor = self.conn.execute("SELECT DISTINCT category FROM config ORDER BY category")
        return [row[0] for row in cursor.fetchall()]

    def get_as_dict(self, category: Optional[str] = None) -> Dict[str, str]:
        """Get configuration as a dictionary.

        Args:
            category: Optional category filter.

        Returns:
            Dict of key -> value pairs.
        """
        if category:
            cursor = self.conn.execute(
                "SELECT key, value FROM config WHERE category = ? ORDER BY key",
                (category,),
            )
        else:
            cursor = self.conn.execute("SELECT key, value FROM config ORDER BY key")
        return dict(cursor.fetchall())

    def update(self, config: Config) -> Config:
        """Update a configuration entry.

        Args:
            config: Config instance with updated fields.

        Returns:
            The updated Config instance.

        Raises:
            DatabaseError: If the update fails.
        """
        try:
            self.conn.execute(
                """UPDATE config SET
                   value = ?, category = ?, description = ?,
                   updated_at = ?, is_sensitive = ?
                   WHERE key = ?""",
                (
                    config.value, config.category, config.description,
                    config.updated_at.isoformat() if config.updated_at else None,
                    int(config.is_sensitive), config.key,
                ),
            )
            self.conn.commit()
            return config
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to update config: {e}", details=str(e))

    def delete(self, key: str) -> bool:
        """Delete a configuration entry by key.

        Args:
            key: Configuration key to delete.

        Returns:
            True if a record was deleted, False if not found.

        Raises:
            DatabaseError: If the delete fails.
        """
        try:
            cursor = self.conn.execute("DELETE FROM config WHERE key = ?", (key,))
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to delete config: {e}", details=str(e))

    def delete_category(self, category: str) -> int:
        """Delete all configuration entries in a category.

        Args:
            category: Category to delete.

        Returns:
            Number of entries deleted.

        Raises:
            DatabaseError: If the delete fails.
        """
        try:
            cursor = self.conn.execute("DELETE FROM config WHERE category = ?", (category,))
            self.conn.commit()
            return cursor.rowcount
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to delete config category: {e}", details=str(e))

    def count(self) -> int:
        """Return the total number of configuration entries."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM config")
        return cursor.fetchone()[0]

    def load_defaults(self, defaults: Dict[str, Dict]) -> int:
        """Load default configuration values (skips existing keys).

        Args:
            defaults: Dict of key -> {value, category, description, is_sensitive}.

        Returns:
            Number of new entries created.
        """
        created = 0
        for key, info in defaults.items():
            if self.get_by_key(key) is None:
                config = Config(
                    key=key,
                    value=info.get("value", ""),
                    category=info.get("category", "general"),
                    description=info.get("description", ""),
                    is_sensitive=info.get("is_sensitive", False),
                )
                self.create(config)
                created += 1
        return created

    @staticmethod
    def _row_to_config(row: sqlite3.Row) -> Config:
        """Convert a database row to a Config instance."""
        data = dict(row)
        for dt_field in ("created_at", "updated_at"):
            if dt_field in data and data[dt_field] and isinstance(data[dt_field], str):
                try:
                    data[dt_field] = datetime.fromisoformat(data[dt_field])
                except (ValueError, TypeError):
                    pass
        if "is_sensitive" in data:
            data["is_sensitive"] = bool(data["is_sensitive"])
        return Config(**{k: v for k, v in data.items() if k in Config.__dataclass_fields__})
