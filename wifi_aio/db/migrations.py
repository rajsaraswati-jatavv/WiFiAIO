"""Database schema migrations.

Provides a migration engine for creating and applying schema
changes to the WiFiAIO database, with version tracking and
rollback support.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from wifi_aio.exceptions import DatabaseError


# Migration definitions: each migration is (version, description, up_sql, down_sql)
_MIGRATIONS: List[Tuple[int, str, str, str]] = [
    (
        1,
        "Create initial schema",
        """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            interface TEXT NOT NULL DEFAULT '',
            scan_type TEXT NOT NULL DEFAULT 'active',
            band TEXT NOT NULL DEFAULT 'both',
            start_time TEXT,
            end_time TEXT,
            duration_seconds REAL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            access_point_count INTEGER DEFAULT 0,
            notes TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS access_points (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            bssid TEXT NOT NULL,
            ssid TEXT DEFAULT '',
            channel INTEGER DEFAULT 0,
            frequency INTEGER DEFAULT 0,
            band TEXT DEFAULT '',
            signal_dbm INTEGER DEFAULT 0,
            signal_quality INTEGER DEFAULT 0,
            encryption TEXT DEFAULT '',
            cipher TEXT DEFAULT '',
            authentication TEXT DEFAULT '',
            wps INTEGER DEFAULT 0,
            wps_version TEXT DEFAULT '',
            wps_pin TEXT DEFAULT '',
            wps_locked INTEGER DEFAULT 0,
            pmf TEXT DEFAULT 'disabled',
            vendor TEXT DEFAULT '',
            first_seen TEXT,
            last_seen TEXT,
            beacon_interval INTEGER DEFAULT 100,
            max_bitrate INTEGER DEFAULT 0,
            ht_capabilities TEXT DEFAULT '',
            vht_capabilities TEXT DEFAULT '',
            he_capabilities TEXT DEFAULT '',
            clients_count INTEGER DEFAULT 0,
            is_hidden INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE INDEX IF NOT EXISTS idx_ap_scan_id ON access_points(scan_id);
        CREATE INDEX IF NOT EXISTS idx_ap_bssid ON access_points(bssid);

        CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            ap_id TEXT,
            mac_address TEXT NOT NULL,
            bssid TEXT DEFAULT '',
            ssid TEXT DEFAULT '',
            signal_dbm INTEGER DEFAULT 0,
            signal_quality INTEGER DEFAULT 0,
            channel INTEGER DEFAULT 0,
            frequency INTEGER DEFAULT 0,
            vendor TEXT DEFAULT '',
            first_seen TEXT,
            last_seen TEXT,
            associated INTEGER DEFAULT 0,
            probes TEXT DEFAULT '[]',
            ip_address TEXT DEFAULT '',
            hostname TEXT DEFAULT '',
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE INDEX IF NOT EXISTS idx_client_scan_id ON clients(scan_id);

        CREATE TABLE IF NOT EXISTS handshakes (
            id TEXT PRIMARY KEY,
            ap_id TEXT,
            bssid TEXT NOT NULL,
            ssid TEXT DEFAULT '',
            capture_file TEXT NOT NULL,
            capture_type TEXT DEFAULT '4way',
            quality TEXT DEFAULT 'unknown',
            channel INTEGER DEFAULT 0,
            encryption TEXT DEFAULT '',
            captured_at TEXT,
            file_size INTEGER DEFAULT 0,
            verified INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            FOREIGN KEY (ap_id) REFERENCES access_points(id)
        );

        CREATE TABLE IF NOT EXISTS cracking_sessions (
            id TEXT PRIMARY KEY,
            handshake_id TEXT,
            bssid TEXT DEFAULT '',
            ssid TEXT DEFAULT '',
            method TEXT DEFAULT 'dictionary',
            wordlist TEXT DEFAULT '',
            rules TEXT DEFAULT '',
            mask TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            progress REAL DEFAULT 0,
            speed INTEGER DEFAULT 0,
            tried INTEGER DEFAULT 0,
            total INTEGER DEFAULT 0,
            start_time TEXT,
            end_time TEXT,
            duration_seconds REAL DEFAULT 0,
            cracked INTEGER DEFAULT 0,
            password TEXT DEFAULT '',
            tool TEXT DEFAULT '',
            gpu_used INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            FOREIGN KEY (handshake_id) REFERENCES handshakes(id)
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id TEXT PRIMARY KEY,
            bssid TEXT NOT NULL,
            ssid TEXT DEFAULT '',
            password TEXT NOT NULL,
            encryption TEXT DEFAULT '',
            source TEXT DEFAULT '',
            session_id TEXT DEFAULT '',
            discovered_at TEXT,
            verified INTEGER DEFAULT 0,
            notes TEXT DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_cred_bssid ON credentials(bssid);

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            ap_id TEXT,
            bssid TEXT NOT NULL,
            ssid TEXT DEFAULT '',
            vulnerability_type TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            cve_id TEXT DEFAULT '',
            description TEXT DEFAULT '',
            recommendation TEXT DEFAULT '',
            discovered_at TEXT,
            verified INTEGER DEFAULT 0,
            false_positive INTEGER DEFAULT 0,
            details TEXT DEFAULT '{}',
            FOREIGN KEY (ap_id) REFERENCES access_points(id)
        );

        CREATE TABLE IF NOT EXISTS config (
            id TEXT PRIMARY KEY,
            key TEXT NOT NULL UNIQUE,
            value TEXT DEFAULT '',
            category TEXT DEFAULT 'general',
            description TEXT DEFAULT '',
            created_at TEXT,
            updated_at TEXT,
            is_sensitive INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_config_key ON config(key);
        """,
        """
        DROP TABLE IF EXISTS config;
        DROP TABLE IF EXISTS vulnerabilities;
        DROP TABLE IF EXISTS credentials;
        DROP TABLE IF EXISTS cracking_sessions;
        DROP TABLE IF EXISTS handshakes;
        DROP TABLE IF EXISTS clients;
        DROP TABLE IF EXISTS access_points;
        DROP TABLE IF EXISTS scans;
        """,
    ),
    (
        2,
        "Add scan results metadata and indexes",
        """
        CREATE TABLE IF NOT EXISTS scan_metadata (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT DEFAULT '',
            FOREIGN KEY (scan_id) REFERENCES scans(id),
            UNIQUE(scan_id, key)
        );
        CREATE INDEX IF NOT EXISTS idx_meta_scan_id ON scan_metadata(scan_id);
        """,
        """
        DROP TABLE IF EXISTS scan_metadata;
        """,
    ),
    (
        3,
        "Add task tracking table",
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            task_type TEXT NOT NULL DEFAULT 'scan',
            status TEXT NOT NULL DEFAULT 'pending',
            progress REAL DEFAULT 0,
            created_at TEXT,
            started_at TEXT,
            completed_at TEXT,
            result TEXT DEFAULT '',
            error TEXT DEFAULT '',
            params TEXT DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_task_status ON tasks(status);
        """,
        """
        DROP TABLE IF EXISTS tasks;
        """,
    ),
]


class DatabaseMigrator:
    """Database schema migration engine.

    Manages schema version tracking, applies pending migrations,
    and supports rollback to previous versions.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create a database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _ensure_version_table(self) -> None:
        """Create the schema_migrations table if it doesn't exist."""
        conn = self._get_connection()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
        """)
        conn.commit()

    def get_current_version(self) -> int:
        """Get the current schema version.

        Returns:
            Current migration version number, or 0 if no migrations applied.
        """
        self._ensure_version_table()
        conn = self._get_connection()
        cursor = conn.execute("SELECT MAX(version) FROM schema_migrations")
        result = cursor.fetchone()
        return result[0] if result and result[0] is not None else 0

    def get_pending_migrations(self) -> List[Tuple[int, str, str, str]]:
        """Get list of migrations that haven't been applied yet.

        Returns:
            List of pending migration tuples.
        """
        current = self.get_current_version()
        return [m for m in _MIGRATIONS if m[0] > current]

    def migrate(self, target_version: Optional[int] = None) -> List[int]:
        """Apply pending migrations up to a target version.

        Args:
            target_version: Target version to migrate to. If None, applies all pending.

        Returns:
            List of applied migration version numbers.

        Raises:
            DatabaseError: If a migration fails.
        """
        self._ensure_version_table()
        conn = self._get_connection()
        applied = []

        pending = self.get_pending_migrations()
        if target_version is not None:
            pending = [m for m in pending if m[0] <= target_version]

        for version, description, up_sql, down_sql in pending:
            try:
                conn.executescript(up_sql)
                conn.execute(
                    "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)",
                    (version, description, datetime.utcnow().isoformat()),
                )
                conn.commit()
                applied.append(version)
            except sqlite3.Error as e:
                conn.rollback()
                raise DatabaseError(
                    f"Migration {version} ({description}) failed: {e}",
                    details=f"Version: {version}, Error: {str(e)}",
                )

        return applied

    def rollback(self, steps: int = 1) -> List[int]:
        """Rollback the last N applied migrations.

        Args:
            steps: Number of migrations to roll back.

        Returns:
            List of rolled-back migration version numbers.

        Raises:
            DatabaseError: If rollback fails.
        """
        self._ensure_version_table()
        conn = self._get_connection()
        current = self.get_current_version()
        rolled_back = []

        applied_migrations = sorted(
            [m for m in _MIGRATIONS if m[0] <= current],
            key=lambda x: x[0],
            reverse=True,
        )

        for version, description, up_sql, down_sql in applied_migrations[:steps]:
            try:
                conn.executescript(down_sql)
                conn.execute(
                    "DELETE FROM schema_migrations WHERE version = ?",
                    (version,),
                )
                conn.commit()
                rolled_back.append(version)
            except sqlite3.Error as e:
                conn.rollback()
                raise DatabaseError(
                    f"Rollback of migration {version} failed: {e}",
                    details=f"Version: {version}, Error: {str(e)}",
                )

        return rolled_back

    def get_migration_history(self) -> List[Dict[str, Any]]:
        """Get the history of applied migrations.

        Returns:
            List of dicts with version, description, applied_at.
        """
        self._ensure_version_table()
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT version, description, applied_at FROM schema_migrations ORDER BY version"
        )
        return [
            {"version": row[0], "description": row[1], "applied_at": row[2]}
            for row in cursor.fetchall()
        ]

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
