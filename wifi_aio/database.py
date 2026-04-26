"""WiFiAIO SQLite database layer.

Provides a thread-safe wrapper around an SQLite database for storing
access-point scan results, session data and audit records.  All
mutations go through a single :class:`threading.Lock` so the database
can be safely shared across threads.
"""

import json
import logging
import os
import shutil
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from wifi_aio.exceptions import DatabaseError

logger = logging.getLogger(__name__)

# Whitelist of allowed column names for the access_points table.
# This prevents SQL-injection via user-supplied column names.
VALID_AP_COLUMNS: Tuple[str, ...] = (
    "id",
    "bssid",
    "ssid",
    "channel",
    "frequency",
    "signal_dbm",
    "security",
    "wps",
    "wps_pin",
    "pmf",
    "standard",
    "band",
    "lat",
    "lon",
    "first_seen",
    "last_seen",
    "handshake_captured",
    "notes",
    "vendor",
    "hidden",
    "clients_count",
)


class Database:
    """Thread-safe SQLite database for WiFiAIO.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.  Parent directories are created
        automatically.
    """

    _SCHEMA_VERSION = 2

    def __init__(self, db_path: str = "/tmp/wifiaio/wifiaio.db"):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ── Connection management ─────────────────────────────────────────

    def _ensure_connection(self) -> sqlite3.Connection:
        """Return the current connection, creating one if needed."""
        if self._conn is None:
            try:
                db_dir = os.path.dirname(self._db_path)
                if db_dir:
                    os.makedirs(db_dir, exist_ok=True)
                self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA foreign_keys=ON")
            except sqlite3.Error as exc:
                raise DatabaseError(f"Cannot open database: {exc}") from exc
        return self._conn

    def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None

    # ── Schema initialisation ─────────────────────────────────────────

    def _init_db(self) -> None:
        """Create tables if they do not already exist."""
        conn = self._ensure_connection()
        with self._lock:
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS access_points (
                        id              INTEGER PRIMARY KEY AUTOINCREMENT,
                        bssid           TEXT NOT NULL UNIQUE,
                        ssid            TEXT DEFAULT '',
                        channel         INTEGER DEFAULT 0,
                        frequency       INTEGER DEFAULT 0,
                        signal_dbm      INTEGER DEFAULT -100,
                        security        TEXT DEFAULT 'OPEN',
                        wps             INTEGER DEFAULT 0,
                        wps_pin         TEXT DEFAULT '',
                        pmf             INTEGER DEFAULT 0,
                        standard        TEXT DEFAULT '',
                        band            TEXT DEFAULT '2.4',
                        lat             REAL DEFAULT 0.0,
                        lon             REAL DEFAULT 0.0,
                        first_seen      TEXT DEFAULT '',
                        last_seen       TEXT DEFAULT '',
                        handshake_captured INTEGER DEFAULT 0,
                        notes           TEXT DEFAULT '',
                        vendor          TEXT DEFAULT '',
                        hidden          INTEGER DEFAULT 0,
                        clients_count   INTEGER DEFAULT 0
                    );

                    CREATE TABLE IF NOT EXISTS scan_sessions (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        start_time TEXT NOT NULL,
                        end_time   TEXT DEFAULT '',
                        interface  TEXT DEFAULT '',
                        notes      TEXT DEFAULT ''
                    );

                    CREATE TABLE IF NOT EXISTS captured_handshakes (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        ap_bssid    TEXT NOT NULL,
                        ap_ssid     TEXT DEFAULT '',
                        file_path   TEXT NOT NULL,
                        captured_at TEXT DEFAULT '',
                        verified    INTEGER DEFAULT 0
                    );

                    CREATE TABLE IF NOT EXISTS audit_log (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp   TEXT NOT NULL,
                        action      TEXT NOT NULL,
                        target      TEXT DEFAULT '',
                        details     TEXT DEFAULT '',
                        severity    TEXT DEFAULT 'INFO'
                    );

                    CREATE TABLE IF NOT EXISTS metadata (
                        key   TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    """
                )
                conn.execute(
                    "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                    ("schema_version", str(self._SCHEMA_VERSION)),
                )
                conn.commit()
            except sqlite3.Error as exc:
                raise DatabaseError(f"Schema init failed: {exc}") from exc

    # ── Backup / restore ──────────────────────────────────────────────

    def backup(self, dest_path: str) -> str:
        """Create a copy of the database at *dest_path*.

        Returns the absolute path of the backup file.
        """
        self._ensure_connection()
        with self._lock:
            try:
                dest_dir = os.path.dirname(dest_path)
                if dest_dir:
                    os.makedirs(dest_dir, exist_ok=True)
                # Use SQLite's online backup API for a consistent snapshot
                dest_conn = sqlite3.connect(dest_path)
                self._conn.backup(dest_conn)
                dest_conn.close()
                logger.info("Database backed up to %s", dest_path)
                return os.path.abspath(dest_path)
            except (sqlite3.Error, OSError) as exc:
                raise DatabaseError(f"Backup failed: {exc}") from exc

    def restore(self, src_path: str) -> None:
        """Replace the current database with the file at *src_path*.

        The existing database is overwritten after closing the current
        connection.
        """
        if not os.path.isfile(src_path):
            raise DatabaseError(f"Restore source not found: {src_path}")
        self.close()
        try:
            shutil.copy2(src_path, self._db_path)
        except OSError as exc:
            raise DatabaseError(f"Restore failed: {exc}") from exc
        self._init_db()
        logger.info("Database restored from %s", src_path)

    # ── CRUD: access_points ───────────────────────────────────────────

    def insert_ap(self, ap_data: Dict[str, Any]) -> int:
        """Insert an access-point record.  Returns the new row ``id``."""
        allowed = {k: v for k, v in ap_data.items() if k in VALID_AP_COLUMNS}
        if "bssid" not in allowed:
            raise DatabaseError("bssid is required when inserting an AP")
        now = datetime.now(timezone.utc).isoformat()
        allowed.setdefault("first_seen", now)
        allowed.setdefault("last_seen", now)

        columns = ", ".join(allowed.keys())
        placeholders = ", ".join("?" for _ in allowed)
        values = list(allowed.values())

        conn = self._ensure_connection()
        with self._lock:
            try:
                cur = conn.execute(
                    f"INSERT OR REPLACE INTO access_points ({columns}) VALUES ({placeholders})",
                    values,
                )
                conn.commit()
                return cur.lastrowid  # type: ignore[return-value]
            except sqlite3.Error as exc:
                raise DatabaseError(f"Insert AP failed: {exc}") from exc

    def update_ap(self, bssid: str, updates: Dict[str, Any]) -> int:
        """Update fields of an AP identified by *bssid*.  Returns rows changed."""
        safe = {k: v for k, v in updates.items() if k in VALID_AP_COLUMNS and k != "id"}
        if not safe:
            return 0
        safe["last_seen"] = datetime.now(timezone.utc).isoformat()

        set_clause = ", ".join(f"{col} = ?" for col in safe)
        values = list(safe.values()) + [bssid]

        conn = self._ensure_connection()
        with self._lock:
            try:
                cur = conn.execute(
                    f"UPDATE access_points SET {set_clause} WHERE bssid = ?",
                    values,
                )
                conn.commit()
                return cur.rowcount
            except sqlite3.Error as exc:
                raise DatabaseError(f"Update AP failed: {exc}") from exc

    def get_ap(self, bssid: str) -> Optional[Dict[str, Any]]:
        """Return a single AP record as a dict, or ``None``."""
        conn = self._ensure_connection()
        with self._lock:
            try:
                cur = conn.execute(
                    "SELECT * FROM access_points WHERE bssid = ?", (bssid,)
                )
                row = cur.fetchone()
                return dict(row) if row else None
            except sqlite3.Error as exc:
                raise DatabaseError(f"Get AP failed: {exc}") from exc

    def delete_ap(self, bssid: str) -> int:
        """Delete an AP by *bssid*.  Returns rows deleted."""
        conn = self._ensure_connection()
        with self._lock:
            try:
                cur = conn.execute(
                    "DELETE FROM access_points WHERE bssid = ?", (bssid,)
                )
                conn.commit()
                return cur.rowcount
            except sqlite3.Error as exc:
                raise DatabaseError(f"Delete AP failed: {exc}") from exc

    def list_aps(
        self,
        filter_col: Optional[str] = None,
        filter_val: Optional[Any] = None,
        order_by: str = "signal_dbm DESC",
        limit: int = 0,
    ) -> List[Dict[str, Any]]:
        """Return AP records, optionally filtered and ordered.

        *filter_col* must be in :data:`VALID_AP_COLUMNS` to prevent
        SQL injection.
        """
        conn = self._ensure_connection()
        query = "SELECT * FROM access_points"
        params: List[Any] = []

        if filter_col and filter_val is not None:
            if filter_col not in VALID_AP_COLUMNS:
                raise DatabaseError(f"Invalid filter column: {filter_col}")
            query += f" WHERE {filter_col} = ?"
            params.append(filter_val)

        # Sanitise order_by – only allow known column names + ASC/DESC
        order_parts = order_by.split()
        if order_parts[0] not in VALID_AP_COLUMNS:
            order_by = "signal_dbm DESC"
        elif len(order_parts) > 1 and order_parts[1].upper() not in ("ASC", "DESC"):
            order_by = f"{order_parts[0]} DESC"
        query += f" ORDER BY {order_by}"

        if limit > 0:
            query += " LIMIT ?"
            params.append(limit)

        with self._lock:
            try:
                cur = conn.execute(query, params)
                return [dict(row) for row in cur.fetchall()]
            except sqlite3.Error as exc:
                raise DatabaseError(f"List APs failed: {exc}") from exc

    def count_aps(self) -> int:
        """Return the total number of AP records."""
        conn = self._ensure_connection()
        with self._lock:
            try:
                cur = conn.execute("SELECT COUNT(*) FROM access_points")
                return cur.fetchone()[0]
            except sqlite3.Error as exc:
                raise DatabaseError(f"Count APs failed: {exc}") from exc

    # ── CRUD: scan_sessions ───────────────────────────────────────────

    def start_session(self, interface: str = "", notes: str = "") -> int:
        """Insert a new scan session.  Returns the session ``id``."""
        now = datetime.now(timezone.utc).isoformat()
        conn = self._ensure_connection()
        with self._lock:
            try:
                cur = conn.execute(
                    "INSERT INTO scan_sessions (start_time, interface, notes) VALUES (?, ?, ?)",
                    (now, interface, notes),
                )
                conn.commit()
                return cur.lastrowid  # type: ignore[return-value]
            except sqlite3.Error as exc:
                raise DatabaseError(f"Start session failed: {exc}") from exc

    def end_session(self, session_id: int) -> None:
        """Set the ``end_time`` of a session to now."""
        now = datetime.now(timezone.utc).isoformat()
        conn = self._ensure_connection()
        with self._lock:
            try:
                conn.execute(
                    "UPDATE scan_sessions SET end_time = ? WHERE id = ?",
                    (now, session_id),
                )
                conn.commit()
            except sqlite3.Error as exc:
                raise DatabaseError(f"End session failed: {exc}") from exc

    # ── CRUD: captured_handshakes ─────────────────────────────────────

    def add_handshake(
        self, bssid: str, ssid: str, file_path: str, verified: bool = False
    ) -> int:
        """Record a captured handshake.  Returns the row ``id``."""
        now = datetime.now(timezone.utc).isoformat()
        conn = self._ensure_connection()
        with self._lock:
            try:
                cur = conn.execute(
                    "INSERT INTO captured_handshakes (ap_bssid, ap_ssid, file_path, captured_at, verified) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (bssid, ssid, file_path, now, int(verified)),
                )
                conn.commit()
                return cur.lastrowid  # type: ignore[return-value]
            except sqlite3.Error as exc:
                raise DatabaseError(f"Add handshake failed: {exc}") from exc

    # ── CRUD: audit_log ───────────────────────────────────────────────

    def audit(self, action: str, target: str = "", details: str = "", severity: str = "INFO") -> None:
        """Append an entry to the audit log."""
        now = datetime.now(timezone.utc).isoformat()
        conn = self._ensure_connection()
        with self._lock:
            try:
                conn.execute(
                    "INSERT INTO audit_log (timestamp, action, target, details, severity) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (now, action, target, details, severity),
                )
                conn.commit()
            except sqlite3.Error as exc:
                raise DatabaseError(f"Audit log failed: {exc}") from exc

    # ── Generic query ─────────────────────────────────────────────────

    def execute(self, sql: str, params: Tuple = ()) -> List[Dict[str, Any]]:
        """Execute an arbitrary SELECT and return rows as dicts.

        **Only SELECT statements are allowed** – anything else raises
        :class:`DatabaseError`.
        """
        normalised = sql.strip().upper()
        if not normalised.startswith("SELECT"):
            raise DatabaseError("Only SELECT queries are permitted via execute()")

        conn = self._ensure_connection()
        with self._lock:
            try:
                cur = conn.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]
            except sqlite3.Error as exc:
                raise DatabaseError(f"Query failed: {exc}") from exc

    # ── Context manager ───────────────────────────────────────────────

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[override]
        self.close()
