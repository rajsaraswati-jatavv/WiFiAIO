"""Database backup and restore operations.

Provides JSON and SQLite backup/restore functionality for the
WiFiAIO database with compression and integrity verification.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from wifi_aio.exceptions import DatabaseError


class DatabaseBackup:
    """Database backup and restore manager.

    Supports full database backup to JSON or SQLite copy,
    with optional gzip compression and checksum verification.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _get_connection(self, readonly: bool = False) -> sqlite3.Connection:
        """Open a database connection.

        Args:
            readonly: If True, open in read-only mode.

        Returns:
            SQLite connection object.

        Raises:
            DatabaseError: If the database cannot be opened.
        """
        if not os.path.exists(self.db_path):
            raise DatabaseError(
                f"Database file not found: {self.db_path}",
                details=f"Path: {self.db_path}",
            )
        try:
            uri = f"file:{self.db_path}?mode=ro" if readonly else self.db_path
            conn = sqlite3.connect(uri, uri=readonly)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            raise DatabaseError(
                f"Cannot open database: {e}",
                details=f"Path: {self.db_path}",
            )

    def backup_to_json(
        self,
        output_path: Optional[str] = None,
        compress: bool = False,
        tables: Optional[List[str]] = None,
    ) -> str:
        """Create a JSON backup of the database.

        Args:
            output_path: Path for the backup file. Auto-generated if None.
            compress: If True, gzip-compress the output.
            tables: List of tables to backup. All tables if None.

        Returns:
            Path to the created backup file.

        Raises:
            DatabaseError: If backup fails.
        """
        conn = self._get_connection(readonly=True)

        try:
            if tables is None:
                cursor = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations'"
                )
                tables = [row[0] for row in cursor.fetchall()]

            backup_data: Dict[str, Any] = {
                "metadata": {
                    "version": "1.0",
                    "source_db": self.db_path,
                    "created_at": datetime.utcnow().isoformat(),
                    "tables": tables,
                },
                "data": {},
            }

            for table in tables:
                cursor = conn.execute(f"SELECT * FROM {table}")
                columns = [desc[0] for desc in cursor.description]
                rows = cursor.fetchall()
                backup_data["data"][table] = {
                    "columns": columns,
                    "rows": [dict(zip(columns, row)) for row in rows],
                }

            # Calculate checksum
            json_bytes = json.dumps(backup_data, indent=2, default=str).encode("utf-8")
            backup_data["metadata"]["checksum"] = hashlib.sha256(json_bytes).hexdigest()

            # Write output
            if output_path is None:
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                output_path = os.path.join(
                    os.path.dirname(self.db_path),
                    f"wifiaio_backup_{timestamp}.json",
                )

            final_json = json.dumps(backup_data, indent=2, default=str)

            if compress:
                if not output_path.endswith(".gz"):
                    output_path += ".gz"
                with gzip.open(output_path, "wt", encoding="utf-8") as f:
                    f.write(final_json)
            else:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(final_json)

            return output_path

        except sqlite3.Error as e:
            raise DatabaseError(f"Backup failed: {e}", details=str(e))
        finally:
            conn.close()

    def restore_from_json(
        self,
        backup_path: str,
        verify_checksum: bool = True,
        drop_existing: bool = False,
    ) -> Dict[str, int]:
        """Restore database from a JSON backup.

        Args:
            backup_path: Path to the backup file.
            verify_checksum: If True, verify backup integrity.
            drop_existing: If True, drop existing tables before restoring.

        Returns:
            Dict of table_name -> row_count for restored tables.

        Raises:
            DatabaseError: If restore fails or checksum mismatch.
        """
        try:
            if backup_path.endswith(".gz"):
                with gzip.open(backup_path, "rt", encoding="utf-8") as f:
                    backup_data = json.load(f)
            else:
                with open(backup_path, "r", encoding="utf-8") as f:
                    backup_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            raise DatabaseError(f"Cannot read backup file: {e}", details=str(e))

        # Verify checksum
        if verify_checksum and "checksum" in backup_data.get("metadata", {}):
            expected = backup_data["metadata"]["checksum"]
            # Remove checksum before re-calculating
            metadata_copy = dict(backup_data["metadata"])
            stored_checksum = metadata_copy.pop("checksum")
            backup_for_check = dict(backup_data)
            backup_for_check["metadata"] = metadata_copy
            actual = hashlib.sha256(
                json.dumps(backup_for_check, indent=2, default=str).encode("utf-8")
            ).hexdigest()
            if actual != expected:
                raise DatabaseError(
                    "Backup checksum verification failed - file may be corrupted",
                    details=f"Expected: {expected}, Got: {actual}",
                )

        conn = self._get_connection()
        try:
            restored_counts: Dict[str, int] = {}

            for table_name, table_data in backup_data.get("data", {}).items():
                columns = table_data.get("columns", [])
                rows = table_data.get("rows", [])

                if drop_existing:
                    conn.execute(f"DROP TABLE IF EXISTS {table_name}")

                # Create table if not exists
                col_defs = ", ".join(f"{col} TEXT" for col in columns)
                conn.execute(f"CREATE TABLE IF NOT EXISTS {table_name} ({col_defs})")

                # Insert rows
                if rows:
                    placeholders = ", ".join("?" * len(columns))
                    conn.executemany(
                        f"INSERT OR REPLACE INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders})",
                        [tuple(row.get(col) for col in columns) for row in rows],
                    )

                restored_counts[table_name] = len(rows)

            conn.commit()
            return restored_counts

        except sqlite3.Error as e:
            conn.rollback()
            raise DatabaseError(f"Restore failed: {e}", details=str(e))
        finally:
            conn.close()

    def backup_to_sqlite(self, output_path: Optional[str] = None) -> str:
        """Create a direct SQLite file copy backup.

        Args:
            output_path: Path for the backup file. Auto-generated if None.

        Returns:
            Path to the created backup file.
        """
        if output_path is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(
                os.path.dirname(self.db_path),
                f"wifiaio_backup_{timestamp}.db",
            )

        # Use SQLite backup API for consistent copy
        source_conn = self._get_connection(readonly=True)
        try:
            dest_conn = sqlite3.connect(output_path)
            source_conn.backup(dest_conn)
            dest_conn.close()
        finally:
            source_conn.close()

        return output_path

    def restore_from_sqlite(self, backup_path: str) -> bool:
        """Restore database from a SQLite file backup.

        Args:
            backup_path: Path to the SQLite backup file.

        Returns:
            True if restore was successful.
        """
        if not os.path.exists(backup_path):
            raise DatabaseError(f"Backup file not found: {backup_path}")

        try:
            # Verify backup is valid SQLite
            test_conn = sqlite3.connect(backup_path)
            test_conn.execute("SELECT count(*) FROM sqlite_master")
            test_conn.close()
        except sqlite3.Error as e:
            raise DatabaseError(f"Invalid SQLite backup: {e}")

        # Replace current database with backup
        shutil.copy2(backup_path, self.db_path)
        return True

    def list_backups(self, backup_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """List available backup files in a directory.

        Args:
            backup_dir: Directory to search. Defaults to DB directory.

        Returns:
            List of backup file info dicts.
        """
        search_dir = backup_dir or os.path.dirname(self.db_path)
        if not os.path.isdir(search_dir):
            return []

        backups = []
        for entry in os.scandir(search_dir):
            if entry.name.startswith("wifiaio_backup_") and (
                entry.name.endswith(".json") or entry.name.endswith(".db") or entry.name.endswith(".json.gz")
            ):
                stat = entry.stat()
                backups.append({
                    "filename": entry.name,
                    "path": entry.path,
                    "size_bytes": stat.st_size,
                    "size_mb": round(stat.st_size / (1024 * 1024), 2),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "compressed": entry.name.endswith(".gz"),
                    "format": "sqlite" if entry.name.endswith(".db") else "json",
                })

        return sorted(backups, key=lambda x: x["modified"], reverse=True)
