"""Scan repository for CRUD operations on scan records.

Provides create, read, update, delete, and query operations
for WiFi network scan data.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

from wifi_aio.db.models import Scan, AccessPoint
from wifi_aio.exceptions import DatabaseError


class ScanRepository:
    """Repository for Scan model CRUD operations."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def create(self, scan: Scan) -> Scan:
        """Create a new scan record.

        Args:
            scan: Scan model instance to persist.

        Returns:
            The created Scan instance.

        Raises:
            DatabaseError: If the insert fails.
        """
        try:
            self.conn.execute(
                """INSERT INTO scans
                   (id, interface, scan_type, band, start_time, end_time,
                    duration_seconds, status, access_point_count, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan.id, scan.interface, scan.scan_type, scan.band,
                    scan.start_time.isoformat() if scan.start_time else None,
                    scan.end_time.isoformat() if scan.end_time else None,
                    scan.duration_seconds, scan.status,
                    scan.access_point_count, scan.notes,
                ),
            )
            self.conn.commit()
            return scan
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to create scan: {e}", details=str(e))

    def get_by_id(self, scan_id: str) -> Optional[Scan]:
        """Get a scan by its ID.

        Args:
            scan_id: Scan ID to look up.

        Returns:
            Scan instance, or None if not found.
        """
        cursor = self.conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_scan(row)

    def get_all(self, limit: int = 100, offset: int = 0) -> List[Scan]:
        """Get all scans with pagination.

        Args:
            limit: Maximum number of records to return.
            offset: Number of records to skip.

        Returns:
            List of Scan instances.
        """
        cursor = self.conn.execute(
            "SELECT * FROM scans ORDER BY start_time DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [self._row_to_scan(row) for row in cursor.fetchall()]

    def get_by_status(self, status: str) -> List[Scan]:
        """Get all scans with a specific status.

        Args:
            status: Status to filter by (pending, running, completed, failed).

        Returns:
            List of matching Scan instances.
        """
        cursor = self.conn.execute(
            "SELECT * FROM scans WHERE status = ? ORDER BY start_time DESC",
            (status,),
        )
        return [self._row_to_scan(row) for row in cursor.fetchall()]

    def get_recent(self, hours: int = 24) -> List[Scan]:
        """Get scans from the last N hours.

        Args:
            hours: Number of hours to look back.

        Returns:
            List of recent Scan instances.
        """
        cutoff = datetime.utcnow().replace(
            hour=datetime.utcnow().hour - hours if datetime.utcnow().hour >= hours else 0
        ).isoformat()
        cursor = self.conn.execute(
            "SELECT * FROM scans WHERE start_time >= ? ORDER BY start_time DESC",
            (cutoff,),
        )
        return [self._row_to_scan(row) for row in cursor.fetchall()]

    def update(self, scan: Scan) -> Scan:
        """Update an existing scan record.

        Args:
            scan: Scan instance with updated fields.

        Returns:
            The updated Scan instance.

        Raises:
            DatabaseError: If the update fails.
        """
        try:
            self.conn.execute(
                """UPDATE scans SET
                   interface = ?, scan_type = ?, band = ?,
                   start_time = ?, end_time = ?, duration_seconds = ?,
                   status = ?, access_point_count = ?, notes = ?
                   WHERE id = ?""",
                (
                    scan.interface, scan.scan_type, scan.band,
                    scan.start_time.isoformat() if scan.start_time else None,
                    scan.end_time.isoformat() if scan.end_time else None,
                    scan.duration_seconds, scan.status,
                    scan.access_point_count, scan.notes, scan.id,
                ),
            )
            self.conn.commit()
            return scan
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to update scan: {e}", details=str(e))

    def delete(self, scan_id: str) -> bool:
        """Delete a scan by ID.

        Args:
            scan_id: Scan ID to delete.

        Returns:
            True if a record was deleted, False if not found.

        Raises:
            DatabaseError: If the delete fails.
        """
        try:
            # Delete related records first
            self.conn.execute("DELETE FROM clients WHERE scan_id = ?", (scan_id,))
            self.conn.execute("DELETE FROM access_points WHERE scan_id = ?", (scan_id,))
            cursor = self.conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to delete scan: {e}", details=str(e))

    def count(self) -> int:
        """Return the total number of scans."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM scans")
        return cursor.fetchone()[0]

    def count_by_status(self) -> Dict[str, int]:
        """Return scan counts grouped by status."""
        cursor = self.conn.execute(
            "SELECT status, COUNT(*) FROM scans GROUP BY status"
        )
        return dict(cursor.fetchall())

    def get_access_points(self, scan_id: str) -> List[AccessPoint]:
        """Get all access points for a scan.

        Args:
            scan_id: Scan ID to query.

        Returns:
            List of AccessPoint instances.
        """
        cursor = self.conn.execute(
            "SELECT * FROM access_points WHERE scan_id = ? ORDER BY signal_dbm DESC",
            (scan_id,),
        )
        return [self._row_to_ap(row) for row in cursor.fetchall()]

    @staticmethod
    def _row_to_scan(row: sqlite3.Row) -> Scan:
        """Convert a database row to a Scan instance."""
        data = dict(row)
        for dt_field in ("start_time", "end_time"):
            if dt_field in data and data[dt_field] and isinstance(data[dt_field], str):
                try:
                    data[dt_field] = datetime.fromisoformat(data[dt_field])
                except (ValueError, TypeError):
                    pass
        return Scan(**{k: v for k, v in data.items() if k in Scan.__dataclass_fields__})

    @staticmethod
    def _row_to_ap(row: sqlite3.Row) -> AccessPoint:
        """Convert a database row to an AccessPoint instance."""
        data = dict(row)
        for dt_field in ("first_seen", "last_seen"):
            if dt_field in data and data[dt_field] and isinstance(data[dt_field], str):
                try:
                    data[dt_field] = datetime.fromisoformat(data[dt_field])
                except (ValueError, TypeError):
                    pass
        # Convert integer boolean fields
        for bool_field in ("wps", "wps_locked", "is_hidden"):
            if bool_field in data:
                data[bool_field] = bool(data[bool_field])
        return AccessPoint(**{k: v for k, v in data.items() if k in AccessPoint.__dataclass_fields__})
