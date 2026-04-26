"""Credential repository for CRUD operations on discovered credentials.

Provides create, read, update, delete, and query operations
for WiFi credential records including passwords and keys.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

from wifi_aio.db.models import Credential
from wifi_aio.exceptions import DatabaseError


class CredentialRepository:
    """Repository for Credential model CRUD operations."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def create(self, credential: Credential) -> Credential:
        """Create a new credential record.

        Args:
            credential: Credential model instance to persist.

        Returns:
            The created Credential instance.

        Raises:
            DatabaseError: If the insert fails.
        """
        try:
            self.conn.execute(
                """INSERT INTO credentials
                   (id, bssid, ssid, password, encryption, source, session_id,
                    discovered_at, verified, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    credential.id, credential.bssid, credential.ssid,
                    credential.password, credential.encryption, credential.source,
                    credential.session_id,
                    credential.discovered_at.isoformat() if credential.discovered_at else None,
                    int(credential.verified), credential.notes,
                ),
            )
            self.conn.commit()
            return credential
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to create credential: {e}", details=str(e))

    def get_by_id(self, cred_id: str) -> Optional[Credential]:
        """Get a credential by ID."""
        cursor = self.conn.execute("SELECT * FROM credentials WHERE id = ?", (cred_id,))
        row = cursor.fetchone()
        return self._row_to_credential(row) if row else None

    def get_by_bssid(self, bssid: str) -> List[Credential]:
        """Get all credentials for a BSSID."""
        cursor = self.conn.execute(
            "SELECT * FROM credentials WHERE bssid = ? ORDER BY discovered_at DESC",
            (bssid,),
        )
        return [self._row_to_credential(row) for row in cursor.fetchall()]

    def get_by_ssid(self, ssid: str) -> List[Credential]:
        """Get credentials by SSID."""
        cursor = self.conn.execute(
            "SELECT * FROM credentials WHERE ssid = ? ORDER BY discovered_at DESC",
            (ssid,),
        )
        return [self._row_to_credential(row) for row in cursor.fetchall()]

    def get_verified(self) -> List[Credential]:
        """Get all verified credentials."""
        cursor = self.conn.execute(
            "SELECT * FROM credentials WHERE verified = 1 ORDER BY discovered_at DESC"
        )
        return [self._row_to_credential(row) for row in cursor.fetchall()]

    def get_unverified(self) -> List[Credential]:
        """Get all unverified credentials."""
        cursor = self.conn.execute(
            "SELECT * FROM credentials WHERE verified = 0 ORDER BY discovered_at DESC"
        )
        return [self._row_to_credential(row) for row in cursor.fetchall()]

    def get_by_source(self, source: str) -> List[Credential]:
        """Get credentials by discovery source."""
        cursor = self.conn.execute(
            "SELECT * FROM credentials WHERE source = ? ORDER BY discovered_at DESC",
            (source,),
        )
        return [self._row_to_credential(row) for row in cursor.fetchall()]

    def search(self, keyword: str, limit: int = 100) -> List[Credential]:
        """Search credentials by keyword in SSID, BSSID, or source."""
        pattern = f"%{keyword}%"
        cursor = self.conn.execute(
            """SELECT * FROM credentials
               WHERE ssid LIKE ? OR bssid LIKE ? OR source LIKE ?
               ORDER BY discovered_at DESC LIMIT ?""",
            (pattern, pattern, pattern, limit),
        )
        return [self._row_to_credential(row) for row in cursor.fetchall()]

    def get_all(self, limit: int = 100, offset: int = 0) -> List[Credential]:
        """Get all credentials with pagination."""
        cursor = self.conn.execute(
            "SELECT * FROM credentials ORDER BY discovered_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [self._row_to_credential(row) for row in cursor.fetchall()]

    def update(self, credential: Credential) -> Credential:
        """Update a credential record."""
        try:
            self.conn.execute(
                """UPDATE credentials SET
                   ssid = ?, password = ?, encryption = ?, source = ?,
                   session_id = ?, verified = ?, notes = ?
                   WHERE id = ?""",
                (
                    credential.ssid, credential.password, credential.encryption,
                    credential.source, credential.session_id,
                    int(credential.verified), credential.notes, credential.id,
                ),
            )
            self.conn.commit()
            return credential
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to update credential: {e}", details=str(e))

    def verify(self, cred_id: str) -> bool:
        """Mark a credential as verified."""
        try:
            cursor = self.conn.execute(
                "UPDATE credentials SET verified = 1 WHERE id = ?", (cred_id,)
            )
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to verify credential: {e}", details=str(e))

    def delete(self, cred_id: str) -> bool:
        """Delete a credential by ID."""
        try:
            cursor = self.conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to delete credential: {e}", details=str(e))

    def count(self) -> int:
        """Return the total number of credentials."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM credentials")
        return cursor.fetchone()[0]

    def count_verified(self) -> int:
        """Return the number of verified credentials."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM credentials WHERE verified = 1")
        return cursor.fetchone()[0]

    def count_by_source(self) -> Dict[str, int]:
        """Return credential counts grouped by source."""
        cursor = self.conn.execute("SELECT source, COUNT(*) FROM credentials GROUP BY source")
        return dict(cursor.fetchall())

    @staticmethod
    def _row_to_credential(row: sqlite3.Row) -> Credential:
        """Convert a database row to a Credential instance."""
        data = dict(row)
        if "discovered_at" in data and data["discovered_at"] and isinstance(data["discovered_at"], str):
            try:
                data["discovered_at"] = datetime.fromisoformat(data["discovered_at"])
            except (ValueError, TypeError):
                pass
        if "verified" in data:
            data["verified"] = bool(data["verified"])
        return Credential(**{k: v for k, v in data.items() if k in Credential.__dataclass_fields__})
