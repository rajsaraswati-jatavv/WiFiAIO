"""Session repository for CRUD operations on cracking/task sessions.

Provides create, read, update, delete, and query operations
for cracking session and task tracking records.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

from wifi_aio.db.models import CrackingSession
from wifi_aio.exceptions import DatabaseError


class SessionRepository:
    """Repository for CrackingSession and task model CRUD operations."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def create(self, session: CrackingSession) -> CrackingSession:
        """Create a new cracking session record.

        Args:
            session: CrackingSession model instance to persist.

        Returns:
            The created CrackingSession instance.

        Raises:
            DatabaseError: If the insert fails.
        """
        try:
            self.conn.execute(
                """INSERT INTO cracking_sessions
                   (id, handshake_id, bssid, ssid, method, wordlist, rules, mask,
                    status, progress, speed, tried, total, start_time, end_time,
                    duration_seconds, cracked, password, tool, gpu_used, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session.id, session.handshake_id, session.bssid, session.ssid,
                    session.method, session.wordlist, session.rules, session.mask,
                    session.status, session.progress, session.speed, session.tried,
                    session.total,
                    session.start_time.isoformat() if session.start_time else None,
                    session.end_time.isoformat() if session.end_time else None,
                    session.duration_seconds, int(session.cracked), session.password,
                    session.tool, int(session.gpu_used), session.notes,
                ),
            )
            self.conn.commit()
            return session
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to create session: {e}", details=str(e))

    def get_by_id(self, session_id: str) -> Optional[CrackingSession]:
        """Get a session by ID."""
        cursor = self.conn.execute("SELECT * FROM cracking_sessions WHERE id = ?", (session_id,))
        row = cursor.fetchone()
        return self._row_to_session(row) if row else None

    def get_all(self, limit: int = 100, offset: int = 0) -> List[CrackingSession]:
        """Get all sessions with pagination."""
        cursor = self.conn.execute(
            "SELECT * FROM cracking_sessions ORDER BY start_time DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [self._row_to_session(row) for row in cursor.fetchall()]

    def get_by_status(self, status: str) -> List[CrackingSession]:
        """Get sessions by status."""
        cursor = self.conn.execute(
            "SELECT * FROM cracking_sessions WHERE status = ? ORDER BY start_time DESC",
            (status,),
        )
        return [self._row_to_session(row) for row in cursor.fetchall()]

    def get_running(self) -> List[CrackingSession]:
        """Get all currently running sessions."""
        return self.get_by_status("running")

    def get_cracked(self) -> List[CrackingSession]:
        """Get all sessions that successfully cracked a password."""
        cursor = self.conn.execute(
            "SELECT * FROM cracking_sessions WHERE cracked = 1 ORDER BY end_time DESC"
        )
        return [self._row_to_session(row) for row in cursor.fetchall()]

    def get_by_method(self, method: str) -> List[CrackingSession]:
        """Get sessions by cracking method."""
        cursor = self.conn.execute(
            "SELECT * FROM cracking_sessions WHERE method = ? ORDER BY start_time DESC",
            (method,),
        )
        return [self._row_to_session(row) for row in cursor.fetchall()]

    def get_by_bssid(self, bssid: str) -> List[CrackingSession]:
        """Get all sessions for a specific BSSID."""
        cursor = self.conn.execute(
            "SELECT * FROM cracking_sessions WHERE bssid = ? ORDER BY start_time DESC",
            (bssid,),
        )
        return [self._row_to_session(row) for row in cursor.fetchall()]

    def update(self, session: CrackingSession) -> CrackingSession:
        """Update a session record."""
        try:
            self.conn.execute(
                """UPDATE cracking_sessions SET
                   status = ?, progress = ?, speed = ?, tried = ?, total = ?,
                   end_time = ?, duration_seconds = ?, cracked = ?, password = ?, notes = ?
                   WHERE id = ?""",
                (
                    session.status, session.progress, session.speed,
                    session.tried, session.total,
                    session.end_time.isoformat() if session.end_time else None,
                    session.duration_seconds, int(session.cracked),
                    session.password, session.notes, session.id,
                ),
            )
            self.conn.commit()
            return session
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to update session: {e}", details=str(e))

    def update_progress(self, session_id: str, progress: float, speed: int, tried: int, total: int) -> bool:
        """Update session progress."""
        try:
            cursor = self.conn.execute(
                """UPDATE cracking_sessions SET
                   progress = ?, speed = ?, tried = ?, total = ?
                   WHERE id = ?""",
                (progress, speed, tried, total, session_id),
            )
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to update session progress: {e}", details=str(e))

    def mark_cracked(self, session_id: str, password: str) -> bool:
        """Mark a session as successfully cracked."""
        try:
            now = datetime.utcnow().isoformat()
            cursor = self.conn.execute(
                """UPDATE cracking_sessions SET
                   status = 'completed', cracked = 1, password = ?,
                   progress = 1.0, end_time = ?
                   WHERE id = ?""",
                (password, now, session_id),
            )
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to mark session as cracked: {e}", details=str(e))

    def mark_failed(self, session_id: str) -> bool:
        """Mark a session as completed without cracking."""
        try:
            now = datetime.utcnow().isoformat()
            cursor = self.conn.execute(
                """UPDATE cracking_sessions SET
                   status = 'completed', cracked = 0, progress = 1.0, end_time = ?
                   WHERE id = ?""",
                (now, session_id),
            )
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to mark session as failed: {e}", details=str(e))

    def stop(self, session_id: str) -> bool:
        """Stop a running session."""
        try:
            now = datetime.utcnow().isoformat()
            cursor = self.conn.execute(
                "UPDATE cracking_sessions SET status = 'stopped', end_time = ? WHERE id = ?",
                (now, session_id),
            )
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to stop session: {e}", details=str(e))

    def delete(self, session_id: str) -> bool:
        """Delete a session by ID."""
        try:
            cursor = self.conn.execute("DELETE FROM cracking_sessions WHERE id = ?", (session_id,))
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to delete session: {e}", details=str(e))

    def count(self) -> int:
        """Return total number of sessions."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM cracking_sessions")
        return cursor.fetchone()[0]

    def count_by_status(self) -> Dict[str, int]:
        """Return session counts grouped by status."""
        cursor = self.execute("SELECT status, COUNT(*) FROM cracking_sessions GROUP BY status")
        return dict(cursor.fetchall())

    def stats(self) -> Dict:
        """Get aggregate session statistics."""
        total = self.count()
        cursor = self.conn.execute("SELECT COUNT(*) FROM cracking_sessions WHERE cracked = 1")
        cracked = cursor.fetchone()[0]
        cursor = self.conn.execute("SELECT AVG(duration_seconds) FROM cracking_sessions WHERE cracked = 1")
        avg_time = cursor.fetchone()[0] or 0
        cursor = self.conn.execute("SELECT AVG(speed) FROM cracking_sessions WHERE status = 'completed'")
        avg_speed = cursor.fetchone()[0] or 0
        return {
            "total_sessions": total,
            "cracked": cracked,
            "failed": total - cracked,
            "success_rate": round(cracked / total * 100, 1) if total > 0 else 0,
            "avg_crack_time_seconds": round(avg_time, 2),
            "avg_speed_hps": round(avg_speed, 0),
        }

    @staticmethod
    def _row_to_session(row: sqlite3.Row) -> CrackingSession:
        """Convert a database row to a CrackingSession instance."""
        data = dict(row)
        for dt_field in ("start_time", "end_time"):
            if dt_field in data and data[dt_field] and isinstance(data[dt_field], str):
                try:
                    data[dt_field] = datetime.fromisoformat(data[dt_field])
                except (ValueError, TypeError):
                    pass
        for bool_field in ("cracked", "gpu_used"):
            if bool_field in data:
                data[bool_field] = bool(data[bool_field])
        return CrackingSession(**{k: v for k, v in data.items() if k in CrackingSession.__dataclass_fields__})
