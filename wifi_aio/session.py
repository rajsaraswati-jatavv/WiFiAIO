"""Session management for WiFiAIO."""

import json
import logging
import os
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from wifi_aio.database import Database
from wifi_aio.exceptions import WiFiAIOError

logger = logging.getLogger(__name__)


class Session:
    """Represents an operational session."""

    def __init__(
        self,
        name: str,
        session_id: Optional[str] = None,
        created_at: Optional[str] = None,
    ):
        self.session_id = session_id or str(uuid.uuid4())
        self.name = name
        self.created_at = created_at or datetime.now().isoformat()
        self.updated_at = self.created_at
        self.data: Dict[str, Any] = {
            "networks": [],
            "captures": [],
            "cracked": [],
            "vulnerabilities": [],
            "notes": "",
            "statistics": {
                "total_networks": 0,
                "total_captures": 0,
                "total_cracked": 0,
                "total_vulns": 0,
                "deauth_frames_sent": 0,
                "scan_count": 0,
            },
        }
        self._start_time = time.time()

    @property
    def duration(self) -> float:
        """Session duration in seconds."""
        return time.time() - self._start_time

    def add_network(self, network: Dict) -> None:
        """Add a scanned network to the session."""
        # Avoid duplicates by BSSID
        bssid = network.get("bssid")
        if bssid and any(n.get("bssid") == bssid for n in self.data["networks"]):
            # Update existing entry
            for i, n in enumerate(self.data["networks"]):
                if n.get("bssid") == bssid:
                    self.data["networks"][i].update(network)
                    break
        else:
            self.data["networks"].append(network)
        self.data["statistics"]["total_networks"] = len(self.data["networks"])
        self._touch()

    def add_capture(self, capture: Dict) -> None:
        """Add a capture result to the session."""
        self.data["captures"].append(capture)
        self.data["statistics"]["total_captures"] = len(self.data["captures"])
        self._touch()

    def add_cracked(self, cracked: Dict) -> None:
        """Add a cracked password result to the session."""
        self.data["cracked"].append(cracked)
        self.data["statistics"]["total_cracked"] = len(self.data["cracked"])
        self._touch()

    def add_vulnerability(self, vuln: Dict) -> None:
        """Add a found vulnerability to the session."""
        self.data["vulnerabilities"].append(vuln)
        self.data["statistics"]["total_vulns"] = len(self.data["vulnerabilities"])
        self._touch()

    def increment_stat(self, key: str, amount: int = 1) -> None:
        """Increment a session statistic counter."""
        if key in self.data["statistics"]:
            self.data["statistics"][key] += amount
        else:
            self.data["statistics"][key] = amount
        self._touch()

    def set_notes(self, notes: str) -> None:
        """Set session notes."""
        self.data["notes"] = notes
        self._touch()

    def _touch(self) -> None:
        """Update the updated_at timestamp."""
        self.updated_at = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        return {
            "session_id": self.session_id,
            "name": self.name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "duration": self.duration,
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Session":
        """Reconstruct a Session from a dict."""
        session = cls(
            name=data.get("name", "unnamed"),
            session_id=data.get("session_id"),
            created_at=data.get("created_at"),
        )
        session.updated_at = data.get("updated_at", session.created_at)
        session.data = data.get("data", session.data)
        return session


class SessionManager:
    """Create, load, save, and manage WiFiAIO sessions."""

    def __init__(self, session_dir: Optional[str] = None, database: Optional[Database] = None):
        self.session_dir = Path(
            os.path.expanduser(session_dir or "~/.config/wifi_aio/sessions")
        )
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.database = database or Database()
        self._current: Optional[Session] = None

    # ── Session Lifecycle ─────────────────────────────────────────────

    def create(self, name: str) -> Session:
        """Create a new session and set it as current.

        Args:
            name: Session name.

        Returns:
            The new Session object.
        """
        session = Session(name=name)
        self._current = session
        self._persist(session)
        logger.info("Created session '%s' (%s)", name, session.session_id)
        return session

    def load(self, session_id: str) -> Session:
        """Load an existing session by ID and set it as current.

        Args:
            session_id: Session UUID.

        Returns:
            The loaded Session object.

        Raises:
            WiFiAIOError: If the session is not found.
        """
        filepath = self.session_dir / f"{session_id}.json"
        if not filepath.exists():
            # Try loading from database
            row = self.database.fetchone("sessions", "name = ?", (session_id,))
            if row and row.get("data"):
                session = Session.from_dict(json.loads(row["data"]))
                self._current = session
                return session
            raise WiFiAIOError(f"Session '{session_id}' not found")

        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        session = Session.from_dict(data)
        self._current = session
        logger.info("Loaded session '%s' (%s)", session.name, session.session_id)
        return session

    def save(self) -> None:
        """Save the current session to disk and database."""
        if self._current is None:
            return
        self._current._touch()
        self._persist(self._current)

    def close(self) -> Optional[Dict]:
        """Close the current session, save it, and return its summary.

        Returns:
            Session summary dict, or None if no session is active.
        """
        if self._current is None:
            return None

        self.save()
        summary = self._current.to_dict()
        logger.info(
            "Closed session '%s' (%s), duration: %.1fs",
            self._current.name,
            self._current.session_id,
            self._current.duration,
        )
        self._current = None
        return summary

    # ── Current Session Access ────────────────────────────────────────

    @property
    def current(self) -> Optional[Session]:
        """The currently active session."""
        return self._current

    def is_active(self) -> bool:
        """Check if there's an active session."""
        return self._current is not None

    def require_session(self) -> Session:
        """Return the current session, raising an error if none is active."""
        if self._current is None:
            raise WiFiAIOError("No active session. Create one first.")
        return self._current

    # ── Session Listing ───────────────────────────────────────────────

    def list_sessions(self) -> List[Dict]:
        """List all saved sessions with basic info."""
        sessions = []
        for filepath in sorted(self.session_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                sessions.append({
                    "session_id": data.get("session_id", ""),
                    "name": data.get("name", ""),
                    "created_at": data.get("created_at", ""),
                    "updated_at": data.get("updated_at", ""),
                    "networks": len(data.get("data", {}).get("networks", [])),
                    "captures": len(data.get("data", {}).get("captures", [])),
                    "cracked": len(data.get("data", {}).get("cracked", [])),
                })
            except (json.JSONDecodeError, OSError):
                continue
        return sessions

    def delete_session(self, session_id: str) -> bool:
        """Delete a saved session.

        Returns:
            True if the session was found and deleted.
        """
        filepath = self.session_dir / f"{session_id}.json"
        if filepath.exists():
            filepath.unlink()
            logger.info("Deleted session %s", session_id)
            return True

        # Try database
        count = self.database.delete("sessions", "name = ?", (session_id,))
        if count > 0:
            logger.info("Deleted session %s from database", session_id)
            return True

        return False

    def export_session(self, session_id: str, format: str = "json",
                       output_path: Optional[str] = None) -> str:
        """Export a session to JSON, CSV, or HTML.

        Returns:
            Path to the exported file.
        """
        session = self.load(session_id)
        from wifi_aio.export_engine import ExportEngine
        engine = ExportEngine()
        return engine.export(
            data=session.to_dict(),
            format=format,
            filename=f"session_{session.name}_{session.session_id[:8]}",
            title=f"WiFiAIO Session: {session.name}",
        )

    # ── Persistence ───────────────────────────────────────────────────

    def _persist(self, session: Session) -> None:
        """Save session to JSON file and database."""
        data = session.to_dict()

        # JSON file
        filepath = self.session_dir / f"{session.session_id}.json"
        try:
            tmp = filepath.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, default=str, ensure_ascii=False)
            tmp.replace(filepath)
        except OSError as exc:
            logger.error("Failed to save session file: %s", exc)

        # Database
        try:
            existing = self.database.fetchone("sessions", "name = ?", (session.session_id,))
            if existing:
                self.database.update(
                    "sessions",
                    {"updated_at": session.updated_at, "data": json.dumps(data, default=str)},
                    "name = ?",
                    (session.session_id,),
                )
            else:
                self.database.insert("sessions", {
                    "name": session.session_id,
                    "created_at": session.created_at,
                    "updated_at": session.updated_at,
                    "data": json.dumps(data, default=str),
                })
        except Exception as exc:
            logger.error("Failed to save session to database: %s", exc)
