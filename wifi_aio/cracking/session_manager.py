"""Cracking session save/resume management.

Saves the state of a cracking session (progress, configuration,
found passwords) to disk so it can be resumed after interruption.
Supports multiple concurrent sessions and automatic checkpointing.
"""

import json
import os
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from wifi_aio.exceptions import CrackingError


# ── Session file format version ────────────────────────────────────────

SESSION_VERSION = 2
SESSIONS_DIR = os.path.join("/tmp", "wifiaio", "sessions")


class CrackingSession:
    """Represents a single cracking session's state."""

    def __init__(
        self,
        session_id: Optional[str] = None,
        name: str = "",
        handshake: Optional[Dict] = None,
        engine: str = "python",
        attack_type: str = "dictionary",
        config: Optional[Dict] = None,
    ) -> None:
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.name = name or f"session-{self.session_id}"
        self.handshake = handshake or {}
        self.engine = engine
        self.attack_type = attack_type
        self.config = config or {}

        self.created_at = time.time()
        self.updated_at = time.time()
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None

        # Progress
        self.tested = 0
        self.total_candidates = 0
        self.found_password: Optional[str] = None
        self.last_password = ""
        self.last_wordlist_line = 0
        self.last_mask_index = 0

        # Status
        self.status = "created"  # created, running, paused, completed, failed
        self.error_message = ""

        # Checkpoints
        self.checkpoints: List[Dict] = []

    @property
    def progress(self) -> float:
        """Progress as a fraction (0.0–1.0)."""
        if self.total_candidates <= 0:
            return 0.0
        return min(1.0, self.tested / self.total_candidates)

    @property
    def progress_percent(self) -> float:
        return self.progress * 100.0

    @property
    def elapsed(self) -> float:
        """Elapsed time in seconds."""
        if self.started_at is None:
            return 0.0
        end = self.finished_at or time.time()
        return end - self.started_at

    @property
    def speed(self) -> float:
        """Passwords tested per second."""
        e = self.elapsed
        return self.tested / e if e > 0 else 0.0

    @property
    def eta(self) -> float:
        """Estimated time remaining in seconds."""
        if self.speed <= 0 or self.total_candidates <= 0:
            return float("inf")
        remaining = self.total_candidates - self.tested
        return remaining / self.speed

    def to_dict(self) -> Dict:
        """Serialize the session to a dictionary."""
        return {
            "version": SESSION_VERSION,
            "session_id": self.session_id,
            "name": self.name,
            "handshake": self.handshake,
            "engine": self.engine,
            "attack_type": self.attack_type,
            "config": self.config,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "tested": self.tested,
            "total_candidates": self.total_candidates,
            "found_password": self.found_password,
            "last_password": self.last_password,
            "last_wordlist_line": self.last_wordlist_line,
            "last_mask_index": self.last_mask_index,
            "status": self.status,
            "error_message": self.error_message,
            "checkpoints": self.checkpoints,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "CrackingSession":
        """Deserialize a session from a dictionary."""
        session = cls(
            session_id=data.get("session_id"),
            name=data.get("name", ""),
            handshake=data.get("handshake", {}),
            engine=data.get("engine", "python"),
            attack_type=data.get("attack_type", "dictionary"),
            config=data.get("config", {}),
        )
        session.created_at = data.get("created_at", time.time())
        session.updated_at = data.get("updated_at", time.time())
        session.started_at = data.get("started_at")
        session.finished_at = data.get("finished_at")
        session.tested = data.get("tested", 0)
        session.total_candidates = data.get("total_candidates", 0)
        session.found_password = data.get("found_password")
        session.last_password = data.get("last_password", "")
        session.last_wordlist_line = data.get("last_wordlist_line", 0)
        session.last_mask_index = data.get("last_mask_index", 0)
        session.status = data.get("status", "created")
        session.error_message = data.get("error_message", "")
        session.checkpoints = data.get("checkpoints", [])
        return session

    def create_checkpoint(self, label: str = "") -> Dict:
        """Create a checkpoint of the current state."""
        checkpoint = {
            "timestamp": time.time(),
            "label": label or f"checkpoint-{len(self.checkpoints)}",
            "tested": self.tested,
            "last_password": self.last_password,
            "last_wordlist_line": self.last_wordlist_line,
            "last_mask_index": self.last_mask_index,
            "status": self.status,
        }
        self.checkpoints.append(checkpoint)
        self.updated_at = time.time()
        return checkpoint

    def restore_checkpoint(self, index: int = -1) -> None:
        """Restore state from a checkpoint."""
        if not self.checkpoints:
            return

        cp = self.checkpoints[index]
        self.tested = cp.get("tested", 0)
        self.last_password = cp.get("last_password", "")
        self.last_wordlist_line = cp.get("last_wordlist_line", 0)
        self.last_mask_index = cp.get("last_mask_index", 0)
        self.status = cp.get("status", "paused")
        self.updated_at = time.time()


class CrackingSessionManager:
    """Manage cracking session persistence (save, load, list, resume).

    Sessions are stored as JSON files in a configurable directory.

    Parameters
    ----------
    sessions_dir:
        Directory for session files.
    auto_checkpoint_interval:
        Automatically create a checkpoint every N seconds (0 = disabled).
    """

    def __init__(
        self,
        sessions_dir: str = SESSIONS_DIR,
        auto_checkpoint_interval: float = 0,
    ) -> None:
        self.sessions_dir = sessions_dir
        self.auto_checkpoint_interval = auto_checkpoint_interval

        self._active_sessions: Dict[str, CrackingSession] = {}
        self._last_checkpoint_time: Dict[str, float] = {}

        # Ensure sessions directory exists
        os.makedirs(self.sessions_dir, exist_ok=True)

    # ── Session lifecycle ──────────────────────────────────────────────

    def create_session(
        self,
        handshake: Dict,
        engine: str = "python",
        attack_type: str = "dictionary",
        name: str = "",
        config: Optional[Dict] = None,
    ) -> CrackingSession:
        """Create a new cracking session."""
        session = CrackingSession(
            name=name,
            handshake=handshake,
            engine=engine,
            attack_type=attack_type,
            config=config or {},
        )
        session.status = "created"
        self._active_sessions[session.session_id] = session
        self.save(session)
        return session

    def save(self, session: CrackingSession) -> None:
        """Save a session to disk."""
        session.updated_at = time.time()
        path = self._session_path(session.session_id)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(session.to_dict(), fh, indent=2, default=str)

    def load(self, session_id: str) -> CrackingSession:
        """Load a session from disk."""
        path = self._session_path(session_id)
        if not os.path.isfile(path):
            raise CrackingError(f"Session not found: {session_id}")

        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        session = CrackingSession.from_dict(data)
        self._active_sessions[session.session_id] = session
        return session

    def delete(self, session_id: str) -> None:
        """Delete a session file."""
        path = self._session_path(session_id)
        if os.path.isfile(path):
            os.unlink(path)
        self._active_sessions.pop(session_id, None)

    def list_sessions(self) -> List[Dict]:
        """List all saved sessions with summary info."""
        sessions = []
        for filename in os.listdir(self.sessions_dir):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(self.sessions_dir, filename)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                sessions.append({
                    "session_id": data.get("session_id", ""),
                    "name": data.get("name", ""),
                    "attack_type": data.get("attack_type", ""),
                    "engine": data.get("engine", ""),
                    "status": data.get("status", ""),
                    "tested": data.get("tested", 0),
                    "total_candidates": data.get("total_candidates", 0),
                    "progress": round(data.get("tested", 0) / max(data.get("total_candidates", 1), 1) * 100, 1),
                    "found_password": data.get("found_password"),
                    "created_at": data.get("created_at", 0),
                    "updated_at": data.get("updated_at", 0),
                })
            except (json.JSONDecodeError, OSError):
                continue
        return sorted(sessions, key=lambda s: s.get("updated_at", 0), reverse=True)

    # ── Session state management ───────────────────────────────────────

    def start_session(self, session_id: str) -> None:
        """Mark a session as running."""
        session = self._get_session(session_id)
        session.started_at = time.time()
        session.status = "running"
        self._last_checkpoint_time[session_id] = time.time()
        self.save(session)

    def pause_session(self, session_id: str) -> None:
        """Pause a running session and create a checkpoint."""
        session = self._get_session(session_id)
        session.status = "paused"
        session.create_checkpoint("pause")
        self.save(session)

    def resume_session(self, session_id: str) -> CrackingSession:
        """Load and prepare a session for resumption."""
        session = self.load(session_id)

        if session.status not in ("paused", "created", "failed"):
            raise CrackingError(
                f"Cannot resume session in state: {session.status}"
            )

        session.status = "running"
        self._last_checkpoint_time[session_id] = time.time()
        self.save(session)
        return session

    def complete_session(
        self,
        session_id: str,
        found_password: Optional[str] = None,
    ) -> None:
        """Mark a session as completed."""
        session = self._get_session(session_id)
        session.status = "completed"
        session.finished_at = time.time()
        session.found_password = found_password
        session.create_checkpoint("completion")
        self.save(session)

    def fail_session(self, session_id: str, error: str = "") -> None:
        """Mark a session as failed."""
        session = self._get_session(session_id)
        session.status = "failed"
        session.error_message = error
        session.finished_at = time.time()
        session.create_checkpoint("failure")
        self.save(session)

    def update_progress(
        self,
        session_id: str,
        tested: int,
        last_password: str = "",
        last_wordlist_line: Optional[int] = None,
        last_mask_index: Optional[int] = None,
    ) -> None:
        """Update a session's progress and auto-checkpoint if needed."""
        session = self._get_session(session_id)
        session.tested = tested
        session.last_password = last_password

        if last_wordlist_line is not None:
            session.last_wordlist_line = last_wordlist_line
        if last_mask_index is not None:
            session.last_mask_index = last_mask_index

        # Auto-checkpoint
        if self.auto_checkpoint_interval > 0:
            last_cp = self._last_checkpoint_time.get(session_id, 0)
            if time.time() - last_cp >= self.auto_checkpoint_interval:
                session.create_checkpoint("auto")
                self._last_checkpoint_time[session_id] = time.time()

        self.save(session)

    def get_session(self, session_id: str) -> CrackingSession:
        """Get a session, loading from disk if needed."""
        return self._get_session(session_id)

    # ── Cleanup ────────────────────────────────────────────────────────

    def cleanup_old_sessions(self, max_age_days: int = 30) -> int:
        """Delete sessions older than *max_age_days*.

        Returns the number of sessions deleted.
        """
        cutoff = time.time() - (max_age_days * 86400)
        deleted = 0

        for filename in os.listdir(self.sessions_dir):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(self.sessions_dir, filename)
            try:
                mtime = os.path.getmtime(path)
                if mtime < cutoff:
                    os.unlink(path)
                    deleted += 1
            except OSError:
                continue

        return deleted

    def cleanup_completed_sessions(self) -> int:
        """Delete all completed sessions."""
        deleted = 0
        for filename in os.listdir(self.sessions_dir):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(self.sessions_dir, filename)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if data.get("status") == "completed":
                    os.unlink(path)
                    deleted += 1
            except (json.JSONDecodeError, OSError):
                continue
        return deleted

    # ── Internals ──────────────────────────────────────────────────────

    def _session_path(self, session_id: str) -> str:
        """Return the file path for a session."""
        return os.path.join(self.sessions_dir, f"{session_id}.json")

    def _get_session(self, session_id: str) -> CrackingSession:
        """Get a session from cache or disk."""
        if session_id in self._active_sessions:
            return self._active_sessions[session_id]
        return self.load(session_id)
