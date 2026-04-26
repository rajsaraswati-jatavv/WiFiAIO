"""Script recorder for recording and replaying user operations.

Captures high-level actions (scan, capture, crack, etc.) and can
persist them to JSON for later replay or sharing.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from wifi_aio.exceptions import AutomationError, WiFiTimeoutError

logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of recordable actions."""
    SCAN = "scan"
    CAPTURE = "capture"
    CRACK = "crack"
    DEAUTH = "deauth"
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    MONITOR_START = "monitor_start"
    MONITOR_STOP = "monitor_stop"
    INTERFACE_CHANGE = "interface_change"
    CUSTOM = "custom"


@dataclass
class RecordedAction:
    """A single recorded user action.

    Attributes:
        action_id: Unique identifier.
        action_type: Category of the action.
        name: Human-readable label.
        timestamp: Epoch seconds when the action was recorded.
        params: Parameters supplied to the action.
        result: Optional snapshot of the action's result.
        duration: How long the original action took (seconds).
        tags: Free-form tags for filtering.
    """

    action_id: str
    action_type: ActionType
    name: str
    timestamp: float
    params: dict[str, Any] = field(default_factory=dict)
    result: Optional[Any] = None
    duration: float = 0.0
    tags: list[str] = field(default_factory=list)


@dataclass
class RecordedScript:
    """A sequence of recorded actions forming a script.

    Attributes:
        script_id: Unique identifier.
        name: Script name.
        description: Optional description.
        created_at: Epoch creation time.
        actions: Ordered list of recorded actions.
        metadata: Arbitrary extra data.
    """

    script_id: str
    name: str
    description: str = ""
    created_at: float = 0.0
    actions: list[RecordedAction] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class ScriptRecorder:
    """Record and replay user operations.

    Supports:
      - Start / stop recording sessions.
      - Add actions manually or via decorator.
      - Persist recordings to JSON files.
      - Load recordings and replay them with configurable delays.

    Example::

        recorder = ScriptRecorder()
        recorder.start_recording("my_session")
        recorder.record_action(ActionType.SCAN, "scan_wifi", params={"interface": "wlan0"})
        recorder.stop_recording()
        recorder.save("my_session.json")

        # Later
        recorder.load("my_session.json")
        recorder.replay("my_session")
    """

    def __init__(self) -> None:
        self._recordings: dict[str, RecordedScript] = {}
        self._active: Optional[str] = None
        self._replay_callbacks: dict[ActionType, Callable[..., Any]] = {}
        self._action_start_time: float = 0.0

    # ── Recording lifecycle ────────────────────────────────────────────

    def start_recording(
        self,
        name: str,
        description: str = "",
        metadata: Optional[dict[str, Any]] = None,
    ) -> str:
        """Begin a new recording session.

        Returns:
            The recording name (acts as session key).
        """
        if self._active is not None:
            raise AutomationError(
                f"Already recording: {self._active}. Stop it first."
            )
        script = RecordedScript(
            script_id=str(uuid.uuid4()),
            name=name,
            description=description,
            created_at=time.time(),
            metadata=metadata or {},
        )
        self._recordings[name] = script
        self._active = name
        logger.info("Started recording: %s", name)
        return name

    def stop_recording(self) -> RecordedScript:
        """Stop the active recording and return the script."""
        if self._active is None:
            raise AutomationError("No active recording to stop")
        name = self._active
        self._active = None
        logger.info(
            "Stopped recording: %s (%d actions)",
            name, len(self._recordings[name].actions),
        )
        return self._recordings[name]

    @property
    def is_recording(self) -> bool:
        return self._active is not None

    @property
    def active_recording(self) -> Optional[str]:
        return self._active

    # ── Action recording ───────────────────────────────────────────────

    def record_action(
        self,
        action_type: ActionType,
        name: str,
        params: Optional[dict[str, Any]] = None,
        result: Optional[Any] = None,
        duration: float = 0.0,
        tags: Optional[list[str]] = None,
    ) -> RecordedAction:
        """Record an action into the active session.

        Must be called between ``start_recording`` and ``stop_recording``.
        """
        if self._active is None:
            raise AutomationError("No active recording session")

        action = RecordedAction(
            action_id=str(uuid.uuid4()),
            action_type=action_type,
            name=name,
            timestamp=time.time(),
            params=params or {},
            result=result,
            duration=duration,
            tags=tags or [],
        )
        self._recordings[self._active].actions.append(action)
        logger.debug("Recorded action: %s (%s)", name, action_type.value)
        return action

    def begin_action(self, action_type: ActionType, name: str,
                     params: Optional[dict[str, Any]] = None,
                     tags: Optional[list[str]] = None) -> None:
        """Mark the start of a timed action. Call ``end_action`` to finish."""
        if self._active is None:
            raise AutomationError("No active recording session")
        self._pending_action = {
            "action_type": action_type,
            "name": name,
            "params": params or {},
            "tags": tags or [],
        }
        self._action_start_time = time.time()

    def end_action(self, result: Optional[Any] = None) -> RecordedAction:
        """Finish the timed action started with ``begin_action``."""
        if self._active is None:
            raise AutomationError("No active recording session")
        if not hasattr(self, "_pending_action") or self._pending_action is None:
            raise AutomationError("No pending action to end")
        duration = time.time() - self._action_start_time
        pending = self._pending_action
        action = self.record_action(
            action_type=pending["action_type"],
            name=pending["name"],
            params=pending["params"],
            result=result,
            duration=duration,
            tags=pending["tags"],
        )
        self._pending_action = None
        return action

    def action_decorator(
        self, action_type: ActionType, name: str,
        params: Optional[dict[str, Any]] = None,
        tags: Optional[list[str]] = None,
    ) -> Callable[..., Any]:
        """Decorator that records a function call as an action.

        Example::

            @recorder.action_decorator(ActionType.SCAN, "my_scan")
            def do_scan(iface):
                ...
        """
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                if self._active is None:
                    return func(*args, **kwargs)
                start = time.time()
                try:
                    ret = func(*args, **kwargs)
                    duration = time.time() - start
                    merged_params = {**(params or {}), "args": args, "kwargs": kwargs}
                    self.record_action(
                        action_type, name, params=merged_params,
                        result=ret, duration=duration, tags=tags,
                    )
                    return ret
                except Exception as exc:
                    duration = time.time() - start
                    merged_params = {**(params or {}), "args": args, "kwargs": kwargs}
                    self.record_action(
                        action_type, name, params=merged_params,
                        result={"error": str(exc)}, duration=duration, tags=tags,
                    )
                    raise
            return wrapper
        return decorator

    # ── Replay ─────────────────────────────────────────────────────────

    def register_replay_handler(
        self, action_type: ActionType, callback: Callable[..., Any]
    ) -> None:
        """Register a callback for replaying actions of a given type.

        The callback receives the RecordedAction as its sole argument.
        """
        self._replay_callbacks[action_type] = callback

    def replay(
        self,
        name: str,
        delay: float = 0.0,
        speed: float = 1.0,
        action_filter: Optional[Callable[[RecordedAction], bool]] = None,
        on_error: str = "continue",
        timeout: float = 0.0,
    ) -> list[tuple[RecordedAction, Optional[Exception]]]:
        """Replay a recorded script.

        Args:
            name: Name of the recording to replay.
            delay: Extra seconds to wait before each action.
            speed: Playback speed multiplier (1.0 = real-time, 2.0 = double).
            action_filter: Optional predicate; only matching actions are replayed.
            on_error: ``"continue"`` or ``"stop"``.
            timeout: Per-action timeout in seconds (0 = no limit).

        Returns:
            List of (action, exception_or_None) tuples.
        """
        script = self._recordings.get(name)
        if script is None:
            raise AutomationError(f"Recording not found: {name}")

        results: list[tuple[RecordedAction, Optional[Exception]]] = []

        for i, action in enumerate(script.actions):
            if action_filter and not action_filter(action):
                continue

            handler = self._replay_callbacks.get(action.action_type)
            if handler is None:
                logger.warning(
                    "No replay handler for action type %s – skipping %s",
                    action.action_type.value, action.name,
                )
                results.append((action, AutomationError(
                    f"No handler for {action.action_type.value}"
                )))
                if on_error == "stop":
                    break
                continue

            # Delay before execution
            if delay > 0:
                time.sleep(delay)

            # Simulate original timing
            if speed > 0 and action.duration > 0 and i > 0:
                original_delay = action.duration / speed
                if original_delay > 0.01:
                    time.sleep(min(original_delay, 60.0))  # cap at 60s

            try:
                if timeout > 0:
                    self._replay_with_timeout(handler, action, timeout)
                else:
                    handler(action)
                results.append((action, None))
            except Exception as exc:
                logger.error("Replay failed for %s: %s", action.name, exc)
                results.append((action, exc))
                if on_error == "stop":
                    break

        return results

    @staticmethod
    def _replay_with_timeout(
        handler: Callable[..., Any], action: RecordedAction, timeout: float
    ) -> None:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(handler, action)
            try:
                future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                raise WiFiTimeoutError(
                    f"Replay of {action.name} timed out after {timeout}s",
                    details="script_recorder_replay_timeout",
                )

    # ── Persistence ────────────────────────────────────────────────────

    def save(self, name: str, filepath: Optional[str | Path] = None) -> Path:
        """Persist a recording to a JSON file.

        Args:
            name: Recording name.
            filepath: Destination path. Defaults to ``<name>.json``.

        Returns:
            The Path the file was written to.
        """
        script = self._recordings.get(name)
        if script is None:
            raise AutomationError(f"Recording not found: {name}")

        dest = Path(filepath) if filepath else Path(f"{name}.json")

        data = {
            "script_id": script.script_id,
            "name": script.name,
            "description": script.description,
            "created_at": script.created_at,
            "metadata": script.metadata,
            "actions": [
                {
                    "action_id": a.action_id,
                    "action_type": a.action_type.value,
                    "name": a.name,
                    "timestamp": a.timestamp,
                    "params": a.params,
                    "result": a.result,
                    "duration": a.duration,
                    "tags": a.tags,
                }
                for a in script.actions
            ],
        }

        dest.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        logger.info("Saved recording %s to %s", name, dest)
        return dest

    def load(self, filepath: str | Path) -> str:
        """Load a recording from a JSON file.

        Returns:
            The recording name (key in internal dict).
        """
        src = Path(filepath)
        if not src.is_file():
            raise AutomationError(f"File not found: {src}")

        data = json.loads(src.read_text(encoding="utf-8"))

        actions: list[RecordedAction] = []
        for a_data in data.get("actions", []):
            actions.append(RecordedAction(
                action_id=a_data["action_id"],
                action_type=ActionType(a_data["action_type"]),
                name=a_data["name"],
                timestamp=a_data["timestamp"],
                params=a_data.get("params", {}),
                result=a_data.get("result"),
                duration=a_data.get("duration", 0.0),
                tags=a_data.get("tags", []),
            ))

        script = RecordedScript(
            script_id=data.get("script_id", str(uuid.uuid4())),
            name=data["name"],
            description=data.get("description", ""),
            created_at=data.get("created_at", 0.0),
            actions=actions,
            metadata=data.get("metadata", {}),
        )
        self._recordings[script.name] = script
        logger.info("Loaded recording %s (%d actions) from %s",
                     script.name, len(actions), src)
        return script.name

    # ── Query ──────────────────────────────────────────────────────────

    def list_recordings(self) -> list[str]:
        """Return names of all stored recordings."""
        return list(self._recordings.keys())

    def get_recording(self, name: str) -> Optional[RecordedScript]:
        """Look up a recording by name."""
        return self._recordings.get(name)

    def delete_recording(self, name: str) -> None:
        """Remove a recording from memory."""
        if name not in self._recordings:
            raise AutomationError(f"Recording not found: {name}")
        if self._active == name:
            raise AutomationError("Cannot delete the active recording")
        del self._recordings[name]

    def __repr__(self) -> str:
        return (
            f"ScriptRecorder(recordings={len(self._recordings)}, "
            f"recording={self._active!r})"
        )
