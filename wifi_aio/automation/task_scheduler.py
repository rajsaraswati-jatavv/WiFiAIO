"""Task scheduler with cron-like recurring scheduling.

Provides a lightweight, in-process scheduler that evaluates cron
expressions and runs callbacks on their schedule.
"""

from __future__ import annotations

import bisect
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from wifi_aio.exceptions import AutomationError, WiFiTimeoutError

logger = logging.getLogger(__name__)


class TaskState(Enum):
    """State of a scheduled task."""
    ACTIVE = "active"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    COMPLETED = "completed"


@dataclass
class CronExpression:
    """Simplified cron expression parser (minute hour day month weekday).

    Each field accepts:
      - ``*``  (match any)
      - ``int``  (exact match)
      - ``int-int``  (range, inclusive)
      - ``int,int``  (list of values)
      - ``*/int``  (step)

    Example::

        # Every weekday at 09:30
        cron = CronExpression(minute=30, hour=9, weekday="1-5")
    """

    minute: str = "*"
    hour: str = "*"
    day: str = "*"
    month: str = "*"
    weekday: str = "*"

    _FIELD_RANGES: dict[str, tuple[int, int]] = field(
        default_factory=lambda: {
            "minute": (0, 59),
            "hour": (0, 23),
            "day": (1, 31),
            "month": (1, 12),
            "weekday": (0, 6),
        },
        repr=False,
    )

    def matches(self, dt: Optional[time.struct_time] = None) -> bool:
        """Return True if *dt* (default: now) satisfies this expression."""
        if dt is None:
            dt = time.localtime()

        checks = [
            self._field_matches(self.minute, dt.tm_min, "minute"),
            self._field_matches(self.hour, dt.tm_hour, "hour"),
            self._field_matches(self.day, dt.tm_mday, "day"),
            self._field_matches(self.month, dt.tm_mon, "month"),
            self._field_matches(self.weekday, dt.tm_wday, "weekday"),
        ]
        return all(checks)

    def next_run(self, after: Optional[float] = None) -> float:
        """Return the epoch timestamp of the next matching time.

        Searches minute-by-minute for up to ~1 year (525 600 minutes).
        """
        start = after if after is not None else time.time()
        ts = start - (start % 60) + 60  # round up to next minute
        limit = start + 525_600 * 60  # ~1 year
        while ts < limit:
            dt = time.localtime(ts)
            if self.matches(dt):
                return ts
            ts += 60
        raise AutomationError("No matching time found within 1 year for cron expression")

    # ── Internal helpers ───────────────────────────────────────────────

    def _field_matches(self, expr: str, value: int, field_name: str) -> bool:
        if expr == "*":
            return True
        lo, hi = self._FIELD_RANGES[field_name]
        allowed = self._parse_field(expr, lo, hi)
        return value in allowed

    @staticmethod
    def _parse_field(expr: str, lo: int, hi: int) -> set[int]:
        values: set[int] = set()
        for part in expr.split(","):
            if "/" in part:
                base, step_s = part.split("/", 1)
                step = int(step_s)
                start = lo if base == "*" else int(base)
                for v in range(start, hi + 1, step):
                    values.add(v)
            elif "-" in part:
                a, b = part.split("-", 1)
                for v in range(int(a), int(b) + 1):
                    values.add(v)
            else:
                values.add(int(part))
        return values


@dataclass
class ScheduledTask:
    """A task managed by the scheduler.

    Attributes:
        task_id: Unique identifier.
        name: Human-readable name.
        callback: Callable to invoke.
        cron: Cron expression determining the schedule.
        state: Current task state.
        args: Positional arguments forwarded to *callback*.
        kwargs: Keyword arguments forwarded to *callback*.
        max_runs: Maximum executions (0 = unlimited).
        run_count: Number of times already executed.
        last_run: Epoch of last execution, or 0.
        next_run: Epoch of next scheduled execution, or 0.
        timeout: Maximum seconds per run (0 = no limit).
        on_error: Callback invoked with (task, exception) on failure.
    """

    task_id: str
    name: str
    callback: Callable[..., Any]
    cron: CronExpression
    state: TaskState = TaskState.ACTIVE
    args: tuple[Any, ...] = ()
    kwargs: dict[str, Any] = field(default_factory=dict)
    max_runs: int = 0
    run_count: int = 0
    last_run: float = 0.0
    next_run: float = 0.0
    timeout: float = 0.0
    on_error: Optional[Callable[["ScheduledTask", Exception], None]] = None


class TaskScheduler:
    """Schedule and execute recurring tasks with cron-like syntax.

    The scheduler runs a background daemon thread that evaluates task
    schedules every second.

    Example::

        scheduler = TaskScheduler()
        task = scheduler.schedule(
            name="daily_scan",
            callback=run_scan,
            cron=CronExpression(minute=0, hour=6),
        )
        scheduler.start()
        # ... later
        scheduler.stop()
    """

    def __init__(self, tick_interval: float = 1.0) -> None:
        self._tasks: dict[str, ScheduledTask] = {}
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._tick_interval = tick_interval
        self._running = False

    # ── Scheduling ─────────────────────────────────────────────────────

    def schedule(
        self,
        name: str,
        callback: Callable[..., Any],
        cron: Optional[CronExpression] = None,
        minute: str = "*",
        hour: str = "*",
        day: str = "*",
        month: str = "*",
        weekday: str = "*",
        args: Optional[tuple[Any, ...]] = None,
        kwargs: Optional[dict[str, Any]] = None,
        max_runs: int = 0,
        timeout: float = 0.0,
        on_error: Optional[Callable[[ScheduledTask, Exception], None]] = None,
    ) -> ScheduledTask:
        """Create and register a new scheduled task.

        Either pass a pre-built *cron* or individual field strings.
        """
        if cron is None:
            cron = CronExpression(
                minute=minute, hour=hour, day=day, month=month, weekday=weekday
            )

        task_id = str(uuid.uuid4())
        task = ScheduledTask(
            task_id=task_id,
            name=name,
            callback=callback,
            cron=cron,
            args=args or (),
            kwargs=kwargs or {},
            max_runs=max_runs,
            timeout=timeout,
            on_error=on_error,
            next_run=cron.next_run(),
        )

        with self._lock:
            self._tasks[task_id] = task

        logger.info("Scheduled task %s (%s) – next run at %s",
                     name, task_id, time.ctime(task.next_run))
        return task

    def cancel(self, task_id: str) -> None:
        """Cancel a scheduled task by its ID."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                raise AutomationError(f"Task not found: {task_id}")
            task.state = TaskState.CANCELLED
        logger.info("Cancelled task %s (%s)", task.name, task_id)

    def pause(self, task_id: str) -> None:
        """Pause a scheduled task."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                raise AutomationError(f"Task not found: {task_id}")
            task.state = TaskState.PAUSED
        logger.info("Paused task %s (%s)", task.name, task_id)

    def resume(self, task_id: str) -> None:
        """Resume a paused task."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                raise AutomationError(f"Task not found: {task_id}")
            if task.state != TaskState.PAUSED:
                raise AutomationError(f"Task {task_id} is not paused")
            task.state = TaskState.ACTIVE
            task.next_run = task.cron.next_run()
        logger.info("Resumed task %s (%s)", task.name, task_id)

    # ── Lifecycle ──────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the scheduler daemon thread."""
        if self._running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, name="TaskScheduler", daemon=True
        )
        self._thread.start()
        self._running = True
        logger.info("TaskScheduler started")

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the scheduler to stop and wait for the thread."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._running = False
        logger.info("TaskScheduler stopped")

    # ── Query ──────────────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._running

    def list_tasks(self) -> list[ScheduledTask]:
        """Return all tasks."""
        with self._lock:
            return list(self._tasks.values())

    def get_task(self, task_id: str) -> Optional[ScheduledTask]:
        """Look up a task by ID."""
        with self._lock:
            return self._tasks.get(task_id)

    # ── Main loop ──────────────────────────────────────────────────────

    def _loop(self) -> None:
        """Background loop that checks and fires tasks."""
        while not self._stop_event.is_set():
            now = time.time()
            with self._lock:
                tasks_snapshot = list(self._tasks.values())

            for task in tasks_snapshot:
                if task.state != TaskState.ACTIVE:
                    continue
                if task.max_runs > 0 and task.run_count >= task.max_runs:
                    task.state = TaskState.COMPLETED
                    continue
                if task.next_run <= now:
                    self._execute_task(task)

            self._stop_event.wait(self._tick_interval)

    def _execute_task(self, task: ScheduledTask) -> None:
        """Run a single task, updating its metadata."""
        logger.info("Executing task %s (%s)", task.name, task.task_id)
        try:
            if task.timeout > 0:
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(task.callback, *task.args, **task.kwargs)
                    try:
                        future.result(timeout=task.timeout)
                    except concurrent.futures.TimeoutError:
                        raise WiFiTimeoutError(
                            f"Task {task.name} timed out after {task.timeout}s",
                            details="task_scheduler_timeout",
                        )
            else:
                task.callback(*task.args, **task.kwargs)

            task.run_count += 1
            task.last_run = time.time()
            task.next_run = task.cron.next_run(after=task.last_run)
            logger.info(
                "Task %s completed (run #%d) – next run at %s",
                task.name, task.run_count, time.ctime(task.next_run),
            )
        except Exception as exc:
            logger.error("Task %s failed: %s", task.name, exc)
            if task.on_error is not None:
                try:
                    task.on_error(task, exc)
                except Exception as handler_exc:
                    logger.error("Error handler for %s raised: %s", task.name, handler_exc)
            task.next_run = task.cron.next_run(after=time.time())

    def __repr__(self) -> str:
        return f"TaskScheduler(tasks={len(self._tasks)}, running={self._running})"
