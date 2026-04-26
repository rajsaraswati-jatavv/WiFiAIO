"""Task scheduler for WiFiAIO."""

import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class ScheduledTask:
    """Represents a scheduled task."""

    def __init__(
        self,
        name: str,
        func: Callable,
        interval: Optional[float] = None,
        run_at: Optional[datetime] = None,
        repeat: bool = False,
        args: tuple = (),
        kwargs: Optional[Dict] = None,
        enabled: bool = True,
    ):
        self.name = name
        self.func = func
        self.interval = interval  # seconds between runs (for repeating tasks)
        self.run_at = run_at      # specific datetime to run at (for one-shot tasks)
        self.repeat = repeat
        self.args = args
        self.kwargs = kwargs or {}
        self.enabled = enabled
        self.last_run: Optional[datetime] = None
        self.next_run: Optional[datetime] = None
        self.run_count: int = 0
        self.error_count: int = 0
        self.last_error: Optional[str] = None
        self.created_at: datetime = datetime.now()

        # Calculate initial next_run
        self._calculate_next_run()

    def _calculate_next_run(self) -> None:
        """Calculate when this task should next run."""
        if self.run_at:
            self.next_run = self.run_at
        elif self.interval and self.interval > 0:
            if self.last_run:
                self.next_run = self.last_run + timedelta(seconds=self.interval)
            else:
                self.next_run = datetime.now() + timedelta(seconds=self.interval)
        else:
            self.next_run = None

    def is_due(self) -> bool:
        """Check if this task is due to run."""
        if not self.enabled or self.next_run is None:
            return False
        return datetime.now() >= self.next_run

    def execute(self) -> Any:
        """Execute the task function."""
        if not self.enabled:
            return None

        try:
            result = self.func(*self.args, **self.kwargs)
            self.last_run = datetime.now()
            self.run_count += 1
            self.last_error = None

            if self.repeat and self.interval:
                self._calculate_next_run()
            elif self.run_at:
                # One-shot task; disable after execution
                self.next_run = None
                self.enabled = False

            return result
        except Exception as exc:
            self.error_count += 1
            self.last_error = str(exc)
            logger.error("Scheduled task '%s' failed: %s", self.name, exc)

            if self.repeat and self.interval:
                self._calculate_next_run()
            return None

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "interval": self.interval,
            "repeat": self.repeat,
            "enabled": self.enabled,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "created_at": self.created_at.isoformat(),
        }


class TaskScheduler:
    """Schedule and execute tasks at intervals or specific times."""

    def __init__(self):
        self._tasks: Dict[str, ScheduledTask] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._running = False

    # ── Scheduling ────────────────────────────────────────────────────

    def schedule_interval(
        self,
        name: str,
        func: Callable,
        interval: float,
        args: tuple = (),
        kwargs: Optional[Dict] = None,
        start_immediately: bool = False,
    ) -> ScheduledTask:
        """Schedule a task to run at a fixed interval.

        Args:
            name: Unique task name.
            func: Callable to execute.
            interval: Seconds between runs.
            args: Positional arguments for the callable.
            kwargs: Keyword arguments for the callable.
            start_immediately: If True, run the task immediately once.

        Returns:
            The ScheduledTask object.
        """
        with self._lock:
            if name in self._tasks:
                raise ValueError(f"Task '{name}' already exists")

            task = ScheduledTask(
                name=name,
                func=func,
                interval=interval,
                repeat=True,
                args=args,
                kwargs=kwargs,
            )
            if start_immediately:
                task.next_run = datetime.now()

            self._tasks[name] = task
            logger.info("Scheduled repeating task '%s' every %.1fs", name, interval)
            return task

    def schedule_once(
        self,
        name: str,
        func: Callable,
        delay: Optional[float] = None,
        run_at: Optional[datetime] = None,
        args: tuple = (),
        kwargs: Optional[Dict] = None,
    ) -> ScheduledTask:
        """Schedule a task to run once.

        Args:
            name: Unique task name.
            func: Callable to execute.
            delay: Seconds from now to run.
            run_at: Specific datetime to run at.
            args: Positional arguments.
            kwargs: Keyword arguments.

        Returns:
            The ScheduledTask object.
        """
        with self._lock:
            if name in self._tasks:
                raise ValueError(f"Task '{name}' already exists")

            if run_at is None and delay is not None:
                run_at = datetime.now() + timedelta(seconds=delay)

            task = ScheduledTask(
                name=name,
                func=func,
                run_at=run_at,
                repeat=False,
                args=args,
                kwargs=kwargs,
            )
            self._tasks[name] = task
            logger.info("Scheduled one-shot task '%s' at %s", name, run_at)
            return task

    def schedule_daily(
        self,
        name: str,
        func: Callable,
        hour: int,
        minute: int = 0,
        args: tuple = (),
        kwargs: Optional[Dict] = None,
    ) -> ScheduledTask:
        """Schedule a task to run daily at a specific time.

        Args:
            name: Unique task name.
            func: Callable to execute.
            hour: Hour (0-23).
            minute: Minute (0-59).
            args: Positional arguments.
            kwargs: Keyword arguments.

        Returns:
            The ScheduledTask object.
        """
        interval = 86400  # 24 hours
        now = datetime.now()
        target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)

        with self._lock:
            if name in self._tasks:
                raise ValueError(f"Task '{name}' already exists")

            task = ScheduledTask(
                name=name,
                func=func,
                interval=interval,
                repeat=True,
                args=args,
                kwargs=kwargs,
            )
            task.next_run = target
            self._tasks[name] = task
            logger.info("Scheduled daily task '%s' at %02d:%02d", name, hour, minute)
            return task

    # ── Task Management ───────────────────────────────────────────────

    def cancel(self, name: str) -> bool:
        """Cancel a scheduled task.

        Returns:
            True if the task was found and cancelled.
        """
        with self._lock:
            task = self._tasks.pop(name, None)
            if task:
                task.enabled = False
                logger.info("Cancelled task '%s'", name)
                return True
            return False

    def pause(self, name: str) -> bool:
        """Pause a scheduled task."""
        with self._lock:
            task = self._tasks.get(name)
            if task:
                task.enabled = False
                return True
            return False

    def resume(self, name: str) -> bool:
        """Resume a paused scheduled task."""
        with self._lock:
            task = self._tasks.get(name)
            if task:
                task.enabled = True
                task._calculate_next_run()
                return True
            return False

    def get_task(self, name: str) -> Optional[ScheduledTask]:
        """Get a task by name."""
        return self._tasks.get(name)

    def list_tasks(self) -> List[Dict]:
        """List all scheduled tasks as dicts."""
        return [t.to_dict() for t in self._tasks.values()]

    def run_task_now(self, name: str) -> Any:
        """Execute a scheduled task immediately, regardless of schedule."""
        with self._lock:
            task = self._tasks.get(name)
        if task is None:
            raise ValueError(f"Task '{name}' not found")
        return task.execute()

    # ── Scheduler Control ─────────────────────────────────────────────

    def start(self, poll_interval: float = 1.0) -> None:
        """Start the scheduler loop in a background thread.

        Args:
            poll_interval: Seconds between checks for due tasks.
        """
        if self._running:
            return

        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            args=(poll_interval,),
            daemon=True,
            name="WiFiAIO-Scheduler",
        )
        self._thread.start()
        logger.info("Task scheduler started")

    def stop(self) -> None:
        """Stop the scheduler loop."""
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("Task scheduler stopped")

    def is_running(self) -> bool:
        """Check if the scheduler is running."""
        return self._running

    def _run_loop(self, poll_interval: float) -> None:
        """Main scheduler loop."""
        while not self._stop_event.is_set():
            try:
                with self._lock:
                    tasks_to_run = [
                        task for task in self._tasks.values()
                        if task.is_due()
                    ]

                for task in tasks_to_run:
                    task.execute()

            except Exception as exc:
                logger.error("Scheduler loop error: %s", exc)

            self._stop_event.wait(poll_interval)

    # ── Convenience Schedules ─────────────────────────────────────────

    def schedule_scan(self, interface: str, interval: float = 300) -> ScheduledTask:
        """Schedule periodic network scanning."""
        from wifi_aio.utils import run_command

        def _do_scan():
            rc, stdout, stderr = run_command(
                ["airodump-ng", interface, "--output-format", "csv",
                 "-w", f"/tmp/wifi_aio_scheduled_scan_{int(time.time())}"],
                timeout=interval - 10,
            )
            return {"returncode": rc, "output": stdout}

        return self.schedule_interval(
            name=f"scan_{interface}",
            func=_do_scan,
            interval=interval,
        )

    def schedule_update_check(self, interval: float = 86400) -> ScheduledTask:
        """Schedule periodic update checks (default: daily)."""
        def _check():
            from wifi_aio.update_checker import check_for_updates
            return check_for_updates()

        return self.schedule_interval(
            name="update_check",
            func=_check,
            interval=interval,
        )

    def schedule_cleanup(self, interval: float = 3600) -> ScheduledTask:
        """Schedule periodic cleanup of old captures/temp files."""
        def _cleanup():
            import glob
            import os
            cleaned = 0
            for pattern in ["/tmp/wifi_aio_scheduled_scan_*", "/tmp/wifi_aio_scan_*"]:
                for f in glob.glob(pattern):
                    try:
                        os.remove(f)
                        cleaned += 1
                    except OSError:
                        pass
            return cleaned

        return self.schedule_interval(
            name="cleanup",
            func=_cleanup,
            interval=interval,
        )
