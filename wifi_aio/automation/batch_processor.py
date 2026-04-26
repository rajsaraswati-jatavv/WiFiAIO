"""Batch processor for running operations on multiple targets.

Supports parallel and sequential execution, per-target timeout,
progress tracking, and result aggregation.
"""

from __future__ import annotations

import concurrent.futures
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from wifi_aio.exceptions import (
    AutomationError,
    WiFiConnectionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


class TargetStatus(Enum):
    """Status for a single target within a batch."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


@dataclass
class TargetResult:
    """Result of processing a single target.

    Attributes:
        target: The target identifier or data.
        status: Final status.
        result: Return value from the operation (on success).
        error: Exception raised (on failure).
        elapsed: Seconds spent on this target.
    """

    target: Any
    status: TargetStatus = TargetStatus.PENDING
    result: Any = None
    error: Optional[Exception] = None
    elapsed: float = 0.0


@dataclass
class BatchResult:
    """Aggregated outcome of a batch operation.

    Attributes:
        batch_id: Unique identifier for this batch run.
        name: Batch name.
        total: Total number of targets.
        succeeded: Count of successful targets.
        failed: Count of failed targets.
        skipped: Count of skipped targets.
        timed_out: Count of timed-out targets.
        target_results: Per-target results keyed by target identifier.
        elapsed: Total wall-clock seconds.
    """

    batch_id: str
    name: str
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    timed_out: int = 0
    target_results: dict[Any, TargetResult] = field(default_factory=dict)
    elapsed: float = 0.0

    @property
    def success_rate(self) -> float:
        """Percentage of targets that succeeded."""
        if self.total == 0:
            return 0.0
        return (self.succeeded / self.total) * 100.0

    @property
    def success(self) -> bool:
        """True if no targets failed or timed out."""
        return self.failed == 0 and self.timed_out == 0


class BatchProcessor:
    """Run operations on multiple targets with configurable parallelism.

    Example::

        processor = BatchProcessor(name="scan_batch", max_workers=4, timeout=30)
        result = processor.run(targets, scan_callback)
        print(f"{result.succeeded}/{result.total} succeeded")
    """

    def __init__(
        self,
        name: str = "batch",
        max_workers: int = 1,
        timeout: float = 0.0,
        retry_count: int = 0,
        retry_delay: float = 1.0,
        on_target_error: Optional[Callable[[Any, Exception], None]] = None,
        skip_condition: Optional[Callable[[Any], bool]] = None,
    ) -> None:
        self.name = name
        self.max_workers = max(1, max_workers)
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.on_target_error = on_target_error
        self.skip_condition = skip_condition
        self._cancel_event = threading.Event()

    # ── Execution ──────────────────────────────────────────────────────

    def run(
        self,
        targets: list[Any],
        operation: Callable[..., Any],
        pre_check: Optional[Callable[[Any], bool]] = None,
    ) -> BatchResult:
        """Execute *operation* on every item in *targets*.

        Args:
            targets: Iterable of target identifiers or data dicts.
            operation: Callable invoked as ``operation(target)``.
            pre_check: Optional callable; if it returns False the target
                       is skipped.

        Returns:
            A BatchResult with per-target outcomes.
        """
        self._cancel_event.clear()
        start = time.time()
        batch_id = str(uuid.uuid4())

        result = BatchResult(
            batch_id=batch_id,
            name=self.name,
            total=len(targets),
        )

        if self.max_workers <= 1:
            self._run_sequential(targets, operation, pre_check, result)
        else:
            self._run_parallel(targets, operation, pre_check, result)

        result.elapsed = time.time() - start
        result.succeeded = sum(
            1 for r in result.target_results.values() if r.status == TargetStatus.SUCCESS
        )
        result.failed = sum(
            1 for r in result.target_results.values() if r.status == TargetStatus.FAILED
        )
        result.skipped = sum(
            1 for r in result.target_results.values() if r.status == TargetStatus.SKIPPED
        )
        result.timed_out = sum(
            1 for r in result.target_results.values() if r.status == TargetStatus.TIMEOUT
        )

        logger.info(
            "Batch %s completed: %d/%d succeeded (%.1f%%) in %.1fs",
            self.name, result.succeeded, result.total,
            result.success_rate, result.elapsed,
        )
        return result

    def cancel(self) -> None:
        """Signal the batch to stop processing further targets."""
        self._cancel_event.set()
        logger.info("Batch %s cancellation requested", self.name)

    # ── Sequential execution ───────────────────────────────────────────

    def _run_sequential(
        self,
        targets: list[Any],
        operation: Callable[..., Any],
        pre_check: Optional[Callable[[Any], bool]],
        result: BatchResult,
    ) -> None:
        for target in targets:
            if self._cancel_event.is_set():
                break
            target_result = self._process_target(target, operation, pre_check)
            result.target_results[target] = target_result

    # ── Parallel execution ─────────────────────────────────────────────

    def _run_parallel(
        self,
        targets: list[Any],
        operation: Callable[..., Any],
        pre_check: Optional[Callable[[Any], bool]],
        result: BatchResult,
    ) -> None:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            future_map: dict[concurrent.futures.Future, Any] = {}
            for target in targets:
                if self._cancel_event.is_set():
                    break
                future = executor.submit(self._process_target, target, operation, pre_check)
                future_map[future] = target

            for future in concurrent.futures.as_completed(future_map):
                target = future_map[future]
                try:
                    target_result = future.result()
                    result.target_results[target] = target_result
                except Exception as exc:
                    result.target_results[target] = TargetResult(
                        target=target,
                        status=TargetStatus.FAILED,
                        error=exc,
                    )

    # ── Per-target processing ──────────────────────────────────────────

    def _process_target(
        self,
        target: Any,
        operation: Callable[..., Any],
        pre_check: Optional[Callable[[Any], bool]],
    ) -> TargetResult:
        """Process a single target with skip/retry/timeout logic."""
        target_result = TargetResult(target=target)

        # Skip check
        if self.skip_condition and self.skip_condition(target):
            target_result.status = TargetStatus.SKIPPED
            return target_result

        if pre_check and not pre_check(target):
            target_result.status = TargetStatus.SKIPPED
            return target_result

        attempts = 1 + self.retry_count
        last_error: Optional[Exception] = None

        for attempt in range(1, attempts + 1):
            target_result.status = TargetStatus.RUNNING
            start = time.time()

            try:
                if self.timeout > 0:
                    ret = self._run_with_timeout(operation, target, self.timeout)
                else:
                    ret = operation(target)

                target_result.status = TargetStatus.SUCCESS
                target_result.result = ret
                target_result.elapsed = time.time() - start
                return target_result

            except WiFiTimeoutError:
                target_result.elapsed = time.time() - start
                target_result.status = TargetStatus.TIMEOUT
                target_result.error = WiFiTimeoutError(
                    f"Target {target} timed out after {self.timeout}s"
                )
                return target_result

            except (WiFiConnectionError, Exception) as exc:
                last_error = exc
                target_result.elapsed = time.time() - start
                if attempt < attempts:
                    logger.debug(
                        "Target %s attempt %d/%d failed: %s – retrying",
                        target, attempt, attempts, exc,
                    )
                    time.sleep(self.retry_delay)

        target_result.status = TargetStatus.FAILED
        target_result.error = last_error

        if self.on_target_error and last_error is not None:
            try:
                self.on_target_error(target, last_error)
            except Exception as handler_exc:
                logger.error("Error handler raised for target %s: %s", target, handler_exc)

        return target_result

    @staticmethod
    def _run_with_timeout(
        operation: Callable[..., Any], target: Any, timeout: float
    ) -> Any:
        """Run *operation(target)* with a wall-clock timeout."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(operation, target)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                raise WiFiTimeoutError(
                    f"Operation on target {target} timed out after {timeout}s",
                    details="batch_processor_timeout",
                )

    def __repr__(self) -> str:
        return (
            f"BatchProcessor(name={self.name!r}, max_workers={self.max_workers}, "
            f"timeout={self.timeout})"
        )
