"""Workflow engine for defining and executing multi-step automation workflows.

Supports conditional branching, error handling strategies, retry logic,
and step-level rollback capabilities.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from wifi_aio.exceptions import (
    AutomationError,
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


class StepStatus(Enum):
    """Status of a single workflow step."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


class ErrorStrategy(Enum):
    """How to handle step failures."""
    STOP = "stop"
    CONTINUE = "continue"
    RETRY = "retry"
    SKIP = "skip"


@dataclass
class WorkflowStep:
    """A single step within a workflow.

    Attributes:
        name: Human-readable step name.
        action: Callable to execute for this step.
        condition: Optional callable that returns True if step should run.
        on_error: Error handling strategy for this step.
        retries: Number of retries when on_error is RETRY.
        retry_delay: Seconds to wait between retries.
        rollback: Optional callable to undo this step's effects.
        timeout: Maximum seconds the step may run (0 = no limit).
        metadata: Arbitrary extra data attached to the step.
    """

    name: str
    action: Callable[..., Any]
    condition: Optional[Callable[..., bool]] = None
    on_error: ErrorStrategy = ErrorStrategy.STOP
    retries: int = 0
    retry_delay: float = 1.0
    rollback: Optional[Callable[..., Any]] = None
    timeout: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    _status: StepStatus = field(default=StepStatus.PENDING, repr=False)
    _result: Any = field(default=None, repr=False)
    _error: Optional[Exception] = field(default=None, repr=False)

    @property
    def status(self) -> StepStatus:
        return self._status

    @property
    def result(self) -> Any:
        return self._result

    @property
    def error(self) -> Optional[Exception]:
        return self._error


@dataclass
class WorkflowResult:
    """Outcome of a complete workflow execution.

    Attributes:
        workflow_id: Unique identifier of the workflow run.
        name: Workflow name.
        success: Whether every step completed successfully.
        step_results: Mapping of step name to its return value.
        step_errors: Mapping of step name to its exception.
        step_statuses: Mapping of step name to its status.
        start_time: Epoch time when execution began.
        end_time: Epoch time when execution ended.
        elapsed: Total wall-clock seconds.
    """

    workflow_id: str
    name: str
    success: bool = False
    step_results: dict[str, Any] = field(default_factory=dict)
    step_errors: dict[str, Optional[Exception]] = field(default_factory=dict)
    step_statuses: dict[str, StepStatus] = field(default_factory=dict)
    start_time: float = 0.0
    end_time: float = 0.0
    elapsed: float = 0.0


class WorkflowEngine:
    """Define and execute multi-step workflows with conditions and error handling.

    Example::

        engine = WorkflowEngine("pentest_workflow")
        engine.add_step(WorkflowStep("scan", scan_networks))
        engine.add_step(WorkflowStep("capture", capture_handshake,
                                     condition=lambda ctx: ctx.get("target")))
        result = engine.run()
    """

    def __init__(self, name: str = "unnamed") -> None:
        self.name = name
        self._steps: list[WorkflowStep] = []
        self._context: dict[str, Any] = {}
        self._step_map: dict[str, WorkflowStep] = {}

    # ── Step management ────────────────────────────────────────────────

    def add_step(self, step: WorkflowStep) -> "WorkflowEngine":
        """Append a step to the workflow. Returns self for chaining."""
        if step.name in self._step_map:
            raise AutomationError(f"Duplicate step name: {step.name}")
        self._steps.append(step)
        self._step_map[step.name] = step
        return self

    def insert_step(self, index: int, step: WorkflowStep) -> "WorkflowEngine":
        """Insert a step at *index*. Returns self for chaining."""
        if step.name in self._step_map:
            raise AutomationError(f"Duplicate step name: {step.name}")
        self._steps.insert(index, step)
        self._step_map[step.name] = step
        return self

    def remove_step(self, name: str) -> None:
        """Remove a step by name."""
        step = self._step_map.pop(name, None)
        if step is None:
            raise AutomationError(f"Step not found: {name}")
        self._steps.remove(step)

    def get_step(self, name: str) -> Optional[WorkflowStep]:
        """Look up a step by name."""
        return self._step_map.get(name)

    @property
    def steps(self) -> list[WorkflowStep]:
        """Return a shallow copy of the step list."""
        return list(self._steps)

    # ── Context management ─────────────────────────────────────────────

    def set_context(self, key: str, value: Any) -> None:
        """Set a shared context variable available to all steps."""
        self._context[key] = value

    def get_context(self, key: str, default: Any = None) -> Any:
        """Retrieve a context variable."""
        return self._context.get(key, default)

    def clear_context(self) -> None:
        """Remove all context variables."""
        self._context.clear()

    # ── Execution ──────────────────────────────────────────────────────

    def run(self, context: Optional[dict[str, Any]] = None) -> WorkflowResult:
        """Execute all steps in order, respecting conditions and error strategies.

        Args:
            context: Optional initial context dict merged into the engine context.

        Returns:
            A WorkflowResult summarising the execution.
        """
        if context:
            self._context.update(context)

        result = WorkflowResult(
            workflow_id=str(uuid.uuid4()),
            name=self.name,
            start_time=time.time(),
        )

        completed_steps: list[WorkflowStep] = []

        for step in self._steps:
            step._status = StepStatus.PENDING

            # Evaluate condition
            if step.condition is not None:
                try:
                    should_run = step.condition(self._context)
                except Exception as exc:
                    logger.warning("Condition evaluation failed for %s: %s", step.name, exc)
                    should_run = False

                if not should_run:
                    step._status = StepStatus.SKIPPED
                    result.step_statuses[step.name] = StepStatus.SKIPPED
                    logger.info("Step %s skipped (condition false)", step.name)
                    continue

            # Execute with retry / timeout
            step_result, step_error = self._execute_step(step)

            if step_error is not None:
                step._error = step_error
                result.step_errors[step.name] = step_error

                if step.on_error == ErrorStrategy.STOP:
                    step._status = StepStatus.FAILED
                    result.step_statuses[step.name] = StepStatus.FAILED
                    self._rollback_completed(completed_steps, result)
                    break
                elif step.on_error == ErrorStrategy.CONTINUE:
                    step._status = StepStatus.FAILED
                    result.step_statuses[step.name] = StepStatus.FAILED
                    logger.warning("Step %s failed but continuing: %s", step.name, step_error)
                elif step.on_error == ErrorStrategy.SKIP:
                    step._status = StepStatus.SKIPPED
                    result.step_statuses[step.name] = StepStatus.SKIPPED
                    logger.info("Step %s skipped after error: %s", step.name, step_error)
                elif step.on_error == ErrorStrategy.RETRY:
                    step._status = StepStatus.FAILED
                    result.step_statuses[step.name] = StepStatus.FAILED
                    logger.warning("Step %s failed after retries: %s", step.name, step_error)
                    self._rollback_completed(completed_steps, result)
                    break
            else:
                step._status = StepStatus.SUCCESS
                step._result = step_result
                result.step_results[step.name] = step_result
                result.step_statuses[step.name] = StepStatus.SUCCESS
                # Store result in context for downstream steps
                self._context[f"result_{step.name}"] = step_result
                completed_steps.append(step)

        result.end_time = time.time()
        result.elapsed = result.end_time - result.start_time
        result.success = all(
            s in (StepStatus.SUCCESS, StepStatus.SKIPPED)
            for s in result.step_statuses.values()
        )

        return result

    # ── Internal helpers ───────────────────────────────────────────────

    def _execute_step(self, step: WorkflowStep) -> tuple[Any, Optional[Exception]]:
        """Run a single step's action, respecting retries and timeout."""
        attempts = 1 + (step.retries if step.on_error == ErrorStrategy.RETRY else 0)
        last_error: Optional[Exception] = None

        for attempt in range(1, attempts + 1):
            step._status = StepStatus.RUNNING
            try:
                if step.timeout > 0:
                    result = self._run_with_timeout(step.action, step.timeout)
                else:
                    result = step.action(self._context)
                return result, None
            except (WiFiConnectionError, WiFiPermissionError, WiFiTimeoutError) as exc:
                last_error = exc
                logger.warning(
                    "Step %s attempt %d/%d failed: %s", step.name, attempt, attempts, exc
                )
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "Step %s attempt %d/%d failed: %s", step.name, attempt, attempts, exc
                )

            if attempt < attempts:
                time.sleep(step.retry_delay)

        return None, last_error

    @staticmethod
    def _run_with_timeout(func: Callable[..., Any], timeout: float) -> Any:
        """Run *func* with a wall-clock timeout using a simple polling approach.

        For production use consider thread/subprocess-based timeouts; this
        implementation uses a bounded loop for zero-dependency operation.
        """
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(func)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                raise WiFiTimeoutError(
                    f"Step timed out after {timeout}s", details="workflow_step_timeout"
                )

    def _rollback_completed(
        self, completed_steps: list[WorkflowStep], result: WorkflowResult
    ) -> None:
        """Attempt to roll back already-completed steps in reverse order."""
        for step in reversed(completed_steps):
            if step.rollback is not None:
                try:
                    step.rollback(self._context)
                    step._status = StepStatus.ROLLED_BACK
                    result.step_statuses[step.name] = StepStatus.ROLLED_BACK
                    logger.info("Rolled back step %s", step.name)
                except Exception as exc:
                    logger.error("Rollback failed for step %s: %s", step.name, exc)

    # ── Dunder helpers ─────────────────────────────────────────────────

    def __repr__(self) -> str:
        return f"WorkflowEngine(name={self.name!r}, steps={len(self._steps)})"
