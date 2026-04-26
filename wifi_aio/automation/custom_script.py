"""Custom script loader and executor with sandboxing.

Loads user Python scripts from file or string, executes them in a
restricted namespace, and captures output/errors safely.
"""

from __future__ import annotations

import io
import logging
import os
import sys
import traceback
import types
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from wifi_aio.exceptions import (
    AutomationError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


@dataclass
class ScriptResult:
    """Outcome of a custom script execution.

    Attributes:
        script_id: Unique identifier for this run.
        script_name: Name or path of the script.
        success: Whether the script completed without unhandled exceptions.
        return_value: Value returned by the script (if any).
        output: Captured stdout content.
        error_output: Captured stderr content.
        exception: The unhandled exception, if any.
        elapsed: Wall-clock seconds.
    """

    script_id: str
    script_name: str
    success: bool = False
    return_value: Any = None
    output: str = ""
    error_output: str = ""
    exception: Optional[Exception] = None
    elapsed: float = 0.0


class CustomScript:
    """Load and execute user Python scripts safely.

    Features:
      - Execute from file path or raw source string.
      - Restrict builtins and block dangerous names (``exec``, ``eval``,
        ``__import__`` by default – customisable).
      - Provide a controlled namespace with optional pre-loaded symbols.
      - Capture stdout / stderr.
      - Optional timeout enforcement.

    Example::

        script = CustomScript(name="hello", source='print("hello")')
        result = script.run()
        assert result.success
        assert result.output.strip() == "hello"
    """

    # Names blocked from the script's builtins by default
    _BLOCKED_BUILTINS: frozenset[str] = frozenset({
        "exec", "eval", "compile", "__import__", "open",
        "input", "breakpoint", "exit", "quit",
    })

    def __init__(
        self,
        name: str = "unnamed",
        source: Optional[str] = None,
        filepath: Optional[str | Path] = None,
        namespace: Optional[dict[str, Any]] = None,
        timeout: float = 0.0,
        blocked_builtins: Optional[frozenset[str]] = None,
        allow_file_access: bool = False,
    ) -> None:
        if source is None and filepath is None:
            raise AutomationError("Either source or filepath must be provided")

        self.name = name
        self._source = source
        self._filepath = Path(filepath) if filepath else None
        self._user_namespace = namespace or {}
        self.timeout = timeout
        self._blocked = blocked_builtins if blocked_builtins is not None else self._BLOCKED_BUILTINS
        self.allow_file_access = allow_file_access

        # Compile lazily on first run
        self._code: Optional[Any] = None

    # ── Source loading ─────────────────────────────────────────────────

    @property
    def source(self) -> str:
        """Return the script source text, loading from file if needed."""
        if self._source is not None:
            return self._source
        if self._filepath is not None:
            try:
                self._source = self._filepath.read_text(encoding="utf-8")
            except OSError as exc:
                raise AutomationError(
                    f"Cannot read script file: {self._filepath}", details=str(exc)
                )
            return self._source
        raise AutomationError("No source available")

    def _compile(self) -> Any:
        """Compile the source into a code object."""
        src = self.source
        try:
            return compile(src, str(self._filepath or f"<{self.name}>"), "exec")
        except SyntaxError as exc:
            raise AutomationError(
                f"Syntax error in script {self.name}: {exc}", details=str(exc)
            )

    # ── Namespace ──────────────────────────────────────────────────────

    def _build_namespace(self) -> dict[str, Any]:
        """Construct the restricted execution namespace."""
        safe_builtins = {
            k: v for k, v in __builtins__.items()
            if k not in self._blocked
        } if isinstance(__builtins__, dict) else {
            k: getattr(__builtins__, k)
            for k in dir(__builtins__)
            if k not in self._blocked and not k.startswith("_")
        }

        if self.allow_file_access and "open" in self._blocked:
            safe_builtins["open"] = open

        ns: dict[str, Any] = {"__builtins__": safe_builtins}
        ns.update(self._user_namespace)
        return ns

    # ── Execution ──────────────────────────────────────────────────────

    def run(self, extra_namespace: Optional[dict[str, Any]] = None) -> ScriptResult:
        """Execute the script and return a ScriptResult.

        Args:
            extra_namespace: Additional symbols injected for this run only.

        Returns:
            A ScriptResult with output, errors, and timing information.
        """
        import time as _time

        script_id = str(uuid.uuid4())
        result = ScriptResult(script_id=script_id, script_name=self.name)
        start = _time.time()

        if self._code is None:
            self._code = self._compile()

        ns = self._build_namespace()
        if extra_namespace:
            ns.update(extra_namespace)

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        captured_out = io.StringIO()
        captured_err = io.StringIO()

        try:
            sys.stdout = captured_out
            sys.stderr = captured_err

            if self.timeout > 0:
                self._run_with_timeout(self._code, ns, self.timeout)
            else:
                exec(self._code, ns)

            result.success = True
            result.return_value = ns.get("__return__")

        except WiFiTimeoutError as exc:
            result.success = False
            result.exception = exc
            result.error_output += f"\nTimeoutError: {exc}"
        except Exception as exc:
            result.success = False
            result.exception = exc
            tb = traceback.format_exc()
            result.error_output += f"\n{tb}"
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        result.output = captured_out.getvalue()
        if not result.error_output:
            result.error_output = captured_err.getvalue()
        else:
            result.error_output += captured_err.getvalue()

        result.elapsed = _time.time() - start
        return result

    @staticmethod
    def _run_with_timeout(code: Any, ns: dict[str, Any], timeout: float) -> None:
        """Execute *code* in a separate thread with a wall-clock timeout."""
        import concurrent.futures

        def _exec() -> None:
            exec(code, ns)

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_exec)
            try:
                future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                raise WiFiTimeoutError(
                    f"Script timed out after {timeout}s",
                    details="custom_script_timeout",
                )

    # ── Convenience class methods ──────────────────────────────────────

    @classmethod
    def from_file(
        cls,
        filepath: str | Path,
        name: Optional[str] = None,
        **kwargs: Any,
    ) -> "CustomScript":
        """Create a CustomScript that loads source from a file."""
        filepath = Path(filepath)
        if not filepath.is_file():
            raise AutomationError(f"Script file not found: {filepath}")
        script_name = name or filepath.stem
        return cls(name=script_name, filepath=filepath, **kwargs)

    @classmethod
    def from_string(
        cls,
        source: str,
        name: str = "inline",
        **kwargs: Any,
    ) -> "CustomScript":
        """Create a CustomScript from a source string."""
        return cls(name=name, source=source, **kwargs)

    def __repr__(self) -> str:
        return f"CustomScript(name={self.name!r}, timeout={self.timeout})"
