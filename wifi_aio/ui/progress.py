"""Progress bars and spinners for CLI/TUI applications.

Provides animated progress indicators, spinners, and task progress
tracking for long-running operations.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from wifi_aio.ui.colors import Colors, get_theme, styled


class SpinnerStyle(Enum):
    """Spinner animation styles."""
    DOTS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    ARROWS = ["←", "↖", "↑", "↗", "→", "↘", "↓", "↙"]
    CLASSIC = ["|", "/", "-", "\\"]
    BLOCKS = ["▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"]
    BRAILLE = ["⡀", "⡄", "⡆", "⡇", "⣇", "⣧", "⣷", "⣿"]
    WAVE = ["🌊", "🌊", "🌊", "🌊", "🌊"]
    SIMPLE = [".", "..", "...", "...."]


class Spinner:
    """Animated spinner for indicating ongoing operations.

    Usage:
        spinner = Spinner("Scanning networks")
        spinner.start()
        # ... do work ...
        spinner.stop()
    """

    def __init__(
        self,
        message: str = "",
        style: SpinnerStyle = SpinnerStyle.DOTS,
        color: str = "primary",
    ):
        self.message = message
        self.style = style
        self.color = color
        self._running = False
        self._frame = 0
        self._start_time: Optional[float] = None

    def _render_frame(self) -> str:
        """Render a single spinner frame."""
        theme = get_theme()
        frames = self.style.value
        char = frames[self._frame % len(frames)]
        elapsed = ""
        if self._start_time:
            secs = time.time() - self._start_time
            elapsed = styled(f" ({secs:.1f}s)", "muted", theme)
        msg = styled(f"  {char} {self.message}", self.color, theme)
        return f"\r{msg}{elapsed}   "

    def update(self, message: Optional[str] = None) -> None:
        """Update the spinner message and advance the frame.

        Args:
            message: New message to display. If None, keeps the current message.
        """
        if message is not None:
            self.message = message
        self._frame += 1
        sys.stdout.write(self._render_frame())
        sys.stdout.flush()

    def start(self) -> None:
        """Start the spinner animation."""
        self._running = True
        self._start_time = time.time()
        self._frame = 0
        sys.stdout.write(self._render_frame())
        sys.stdout.flush()

    def stop(self, final_message: Optional[str] = None) -> None:
        """Stop the spinner animation.

        Args:
            final_message: Optional final message to display (e.g., "Done!").
        """
        self._running = False
        if final_message:
            theme = get_theme()
            msg = styled(f"  ✓ {final_message}", "success", theme)
            sys.stdout.write(f"\r{msg}{' ' * 20}\n")
        else:
            sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    @property
    def elapsed(self) -> float:
        """Return elapsed time in seconds since start."""
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time


class ProgressBarWidget:
    """Animated progress bar widget for tracking operation progress.

    Usage:
        bar = ProgressBarWidget(total=100, description="Cracking")
        bar.update(25)
        bar.update(50)
        bar.complete()
    """

    def __init__(
        self,
        total: int = 100,
        description: str = "",
        width: int = 30,
        fill_char: str = "█",
        empty_char: str = "░",
    ):
        self.total = max(1, total)
        self.description = description
        self.width = width
        self.fill_char = fill_char
        self.empty_char = empty_char
        self.current = 0
        self._start_time: Optional[float] = None
        self._last_update: Optional[float] = None

    def update(self, current: int, description: Optional[str] = None) -> None:
        """Update the progress bar.

        Args:
            current: Current progress value.
            description: Optional description update.
        """
        self.current = min(current, self.total)
        if description is not None:
            self.description = description
        if self._start_time is None:
            self._start_time = time.time()
        self._last_update = time.time()
        self._render()

    def increment(self, amount: int = 1, description: Optional[str] = None) -> None:
        """Increment the progress by a given amount.

        Args:
            amount: Amount to increment.
            description: Optional description update.
        """
        self.update(self.current + amount, description)

    def complete(self, message: str = "Complete") -> None:
        """Mark the progress as complete.

        Args:
            message: Completion message.
        """
        self.current = self.total
        self._render()
        theme = get_theme()
        sys.stdout.write(f"\r  {styled('✓', 'success', theme)} {message}{' ' * 30}\n")
        sys.stdout.flush()

    def _render(self) -> None:
        """Render the progress bar to stdout."""
        theme = get_theme()
        progress = self.current / self.total
        filled = int(self.width * progress)
        empty = self.width - filled
        bar = self.fill_char * filled + self.empty_char * empty
        percentage = int(progress * 100)

        # Calculate ETA
        eta_str = ""
        if self._start_time and self.current > 0:
            elapsed = time.time() - self._start_time
            rate = self.current / elapsed
            remaining = (self.total - self.current) / rate if rate > 0 else 0
            eta_str = styled(f" ETA: {remaining:.0f}s", "muted", theme)

        desc = styled(f"  {self.description}", "info", theme) if self.description else ""
        pct = styled(f"{percentage}%", "accent", theme)
        count = styled(f"({self.current}/{self.total})", "muted", theme)

        line = f"\r{desc} [{bar}] {pct} {count}{eta_str}"
        sys.stdout.write(line)
        sys.stdout.flush()


@dataclass
class TaskProgress:
    """Tracks progress for a named task with sub-tasks."""
    name: str
    total: int = 100
    current: int = 0
    status: str = "pending"  # pending, running, completed, failed
    sub_tasks: List["TaskProgress"] = field(default_factory=list)
    start_time: Optional[float] = None
    end_time: Optional[float] = None

    def start(self) -> None:
        """Mark the task as running."""
        self.status = "running"
        self.start_time = time.time()

    def update(self, current: int) -> None:
        """Update the current progress value."""
        self.current = min(current, self.total)

    def complete(self) -> None:
        """Mark the task as completed."""
        self.status = "completed"
        self.current = self.total
        self.end_time = time.time()

    def fail(self, reason: str = "") -> None:
        """Mark the task as failed."""
        self.status = "failed"
        self.end_time = time.time()

    @property
    def progress(self) -> float:
        """Return progress as a value from 0.0 to 1.0."""
        if self.total <= 0:
            return 0.0
        return min(1.0, self.current / self.total)

    @property
    def elapsed(self) -> float:
        """Return elapsed time in seconds."""
        if self.start_time is None:
            return 0.0
        end = self.end_time or time.time()
        return end - self.start_time

    def add_sub_task(self, name: str, total: int = 100) -> "TaskProgress":
        """Add a sub-task and return it.

        Args:
            name: Sub-task name.
            total: Sub-task total.

        Returns:
            The new TaskProgress sub-task.
        """
        task = TaskProgress(name=name, total=total)
        self.sub_tasks.append(task)
        return task

    def render_summary(self) -> str:
        """Render a summary of the task progress.

        Returns:
            Multi-line summary string.
        """
        theme = get_theme()
        status_icons = {
            "pending": styled("○", "muted", theme),
            "running": styled("◉", "warning", theme),
            "completed": styled("●", "success", theme),
            "failed": styled("✗", "error", theme),
        }
        icon = status_icons.get(self.status, "○")
        line = f"  {icon} {self.name}"

        if self.status == "running":
            pct = int(self.progress * 100)
            line += styled(f" [{pct}%]", "info", theme)
        elif self.status == "completed":
            line += styled(f" [{self.elapsed:.1f}s]", "muted", theme)

        lines = [line]
        for sub in self.sub_tasks:
            sub_icon = status_icons.get(sub.status, "○")
            sub_line = f"    {sub_icon} {sub.name}"
            if sub.status == "running":
                pct = int(sub.progress * 100)
                sub_line += styled(f" [{pct}%]", "info", theme)
            elif sub.status == "completed":
                sub_line += styled(f" [{sub.elapsed:.1f}s]", "muted", theme)
            lines.append(sub_line)

        return "\n".join(lines)
