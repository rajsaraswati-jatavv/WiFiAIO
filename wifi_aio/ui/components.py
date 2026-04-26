"""UI components for terminal user interface.

Provides tables, menus, forms, dialogs, and selection lists for
building interactive TUI applications.
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from wifi_aio.ui.colors import Colors, get_theme, styled
from wifi_aio.exceptions import WiFiConnectionError


class Table:
    """Terminal table component for displaying tabular data.

    Supports column alignment, headers, row highlighting, and
    automatic column width calculation.
    """

    def __init__(
        self,
        headers: List[str],
        alignments: Optional[List[str]] = None,
        title: Optional[str] = None,
        style: str = "default",
    ):
        self.headers = headers
        self.alignments = alignments or ["left"] * len(headers)
        self.title = title
        self.style = style
        self.rows: List[List[str]] = []
        self.row_highlights: List[Optional[str]] = []
        self._col_widths: List[int] = [len(h) for h in headers]

    def add_row(self, row: List[str], highlight: Optional[str] = None) -> None:
        """Add a row to the table.

        Args:
            row: List of cell values (one per column).
            highlight: Optional color style for the row.
        """
        self.rows.append([str(v) for v in row])
        self.row_highlights.append(highlight)
        for i, val in enumerate(row):
            if i < len(self._col_widths):
                self._col_widths[i] = max(self._col_widths[i], len(str(val)))

    def add_rows(self, rows: List[List[str]], highlight: Optional[str] = None) -> None:
        """Add multiple rows to the table."""
        for row in rows:
            self.add_row(row, highlight)

    def render(self) -> str:
        """Render the table as a formatted string.

        Returns:
            Multi-line string containing the formatted table.
        """
        term_width = shutil.get_terminal_size().columns
        theme = get_theme()
        lines: List[str] = []

        # Title
        if self.title:
            lines.append(styled(f"  {self.title}", "primary", theme))
            lines.append("")

        # Separator
        sep = "+" + "+".join("-" * (w + 2) for w in self._col_widths) + "+"

        # Header
        header_cells = []
        for i, h in enumerate(self.headers):
            header_cells.append(self._align_cell(h, self._col_widths[i], self.alignments[i]))
        header_line = "|" + "|".join(f" {c} " for c in header_cells) + "|"

        lines.append(sep)
        lines.append(styled(header_line, "accent", theme))
        lines.append(sep)

        # Rows
        for row_idx, row in enumerate(self.rows):
            cells = []
            for i, val in enumerate(row):
                if i < len(self._col_widths):
                    cells.append(self._align_cell(val, self._col_widths[i], self.alignments[min(i, len(self.alignments) - 1)]))
            row_line = "|" + "|".join(f" {c} " for c in cells) + "|"
            hl = self.row_highlights[row_idx]
            if hl:
                lines.append(styled(row_line, hl, theme))
            else:
                lines.append(row_line)

        lines.append(sep)
        return "\n".join(lines)

    def print(self) -> None:
        """Print the table to stdout."""
        print(self.render())

    @staticmethod
    def _align_cell(text: str, width: int, alignment: str) -> str:
        """Align cell text within a given width."""
        if alignment == "right":
            return text.rjust(width)
        elif alignment == "center":
            return text.center(width)
        return text.ljust(width)


class Menu:
    """Interactive menu component for option selection.

    Renders a numbered list of options and returns the user's selection.
    """

    def __init__(
        self,
        title: str,
        options: List[str],
        allow_back: bool = True,
        allow_quit: bool = True,
    ):
        self.title = title
        self.options = options
        self.allow_back = allow_back
        self.allow_quit = allow_quit

    def render(self) -> str:
        """Render the menu as a formatted string."""
        theme = get_theme()
        lines: List[str] = []
        lines.append("")
        lines.append(styled(f"  {self.title}", "primary", theme))
        lines.append(styled("  " + "=" * len(self.title), "muted", theme))
        lines.append("")

        for i, option in enumerate(self.options):
            num = styled(f"  [{i + 1}]", "accent", theme)
            lines.append(f"{num} {option}")

        if self.allow_back:
            lines.append(styled(f"  [0]", "muted", theme) + " Back")
        if self.allow_quit:
            lines.append(styled(f"  [q]", "muted", theme) + " Quit")

        lines.append("")
        return "\n".join(lines)

    def display_and_select(self) -> Optional[int]:
        """Display the menu and get user selection.

        Returns:
            Selected option index (0-based), or None for back/quit.
        """
        print(self.render())
        while True:
            try:
                choice = input(styled("  Select> ", "accent", get_theme())).strip().lower()
            except (EOFError, KeyboardInterrupt):
                return None

            if choice == "q" and self.allow_quit:
                return None
            if choice == "0" and self.allow_back:
                return None
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(self.options):
                    return idx
            except ValueError:
                pass

            print(styled("  Invalid selection. Try again.", "error", get_theme()))


@dataclass
class FormField:
    """A single form field definition."""
    name: str
    label: str
    field_type: str = "text"  # text, password, number, select, bool
    default: Optional[str] = None
    required: bool = True
    choices: Optional[List[str]] = None
    validator: Optional[Callable[[str], bool]] = None


class Form:
    """Interactive form component for data entry.

    Supports text, password, number, select, and boolean field types
    with validation.
    """

    def __init__(self, title: str, fields: List[FormField]):
        self.title = title
        self.fields = fields
        self.data: Dict[str, str] = {}

    def render(self) -> str:
        """Render the form header."""
        theme = get_theme()
        lines: List[str] = []
        lines.append("")
        lines.append(styled(f"  {self.title}", "primary", theme))
        lines.append(styled("  " + "=" * len(self.title), "muted", theme))
        lines.append("")
        return "\n".join(lines)

    def display_and_collect(self) -> Optional[Dict[str, str]]:
        """Display the form and collect user input.

        Returns:
            Dict of field_name -> value, or None if cancelled.
        """
        print(self.render())
        theme = get_theme()

        for f in self.fields:
            while True:
                prompt_text = styled(f"  {f.label}", "info", theme)
                if f.default:
                    prompt_text += styled(f" [{f.default}]", "muted", theme)
                prompt_text += ": "

                if f.field_type == "password":
                    import getpass
                    value = getpass.getpass(prompt_text)
                elif f.field_type == "select" and f.choices:
                    print(prompt_text)
                    for i, choice in enumerate(f.choices):
                        print(f"    [{i + 1}] {choice}")
                    raw = input(styled("  Select> ", "accent", theme)).strip()
                    try:
                        idx = int(raw) - 1
                        if 0 <= idx < len(f.choices):
                            value = f.choices[idx]
                        else:
                            print(styled("  Invalid selection.", "error", theme))
                            continue
                    except ValueError:
                        print(styled("  Invalid selection.", "error", theme))
                        continue
                elif f.field_type == "bool":
                    raw = input(prompt_text + styled("(y/n) ", "muted", theme)).strip().lower()
                    value = "true" if raw in ("y", "yes", "1") else "false"
                else:
                    value = input(prompt_text).strip()

                if not value and f.default:
                    value = f.default
                if f.required and not value:
                    print(styled("  This field is required.", "error", theme))
                    continue
                if f.validator and value and not f.validator(value):
                    print(styled("  Invalid value.", "error", theme))
                    continue

                self.data[f.name] = value
                break

        return dict(self.data)


class Dialog:
    """Modal dialog component for confirmations and alerts."""

    def __init__(self, title: str, message: str, dialog_type: str = "info"):
        self.title = title
        self.message = message
        self.dialog_type = dialog_type  # info, warning, error, confirm

    def render(self) -> str:
        """Render the dialog as a formatted string."""
        theme = get_theme()
        width = min(60, shutil.get_terminal_size().columns - 4)
        style_map = {"info": "info", "warning": "warning", "error": "error", "confirm": "primary"}
        style = style_map.get(self.dialog_type, "info")

        lines: List[str] = []
        lines.append("+" + "-" * (width + 2) + "+")
        lines.append("| " + styled(self.title.center(width), style, theme) + " |")
        lines.append("+" + "-" * (width + 2) + "+")

        words = self.message.split()
        current_line = ""
        for word in words:
            if len(current_line) + len(word) + 1 <= width:
                current_line = f"{current_line} {word}" if current_line else word
            else:
                lines.append("| " + current_line.ljust(width) + " |")
                current_line = word
        if current_line:
            lines.append("| " + current_line.ljust(width) + " |")

        lines.append("+" + "-" * (width + 2) + "+")
        return "\n".join(lines)

    def show(self) -> None:
        """Display the dialog and wait for acknowledgment."""
        print(self.render())
        if self.dialog_type == "confirm":
            response = input(styled("  Confirm (y/n): ", "warning", get_theme())).strip().lower()
            return response in ("y", "yes")
        input(styled("  Press Enter to continue...", "muted", get_theme()))
        return True


class SelectList:
    """Multi-select list component for choosing multiple items."""

    def __init__(self, title: str, items: List[str], allow_empty: bool = False):
        self.title = title
        self.items = items
        self.allow_empty = allow_empty

    def display_and_select(self) -> List[int]:
        """Display the list and collect user selections.

        Returns:
            List of selected indices (0-based).
        """
        theme = get_theme()
        print()
        print(styled(f"  {self.title}", "primary", theme))
        print(styled("  Enter comma-separated numbers (e.g., 1,3,5)", "muted", theme))
        print()

        for i, item in enumerate(self.items):
            print(styled(f"  [{i + 1}]", "accent", theme) + f" {item}")

        while True:
            raw = input(styled("\n  Select> ", "accent", theme)).strip()
            if not raw and self.allow_empty:
                return []
            try:
                indices = [int(x.strip()) - 1 for x in raw.split(",")]
                if all(0 <= idx < len(self.items) for idx in indices):
                    return indices
            except ValueError:
                pass
            print(styled("  Invalid selection.", "error", theme))

    def render(self) -> str:
        """Render the selection list."""
        theme = get_theme()
        lines = [styled(f"  {self.title}", "primary", theme)]
        for i, item in enumerate(self.items):
            lines.append(styled(f"  [{i + 1}]", "accent", theme) + f" {item}")
        return "\n".join(lines)


class ProgressBar:
    """Simple text-based progress bar for display in tables or inline."""

    def __init__(self, width: int = 20, fill_char: str = "█", empty_char: str = "░"):
        self.width = width
        self.fill_char = fill_char
        self.empty_char = empty_char

    def render(self, progress: float) -> str:
        """Render a progress bar at the given progress level.

        Args:
            progress: Progress value from 0.0 to 1.0.

        Returns:
            Formatted progress bar string.
        """
        progress = max(0.0, min(1.0, progress))
        filled = int(self.width * progress)
        empty = self.width - filled
        bar = self.fill_char * filled + self.empty_char * empty
        percentage = int(progress * 100)
        theme = get_theme()
        if progress >= 1.0:
            return styled(f"[{bar}] {percentage}%", "success", theme)
        elif progress >= 0.5:
            return styled(f"[{bar}] {percentage}%", "warning", theme)
        else:
            return styled(f"[{bar}] {percentage}%", "info", theme)
