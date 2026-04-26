"""WiFiAIO logging setup.

Configures a dual-handler logger (file + console) with optional colour
output on the console and :func:`logging.handlers.RotatingFileHandler`
for the file stream.
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from typing import Optional

# ── ANSI colour codes ────────────────────────────────────────────────

_COLOURS = {
    "DEBUG": "\033[36m",       # cyan
    "INFO": "\033[32m",        # green
    "WARNING": "\033[33m",     # yellow
    "ERROR": "\033[31m",       # red
    "CRITICAL": "\033[1;31m",  # bold red
}
_RESET = "\033[0m"


class _ColourFormatter(logging.Formatter):
    """Adds ANSI colour escapes to the level-name in console output."""

    def format(self, record: logging.LogRecord) -> str:
        colour = _COLOURS.get(record.levelname, "")
        record.levelname = f"{colour}{record.levelname}{_RESET}"
        return super().format(record)


# ── Public API ───────────────────────────────────────────────────────

def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    max_size_mb: int = 10,
    backup_count: int = 5,
    console_colours: bool = True,
) -> logging.Logger:
    """Configure and return the ``wifi_aio`` root logger.

    Parameters
    ----------
    level:
        Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    log_file:
        Path to the log file.  If ``None`` the file handler is skipped.
    max_size_mb:
        Maximum size of each log file before rotation (MiB).
    backup_count:
        Number of rotated log files to keep.
    console_colours:
        Whether to emit ANSI colours on the console handler.
    """
    pkg_logger = logging.getLogger("wifi_aio")
    pkg_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove any existing handlers to avoid duplicates on re-init
    pkg_logger.handlers.clear()

    fmt = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    if console_colours and sys.stderr.isatty():
        console_handler.setFormatter(_ColourFormatter(fmt, datefmt=datefmt))
    else:
        console_handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
    pkg_logger.addHandler(console_handler)

    # File handler (rotating)
    if log_file:
        log_dir = os.path.dirname(log_file)
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError:
            pass  # best-effort – logging will still work to console
        try:
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_size_mb * 1024 * 1024,
                backupCount=backup_count,
                encoding="utf-8",
            )
            file_handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
            pkg_logger.addHandler(file_handler)
        except OSError as exc:
            pkg_logger.warning("Could not create file handler for %s: %s", log_file, exc)

    return pkg_logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``wifi_aio`` namespace."""
    if not name.startswith("wifi_aio"):
        name = f"wifi_aio.{name}"
    return logging.getLogger(name)
