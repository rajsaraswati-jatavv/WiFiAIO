"""WiFiAIO UI sub-package.

Provides terminal user interface components including color themes,
ASCII art, display helpers, progress indicators, and input handling.
"""

from wifi_aio.ui.colors import Colors, Theme, THEMES, get_theme, set_theme
from wifi_aio.ui.components import (
    Table, Menu, Form, Dialog, SelectList, ProgressBar,
)
from wifi_aio.ui.display import (
    Banner, Header, Section, FormattedOutput, KeyValueList,
)
from wifi_aio.ui.ascii_art import ASCIIArt, WIFI_AIO_LOGO, WIFI_AIO_SMALL
from wifi_aio.ui.progress import (
    Spinner, ProgressBarWidget, SpinnerStyle, TaskProgress,
)
from wifi_aio.ui.input_handler import (
    InputHandler, prompt, confirm, select, multi_select,
)

__all__ = [
    "Colors",
    "Theme",
    "THEMES",
    "get_theme",
    "set_theme",
    "Table",
    "Menu",
    "Form",
    "Dialog",
    "SelectList",
    "ProgressBar",
    "Banner",
    "Header",
    "Section",
    "FormattedOutput",
    "KeyValueList",
    "ASCIIArt",
    "WIFI_AIO_LOGO",
    "WIFI_AIO_SMALL",
    "Spinner",
    "ProgressBarWidget",
    "SpinnerStyle",
    "TaskProgress",
    "InputHandler",
    "prompt",
    "confirm",
    "select",
    "multi_select",
]
