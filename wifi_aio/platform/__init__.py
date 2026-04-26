"""WiFiAIO platform sub-package.

Provides platform-specific adapters for WiFi operations across
different operating systems including Linux, Windows, macOS, and Termux.
"""

from wifi_aio.platform.base import BasePlatform
from wifi_aio.platform.linux import LinuxPlatform
from wifi_aio.platform.windows import WindowsPlatform
from wifi_aio.platform.macos import MacOSPlatform
from wifi_aio.platform.termux import TermuxPlatform
from wifi_aio.platform.factory import PlatformFactory

__all__ = [
    "BasePlatform",
    "LinuxPlatform",
    "WindowsPlatform",
    "MacOSPlatform",
    "TermuxPlatform",
    "PlatformFactory",
]
