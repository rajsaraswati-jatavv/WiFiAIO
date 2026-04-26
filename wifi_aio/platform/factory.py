"""Platform factory for WiFiAIO.

Auto-detects the current operating system and returns the appropriate
platform adapter instance.
"""

from __future__ import annotations

import os
import platform
import sys
from typing import Optional

from wifi_aio.platform.base import BasePlatform
from wifi_aio.platform.linux import LinuxPlatform
from wifi_aio.platform.windows import WindowsPlatform
from wifi_aio.platform.macos import MacOSPlatform
from wifi_aio.platform.termux import TermuxPlatform
from wifi_aio.exceptions import WiFiConnectionError


class PlatformFactory:
    """Factory for creating platform-specific WiFi adapters.

    Automatically detects the current operating system and returns
    the correct platform adapter. Supports Linux, Windows, macOS,
    and Termux (Android).
    """

    _instance: Optional[BasePlatform] = None
    _platform_override: Optional[str] = None

    @classmethod
    def detect_platform(cls) -> str:
        """Detect the current platform.

        Returns:
            Platform name string: 'linux', 'windows', 'macos', or 'termux'.

        Raises:
            WiFiConnectionError: If the platform is not supported.
        """
        # Check for override
        if cls._platform_override:
            return cls._platform_override

        # Check for Termux specifically (Android)
        if cls._is_termux():
            return "termux"

        # Standard platform detection
        system = platform.system().lower()

        if system == "linux":
            return "linux"
        elif system == "windows":
            return "windows"
        elif system == "darwin":
            return "macos"
        else:
            raise WiFiConnectionError(
                f"Unsupported platform: {system}",
                details=f"WiFiAIO supports Linux, Windows, macOS, and Termux. "
                f"Detected system: {system} ({platform.platform()})",
            )

    @classmethod
    def _is_termux(cls) -> bool:
        """Check if running inside Termux on Android."""
        # Check for Termux-specific paths and environment variables
        termux_indicators = [
            os.path.exists("/data/data/com.termux"),
            "TERMUX_VERSION" in os.environ,
            "TERMUX_MAIN_PACKAGE_FORMAT" in os.environ,
            os.path.exists("/system/bin/toybox") and "com.termux" in os.environ.get("PATH", ""),
        ]
        # Also check for termux-specific PREFIX
        prefix = os.environ.get("PREFIX", "")
        if "/com.termux/" in prefix:
            return True

        return any(termux_indicators)

    @classmethod
    def create(cls, platform_name: Optional[str] = None) -> BasePlatform:
        """Create and return a platform adapter instance.

        Args:
            platform_name: Optional platform name override. If None,
                auto-detects the platform.

        Returns:
            A BasePlatform subclass instance for the detected/specified platform.

        Raises:
            WiFiConnectionError: If the platform is not supported.
        """
        if platform_name:
            name = platform_name.lower()
        else:
            name = cls.detect_platform()

        if name == "linux":
            return LinuxPlatform()
        elif name == "windows":
            return WindowsPlatform()
        elif name == "macos":
            return MacOSPlatform()
        elif name == "termux":
            return TermuxPlatform()
        else:
            raise WiFiConnectionError(
                f"Unsupported platform: {name}",
                details="Supported platforms: linux, windows, macos, termux",
            )

    @classmethod
    def get_instance(cls) -> BasePlatform:
        """Get or create the singleton platform adapter instance.

        Returns:
            The cached BasePlatform instance, or a new one if not yet created.
        """
        if cls._instance is None:
            cls._instance = cls.create()
        return cls._instance

    @classmethod
    def set_override(cls, platform_name: str) -> None:
        """Set a platform override for testing purposes.

        Args:
            platform_name: The platform name to force ('linux', 'windows',
                'macos', 'termux').
        """
        cls._platform_override = platform_name
        cls._instance = None  # Reset cached instance

    @classmethod
    def clear_override(cls) -> None:
        """Clear any platform override."""
        cls._platform_override = None
        cls._instance = None

    @classmethod
    def reset(cls) -> None:
        """Reset the factory state (clear instance and override)."""
        cls._instance = None
        cls._platform_override = None

    @classmethod
    def get_supported_platforms(cls) -> list:
        """Return a list of supported platform names.

        Returns:
            List of platform name strings.
        """
        return ["linux", "windows", "macos", "termux"]

    @classmethod
    def is_platform_supported(cls, platform_name: str) -> bool:
        """Check if a platform is supported.

        Args:
            platform_name: The platform name to check.

        Returns:
            True if the platform is supported.
        """
        return platform_name.lower() in cls.get_supported_platforms()
