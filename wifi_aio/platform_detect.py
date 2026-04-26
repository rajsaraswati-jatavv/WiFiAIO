"""WiFiAIO platform detection.

Identifies the running operating system and environment so that other
modules can adapt their behaviour (e.g. choose ``iw`` vs. ``netsh``,
decide whether root is required, detect Kali/Termux).
"""

import os
import platform
import subprocess
import sys
from enum import Enum
from typing import Dict, Optional

from wifi_aio.logger import get_logger

logger = get_logger("platform_detect")


class PlatformType(str, Enum):
    """Supported platform identifiers."""
    LINUX = "linux"
    KALI = "kali"
    WINDOWS = "windows"
    MACOS = "macos"
    TERMUX = "termux"
    WSL = "wsl"
    UNKNOWN = "unknown"


class PlatformInfo:
    """Read-only container for everything we know about the current platform."""

    def __init__(
        self,
        platform_type: PlatformType,
        is_root: bool,
        python_version: str,
        arch: str,
        distro_name: str,
        distro_version: str,
        has_aircrack: bool,
        has_iw: bool,
        has_ip: bool,
        has_networkmanager: bool,
        details: Dict[str, str],
    ):
        self.platform_type = platform_type
        self.is_root = is_root
        self.python_version = python_version
        self.arch = arch
        self.distro_name = distro_name
        self.distro_version = distro_version
        self.has_aircrack = has_aircrack
        self.has_iw = has_iw
        self.has_ip = has_ip
        self.has_networkmanager = has_networkmanager
        self.details = details

    def __repr__(self) -> str:
        return (
            f"PlatformInfo(type={self.platform_type.value}, root={self.is_root}, "
            f"distro={self.distro_name} {self.distro_version})"
        )


def detect_platform() -> PlatformInfo:
    """Detect the current platform and return a :class:`PlatformInfo`.

    This function is the single source of truth for platform detection.
    """
    ptype = _detect_os_type()
    is_root = _is_root()
    python_version = platform.python_version()
    arch = platform.machine()
    distro_name, distro_version = _detect_distro(ptype)
    has_aircrack = _command_exists("aircrack-ng")
    has_iw = _command_exists("iw")
    has_ip = _command_exists("ip")
    has_nm = _has_networkmanager(ptype)

    details: Dict[str, str] = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "node": platform.node(),
    }

    # Termux-specific info
    if ptype == PlatformType.TERMUX:
        prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
        details["termux_prefix"] = prefix

    # WSL info
    if ptype == PlatformType.WSL:
        details["wsl_distro"] = distro_name

    info = PlatformInfo(
        platform_type=ptype,
        is_root=is_root,
        python_version=python_version,
        arch=arch,
        distro_name=distro_name,
        distro_version=distro_version,
        has_aircrack=has_aircrack,
        has_iw=has_iw,
        has_ip=has_ip,
        has_networkmanager=has_nm,
        details=details,
    )
    logger.info("Detected platform: %s", info)
    return info


# ── Private helpers ──────────────────────────────────────────────────

def _detect_os_type() -> PlatformType:
    """Determine the broad OS category."""
    system = platform.system().lower()

    # Termux check (Android)
    if os.path.isdir("/data/data/com.termux"):
        return PlatformType.TERMUX

    # WSL check
    try:
        with open("/proc/version", "r") as fh:
            version_text = fh.read().lower()
            if "microsoft" in version_text or "wsl" in version_text:
                return PlatformType.WSL
    except OSError:
        pass

    if system == "linux":
        # Kali check
        try:
            with open("/etc/os-release", "r") as fh:
                os_release = fh.read().lower()
                if "kali" in os_release:
                    return PlatformType.KALI
        except OSError:
            pass
        return PlatformType.LINUX

    if system == "windows":
        return PlatformType.WINDOWS

    if system == "darwin":
        return PlatformType.MACOS

    return PlatformType.UNKNOWN


def _detect_distro(ptype: PlatformType) -> tuple:
    """Return (distro_name, distro_version) from /etc/os-release or registry."""
    if ptype in (PlatformType.WINDOWS,):
        return "Windows", platform.version()

    if ptype in (PlatformType.MACOS,):
        return "macOS", platform.mac_ver()[0]

    if ptype == PlatformType.TERMUX:
        return "Termux", os.environ.get("TERMUX_VERSION", "unknown")

    # Linux / Kali / WSL – read /etc/os-release
    try:
        info: Dict[str, str] = {}
        with open("/etc/os-release", "r") as fh:
            for line in fh:
                if "=" in line:
                    key, _, value = line.strip().partition("=")
                    info[key] = value.strip('"')
        return info.get("NAME", "Linux"), info.get("VERSION_ID", "unknown")
    except OSError:
        return "Linux", "unknown"


def _is_root() -> bool:
    """Return ``True`` if the current process has root / admin privileges."""
    if platform.system().lower() == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        except Exception:
            return False
    return os.geteuid() == 0


def _command_exists(cmd: str) -> bool:
    """Return ``True`` if *cmd* is on ``$PATH``."""
    try:
        result = subprocess.run(
            ["which", cmd],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _has_networkmanager(ptype: PlatformType) -> bool:
    """Return ``True`` if NetworkManager is likely available."""
    if ptype not in (PlatformType.LINUX, PlatformType.KALI, PlatformType.WSL):
        return False
    return _command_exists("nmcli")


# ── Module-level cache ───────────────────────────────────────────────

_cached_info: Optional[PlatformInfo] = None


def get_platform_info() -> PlatformInfo:
    """Return cached platform info, detecting on first call."""
    global _cached_info
    if _cached_info is None:
        _cached_info = detect_platform()
    return _cached_info
