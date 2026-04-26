"""Auto-installer for missing WiFiAIO dependencies."""

import logging
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

from wifi_aio.constants import PYTHON_DEPS, SYSTEM_TOOLS
from wifi_aio.utils import which_tool, run_command, is_root
from wifi_aio.platform_detect import detect_platform, Platform

logger = logging.getLogger(__name__)

# Map of package names: pip name → system package name per distro
_SYSTEM_PACKAGE_MAP: Dict[str, Dict[str, str]] = {
    "scapy": {"apt": "python3-scapy", "dnf": "python3-scapy", "pacman": "python-scapy"},
    "rich": {"apt": "python3-rich", "dnf": "python3-rich", "pacman": "python-rich"},
    "requests": {"apt": "python3-requests", "dnf": "python3-requests", "pacman": "python-requests"},
    "cryptography": {"apt": "python3-cryptography", "dnf": "python3-cryptography", "pacman": "python-cryptography"},
    "beautifulsoup4": {"apt": "python3-bs4", "dnf": "python3-beautifulsoup4", "pacman": "python-beautifulsoup4"},
    "netaddr": {"apt": "python3-netaddr", "dnf": "python3-netaddr", "pacman": "python-netaddr"},
    "psutil": {"apt": "python3-psutil", "dnf": "python3-psutil", "pacman": "python-psutil"},
    "flask": {"apt": "python3-flask", "dnf": "python3-flask", "pacman": "python-flask"},
    "schedule": {"apt": "python3-schedule", "dnf": "python3-schedule", "pacman": "python-schedule"},
    "textual": {"apt": "", "dnf": "", "pacman": "python-textual"},
    "manuf": {"apt": "", "dnf": "", "pacman": ""},
}

# Map of tool names to system packages
_TOOL_PACKAGE_MAP: Dict[str, Dict[str, str]] = {
    "aircrack-ng": {"apt": "aircrack-ng", "dnf": "aircrack-ng", "pacman": "aircrack-ng"},
    "reaver": {"apt": "reaver", "dnf": "reaver", "pacman": "reaver"},
    "bully": {"apt": "bully", "dnf": "bully", "pacman": "bully"},
    "hostapd": {"apt": "hostapd", "dnf": "hostapd", "pacman": "hostapd"},
    "dnsmasq": {"apt": "dnsmasq", "dnf": "dnsmasq", "pacman": "dnsmasq"},
    "tshark": {"apt": "tshark", "dnf": "wireshark-cli", "pacman": "wireshark-cli"},
    "tcpdump": {"apt": "tcpdump", "dnf": "tcpdump", "pacman": "tcpdump"},
    "nmap": {"apt": "nmap", "dnf": "nmap", "pacman": "nmap"},
    "hashcat": {"apt": "hashcat", "dnf": "hashcat", "pacman": "hashcat"},
    "john": {"apt": "john", "dnf": "john", "pacman": "john"},
}


def auto_install(
    python_packages: Optional[List[str]] = None,
    system_tools: Optional[List[str]] = None,
    prefer_system: bool = True,
    dry_run: bool = False,
) -> Dict[str, str]:
    """Auto-install missing Python packages and system tools.

    Args:
        python_packages: List of pip package names to install if missing.
            Defaults to all PYTHON_DEPS keys.
        system_tools: List of tool names to install if missing.
            Defaults to common WiFi tools.
        prefer_system: If True, try system package manager before pip.
        dry_run: If True, only report what would be installed.

    Returns:
        Dict mapping package/tool name → 'installed', 'skipped', 'failed', or 'dry_run'.
    """
    results: Dict[str, str] = {}

    # Determine platform
    platform_info = detect_platform()
    pkg_manager = platform_info.package_manager

    # Install Python packages
    if python_packages is None:
        python_packages = list(PYTHON_DEPS.keys())

    for pkg in python_packages:
        if _is_python_package_installed(pkg):
            results[pkg] = "skipped"
            continue

        if dry_run:
            results[pkg] = "dry_run"
            continue

        # Try system package first
        if prefer_system and pkg_manager:
            sys_pkg = _SYSTEM_PACKAGE_MAP.get(pkg, {}).get(pkg_manager, "")
            if sys_pkg:
                success = _install_system_package(sys_pkg, pkg_manager)
                if success and _is_python_package_installed(pkg):
                    results[pkg] = "installed"
                    logger.info("Installed %s via system package %s", pkg, sys_pkg)
                    continue

        # Fall back to pip
        success = _install_pip_package(pkg)
        results[pkg] = "installed" if success else "failed"
        if success:
            logger.info("Installed %s via pip", pkg)

    # Install system tools
    if system_tools is None:
        system_tools = ["aircrack-ng", "hostapd", "dnsmasq", "nmap", "tshark"]

    for tool in system_tools:
        if which_tool(tool) is not None:
            results[tool] = "skipped"
            continue

        if dry_run:
            results[tool] = "dry_run"
            continue

        if not pkg_manager:
            results[tool] = "failed"
            continue

        sys_pkg = _TOOL_PACKAGE_MAP.get(tool, {}).get(pkg_manager, tool)
        success = _install_system_package(sys_pkg, pkg_manager)
        results[tool] = "installed" if success else "failed"
        if success:
            logger.info("Installed system tool %s", tool)

    return results


def _is_python_package_installed(package: str) -> bool:
    """Check if a Python package is installed and importable."""
    try:
        importlib = __import__("importlib")
        importlib.import_module(package)
        return True
    except ImportError:
        # Some packages have different import names
        import_names = {
            "beautifulsoup4": "bs4",
            "Pillow": "PIL",
            "pyyaml": "yaml",
            "python-dateutil": "dateutil",
        }
        alt = import_names.get(package)
        if alt:
            try:
                importlib.import_module(alt)
                return True
            except ImportError:
                pass
        return False


def _install_pip_package(package: str, version: Optional[str] = None) -> bool:
    """Install a Python package via pip."""
    spec = package
    if version:
        spec = f"{package}>={version}"

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", spec],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.error("pip install %s failed: %s", spec, exc)
        return False


def _install_system_package(package: str, pkg_manager: str) -> bool:
    """Install a system package using the detected package manager."""
    if not is_root():
        logger.warning("System package installation requires root (sudo)")
        return False

    commands = {
        "apt": ["apt-get", "install", "-y", package],
        "dnf": ["dnf", "install", "-y", package],
        "yum": ["yum", "install", "-y", package],
        "pacman": ["pacman", "-S", "--noconfirm", package],
        "zypper": ["zypper", "install", "-y", package],
        "apk": ["apk", "add", package],
        "pkg": ["pkg", "install", "-y", package],
    }

    cmd = commands.get(pkg_manager)
    if cmd is None:
        logger.error("Unsupported package manager: %s", pkg_manager)
        return False

    rc, _, stderr = run_command(cmd, timeout=120, sudo=not is_root())
    if rc != 0:
        logger.error("Failed to install %s: %s", package, stderr)
        return False
    return True
