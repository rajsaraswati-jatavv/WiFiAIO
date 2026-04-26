"""Dependency checker for WiFiAIO — system and Python dependencies with version comparison."""

import importlib
import logging
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

from wifi_aio.constants import PYTHON_DEPS, SYSTEM_TOOLS
from wifi_aio.utils import which_tool

logger = logging.getLogger(__name__)


class DependencyStatus:
    """Status of a single dependency."""

    def __init__(self, name: str, dep_type: str, installed: bool,
                 required_version: str = "", installed_version: str = "",
                 path: str = "", message: str = ""):
        self.name = name
        self.dep_type = dep_type  # "python" or "system"
        self.installed = installed
        self.required_version = required_version
        self.installed_version = installed_version
        self.path = path
        self.message = message

    @property
    def version_ok(self) -> bool:
        """Check if the installed version meets the required minimum."""
        if not self.required_version or not self.installed_version:
            return self.installed
        return _compare_versions(self.installed_version, self.required_version) >= 0

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "type": self.dep_type,
            "installed": self.installed,
            "required_version": self.required_version,
            "installed_version": self.installed_version,
            "path": self.path,
            "version_ok": self.version_ok,
            "message": self.message,
        }


def check_dependencies(
    check_python: bool = True,
    check_system: bool = True,
    python_packages: Optional[List[str]] = None,
    system_tools: Optional[List[str]] = None,
) -> Dict[str, DependencyStatus]:
    """Check all dependencies and return their status.

    Args:
        check_python: Whether to check Python package dependencies.
        check_system: Whether to check system tool dependencies.
        python_packages: Specific Python packages to check (defaults to PYTHON_DEPS).
        system_tools: Specific system tools to check (defaults to SYSTEM_TOOLS).

    Returns:
        Dict mapping dependency name → DependencyStatus.
    """
    results: Dict[str, DependencyStatus] = {}

    if check_python:
        packages = python_packages or list(PYTHON_DEPS.keys())
        for pkg in packages:
            required_version = PYTHON_DEPS.get(pkg, "")
            results[pkg] = _check_python_dep(pkg, required_version)

    if check_system:
        tools = system_tools or SYSTEM_TOOLS
        for tool in tools:
            results[tool] = _check_system_dep(tool)

    return results


def check_python_package(package: str, min_version: str = "") -> DependencyStatus:
    """Check a single Python package dependency."""
    return _check_python_dep(package, min_version)


def check_system_tool(tool_name: str) -> DependencyStatus:
    """Check a single system tool dependency."""
    return _check_system_dep(tool_name)


def get_missing_dependencies(results: Optional[Dict[str, DependencyStatus]] = None) -> List[str]:
    """Return a list of names of missing or version-mismatched dependencies."""
    if results is None:
        results = check_dependencies()
    missing = []
    for name, status in results.items():
        if not status.installed or not status.version_ok:
            missing.append(name)
    return missing


def _check_python_dep(package: str, required_version: str = "") -> DependencyStatus:
    """Check a Python package and its version."""
    # Map package names to import names
    import_map = {
        "beautifulsoup4": "bs4",
        "Pillow": "PIL",
        "pyyaml": "yaml",
        "python-dateutil": "dateutil",
        "scapy": "scapy.all",
    }
    import_name = import_map.get(package, package)

    try:
        mod = importlib.import_module(import_name)
        installed_version = getattr(mod, "__version__", "")

        # Try to get version from importlib.metadata as fallback
        if not installed_version:
            try:
                from importlib.metadata import version as meta_version
                installed_version = meta_version(package)
            except Exception:
                installed_version = "unknown"

        if required_version and installed_version and installed_version != "unknown":
            version_ok = _compare_versions(installed_version, required_version) >= 0
            message = "" if version_ok else f"Requires ≥{required_version}, found {installed_version}"
        else:
            version_ok = True
            message = ""

        return DependencyStatus(
            name=package,
            dep_type="python",
            installed=True,
            required_version=required_version,
            installed_version=installed_version,
            path=getattr(mod, "__file__", ""),
            message=message,
        )
    except ImportError:
        return DependencyStatus(
            name=package,
            dep_type="python",
            installed=False,
            required_version=required_version,
            message=f"Not installed (requires ≥{required_version})" if required_version else "Not installed",
        )


def _check_system_dep(tool_name: str) -> DependencyStatus:
    """Check a system tool dependency."""
    tool_path = which_tool(tool_name)

    if tool_path is None:
        return DependencyStatus(
            name=tool_name,
            dep_type="system",
            installed=False,
            message="Not found on PATH",
        )

    # Try to get version
    installed_version = _get_tool_version(tool_name, tool_path)

    return DependencyStatus(
        name=tool_name,
        dep_type="system",
        installed=True,
        installed_version=installed_version,
        path=tool_path,
    )


def _get_tool_version(tool_name: str, tool_path: str) -> str:
    """Attempt to get the version string of a system tool."""
    version_flags = ["--version", "-V", "version"]
    for flag in version_flags:
        try:
            result = subprocess.run(
                [tool_path, flag],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = (result.stdout or result.stderr or "").strip()
            if output:
                # Extract version number from output
                import re
                match = re.search(r"(\d+\.\d+(?:\.\d+)?)", output)
                if match:
                    return match.group(1)
                return output.split("\n")[0][:50]
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue
    return ""


def _compare_versions(installed: str, required: str) -> int:
    """Compare two version strings. Returns >0 if installed > required."""
    def normalize(v: str) -> list:
        parts = []
        for segment in v.split("."):
            num = ""
            for ch in segment:
                if ch.isdigit():
                    num += ch
                else:
                    break
            parts.append(int(num) if num else 0)
        return parts

    a = normalize(installed)
    b = normalize(required)
    max_len = max(len(a), len(b))
    a.extend([0] * (max_len - len(a)))
    b.extend([0] * (max_len - len(b)))

    for x, y in zip(a, b):
        if x != y:
            return x - y
    return 0
