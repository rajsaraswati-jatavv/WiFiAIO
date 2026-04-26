"""Tool detector for discovering installed security tools.

Scans the system for WiFi security tools, checks versions,
and reports availability and compatibility.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from wifi_aio.exceptions import AutomationError

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """Category of a security tool."""
    SCANNING = "scanning"
    CAPTURE = "capture"
    CRACKING = "cracking"
    WPS = "wps"
    MITM = "mitm"
    MONITORING = "monitoring"
    NETWORK = "network"
    ANALYSIS = "analysis"
    SPOOFING = "spoofing"
    EXPLOITATION = "exploitation"
    FORENSICS = "forensics"


class ToolStatus(Enum):
    """Installation status of a tool."""
    INSTALLED = "installed"
    NOT_FOUND = "not_found"
    VERSION_MISMATCH = "version_mismatch"
    NO_PERMISSION = "no_permission"


@dataclass
class ToolInfo:
    """Information about a detected security tool.

    Attributes:
        name: Tool name.
        category: Tool category.
        status: Installation status.
        path: Full path to the binary.
        version: Detected version string.
        min_version: Minimum required version.
        description: Brief description.
        requires_root: Whether root is needed.
        capabilities: List of capability strings.
    """

    name: str = ""
    category: ToolCategory = ToolCategory.SCANNING
    status: ToolStatus = ToolStatus.NOT_FOUND
    path: str = ""
    version: str = ""
    min_version: str = ""
    description: str = ""
    requires_root: bool = False
    capabilities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "status": self.status.value,
            "path": self.path,
            "version": self.version,
            "min_version": self.min_version,
            "description": self.description,
            "requires_root": self.requires_root,
            "capabilities": self.capabilities,
        }

    @property
    def is_available(self) -> bool:
        return self.status == ToolStatus.INSTALLED


# Registry of known WiFi security tools
TOOL_REGISTRY: list[dict[str, Any]] = [
    {
        "name": "aircrack-ng",
        "binary": "aircrack-ng",
        "category": ToolCategory.CRACKING,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "min_version": "1.6",
        "description": "WEP/WPA-PSK key cracker",
        "requires_root": False,
        "capabilities": ["wep_crack", "wpa_crack", "dictionary"],
    },
    {
        "name": "airodump-ng",
        "binary": "airodump-ng",
        "category": ToolCategory.SCANNING,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "description": "Packet capture and AP discovery",
        "requires_root": True,
        "capabilities": ["scan", "capture", "csv_export"],
    },
    {
        "name": "aireplay-ng",
        "binary": "aireplay-ng",
        "category": ToolCategory.CAPTURE,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "description": "Frame injection (deauth, fake auth, ARP replay)",
        "requires_root": True,
        "capabilities": ["deauth", "fake_auth", "arp_replay", "injection"],
    },
    {
        "name": "airmon-ng",
        "binary": "airmon-ng",
        "category": ToolCategory.CAPTURE,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "description": "Monitor mode management",
        "requires_root": True,
        "capabilities": ["monitor_mode", "kill_network_manager"],
    },
    {
        "name": "hashcat",
        "binary": "hashcat",
        "category": ToolCategory.CRACKING,
        "version_flag": "--version",
        "version_regex": r"v(\d+\.\d+[\.\d]*)",
        "min_version": "6.0",
        "description": "GPU-accelerated password cracker",
        "requires_root": False,
        "capabilities": ["dictionary", "mask", "hybrid", "rule", "gpu"],
    },
    {
        "name": "john",
        "binary": "john",
        "category": ToolCategory.CRACKING,
        "version_flag": "--list=build-info",
        "version_regex": r"version:\s*(\d+\.\d+[\.\d]*)",
        "description": "John the Ripper password cracker",
        "requires_root": False,
        "capabilities": ["dictionary", "incremental", "rules", "wpapsk"],
    },
    {
        "name": "reaver",
        "binary": "reaver",
        "category": ToolCategory.WPS,
        "version_flag": "--version",
        "version_regex": r"reaver\s+v(\d+\.\d+[\.\d]*)",
        "description": "WPS PIN brute-force and Pixie Dust",
        "requires_root": True,
        "capabilities": ["pixie_dust", "pin_bruteforce"],
    },
    {
        "name": "bully",
        "binary": "bully",
        "category": ToolCategory.WPS,
        "version_flag": "--help",
        "version_regex": r"bully\s+v(\d+\.\d+[\.\d]*)",
        "description": "WPS PIN brute-force alternative",
        "requires_root": True,
        "capabilities": ["pixie_dust", "pin_bruteforce"],
    },
    {
        "name": "wash",
        "binary": "wash",
        "category": ToolCategory.WPS,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "description": "WPS network scanner",
        "requires_root": True,
        "capabilities": ["wps_scan"],
    },
    {
        "name": "bettercap",
        "binary": "bettercap",
        "category": ToolCategory.MITM,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "description": "MITM, ARP spoofing, network attack framework",
        "requires_root": True,
        "capabilities": ["arp_spoof", "dns_spoof", "sniff", "proxy", "wifi"],
    },
    {
        "name": "kismet",
        "binary": "kismet",
        "category": ToolCategory.MONITORING,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "description": "Wireless IDS and monitor",
        "requires_root": True,
        "capabilities": ["passive_scan", "alert", "device_tracking"],
    },
    {
        "name": "nmap",
        "binary": "nmap",
        "category": ToolCategory.NETWORK,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "description": "Network scanner and service enumerator",
        "requires_root": False,
        "capabilities": ["port_scan", "os_detect", "vuln_scan", "service_detect"],
    },
    {
        "name": "tshark",
        "binary": "tshark",
        "category": ToolCategory.ANALYSIS,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "description": "Command-line network protocol analyzer",
        "requires_root": True,
        "capabilities": ["capture", "decode", "filter", "statistics"],
    },
    {
        "name": "macchanger",
        "binary": "macchanger",
        "category": ToolCategory.SPOOFING,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "description": "MAC address spoofing utility",
        "requires_root": True,
        "capabilities": ["mac_randomize", "mac_set", "mac_reset"],
    },
    {
        "name": "hostapd",
        "binary": "hostapd",
        "category": ToolCategory.EXPLOITATION,
        "version_flag": "-v",
        "version_regex": r"hostapd\s+v(\d+\.\d+[\.\d]*)",
        "description": "Rogue AP / access point daemon",
        "requires_root": True,
        "capabilities": ["rogue_ap", "evil_twin"],
    },
    {
        "name": "dnsmasq",
        "binary": "dnsmasq",
        "category": ToolCategory.EXPLOITATION,
        "version_flag": "--version",
        "version_regex": r"Dnsmasq\s+version\s+(\d+\.\d+[\.\d]*)",
        "description": "DHCP/DNS server for rogue APs",
        "requires_root": True,
        "capabilities": ["dhcp", "dns"],
    },
    {
        "name": "hcxpcapngtool",
        "binary": "hcxpcapngtool",
        "category": ToolCategory.CRACKING,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "description": "Convert PCAP to hashcat formats",
        "requires_root": False,
        "capabilities": ["pcap_convert", "pmkid_extract", "hash_conversion"],
    },
    {
        "name": "hcxdumptool",
        "binary": "hcxdumptool",
        "category": ToolCategory.CAPTURE,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "description": "PMKID/handshake capture tool",
        "requires_root": True,
        "capabilities": ["pmkid_capture", "handshake_capture"],
    },
    {
        "name": "mdk4",
        "binary": "mdk4",
        "category": ToolCategory.EXPLOITATION,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "description": "WiFi DoS and frame injection tool",
        "requires_root": True,
        "capabilities": ["deauth", "beacon_flood", "auth_dos"],
    },
    {
        "name": "wireshark",
        "binary": "wireshark",
        "category": ToolCategory.ANALYSIS,
        "version_flag": "--version",
        "version_regex": r"(\d+\.\d+[\.\d]*)",
        "description": "GUI network protocol analyzer",
        "requires_root": False,
        "capabilities": ["gui_analysis", "pcap_read"],
    },
]


class ToolDetector:
    """Detect which security tools are installed on the system.

    Scans for tools in the PATH and common installation directories,
    checks versions, and reports availability.

    Example::

        detector = ToolDetector()
        results = detector.detect_all()
        for tool in results:
            print(f"{tool.name}: {tool.status.value} ({tool.version})")

        available = detector.get_available_tools()
        missing = detector.get_missing_tools()
        categories = detector.get_by_category(ToolCategory.CRACKING)
    """

    EXTRA_PATHS = [
        "/usr/sbin",
        "/usr/local/sbin",
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/opt/local/bin",
        "/snap/bin",
        "/usr/bin",
        "/sbin",
    ]

    def __init__(self) -> None:
        self._results: dict[str, ToolInfo] = {}

    def _find_binary(self, name: str) -> Optional[str]:
        """Find a binary on the system."""
        # Check PATH first
        found = shutil.which(name)
        if found:
            return found

        # Check extra paths
        for directory in self.EXTRA_PATHS:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate

        return None

    def _get_version(self, path: str, version_flag: str, version_regex: str) -> str:
        """Get the version string from a tool."""
        try:
            result = subprocess.run(
                [path, version_flag],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout + result.stderr
            match = re.search(version_regex, output)
            if match:
                return match.group(1)
        except (subprocess.TimeoutExpired, OSError):
            pass
        return ""

    def _check_root_access(self) -> bool:
        """Check if we have root privileges."""
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False

    # ── Detection ──────────────────────────────────────────────────────

    def detect(self, tool_name: str) -> ToolInfo:
        """Detect a single tool by name.

        Args:
            tool_name: Name from the TOOL_REGISTRY.

        Returns:
            ToolInfo with detection results.
        """
        # Find tool in registry
        registry_entry = None
        for entry in TOOL_REGISTRY:
            if entry["name"] == tool_name:
                registry_entry = entry
                break

        if registry_entry is None:
            # Custom tool – try to find it anyway
            path = self._find_binary(tool_name)
            return ToolInfo(
                name=tool_name,
                status=ToolStatus.INSTALLED if path else ToolStatus.NOT_FOUND,
                path=path or "",
            )

        binary = registry_entry["binary"]
        path = self._find_binary(binary)

        info = ToolInfo(
            name=registry_entry["name"],
            category=registry_entry["category"],
            description=registry_entry.get("description", ""),
            requires_root=registry_entry.get("requires_root", False),
            capabilities=registry_entry.get("capabilities", []),
            min_version=registry_entry.get("min_version", ""),
        )

        if path is None:
            info.status = ToolStatus.NOT_FOUND
            self._results[info.name] = info
            return info

        info.path = path

        # Get version
        version_flag = registry_entry.get("version_flag", "--version")
        version_regex = registry_entry.get("version_regex", r"(\d+\.\d+[\.\d]*)")
        version = self._get_version(path, version_flag, version_regex)
        info.version = version

        # Check minimum version
        if info.min_version and version:
            try:
                if self._compare_versions(version, info.min_version) < 0:
                    info.status = ToolStatus.VERSION_MISMATCH
                    self._results[info.name] = info
                    return info
            except (ValueError, IndexError):
                pass

        # Check root requirement
        if info.requires_root and not self._check_root_access():
            info.status = ToolStatus.NO_PERMISSION
        else:
            info.status = ToolStatus.INSTALLED

        self._results[info.name] = info
        return info

    def detect_all(self) -> list[ToolInfo]:
        """Detect all tools in the registry.

        Returns:
            List of ToolInfo for every registered tool.
        """
        results: list[ToolInfo] = []
        for entry in TOOL_REGISTRY:
            info = self.detect(entry["name"])
            results.append(info)
        return results

    def detect_custom(self, binary: str, name: Optional[str] = None) -> ToolInfo:
        """Detect a custom tool not in the registry.

        Args:
            binary: Binary name to search for.
            name: Optional display name.

        Returns:
            ToolInfo with detection results.
        """
        path = self._find_binary(binary)
        version = ""
        if path:
            version = self._get_version(path, "--version", r"(\d+\.\d+[\.\d]*)")

        info = ToolInfo(
            name=name or binary,
            status=ToolStatus.INSTALLED if path else ToolStatus.NOT_FOUND,
            path=path or "",
            version=version,
        )
        self._results[info.name] = info
        return info

    # ── Queries ────────────────────────────────────────────────────────

    def get_available_tools(self) -> list[ToolInfo]:
        """Get all installed and available tools."""
        if not self._results:
            self.detect_all()
        return [t for t in self._results.values() if t.is_available]

    def get_missing_tools(self) -> list[ToolInfo]:
        """Get all tools that are not installed."""
        if not self._results:
            self.detect_all()
        return [t for t in self._results.values() if not t.is_available]

    def get_by_category(self, category: ToolCategory) -> list[ToolInfo]:
        """Get tools filtered by category."""
        if not self._results:
            self.detect_all()
        return [t for t in self._results.values() if t.category == category]

    def get_tool(self, name: str) -> Optional[ToolInfo]:
        """Look up a specific tool by name."""
        if name not in self._results:
            return self.detect(name)
        return self._results.get(name)

    def get_capabilities(self) -> dict[str, list[str]]:
        """Get a mapping of capability → list of tools that provide it."""
        if not self._results:
            self.detect_all()

        capabilities: dict[str, list[str]] = {}
        for tool in self._results.values():
            if tool.is_available:
                for cap in tool.capabilities:
                    capabilities.setdefault(cap, []).append(tool.name)
        return capabilities

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of tool availability."""
        if not self._results:
            self.detect_all()

        total = len(self._results)
        installed = sum(1 for t in self._results.values() if t.is_available)
        by_category: dict[str, int] = {}
        for t in self._results.values():
            if t.is_available:
                by_category[t.category.value] = by_category.get(t.category.value, 0) + 1

        return {
            "total_tools": total,
            "installed": installed,
            "missing": total - installed,
            "by_category": by_category,
            "root_available": self._check_root_access(),
        }

    # ── Version comparison ─────────────────────────────────────────────

    @staticmethod
    def _compare_versions(v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""
        parts1 = [int(p) for p in v1.split(".") if p.isdigit()]
        parts2 = [int(p) for p in v2.split(".") if p.isdigit()]

        for a, b in zip(parts1, parts2):
            if a < b:
                return -1
            if a > b:
                return 1

        if len(parts1) < len(parts2):
            return -1
        if len(parts1) > len(parts2):
            return 1
        return 0

    def __repr__(self) -> str:
        return f"ToolDetector(tools_scanned={len(self._results)})"
