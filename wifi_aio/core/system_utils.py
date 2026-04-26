"""System utility functions for WiFiAIO.

Provides root privilege checking, CPU/memory information,
process management, and service management.
"""

import logging
import os
import re
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import (
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


class SystemUtils:
    """System-level utilities for WiFiAIO operations."""

    # ------------------------------------------------------------------
    # Root / Permission checks
    # ------------------------------------------------------------------

    @staticmethod
    def is_root() -> bool:
        """Check if the current process is running as root.

        Returns:
            True if running as root (UID 0).
        """
        return os.geteuid() == 0

    @staticmethod
    def require_root(action: str = "this operation") -> None:
        """Raise an exception if not running as root.

        Args:
            action: Description of the operation for the error message.

        Raises:
            WiFiPermissionError: If not running as root.
        """
        if os.geteuid() != 0:
            raise WiFiPermissionError(f"Root privileges required for {action}")

    @staticmethod
    def get_current_user() -> str:
        """Get the current username.

        Returns:
            Username string.
        """
        import getpass
        try:
            return getpass.getuser()
        except Exception:
            return os.environ.get("USER", "unknown")

    # ------------------------------------------------------------------
    # CPU / Memory information
    # ------------------------------------------------------------------

    @staticmethod
    def get_cpu_info() -> Dict[str, str]:
        """Get CPU information.

        Returns:
            Dict with CPU details: model, cores, architecture, frequency.
        """
        info: Dict[str, str] = {
            "model": "unknown",
            "cores": "0",
            "architecture": "unknown",
            "frequency_mhz": "0",
        }

        try:
            import psutil
            info["cores"] = str(psutil.cpu_count(logical=True))
            info["physical_cores"] = str(psutil.cpu_count(logical=False))
            freq = psutil.cpu_freq()
            if freq:
                info["frequency_mhz"] = str(round(freq.current, 1))
                info["max_frequency_mhz"] = str(round(freq.max, 1))
        except ImportError:
            pass

        # Read from /proc/cpuinfo on Linux
        try:
            with open("/proc/cpuinfo", "r") as fh:
                for line in fh:
                    if line.startswith("model name"):
                        info["model"] = line.split(":")[1].strip()
                    elif line.startswith("cpu MHz"):
                        info["frequency_mhz"] = line.split(":")[1].strip()
                    elif line.startswith("cpu cores"):
                        info["cores"] = line.split(":")[1].strip()
        except OSError:
            pass

        # Architecture
        import platform
        info["architecture"] = platform.machine()

        return info

    @staticmethod
    def get_memory_info() -> Dict[str, float]:
        """Get memory information.

        Returns:
            Dict with memory stats in MB: total, available, used, percent.
        """
        info: Dict[str, float] = {
            "total_mb": 0.0,
            "available_mb": 0.0,
            "used_mb": 0.0,
            "percent": 0.0,
        }

        try:
            import psutil
            mem = psutil.virtual_memory()
            info["total_mb"] = round(mem.total / (1024 * 1024), 1)
            info["available_mb"] = round(mem.available / (1024 * 1024), 1)
            info["used_mb"] = round(mem.used / (1024 * 1024), 1)
            info["percent"] = round(mem.percent, 1)
            info["swap_total_mb"] = round(psutil.swap_memory().total / (1024 * 1024), 1)
            info["swap_used_mb"] = round(psutil.swap_memory().used / (1024 * 1024), 1)
            info["swap_percent"] = round(psutil.swap_memory().percent, 1)
        except ImportError:
            # Fallback: read /proc/meminfo
            try:
                with open("/proc/meminfo", "r") as fh:
                    for line in fh:
                        parts = line.split()
                        if len(parts) >= 2:
                            key = parts[0].rstrip(":")
                            value_kb = int(parts[1])
                            value_mb = round(value_kb / 1024, 1)
                            if key == "MemTotal":
                                info["total_mb"] = value_mb
                            elif key == "MemAvailable":
                                info["available_mb"] = value_mb
                            elif key == "MemFree":
                                if info["available_mb"] == 0:
                                    info["available_mb"] = value_mb
                            elif key == "SwapTotal":
                                info["swap_total_mb"] = value_mb
                            elif key == "SwapFree":
                                swap_used = info.get("swap_total_mb", 0) - value_mb
                                info["swap_used_mb"] = round(swap_used, 1)
                    info["used_mb"] = round(info["total_mb"] - info["available_mb"], 1)
                    if info["total_mb"] > 0:
                        info["percent"] = round(info["used_mb"] / info["total_mb"] * 100, 1)
            except OSError:
                pass

        return info

    @staticmethod
    def get_disk_info() -> List[Dict[str, float]]:
        """Get disk usage information.

        Returns:
            List of dicts with disk stats: mount, total_gb, used_gb, free_gb, percent.
        """
        disks = []

        try:
            import psutil
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disks.append({
                        "mount": partition.mountpoint,
                        "device": partition.device,
                        "fstype": partition.fstype,
                        "total_gb": round(usage.total / (1024 ** 3), 2),
                        "used_gb": round(usage.used / (1024 ** 3), 2),
                        "free_gb": round(usage.free / (1024 ** 3), 2),
                        "percent": round(usage.percent, 1),
                    })
                except PermissionError:
                    continue
        except ImportError:
            # Fallback: df command
            try:
                result = subprocess.run(
                    ["df", "-h", "-P"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        disks.append({
                            "mount": parts[5],
                            "device": parts[0],
                            "total_gb": float(parts[1].rstrip("G")),
                            "used_gb": float(parts[2].rstrip("G")),
                            "free_gb": float(parts[3].rstrip("G")),
                            "percent": float(parts[4].rstrip("%")),
                        })
            except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
                pass

        return disks

    @staticmethod
    def get_system_load() -> Dict[str, float]:
        """Get system load averages.

        Returns:
            Dict with: load_1min, load_5min, load_15min.
        """
        try:
            load1, load5, load15 = os.getloadavg()
            return {
                "load_1min": round(load1, 2),
                "load_5min": round(load5, 2),
                "load_15min": round(load15, 2),
            }
        except OSError:
            # Fallback
            try:
                with open("/proc/loadavg", "r") as fh:
                    parts = fh.read().split()
                    return {
                        "load_1min": float(parts[0]),
                        "load_5min": float(parts[1]),
                        "load_15min": float(parts[2]),
                    }
            except (OSError, ValueError, IndexError):
                return {"load_1min": 0.0, "load_5min": 0.0, "load_15min": 0.0}

    def get_system_info(self) -> Dict:
        """Get comprehensive system information.

        Returns:
            Dict with CPU, memory, disk, load, OS info.
        """
        import platform

        return {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "kernel": platform.release(),
            "cpu": self.get_cpu_info(),
            "memory": self.get_memory_info(),
            "disk": self.get_disk_info(),
            "load": self.get_system_load(),
            "is_root": self.is_root(),
            "user": self.get_current_user(),
        }

    # ------------------------------------------------------------------
    # Process management
    # ------------------------------------------------------------------

    @staticmethod
    def list_processes(
        name_filter: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """List running processes.

        Args:
            name_filter: Optional process name filter (case-insensitive).

        Returns:
            List of dicts with: pid, name, user, cpu_percent, memory_mb.
        """
        processes = []

        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_info"]):
                try:
                    info = proc.info
                    name = info.get("name", "")
                    if name_filter and name_filter.lower() not in name.lower():
                        continue
                    mem_info = info.get("memory_info")
                    processes.append({
                        "pid": str(info.get("pid", "")),
                        "name": name,
                        "user": info.get("username", ""),
                        "cpu_percent": str(info.get("cpu_percent", 0)),
                        "memory_mb": str(round(mem_info.rss / (1024 * 1024), 1)) if mem_info else "0",
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except ImportError:
            # Fallback: ps command
            try:
                cmd = ["ps", "aux"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                for line in result.stdout.splitlines()[1:]:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        name = parts[10].split("/")[-1]
                        if name_filter and name_filter.lower() not in name.lower():
                            continue
                        processes.append({
                            "pid": parts[1],
                            "name": name,
                            "user": parts[0],
                            "cpu_percent": parts[2],
                            "memory_mb": str(round(float(parts[5]) / 1024, 1)),
                        })
            except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
                pass

        return processes

    @staticmethod
    def kill_process(pid: int, signal: str = "SIGTERM") -> bool:
        """Kill a process by PID.

        Args:
            pid: Process ID.
            signal: Signal to send (SIGTERM, SIGKILL, etc.).

        Returns:
            True if the process was killed successfully.
        """
        try:
            import psutil
            proc = psutil.Process(pid)
            sig = getattr(psutil.signal, signal, psutil.signal.SIGTERM)
            proc.send_signal(sig)
            return True
        except ImportError:
            pass
        except Exception:
            pass

        # Fallback: os.kill
        try:
            import signal as sig_module
            sig_num = getattr(sig_module, signal, sig_module.SIGTERM)
            os.kill(pid, sig_num)
            return True
        except (OSError, ProcessLookupError):
            return False

    @staticmethod
    def kill_process_by_name(name: str) -> int:
        """Kill all processes matching a name.

        Args:
            name: Process name to match.

        Returns:
            Number of processes killed.
        """
        killed = 0
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    if proc.info["name"] and name.lower() in proc.info["name"].lower():
                        proc.kill()
                        killed += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except ImportError:
            try:
                result = subprocess.run(
                    ["pkill", "-f", name],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    killed = 1  # pkill doesn't easily return count
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return killed

    @staticmethod
    def get_process_info(pid: int) -> Optional[Dict]:
        """Get detailed information about a specific process.

        Args:
            pid: Process ID.

        Returns:
            Dict with process info or None.
        """
        try:
            import psutil
            proc = psutil.Process(pid)
            return {
                "pid": proc.pid,
                "name": proc.name(),
                "exe": proc.exe() if proc.exe() else "",
                "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else "",
                "status": proc.status(),
                "username": proc.username(),
                "cpu_percent": proc.cpu_percent(),
                "memory_mb": round(proc.memory_info().rss / (1024 * 1024), 1),
                "create_time": proc.create_time(),
                "num_threads": proc.num_threads(),
                "ppid": proc.ppid(),
            }
        except ImportError:
            pass
        except Exception:
            pass

        # Fallback
        try:
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "pid,ppid,user,%cpu,%mem,stat,comm,args"],
                capture_output=True, text=True, timeout=5,
            )
            lines = result.stdout.strip().splitlines()
            if len(lines) >= 2:
                parts = lines[1].split(None, 7)
                return {
                    "pid": parts[0],
                    "ppid": parts[1] if len(parts) > 1 else "",
                    "username": parts[2] if len(parts) > 2 else "",
                    "cpu_percent": parts[3] if len(parts) > 3 else "",
                    "memory_percent": parts[4] if len(parts) > 4 else "",
                    "status": parts[5] if len(parts) > 5 else "",
                    "name": parts[6] if len(parts) > 6 else "",
                    "cmdline": parts[7] if len(parts) > 7 else "",
                }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return None

    # ------------------------------------------------------------------
    # Service management
    # ------------------------------------------------------------------

    @staticmethod
    def start_service(service_name: str) -> bool:
        """Start a system service.

        Args:
            service_name: Name of the service (e.g., 'NetworkManager').

        Returns:
            True if the service started successfully.
        """
        try:
            result = subprocess.run(
                ["systemctl", "start", service_name],
                capture_output=True, text=True, timeout=30,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Try service command
            try:
                result = subprocess.run(
                    ["service", service_name, "start"],
                    capture_output=True, text=True, timeout=30,
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return False

    @staticmethod
    def stop_service(service_name: str) -> bool:
        """Stop a system service.

        Args:
            service_name: Name of the service.

        Returns:
            True if the service stopped successfully.
        """
        try:
            result = subprocess.run(
                ["systemctl", "stop", service_name],
                capture_output=True, text=True, timeout=30,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            try:
                result = subprocess.run(
                    ["service", service_name, "stop"],
                    capture_output=True, text=True, timeout=30,
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return False

    @staticmethod
    def restart_service(service_name: str) -> bool:
        """Restart a system service.

        Returns:
            True if the service restarted successfully.
        """
        try:
            result = subprocess.run(
                ["systemctl", "restart", service_name],
                capture_output=True, text=True, timeout=30,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            try:
                result = subprocess.run(
                    ["service", service_name, "restart"],
                    capture_output=True, text=True, timeout=30,
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return False

    @staticmethod
    def get_service_status(service_name: str) -> Dict[str, str]:
        """Get the status of a system service.

        Returns:
            Dict with: active, status, description.
        """
        status: Dict[str, str] = {
            "service": service_name,
            "active": "unknown",
            "status": "unknown",
        }

        try:
            result = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True, text=True, timeout=10,
            )
            status["active"] = result.stdout.strip()

            result = subprocess.run(
                ["systemctl", "status", service_name],
                capture_output=True, text=True, timeout=10,
            )
            # Extract description
            for line in result.stdout.splitlines():
                if "Description=" in line or service_name in line.lower():
                    match = re.search(r"[-–]\s+(.+)", line)
                    if match:
                        status["description"] = match.group(1).strip()
                        break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Try service command
            try:
                result = subprocess.run(
                    ["service", service_name, "status"],
                    capture_output=True, text=True, timeout=10,
                )
                if "running" in result.stdout.lower():
                    status["active"] = "active"
                elif "stopped" in result.stdout.lower():
                    status["active"] = "inactive"
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return status

    @staticmethod
    def enable_service(service_name: str) -> bool:
        """Enable a service to start on boot.

        Returns:
            True if successful.
        """
        try:
            result = subprocess.run(
                ["systemctl", "enable", service_name],
                capture_output=True, text=True, timeout=30,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    @staticmethod
    def disable_service(service_name: str) -> bool:
        """Disable a service from starting on boot.

        Returns:
            True if successful.
        """
        try:
            result = subprocess.run(
                ["systemctl", "disable", service_name],
                capture_output=True, text=True, timeout=30,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    # ------------------------------------------------------------------
    # Network utilities
    # ------------------------------------------------------------------

    @staticmethod
    def get_network_interfaces() -> List[Dict[str, str]]:
        """Get list of all network interfaces.

        Returns:
            List of dicts with: name, state, mac, ip, mtu.
        """
        interfaces = []

        try:
            import psutil
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()

            for name, addr_list in addrs.items():
                iface = {"name": name, "ip": "", "mac": "", "state": "unknown", "mtu": "0"}

                for addr in addr_list:
                    if addr.family.name == "AF_INET":
                        iface["ip"] = addr.address
                    elif addr.family.name == "AF_PACKET":
                        iface["mac"] = addr.address

                if name in stats:
                    iface["state"] = "up" if stats[name].isup else "down"
                    iface["mtu"] = str(stats[name].mtu)

                interfaces.append(iface)
        except ImportError:
            # Fallback
            try:
                result = subprocess.run(
                    ["ip", "addr", "show"],
                    capture_output=True, text=True, timeout=10,
                )
                current = {}
                for line in result.stdout.splitlines():
                    match = re.match(r"^\d+:\s+(\S+):", line)
                    if match:
                        if current:
                            interfaces.append(current)
                        name = match.group(1).rstrip("@").split("@")[0]
                        current = {"name": name, "ip": "", "mac": "", "state": "unknown", "mtu": "0"}
                    elif current:
                        if "link/ether" in line:
                            current["mac"] = line.split()[1]
                        elif "inet " in line:
                            current["ip"] = line.split()[1].split("/")[0]
                        elif "state UP" in line:
                            current["state"] = "up"
                        elif "state DOWN" in line:
                            current["state"] = "down"
                if current:
                    interfaces.append(current)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return interfaces

    @staticmethod
    def get_default_gateway() -> str:
        """Get the default gateway IP address.

        Returns:
            Gateway IP string.
        """
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
            parts = result.stdout.split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Fallback: read /proc/net/route
        try:
            with open("/proc/net/route", "r") as fh:
                for line in fh:
                    fields = line.strip().split()
                    if len(fields) >= 3 and fields[1] == "00000000":
                        # Convert packed IP
                        packed = int(fields[2], 16)
                        return f"{packed & 0xFF}.{(packed >> 8) & 0xFF}.{(packed >> 16) & 0xFF}.{(packed >> 24) & 0xFF}"
        except OSError:
            pass

        return ""

    @staticmethod
    def get_dns_servers() -> List[str]:
        """Get configured DNS servers.

        Returns:
            List of DNS server IP addresses.
        """
        servers = []

        # Try resolv.conf
        try:
            with open("/etc/resolv.conf", "r") as fh:
                for line in fh:
                    if line.startswith("nameserver"):
                        server = line.split()[1]
                        servers.append(server)
        except OSError:
            pass

        # Try systemd-resolve
        if not servers:
            try:
                result = subprocess.run(
                    ["resolvectl", "status"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in result.stdout.splitlines():
                    if "DNS Servers:" in line:
                        match = re.findall(r"(\d+\.\d+\.\d+\.\d+)", line)
                        servers.extend(match)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return servers

    # ------------------------------------------------------------------
    # Package management
    # ------------------------------------------------------------------

    @staticmethod
    def is_installed(command: str) -> bool:
        """Check if a command/tool is installed.

        Args:
            command: Command name to check.

        Returns:
            True if the command is found in PATH.
        """
        return shutil.which(command) is not None

    @staticmethod
    def install_package(package: str) -> bool:
        """Install a system package.

        Tries apt, dnf, pacman, and apk.

        Returns:
            True if installation was successful.
        """
        package_managers = [
            (["apt-get", "install", "-y", package], "apt"),
            (["dnf", "install", "-y", package], "dnf"),
            (["pacman", "-S", "--noconfirm", package], "pacman"),
            (["apk", "add", package], "apk"),
        ]

        for cmd, manager in package_managers:
            if shutil.which(cmd[0]):
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True, text=True, timeout=300,
                    )
                    if result.returncode == 0:
                        return True
                except subprocess.TimeoutExpired:
                    continue

        return False

    @staticmethod
    def check_dependencies(tools: List[str]) -> Dict[str, bool]:
        """Check which tools are installed.

        Args:
            tools: List of tool/command names.

        Returns:
            Dict mapping tool name -> installed (bool).
        """
        return {tool: shutil.which(tool) is not None for tool in tools}
