"""Cracking speed benchmarking.

Benchmarks WPA/WPA2 cracking speed across different engines (pure
Python, hashcat, aircrack-ng) and provides performance metrics for
planning cracking sessions.
"""

import hashlib
import hmac
import os
import struct
import time
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import CrackingError, WiFiPermissionError, WiFiTimeoutError
from wifi_aio.utils import run_command


# ── Benchmark defaults ─────────────────────────────────────────────────

BENCHMARK_DURATION = 10  # seconds
BENCHMARK_PASSWORD = "benchmark123"
BENCHMARK_SSID = "BenchmarkAP"


class BenchmarkResult:
    """Result of a single benchmark run."""

    def __init__(
        self,
        engine: str,
        speed: float,
        duration: float,
        iterations: int,
        device: str = "",
        notes: str = "",
    ) -> None:
        self.engine = engine
        self.speed = speed  # passwords/second
        self.duration = duration
        self.iterations = iterations
        self.device = device
        self.notes = notes

    @property
    def speed_khs(self) -> float:
        """Speed in thousands of hashes per second."""
        return self.speed / 1000.0

    @property
    def speed_mhs(self) -> float:
        """Speed in millions of hashes per second."""
        return self.speed / 1_000_000.0

    def estimate_time(self, total_passwords: int) -> float:
        """Estimate time in seconds to test *total_passwords*."""
        return total_passwords / self.speed if self.speed > 0 else float("inf")

    def estimate_time_str(self, total_passwords: int) -> str:
        """Return a human-readable time estimate."""
        seconds = self.estimate_time(total_passwords)
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds / 60:.1f}m"
        elif seconds < 86400:
            return f"{seconds / 3600:.1f}h"
        elif seconds < 86400 * 365:
            return f"{seconds / 86400:.1f}d"
        else:
            return f"{seconds / (86400 * 365):.1f}y"

    def to_dict(self) -> Dict:
        return {
            "engine": self.engine,
            "speed": self.speed,
            "speed_khs": self.speed_khs,
            "speed_mhs": self.speed_mhs,
            "duration": self.duration,
            "iterations": self.iterations,
            "device": self.device,
            "notes": self.notes,
        }

    def __repr__(self) -> str:
        if self.speed >= 1_000_000:
            speed_str = f"{self.speed_mhs:.2f} MH/s"
        elif self.speed >= 1000:
            speed_str = f"{self.speed_khs:.2f} KH/s"
        else:
            speed_str = f"{self.speed:.2f} H/s"
        return f"BenchmarkResult({self.engine}: {speed_str})"


class Benchmark:
    """Benchmark WPA/WPA2 cracking speed.

    Provides methods to benchmark different cracking engines and
    compare their performance.

    Parameters
    ----------
    ssid:
        SSID to use for PMK derivation benchmark.
    duration:
        Duration of each benchmark in seconds.
    """

    def __init__(
        self,
        ssid: str = BENCHMARK_SSID,
        duration: float = BENCHMARK_DURATION,
    ) -> None:
        self.ssid = ssid
        self.duration = duration

        self._results: List[BenchmarkResult] = []

    # ── Public API ─────────────────────────────────────────────────────

    def run_python(self, duration: Optional[float] = None) -> BenchmarkResult:
        """Benchmark pure-Python PBKDF2 PMK derivation."""
        dur = duration or self.duration
        ssid_bytes = self.ssid.encode("utf-8")
        iterations = 0
        start = time.monotonic()

        while time.monotonic() - start < dur:
            # Simulate the most expensive part of WPA cracking: PBKDF2
            hashlib.pbkdf2_hmac(
                "sha1",
                f"bench{iterations:08d}".encode("utf-8"),
                ssid_bytes,
                4096,
                dklen=32,
            )
            iterations += 1

        elapsed = time.monotonic() - start
        speed = iterations / elapsed

        result = BenchmarkResult(
            engine="python",
            speed=speed,
            duration=elapsed,
            iterations=iterations,
            device="CPU (Python hashlib)",
            notes="Pure Python PBKDF2-SHA1 with hashlib",
        )
        self._results.append(result)
        return result

    def run_hashcat(self, duration: Optional[float] = None) -> Optional[BenchmarkResult]:
        """Benchmark hashcat cracking speed.

        Returns ``None`` if hashcat is not available.
        """
        try:
            rc, stdout, stderr = run_command(
                ["hashcat", "-b", "-m", "22000", "--force"],
                timeout=120,
            )
        except Exception:
            return None

        if rc != 0:
            return None

        # Parse hashcat benchmark output
        speed = 0.0
        device = ""
        for line in stdout.splitlines():
            # hashcat outputs lines like:
            # Hashtype: WPA-PBKDF2-PMKID+EAPOL (22000) - 1234.5 MH/s
            if "22000" in line and "H/s" in line:
                speed = self._parse_hashcat_speed(line)
            if "Device" in line or "GPU" in line or "CPU" in line:
                device = line.strip()

        if speed == 0.0:
            # Try alternate parsing
            for line in stdout.splitlines():
                if "/s" in line and any(c.isdigit() for c in line):
                    speed = self._parse_hashcat_speed(line)
                    break

        result = BenchmarkResult(
            engine="hashcat",
            speed=speed,
            duration=duration or self.duration,
            iterations=int(speed * (duration or self.duration)),
            device=device,
            notes="hashcat GPU/CPU benchmark mode 22000",
        )
        self._results.append(result)
        return result

    def run_aircrack(self, duration: Optional[float] = None) -> Optional[BenchmarkResult]:
        """Benchmark aircrack-ng speed.

        Returns ``None`` if aircrack-ng is not available.
        """
        try:
            rc, stdout, stderr = run_command(
                ["aircrack-ng", "--help"],
                timeout=10,
            )
        except Exception:
            return None

        # aircrack-ng doesn't have a proper benchmark mode;
        # we estimate based on CPU info
        speed = self._estimate_aircrack_speed()
        result = BenchmarkResult(
            engine="aircrack-ng",
            speed=speed,
            duration=duration or self.duration,
            iterations=int(speed * (duration or self.duration)),
            device="CPU (estimated)",
            notes="Estimated speed based on CPU benchmarks",
        )
        self._results.append(result)
        return result

    def run_all(self, duration: Optional[float] = None) -> List[BenchmarkResult]:
        """Run all available benchmarks."""
        results = []

        # Python is always available
        results.append(self.run_python(duration))

        # Try hashcat
        hc_result = self.run_hashcat(duration)
        if hc_result is not None:
            results.append(hc_result)

        # Try aircrack-ng
        ac_result = self.run_aircrack(duration)
        if ac_result is not None:
            results.append(ac_result)

        return results

    @property
    def results(self) -> List[BenchmarkResult]:
        return self._results

    @property
    def best_result(self) -> Optional[BenchmarkResult]:
        """Return the fastest benchmark result."""
        if not self._results:
            return None
        return max(self._results, key=lambda r: r.speed)

    def compare(self) -> Dict:
        """Compare all benchmark results."""
        if not self._results:
            return {}

        best = self.best_result
        return {
            "best_engine": best.engine if best else None,
            "best_speed": best.speed if best else 0,
            "results": [r.to_dict() for r in self._results],
            "speedup": {
                r.engine: r.speed / self._results[0].speed
                if self._results[0].speed > 0 and r != self._results[0]
                else 1.0
                for r in self._results
            },
        }

    def estimate_crack_time(
        self,
        total_passwords: int,
        engine: Optional[str] = None,
    ) -> Dict:
        """Estimate cracking time for a given number of passwords.

        If *engine* is specified, use that engine's speed; otherwise
        use the best available result.
        """
        if engine:
            result = next((r for r in self._results if r.engine == engine), None)
        else:
            result = self.best_result

        if result is None:
            return {
                "total_passwords": total_passwords,
                "engine": None,
                "speed": 0,
                "estimated_seconds": float("inf"),
                "estimated_str": "N/A",
            }

        est = result.estimate_time(total_passwords)
        return {
            "total_passwords": total_passwords,
            "engine": result.engine,
            "speed": result.speed,
            "estimated_seconds": est,
            "estimated_str": result.estimate_time_str(total_passwords),
        }

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _parse_hashcat_speed(line: str) -> float:
        """Parse a speed value from a hashcat output line."""
        # Look for patterns like "1234.5 MH/s", "567.8 kH/s", "90.1 H/s"
        import re
        match = re.search(r"([\d,.]+)\s*([kKMGT]?)H/s", line)
        if not match:
            return 0.0

        value_str = match.group(1).replace(",", "")
        multiplier = match.group(2)

        try:
            value = float(value_str)
        except ValueError:
            return 0.0

        multipliers = {
            "": 1, "k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12,
        }
        return value * multipliers.get(multiplier, 1)

    @staticmethod
    def _estimate_aircrack_speed() -> float:
        """Estimate aircrack-ng speed based on CPU count."""
        cpu_count = os.cpu_count() or 1
        # Rough estimate: ~500-1000 PMK/s per CPU core with aircrack-ng
        return cpu_count * 750.0
