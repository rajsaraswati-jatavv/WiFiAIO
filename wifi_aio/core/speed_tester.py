"""Network speed testing and latency measurement.

Provides download/upload speed tests, latency testing, and jitter measurement
using public speed test servers and raw socket operations.
"""

import json
import logging
import math
import os
import re
import socket
import ssl
import subprocess
import time
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)

# Public servers for speed testing
SPEED_TEST_DOWNLOAD_URLS = [
    "http://speedtest.tele2.net/1MB.zip",
    "http://speedtest.tele2.net/10MB.zip",
    "http://proof.ovh.net/files/1Mb.dat",
    "http://cachefly.cachefly.net/1mb.test",
]

SPEED_TEST_UPLOAD_URLS = [
    "http://speedtest.tele2.net/upload.php",
]

LATENCY_TARGETS = [
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
    "208.67.222.222",
]


class SpeedTester:
    """Measure network download/upload speed, latency, and jitter."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self._results: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Download speed test
    # ------------------------------------------------------------------

    def download_speed_test(
        self,
        url: Optional[str] = None,
        duration: int = 10,
        chunk_size: int = 65536,
    ) -> Dict[str, float]:
        """Test download speed.

        Args:
            url: URL to download from. If None, uses default servers.
            duration: Maximum test duration in seconds.
            chunk_size: Download chunk size in bytes.

        Returns:
            Dict with: speed_mbps, speed_kbps, bytes_received, elapsed_seconds,
            effective_url.
        """
        import urllib.request

        target_url = url or SPEED_TEST_DOWNLOAD_URLS[2]
        bytes_received = 0
        start_time = time.time()

        try:
            req = urllib.request.Request(target_url, method="GET")
            req.add_header("User-Agent", "WiFiAIO/1.0")
            req.add_header("Connection", "close")

            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=duration + 5, context=ctx) as resp:
                while True:
                    elapsed = time.time() - start_time
                    if elapsed >= duration:
                        break
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    bytes_received += len(chunk)

        except Exception as exc:
            logger.warning("Download test failed for %s: %s", target_url, exc)
            raise WiFiConnectionError(f"Download test failed: {exc}")

        elapsed = time.time() - start_time
        if elapsed == 0 or bytes_received == 0:
            return {
                "speed_mbps": 0.0,
                "speed_kbps": 0.0,
                "bytes_received": 0,
                "elapsed_seconds": 0.0,
                "effective_url": target_url,
            }

        speed_bps = (bytes_received * 8) / elapsed
        speed_kbps = speed_bps / 1000
        speed_mbps = speed_kbps / 1000

        result = {
            "speed_mbps": round(speed_mbps, 2),
            "speed_kbps": round(speed_kbps, 2),
            "bytes_received": bytes_received,
            "elapsed_seconds": round(elapsed, 3),
            "effective_url": target_url,
        }
        self._results["download"] = speed_mbps
        return result

    # ------------------------------------------------------------------
    # Upload speed test
    # ------------------------------------------------------------------

    def upload_speed_test(
        self,
        url: Optional[str] = None,
        duration: int = 10,
        chunk_size: int = 65536,
        data_size: int = 1024 * 1024,
    ) -> Dict[str, float]:
        """Test upload speed.

        Args:
            url: Upload endpoint URL.
            duration: Maximum test duration in seconds.
            chunk_size: Upload chunk size in bytes.
            data_size: Total data to upload in bytes.

        Returns:
            Dict with: speed_mbps, speed_kbps, bytes_sent, elapsed_seconds.
        """
        import urllib.request

        target_url = url or SPEED_TEST_UPLOAD_URLS[0]
        # Generate random payload
        payload = os.urandom(min(data_size, chunk_size))
        bytes_sent = 0
        start_time = time.time()

        try:
            while True:
                elapsed = time.time() - start_time
                if elapsed >= duration or bytes_sent >= data_size:
                    break

                req = urllib.request.Request(
                    target_url,
                    data=payload,
                    method="POST",
                )
                req.add_header("User-Agent", "WiFiAIO/1.0")
                req.add_header("Content-Type", "application/octet-stream")

                ctx = ssl.create_default_context()
                try:
                    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                        resp.read()
                    bytes_sent += len(payload)
                except Exception:
                    break

        except Exception as exc:
            logger.warning("Upload test failed: %s", exc)
            raise WiFiConnectionError(f"Upload test failed: {exc}")

        elapsed = time.time() - start_time
        if elapsed == 0 or bytes_sent == 0:
            return {
                "speed_mbps": 0.0,
                "speed_kbps": 0.0,
                "bytes_sent": 0,
                "elapsed_seconds": 0.0,
                "effective_url": target_url,
            }

        speed_bps = (bytes_sent * 8) / elapsed
        speed_kbps = speed_bps / 1000
        speed_mbps = speed_kbps / 1000

        result = {
            "speed_mbps": round(speed_mbps, 2),
            "speed_kbps": round(speed_kbps, 2),
            "bytes_sent": bytes_sent,
            "elapsed_seconds": round(elapsed, 3),
            "effective_url": target_url,
        }
        self._results["upload"] = speed_mbps
        return result

    # ------------------------------------------------------------------
    # Latency test
    # ------------------------------------------------------------------

    def latency_test(
        self,
        host: str = "1.1.1.1",
        count: int = 10,
        timeout: float = 2.0,
    ) -> Dict[str, float]:
        """Measure network latency (ICMP ping).

        Args:
            host: Target host or IP address.
            count: Number of pings to send.
            timeout: Timeout per ping in seconds.

        Returns:
            Dict with: min_ms, max_ms, avg_ms, packet_loss_percent, jitter_ms,
            samples.
        """
        latencies: List[float] = []
        lost = 0

        for i in range(count):
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", str(int(timeout)), host],
                    capture_output=True, text=True, timeout=timeout + 5,
                )
                if result.returncode == 0:
                    match = re.search(r"time=([\d.]+)\s*ms", result.stdout)
                    if match:
                        latencies.append(float(match.group(1)))
                    else:
                        lost += 1
                else:
                    lost += 1
            except subprocess.TimeoutExpired:
                lost += 1

        if not latencies:
            return {
                "min_ms": 0.0,
                "max_ms": 0.0,
                "avg_ms": 0.0,
                "packet_loss_percent": 100.0,
                "jitter_ms": 0.0,
                "samples": 0,
            }

        min_lat = min(latencies)
        max_lat = max(latencies)
        avg_lat = sum(latencies) / len(latencies)
        packet_loss = (lost / count) * 100

        # Calculate jitter (average of consecutive differences)
        jitter = self._calculate_jitter(latencies)

        result = {
            "min_ms": round(min_lat, 3),
            "max_ms": round(max_lat, 3),
            "avg_ms": round(avg_lat, 3),
            "packet_loss_percent": round(packet_loss, 1),
            "jitter_ms": round(jitter, 3),
            "samples": len(latencies),
        }
        self._results["latency"] = avg_lat
        self._results["jitter"] = jitter
        return result

    def multi_target_latency(
        self,
        hosts: Optional[List[str]] = None,
        count: int = 5,
    ) -> Dict[str, Dict[str, float]]:
        """Test latency against multiple targets.

        Args:
            hosts: List of target hosts. Defaults to well-known DNS servers.
            count: Pings per target.

        Returns:
            Dict mapping host -> latency result dict.
        """
        targets = hosts or LATENCY_TARGETS
        results = {}
        for host in targets:
            results[host] = self.latency_test(host, count=count)
        return results

    # ------------------------------------------------------------------
    # Jitter measurement
    # ------------------------------------------------------------------

    def jitter_test(
        self,
        host: str = "1.1.1.1",
        count: int = 20,
        interval: float = 0.5,
    ) -> Dict[str, float]:
        """Measure jitter (variation in latency).

        Jitter is calculated as the mean deviation between consecutive
        latency measurements.

        Args:
            host: Target host.
            count: Number of samples.
            interval: Time between samples in seconds.

        Returns:
            Dict with: jitter_ms, avg_latency_ms, min_ms, max_ms, 
            variation_coefficient.
        """
        latencies: List[float] = []

        for i in range(count):
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "2", host],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    match = re.search(r"time=([\d.]+)\s*ms", result.stdout)
                    if match:
                        latencies.append(float(match.group(1)))
            except subprocess.TimeoutExpired:
                pass
            if i < count - 1:
                time.sleep(interval)

        if len(latencies) < 2:
            return {
                "jitter_ms": 0.0,
                "avg_latency_ms": 0.0,
                "min_ms": 0.0,
                "max_ms": 0.0,
                "variation_coefficient": 0.0,
            }

        jitter = self._calculate_jitter(latencies)
        avg_lat = sum(latencies) / len(latencies)
        min_lat = min(latencies)
        max_lat = max(latencies)

        # Coefficient of variation
        if avg_lat > 0:
            variance = sum((x - avg_lat) ** 2 for x in latencies) / len(latencies)
            std_dev = math.sqrt(variance)
            cv = (std_dev / avg_lat) * 100
        else:
            cv = 0.0

        result = {
            "jitter_ms": round(jitter, 3),
            "avg_latency_ms": round(avg_lat, 3),
            "min_ms": round(min_lat, 3),
            "max_ms": round(max_lat, 3),
            "variation_coefficient": round(cv, 2),
        }
        self._results["jitter"] = jitter
        return result

    @staticmethod
    def _calculate_jitter(latencies: List[float]) -> float:
        """Calculate jitter as mean absolute deviation of consecutive differences.

        RFC 3550 jitter formula: J = J + (|D(i-1,i)| - J)/16
        Simplified: mean of |latency[i] - latency[i-1]|
        """
        if len(latencies) < 2:
            return 0.0
        diffs = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
        return sum(diffs) / len(diffs)

    # ------------------------------------------------------------------
    # Combined speed test
    # ------------------------------------------------------------------

    def full_speed_test(self, duration: int = 10) -> Dict[str, Dict[str, float]]:
        """Run a full speed test suite (download, upload, latency, jitter).

        Args:
            duration: Duration for speed tests in seconds.

        Returns:
            Dict with 'download', 'upload', 'latency', 'jitter' result dicts.
        """
        results = {}

        logger.info("Starting download speed test...")
        try:
            results["download"] = self.download_speed_test(duration=duration)
        except WiFiConnectionError:
            results["download"] = {"speed_mbps": 0.0, "error": "test_failed"}

        logger.info("Starting upload speed test...")
        try:
            results["upload"] = self.upload_speed_test(duration=duration)
        except WiFiConnectionError:
            results["upload"] = {"speed_mbps": 0.0, "error": "test_failed"}

        logger.info("Starting latency test...")
        results["latency"] = self.latency_test()

        logger.info("Starting jitter test...")
        results["jitter"] = self.jitter_test(count=10)

        return results

    # ------------------------------------------------------------------
    # DNS resolution speed
    # ------------------------------------------------------------------

    def dns_speed_test(
        self,
        domain: str = "google.com",
        dns_server: Optional[str] = None,
        count: int = 5,
    ) -> Dict[str, float]:
        """Test DNS resolution speed.

        Args:
            domain: Domain to resolve.
            dns_server: DNS server to use (None for system default).
            count: Number of resolution attempts.

        Returns:
            Dict with: avg_ms, min_ms, max_ms, success_count.
        """
        times: List[float] = []

        for _ in range(count):
            start = time.time()
            try:
                if dns_server:
                    result = subprocess.run(
                        ["nslookup", domain, dns_server],
                        capture_output=True, text=True, timeout=5,
                    )
                else:
                    result = subprocess.run(
                        ["nslookup", domain],
                        capture_output=True, text=True, timeout=5,
                    )
                elapsed = (time.time() - start) * 1000
                if result.returncode == 0 and "Name:" in result.stdout or "Address:" in result.stdout:
                    times.append(elapsed)
            except subprocess.TimeoutExpired:
                pass

        if not times:
            return {"avg_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "success_count": 0}

        return {
            "avg_ms": round(sum(times) / len(times), 3),
            "min_ms": round(min(times), 3),
            "max_ms": round(max(times), 3),
            "success_count": len(times),
        }

    # ------------------------------------------------------------------
    # TCP throughput test
    # ------------------------------------------------------------------

    def tcp_throughput_test(
        self,
        host: str = "1.1.1.1",
        port: int = 443,
        duration: int = 5,
    ) -> Dict[str, float]:
        """Test raw TCP throughput to a host.

        Args:
            host: Target host.
            port: Target port.
            duration: Test duration in seconds.

        Returns:
            Dict with: throughput_mbps, bytes_transferred, elapsed_seconds.
        """
        total_bytes = 0
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(duration + 5)

            ctx = ssl.create_default_context()
            wrapped_sock = ctx.wrap_socket(sock, server_hostname=host)
            wrapped_sock.connect((host, port))

            # Send data as fast as possible
            payload = b"\x00" * 65536
            while time.time() - start_time < duration:
                try:
                    wrapped_sock.send(payload)
                    total_bytes += len(payload)
                except (socket.timeout, BrokenPipeError, ConnectionResetError):
                    break

            wrapped_sock.close()

        except (socket.error, ssl.SSLError, OSError) as exc:
            logger.warning("TCP throughput test failed: %s", exc)

        elapsed = time.time() - start_time
        throughput_bps = (total_bytes * 8) / elapsed if elapsed > 0 else 0
        throughput_mbps = throughput_bps / 1_000_000

        return {
            "throughput_mbps": round(throughput_mbps, 2),
            "bytes_transferred": total_bytes,
            "elapsed_seconds": round(elapsed, 3),
        }

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def get_results(self) -> Dict[str, float]:
        """Get the latest test results."""
        return dict(self._results)

    @staticmethod
    def classify_connection(download_mbps: float) -> str:
        """Classify connection quality based on download speed.

        Returns:
            Classification string: 'excellent', 'good', 'fair', 'poor', 'very_poor'.
        """
        if download_mbps >= 100:
            return "excellent"
        elif download_mbps >= 50:
            return "good"
        elif download_mbps >= 25:
            return "fair"
        elif download_mbps >= 5:
            return "poor"
        else:
            return "very_poor"
