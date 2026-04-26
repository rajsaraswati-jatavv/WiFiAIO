"""
WiFiAIO Signal Analyzer Module

Channel survey, signal measurement, heatmap generation, and monitoring.

FIX: Uses "while self._running:" (not "while self._running is False or self._running"),
sets self._running=True at start of measure_signal, uses "is not None" for signal_dbm checks.
"""

import os
import re
import time
import json
import logging
import subprocess
import threading
from typing import List, Dict, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    SignalAnalysisError,
)

logger = logging.getLogger(__name__)


@dataclass
class SignalMeasurement:
    """A single signal strength measurement."""
    timestamp: float
    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    frequency: int = 0
    signal_dbm: int = 0
    noise_dbm: int = 0
    snr: float = 0.0
    quality: int = 0  # 0-100
    tx_rate: float = 0.0
    rx_rate: float = 0.0
    link_speed: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "frequency": self.frequency,
            "signal_dbm": self.signal_dbm,
            "noise_dbm": self.noise_dbm,
            "snr": self.snr,
            "quality": self.quality,
            "tx_rate": self.tx_rate,
            "rx_rate": self.rx_rate,
            "link_speed": self.link_speed,
        }


@dataclass
class ChannelInfo:
    """Information about a WiFi channel."""
    channel: int = 0
    frequency: int = 0
    utilization: float = 0.0
    noise_dbm: int = 0
    ap_count: int = 0
    client_count: int = 0
    interference_level: str = "low"  # low, medium, high

    def to_dict(self) -> Dict[str, Any]:
        return {
            "channel": self.channel,
            "frequency": self.frequency,
            "utilization": self.utilization,
            "noise_dbm": self.noise_dbm,
            "ap_count": self.ap_count,
            "client_count": self.client_count,
            "interference_level": self.interference_level,
        }


@dataclass
class HeatmapPoint:
    """A data point for signal heatmap."""
    x: float = 0.0
    y: float = 0.0
    signal_dbm: int = 0
    bssid: str = ""
    channel: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "x": self.x,
            "y": self.y,
            "signal_dbm": self.signal_dbm,
            "bssid": self.bssid,
            "channel": self.channel,
        }


class SignalAnalyzer:
    """
    WiFi signal analyzer for channel surveys, signal measurement,
    heatmap generation, and continuous monitoring.
    """

    # 2.4 GHz channel-frequency mapping
    CHANNEL_FREQ_2GHZ = {
        1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432,
        6: 2437, 7: 2442, 8: 2447, 9: 2452, 10: 2457,
        11: 2462, 12: 2467, 13: 2472, 14: 2484,
    }

    # 5 GHz channel-frequency mapping (common channels)
    CHANNEL_FREQ_5GHZ = {
        36: 5180, 40: 5200, 44: 5220, 48: 5240,
        52: 5260, 56: 5280, 60: 5300, 64: 5320,
        100: 5500, 104: 5520, 108: 5540, 112: 5560,
        116: 5580, 120: 5600, 124: 5620, 128: 5640,
        132: 5660, 136: 5680, 140: 5700, 144: 5720,
        149: 5745, 153: 5765, 157: 5785, 161: 5805,
        165: 5825,
    }

    def __init__(self, interface: str = "wlan0"):
        """
        Initialize SignalAnalyzer.

        Args:
            interface: Wireless interface name.
        """
        self.interface = interface
        self._running = False
        self._measurements: List[SignalMeasurement] = []
        self._channel_survey: Dict[int, ChannelInfo] = {}
        self._heatmap_points: List[HeatmapPoint] = []
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_callback: Optional[Callable] = None

    def _check_root(self) -> None:
        """Verify running as root."""
        if os.geteuid() != 0:
            raise WiFiPermissionError("Signal analysis requires root privileges")

    def _run_command(self, cmd: List[str], timeout: int = 30) -> Tuple[str, int]:
        """Run a command and return (output, returncode)."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError(f"Command timed out: {' '.join(cmd)}")
        except FileNotFoundError:
            return "", -1

    def _signal_to_quality(self, signal_dbm: int) -> int:
        """Convert signal strength in dBm to quality percentage (0-100)."""
        # Typical range: -100 dBm (worst) to -30 dBm (best)
        if signal_dbm >= -30:
            return 100
        elif signal_dbm <= -100:
            return 0
        else:
            return int(2 * (signal_dbm + 100))

    def _calculate_snr(self, signal_dbm: int, noise_dbm: int) -> float:
        """Calculate Signal-to-Noise Ratio."""
        return float(signal_dbm - noise_dbm)

    def measure_signal(self, bssid: str = "", channel: Optional[int] = None,
                       count: int = 10, interval: float = 1.0) -> List[SignalMeasurement]:
        """
        Measure signal strength for a specific network.

        FIX: Sets self._running=True at start of measurement.
        Uses "is not None" for signal_dbm checks.

        Args:
            bssid: Target BSSID (empty for all).
            channel: Specific channel to scan.
            count: Number of measurements to take.
            interval: Interval between measurements in seconds.

        Returns:
            List of SignalMeasurement objects.
        """
        self._check_root()
        self._running = True  # FIX: Set at start
        measurements: List[SignalMeasurement] = []

        try:
            for i in range(count):
                if not self._running:
                    break

                measurement = self._take_measurement(bssid, channel)
                if measurement is not None:
                    # FIX: Use "is not None" for signal_dbm check
                    if measurement.signal_dbm is not None and measurement.signal_dbm != 0:
                        measurements.append(measurement)
                        self._measurements.append(measurement)

                if i < count - 1:
                    time.sleep(interval)
        finally:
            self._running = False

        return measurements

    def _take_measurement(self, bssid: str = "",
                          channel: Optional[int] = None) -> Optional[SignalMeasurement]:
        """Take a single signal measurement using iw."""
        output, rc = self._run_command(["iw", "dev", self.interface, "scan"])

        if rc != 0:
            # Try iwconfig as fallback
            output, rc = self._run_command(["iwconfig", self.interface])
            if rc != 0:
                return None

        now = time.time()
        current_ap: Optional[SignalMeasurement] = None

        for line in output.splitlines():
            line = line.strip()

            bssid_match = re.match(r"^BSSID\s+([0-9a-fA-F:]+)", line)
            if bssid_match:
                if current_ap is not None:
                    if not bssid or current_ap.bssid.lower() == bssid.lower():
                        return current_ap
                current_ap = SignalMeasurement(timestamp=now, bssid=bssid_match.group(1).lower())
                continue

            if current_ap is None:
                continue

            ssid_match = re.match(r"^SSID:\s*(.*)", line)
            if ssid_match:
                current_ap.ssid = ssid_match.group(1).strip()
                continue

            signal_match = re.match(r"^signal:\s*(-?\d+(?:\.\d+)?)\s*dBm", line)
            if signal_match:
                current_ap.signal_dbm = int(float(signal_match.group(1)))
                current_ap.quality = self._signal_to_quality(current_ap.signal_dbm)
                continue

            freq_match = re.match(r"^freq:\s*(\d+)", line)
            if freq_match:
                current_ap.frequency = int(freq_match.group(1))
                current_ap.channel = self._freq_to_channel(current_ap.frequency)
                continue

        # Return last AP if it matches
        if current_ap is not None:
            if not bssid or current_ap.bssid.lower() == bssid.lower():
                return current_ap

        return None

    def _freq_to_channel(self, frequency: int) -> int:
        """Convert frequency to channel number."""
        for ch, freq in self.CHANNEL_FREQ_2GHZ.items():
            if freq == frequency:
                return ch
        for ch, freq in self.CHANNEL_FREQ_5GHZ.items():
            if freq == frequency:
                return ch
        # Calculate from frequency
        if 2412 <= frequency <= 2484:
            return (frequency - 2407) // 5
        elif 5170 <= frequency <= 5885:
            return (frequency - 5000) // 5
        return 0

    def channel_survey(self, band: str = "2.4GHz",
                       channels: Optional[List[int]] = None) -> Dict[int, ChannelInfo]:
        """
        Perform a channel utilization survey.

        Args:
            band: Frequency band ("2.4GHz" or "5GHz").
            channels: Specific channels to survey (None = all in band).

        Returns:
            Dictionary of channel number -> ChannelInfo.
        """
        self._check_root()
        self._channel_survey.clear()

        if channels is None:
            if band == "2.4GHz":
                channels = list(range(1, 14))
            else:
                channels = list(self.CHANNEL_FREQ_5GHZ.keys())

        for ch in channels:
            if not self._running:
                break

            channel_info = self._survey_channel(ch)
            if channel_info is not None:
                self._channel_survey[ch] = channel_info

            # Brief pause between channels
            time.sleep(0.2)

        return self._channel_survey

    def _survey_channel(self, channel: int) -> Optional[ChannelInfo]:
        """Survey a single channel."""
        # Set channel
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                check=True, capture_output=True, timeout=10
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None

        time.sleep(0.5)  # Settle time

        # Get survey data from iw
        output, rc = self._run_command(
            ["iw", "dev", self.interface, "survey", "dump"]
        )

        info = ChannelInfo(channel=channel)

        if rc == 0:
            # Parse survey dump
            in_channel = False
            for line in output.splitlines():
                stripped = line.strip()
                if f"frequency: {self.CHANNEL_FREQ_2GHZ.get(channel, 0)}" in stripped or \
                   f"frequency: {self.CHANNEL_FREQ_5GHZ.get(channel, 0)}" in stripped:
                    in_channel = True
                    info.frequency = self.CHANNEL_FREQ_2GHZ.get(
                        channel, self.CHANNEL_FREQ_5GHZ.get(channel, 0)
                    )
                    continue

                if in_channel:
                    if stripped.startswith("[in use]"):
                        continue
                    if "noise:" in stripped:
                        try:
                            info.noise_dbm = int(stripped.split("noise:")[1].strip().split()[0])
                        except (ValueError, IndexError):
                            pass
                    elif "channel active time:" in stripped:
                        pass
                    elif "busy time:" in stripped:
                        pass
                    elif stripped.startswith("frequency:") or stripped == "":
                        in_channel = False

        # Count APs on this channel via scan
        output, rc = self._run_command(["iw", "dev", self.interface, "scan"])
        if rc == 0:
            ap_count = 0
            current_channel = 0
            for line in output.splitlines():
                stripped = line.strip()
                freq_match = re.match(r"^freq:\s*(\d+)", stripped)
                if freq_match:
                    freq = int(freq_match.group(1))
                    current_channel = self._freq_to_channel(freq)
                if current_channel == channel:
                    if "BSSID" in stripped:
                        ap_count += 1
                        current_channel = 0  # Reset to avoid double counting
            info.ap_count = ap_count

        # Determine interference level
        if info.ap_count > 5 or info.noise_dbm > -80:
            info.interference_level = "high"
        elif info.ap_count > 2 or info.noise_dbm > -85:
            info.interference_level = "medium"
        else:
            info.interference_level = "low"

        return info

    def get_best_channel(self, band: str = "2.4GHz") -> Optional[int]:
        """
        Find the best (least congested) channel.

        Args:
            band: Frequency band.

        Returns:
            Best channel number or None.
        """
        survey = self.channel_survey(band)
        if not survey:
            return None

        # Score each channel: lower AP count + lower noise = better
        scored = []
        for ch, info in survey.items():
            # Avoid overlap channels in 2.4GHz (1,6,11 preferred)
            overlap_penalty = 0
            if band == "2.4GHz" and ch not in (1, 6, 11):
                overlap_penalty = 2

            score = info.ap_count + (info.noise_dbm + 100) / 20 + overlap_penalty
            scored.append((ch, score))

        if not scored:
            return None

        scored.sort(key=lambda x: x[1])
        return scored[0][0]

    def add_heatmap_point(self, x: float, y: float, bssid: str = "",
                          channel: Optional[int] = None) -> HeatmapPoint:
        """
        Add a measurement point to the heatmap.

        Args:
            x: X coordinate.
            y: Y coordinate.
            bssid: Target BSSID.
            channel: Target channel.

        Returns:
            HeatmapPoint with measured signal.
        """
        measurement = self._take_measurement(bssid, channel)
        point = HeatmapPoint(
            x=x, y=y,
            signal_dbm=measurement.signal_dbm if measurement else 0,
            bssid=bssid,
            channel=channel or 0,
        )
        self._heatmap_points.append(point)
        return point

    def generate_heatmap(self, output_path: str, bssid: str = "",
                          grid_width: int = 50, grid_height: int = 50) -> str:
        """
        Generate a signal strength heatmap from collected data points.

        Uses interpolation between measurement points to create a
        continuous heatmap visualization.

        Args:
            output_path: Output file path.
            bssid: Filter by BSSID.
            grid_width: Grid width in pixels.
            grid_height: Grid height in pixels.

        Returns:
            Path to generated heatmap file.
        """
        points = self._heatmap_points
        if bssid:
            points = [p for p in points if p.bssid.lower() == bssid.lower()]

        if not points:
            raise SignalAnalysisError("No heatmap data points available")

        # Calculate bounds
        x_min = min(p.x for p in points)
        x_max = max(p.x for p in points)
        y_min = min(p.y for p in points)
        y_max = max(p.y for p in points)

        if x_max == x_min:
            x_max = x_min + 1
        if y_max == y_min:
            y_max = y_min + 1

        # Generate grid using IDW (Inverse Distance Weighting) interpolation
        grid = []
        power = 2.0  # IDW power parameter

        for gy in range(grid_height):
            row = []
            for gx in range(grid_width):
                x = x_min + (x_max - x_min) * gx / (grid_width - 1)
                y = y_min + (y_max - y_min) * gy / (grid_height - 1)

                # IDW interpolation
                weight_sum = 0.0
                value_sum = 0.0

                for point in points:
                    dist = ((x - point.x) ** 2 + (y - point.y) ** 2) ** 0.5
                    if dist < 0.001:
                        weight = 1e10
                    else:
                        weight = 1.0 / (dist ** power)
                    weight_sum += weight
                    value_sum += weight * point.signal_dbm

                if weight_sum > 0:
                    interpolated = value_sum / weight_sum
                else:
                    interpolated = -100

                row.append(interpolated)
            grid.append(row)

        # Export as JSON (for frontend visualization)
        heatmap_data = {
            "grid": grid,
            "bounds": {"x_min": x_min, "x_max": x_max, "y_min": y_min, "y_max": y_max},
            "dimensions": {"width": grid_width, "height": grid_height},
            "points": [p.to_dict() for p in points],
            "signal_range": {
                "min": min(p.signal_dbm for p in points),
                "max": max(p.signal_dbm for p in points),
            },
        }

        try:
            with open(output_path, "w") as f:
                json.dump(heatmap_data, f, indent=2)
            logger.info("Heatmap exported to %s", output_path)
        except OSError as e:
            raise SignalAnalysisError(f"Failed to export heatmap: {e}")

        return output_path

    def start_monitoring(self, bssid: str = "", channel: Optional[int] = None,
                          interval: float = 1.0,
                          callback: Optional[Callable] = None) -> None:
        """
        Start continuous signal monitoring.

        Args:
            bssid: Target BSSID.
            channel: Target channel.
            interval: Measurement interval in seconds.
            callback: Called with each SignalMeasurement.
        """
        if self._running:
            raise SignalAnalysisError("Monitoring is already running")

        self._monitor_callback = callback
        self._running = True

        def monitor_loop():
            logger.info("Signal monitoring started for %s", bssid or "all networks")
            while self._running:  # FIX: Correct loop condition
                measurement = self._take_measurement(bssid, channel)
                if measurement is not None:
                    # FIX: Use "is not None" for signal_dbm checks
                    if measurement.signal_dbm is not None:
                        self._measurements.append(measurement)
                        if self._monitor_callback:
                            self._monitor_callback(measurement)
                if interval > 0 and self._running:
                    time.sleep(interval)
            logger.info("Signal monitoring stopped")

        self._monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop_monitoring(self) -> None:
        """Stop continuous signal monitoring."""
        self._running = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        self._monitor_thread = None
        self._monitor_callback = None
        logger.info("Signal monitoring stopped")

    def get_measurements(self, bssid: str = "",
                         since: float = 0.0) -> List[SignalMeasurement]:
        """
        Get collected measurements.

        Args:
            bssid: Filter by BSSID.
            since: Only return measurements after this timestamp.

        Returns:
            List of SignalMeasurement objects.
        """
        results = self._measurements
        if since > 0:
            results = [m for m in results if m.timestamp >= since]
        if bssid:
            results = [m for m in results if m.bssid.lower() == bssid.lower()]
        return results

    def get_signal_stats(self, bssid: str = "") -> Dict[str, Any]:
        """
        Get signal statistics for a BSSID.

        Args:
            bssid: Target BSSID.

        Returns:
            Dictionary with signal statistics.
        """
        measurements = self._measurements
        if bssid:
            measurements = [m for m in measurements if m.bssid.lower() == bssid.lower()]

        if not measurements:
            return {"error": "No measurements available"}

        signals = [m.signal_dbm for m in measurements if m.signal_dbm is not None]
        if not signals:
            return {"error": "No valid signal measurements"}

        return {
            "count": len(signals),
            "avg_signal": sum(signals) / len(signals),
            "min_signal": min(signals),
            "max_signal": max(signals),
            "current_signal": signals[-1],
            "avg_quality": self._signal_to_quality(int(sum(signals) / len(signals))),
            "bssid": bssid,
        }

    def clear_data(self) -> None:
        """Clear all collected measurement data."""
        self._measurements.clear()
        self._channel_survey.clear()
        self._heatmap_points.clear()

    def export_measurements(self, filepath: str, format: str = "json") -> None:
        """
        Export measurements to file.

        Args:
            filepath: Output file path.
            format: Export format ('json' or 'csv').
        """
        if format == "json":
            data = [m.to_dict() for m in self._measurements]
            try:
                with open(filepath, "w") as f:
                    json.dump(data, f, indent=2, default=str)
            except OSError as e:
                raise SignalAnalysisError(f"Failed to export: {e}")

        elif format == "csv":
            try:
                with open(filepath, "w") as f:
                    headers = [
                        "timestamp", "bssid", "ssid", "channel", "frequency",
                        "signal_dbm", "noise_dbm", "snr", "quality"
                    ]
                    f.write(",".join(headers) + "\n")
                    for m in self._measurements:
                        row = [
                            str(m.timestamp), m.bssid, f'"{m.ssid}"',
                            str(m.channel), str(m.frequency),
                            str(m.signal_dbm), str(m.noise_dbm),
                            str(m.snr), str(m.quality),
                        ]
                        f.write(",".join(row) + "\n")
            except OSError as e:
                raise SignalAnalysisError(f"Failed to export CSV: {e}")

    def is_running(self) -> bool:
        """Check if monitoring is running."""
        return self._running
