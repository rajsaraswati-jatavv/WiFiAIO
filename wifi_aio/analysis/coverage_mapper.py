"""CoverageMapper – signal coverage heatmaps with coordinates.

Maps signal-strength measurements to physical coordinates and generates
heatmap data that can be rendered by external visualisation tools.
"""

import json
import math
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import WiFiConnectionError
from wifi_aio.logger import get_logger

logger = get_logger("analysis.coverage_mapper")


class CoverageMapper:
    """Generate signal coverage heatmap data from measurement points.

    Parameters
    ----------
    grid_resolution:
        Number of interpolation steps between measurement points when
        generating a dense grid.
    default_signal_floor:
        dBm value used for areas with no measurements (default -100).
    """

    def __init__(
        self,
        grid_resolution: int = 10,
        default_signal_floor: float = -100.0,
    ) -> None:
        self.grid_resolution = grid_resolution
        self.default_signal_floor = default_signal_floor
        self._measurements: List[Dict] = []

    # ── Data collection ────────────────────────────────────────────────

    def add_measurement(
        self,
        x: float,
        y: float,
        signal_dbm: float,
        bssid: str = "",
        ssid: str = "",
        floor: str = "",
        timestamp: Optional[float] = None,
    ) -> None:
        """Add a signal measurement at a specific coordinate.

        Parameters
        ----------
        x, y:
            Spatial coordinates (meters, feet, or arbitrary units).
        signal_dbm:
            Measured signal strength in dBm.
        bssid:
            BSSID of the AP being measured.
        ssid:
            SSID of the AP.
        floor:
            Floor/zone identifier for multi-story mapping.
        timestamp:
            Optional epoch timestamp; defaults to now.
        """
        import time
        self._measurements.append({
            "x": x,
            "y": y,
            "signal_dbm": signal_dbm,
            "bssid": bssid.lower() if bssid else "",
            "ssid": ssid,
            "floor": floor,
            "timestamp": timestamp or time.time(),
        })

    def add_measurements(self, points: List[Dict]) -> int:
        """Bulk-add measurement dicts.

        Each dict must have ``x``, ``y``, and ``signal_dbm`` keys.
        Returns the number of points added.
        """
        for pt in points:
            self.add_measurement(
                x=pt["x"],
                y=pt["y"],
                signal_dbm=pt["signal_dbm"],
                bssid=pt.get("bssid", ""),
                ssid=pt.get("ssid", ""),
                floor=pt.get("floor", ""),
                timestamp=pt.get("timestamp"),
            )
        return len(points)

    def clear(self) -> None:
        """Remove all measurement data."""
        self._measurements.clear()

    # ── Heatmap generation ─────────────────────────────────────────────

    def generate_heatmap(
        self,
        bssid: str = "",
        floor: str = "",
    ) -> Dict[str, object]:
        """Generate a heatmap grid from collected measurements.

        Parameters
        ----------
        bssid:
            Filter measurements to this BSSID (empty = all).
        floor:
            Filter measurements to this floor (empty = all).

        Returns a dict with:

        * ``grid`` – 2D list of signal values (rows × cols)
        * ``x_range`` – (min, max) of x coordinates
        * ``y_range`` – (min, max) of y coordinates
        * ``resolution`` – grid resolution
        * ``measurement_count`` – number of points used
        """
        points = self._filter(bssid, floor)
        if not points:
            return {
                "grid": [],
                "x_range": (0, 0),
                "y_range": (0, 0),
                "resolution": self.grid_resolution,
                "measurement_count": 0,
            }

        xs = [p["x"] for p in points]
        ys = [p["y"] for p in points]
        x_min, x_max = min(xs), max(xs)
        y_min, y_max = min(ys), max(ys)

        cols = max(2, int((x_max - x_min) / (self.grid_resolution or 1)) + 1)
        rows = max(2, int((y_max - y_min) / (self.grid_resolution or 1)) + 1)

        # Initialise grid with the floor value
        grid: List[List[float]] = [
            [self.default_signal_floor for _ in range(cols)]
            for _ in range(rows)
        ]

        # Fill grid cells using inverse-distance weighting (IDW)
        for row in range(rows):
            for col in range(cols):
                gx = x_min + col * (x_max - x_min) / max(1, cols - 1)
                gy = y_min + row * (y_max - y_min) / max(1, rows - 1)
                grid[row][col] = self._idw_interpolate(gx, gy, points)

        return {
            "grid": grid,
            "x_range": (x_min, x_max),
            "y_range": (y_min, y_max),
            "resolution": self.grid_resolution,
            "measurement_count": len(points),
        }

    # ── Coverage statistics ────────────────────────────────────────────

    def coverage_stats(
        self,
        bssid: str = "",
        floor: str = "",
        threshold_dbm: float = -70.0,
    ) -> Dict[str, object]:
        """Calculate coverage statistics for measured area.

        Parameters
        ----------
        bssid:
            Filter to this BSSID.
        floor:
            Filter to this floor.
        threshold_dbm:
            Signal level considered "covered" (default -70 dBm).

        Returns coverage percentage, average signal, and area estimate.
        """
        points = self._filter(bssid, floor)
        if not points:
            return {
                "total_points": 0,
                "covered_points": 0,
                "coverage_pct": 0.0,
                "avg_signal": 0.0,
                "min_signal": 0.0,
                "max_signal": 0.0,
            }

        signals = [p["signal_dbm"] for p in points]
        covered = sum(1 for s in signals if s >= threshold_dbm)

        return {
            "total_points": len(points),
            "covered_points": covered,
            "coverage_pct": round(covered / len(points) * 100, 1),
            "avg_signal": round(sum(signals) / len(signals), 1),
            "min_signal": min(signals),
            "max_signal": max(signals),
            "threshold_dbm": threshold_dbm,
        }

    # ── Dead-spot detection ────────────────────────────────────────────

    def detect_dead_spots(
        self,
        bssid: str = "",
        floor: str = "",
        threshold_dbm: float = -80.0,
    ) -> List[Dict[str, float]]:
        """Find measurement points below the dead-spot threshold.

        Returns a list of dicts with ``x``, ``y``, and ``signal_dbm``.
        """
        points = self._filter(bssid, floor)
        return [
            {"x": p["x"], "y": p["y"], "signal_dbm": p["signal_dbm"]}
            for p in points
            if p["signal_dbm"] < threshold_dbm
        ]

    # ── Export ─────────────────────────────────────────────────────────

    def export_json(self, path: str, bssid: str = "", floor: str = "") -> str:
        """Export the heatmap data as a JSON file.

        Returns the path written.
        """
        data = self.generate_heatmap(bssid, floor)
        os_dir = path.rsplit("/", 1)[0] if "/" in path else "."
        if os_dir:
            import os
            os.makedirs(os_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        logger.info("Heatmap exported to %s", path)
        return path

    def export_csv(self, path: str, bssid: str = "", floor: str = "") -> str:
        """Export raw measurements as CSV.

        Columns: x, y, signal_dbm, bssid, ssid, floor.
        """
        import csv
        import os

        points = self._filter(bssid, floor)
        os_dir = path.rsplit("/", 1)[0] if "/" in path else "."
        if os_dir:
            os.makedirs(os_dir, exist_ok=True)

        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["x", "y", "signal_dbm", "bssid", "ssid", "floor"])
            for p in points:
                writer.writerow([p["x"], p["y"], p["signal_dbm"], p["bssid"], p["ssid"], p["floor"]])

        logger.info("Measurements exported as CSV to %s", path)
        return path

    # ── Summary ────────────────────────────────────────────────────────

    def summary(self) -> Dict[str, object]:
        """Return a summary of the measurement data."""
        if not self._measurements:
            return {"total_measurements": 0, "bssids": [], "floors": []}

        bssids = sorted(set(p["bssid"] for p in self._measurements if p["bssid"]))
        floors = sorted(set(p["floor"] for p in self._measurements if p["floor"]))
        signals = [p["signal_dbm"] for p in self._measurements]

        return {
            "total_measurements": len(self._measurements),
            "bssids": bssids,
            "floors": floors,
            "signal_range": (min(signals), max(signals)),
            "avg_signal": round(sum(signals) / len(signals), 1),
        }

    # ── Internals ──────────────────────────────────────────────────────

    def _filter(self, bssid: str, floor: str) -> List[Dict]:
        """Filter measurements by BSSID and/or floor."""
        points = self._measurements
        if bssid:
            bssid = bssid.lower()
            points = [p for p in points if p["bssid"] == bssid]
        if floor:
            points = [p for p in points if p["floor"] == floor]
        return points

    @staticmethod
    def _idw_interpolate(
        gx: float,
        gy: float,
        points: List[Dict],
        power: float = 2.0,
    ) -> float:
        """Inverse-distance-weighted interpolation at (gx, gy).

        Uses all *points* with power weighting.  Falls back to the
        nearest point if the query location coincides with a measurement.
        """
        weights: float = 0.0
        weighted_sum: float = 0.0

        for p in points:
            dist = math.sqrt((p["x"] - gx) ** 2 + (p["y"] - gy) ** 2)
            if dist < 0.01:
                return p["signal_dbm"]
            w = 1.0 / (dist ** power)
            weights += w
            weighted_sum += w * p["signal_dbm"]

        return round(weighted_sum / weights, 1) if weights > 0 else -100.0
