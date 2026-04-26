"""SignalProcessor – signal smoothing, filtering, and averaging.

Provides digital-signal-processing style operations on sequences of
WiFi signal-strength measurements: moving averages, exponential
smoothing, median filtering, and outlier removal.
"""

import math
from typing import List, Optional, Sequence

from wifi_aio.exceptions import WiFiConnectionError
from wifi_aio.logger import get_logger

logger = get_logger("analysis.signal_processor")


class SignalProcessor:
    """Process and smooth WiFi signal-strength measurements.

    All methods operate on plain lists of integers/floats (dBm values)
    and return new lists – the input is never mutated.
    """

    # ── Moving averages ────────────────────────────────────────────────

    @staticmethod
    def simple_moving_average(signals: Sequence[float], window: int = 5) -> List[float]:
        """Compute a simple moving average over *signals*.

        Parameters
        ----------
        signals:
            Sequence of signal-strength measurements (dBm).
        window:
            Size of the moving-average window.

        Returns a list of the same length as *signals*; the first
        ``window - 1`` entries are filled with the expanding average.
        """
        if window < 1:
            raise ValueError("Window size must be >= 1")
        result: List[float] = []
        for i in range(len(signals)):
            start = max(0, i - window + 1)
            segment = signals[start: i + 1]
            result.append(round(sum(segment) / len(segment), 2))
        return result

    @staticmethod
    def weighted_moving_average(signals: Sequence[float], window: int = 5) -> List[float]:
        """Compute a linearly-weighted moving average (recent samples weight more).

        Weight for sample *k* (0 = oldest in window) is ``k + 1``.
        """
        if window < 1:
            raise ValueError("Window size must be >= 1")
        result: List[float] = []
        for i in range(len(signals)):
            start = max(0, i - window + 1)
            segment = list(signals[start: i + 1])
            weights = list(range(1, len(segment) + 1))
            wma = sum(s * w for s, w in zip(segment, weights)) / sum(weights)
            result.append(round(wma, 2))
        return result

    @staticmethod
    def exponential_moving_average(signals: Sequence[float], alpha: float = 0.3) -> List[float]:
        """Compute an exponential moving average (EMA).

        Parameters
        ----------
        signals:
            Sequence of signal measurements.
        alpha:
            Smoothing factor (0 < alpha <= 1).  Higher values give more
            weight to recent observations.
        """
        if not 0 < alpha <= 1:
            raise ValueError("Alpha must be in (0, 1]")
        result: List[float] = []
        ema = float(signals[0]) if signals else 0.0
        for val in signals:
            ema = alpha * val + (1 - alpha) * ema
            result.append(round(ema, 2))
        return result

    # ── Median filter ──────────────────────────────────────────────────

    @staticmethod
    def median_filter(signals: Sequence[float], window: int = 3) -> List[float]:
        """Apply a median filter to remove spike noise.

        For each position the median of the surrounding *window* samples
        is taken.  Edge positions use a smaller, symmetric window.
        """
        if window < 1 or window % 2 == 0:
            raise ValueError("Window must be a positive odd integer")

        half = window // 2
        result: List[float] = []
        sig_list = list(signals)

        for i in range(len(sig_list)):
            start = max(0, i - half)
            end = min(len(sig_list), i + half + 1)
            segment = sorted(sig_list[start:end])
            mid = len(segment) // 2
            if len(segment) % 2 == 0:
                median_val = (segment[mid - 1] + segment[mid]) / 2
            else:
                median_val = segment[mid]
            result.append(round(median_val, 2))
        return result

    # ── Outlier removal ────────────────────────────────────────────────

    @staticmethod
    def remove_outliers(
        signals: Sequence[float],
        method: str = "iqr",
        threshold: float = 1.5,
    ) -> List[float]:
        """Remove outlier measurements using the specified method.

        Parameters
        ----------
        signals:
            Signal measurements.
        method:
            ``"iqr"`` – Interquartile Range method (default).
            ``"zscore"`` – Z-score method.
        threshold:
            For IQR: multiplier for the IQR range (default 1.5).
            For Z-score: number of standard deviations (default 1.5).

        Returns a list with outliers replaced by the nearest inlier value.
        """
        if len(signals) < 4:
            return list(signals)

        sorted_vals = sorted(signals)

        if method == "iqr":
            q1_idx = len(sorted_vals) // 4
            q3_idx = 3 * len(sorted_vals) // 4
            q1 = sorted_vals[q1_idx]
            q3 = sorted_vals[q3_idx]
            iqr = q3 - q1
            lower = q1 - threshold * iqr
            upper = q3 + threshold * iqr
        elif method == "zscore":
            mean = sum(signals) / len(signals)
            std = math.sqrt(sum((x - mean) ** 2 for x in signals) / len(signals))
            if std == 0:
                return list(signals)
            lower = mean - threshold * std
            upper = mean + threshold * std
        else:
            raise ValueError(f"Unknown method: {method!r}")

        # Replace outliers with the nearest bound
        result: List[float] = []
        for val in signals:
            if val < lower:
                result.append(round(lower, 2))
            elif val > upper:
                result.append(round(upper, 2))
            else:
                result.append(val)
        return result

    # ── Averaging ──────────────────────────────────────────────────────

    @staticmethod
    def mean(signals: Sequence[float]) -> float:
        """Return the arithmetic mean of the signal values."""
        if not signals:
            return 0.0
        return round(sum(signals) / len(signals), 2)

    @staticmethod
    def median(signals: Sequence[float]) -> float:
        """Return the median of the signal values."""
        if not signals:
            return 0.0
        s = sorted(signals)
        mid = len(s) // 2
        if len(s) % 2 == 0:
            return round((s[mid - 1] + s[mid]) / 2, 2)
        return round(s[mid], 2)

    @staticmethod
    def standard_deviation(signals: Sequence[float]) -> float:
        """Return the population standard deviation."""
        if len(signals) < 2:
            return 0.0
        mean = sum(signals) / len(signals)
        variance = sum((x - mean) ** 2 for x in signals) / len(signals)
        return round(math.sqrt(variance), 2)

    @staticmethod
    def signal_variance(signals: Sequence[float]) -> float:
        """Return the population variance of the signal values."""
        if len(signals) < 2:
            return 0.0
        mean = sum(signals) / len(signals)
        return round(sum((x - mean) ** 2 for x in signals) / len(signals), 2)

    # ── Quality assessment ─────────────────────────────────────────────

    @staticmethod
    def signal_quality(signal_dbm: float) -> str:
        """Return a qualitative label for a signal strength value.

        Returns one of: ``"excellent"``, ``"good"``, ``"fair"``,
        ``"poor"``, ``"unusable"``.
        """
        if signal_dbm >= -50:
            return "excellent"
        elif signal_dbm >= -60:
            return "good"
        elif signal_dbm >= -70:
            return "fair"
        elif signal_dbm >= -80:
            return "poor"
        else:
            return "unusable"

    @staticmethod
    def signal_percentage(signal_dbm: float, min_dbm: float = -100, max_dbm: float = -30) -> int:
        """Convert a dBm value to a 0–100 quality percentage.

        Uses linear interpolation between *min_dbm* (0%) and *max_dbm* (100%).
        """
        clamped = max(min_dbm, min(max_dbm, signal_dbm))
        pct = ((clamped - min_dbm) / (max_dbm - min_dbm)) * 100
        return round(pct)
