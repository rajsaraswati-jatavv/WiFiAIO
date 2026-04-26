"""WiFiStatistics – mean/median/percentile signal stats, channel distribution.

Provides statistical analysis functions for WiFi signal-strength and
channel data: central tendency, dispersion, percentiles, and channel
distribution histograms.
"""

import math
from collections import Counter
from typing import Dict, List, Optional, Sequence

from wifi_aio.constants import CHANNELS_2GHZ, CHANNELS_5GHZ
from wifi_aio.exceptions import WiFiConnectionError
from wifi_aio.logger import get_logger

logger = get_logger("analysis.statistics")


class WiFiStatistics:
    """Statistical analysis of WiFi scan data.

    Parameters
    ----------
    scan_results:
        List of scan-result dicts with ``"signal_dbm"`` and
        ``"channel"`` keys (and optionally ``"ssid"``, ``"bssid"``,
        ``"security"``).
    """

    def __init__(self, scan_results: Optional[List[Dict]] = None) -> None:
        self.scan_results: List[Dict] = scan_results or []

    def set_scan_results(self, results: List[Dict]) -> None:
        """Replace the current scan data."""
        self.scan_results = results

    # ── Signal strength statistics ─────────────────────────────────────

    def signal_mean(self) -> float:
        """Return the arithmetic mean of all signal strengths."""
        signals = self._extract_signals()
        return round(sum(signals) / len(signals), 2) if signals else 0.0

    def signal_median(self) -> float:
        """Return the median signal strength."""
        signals = self._extract_signals()
        if not signals:
            return 0.0
        s = sorted(signals)
        mid = len(s) // 2
        if len(s) % 2 == 0:
            return round((s[mid - 1] + s[mid]) / 2, 2)
        return round(s[mid], 2)

    def signal_percentile(self, p: float) -> float:
        """Return the *p*-th percentile of signal strengths.

        Uses linear interpolation between adjacent ranks.
        """
        signals = self._extract_signals()
        if not signals:
            return 0.0
        s = sorted(signals)
        rank = (p / 100) * (len(s) - 1)
        lower = int(math.floor(rank))
        upper = int(math.ceil(rank))
        if lower == upper:
            return round(s[lower], 2)
        frac = rank - lower
        return round(s[lower] + frac * (s[upper] - s[lower]), 2)

    def signal_std_dev(self) -> float:
        """Return the population standard deviation of signal strengths."""
        signals = self._extract_signals()
        if len(signals) < 2:
            return 0.0
        mean = sum(signals) / len(signals)
        variance = sum((x - mean) ** 2 for x in signals) / len(signals)
        return round(math.sqrt(variance), 2)

    def signal_variance(self) -> float:
        """Return the population variance of signal strengths."""
        signals = self._extract_signals()
        if len(signals) < 2:
            return 0.0
        mean = sum(signals) / len(signals)
        return round(sum((x - mean) ** 2 for x in signals) / len(signals), 2)

    def signal_range(self) -> Dict[str, float]:
        """Return min, max, and range of signal strengths."""
        signals = self._extract_signals()
        if not signals:
            return {"min": 0.0, "max": 0.0, "range": 0.0}
        mn, mx = min(signals), max(signals)
        return {"min": mn, "max": mx, "range": round(mx - mn, 2)}

    def signal_mode(self) -> float:
        """Return the most common signal strength value."""
        signals = self._extract_signals()
        if not signals:
            return 0.0
        counter = Counter(signals)
        return counter.most_common(1)[0][0]

    # ── Full signal summary ────────────────────────────────────────────

    def signal_summary(self) -> Dict[str, float]:
        """Return a comprehensive signal-strength statistical summary."""
        return {
            "count": len(self._extract_signals()),
            "mean": self.signal_mean(),
            "median": self.signal_median(),
            "mode": self.signal_mode(),
            "std_dev": self.signal_std_dev(),
            "variance": self.signal_variance(),
            "min": self.signal_range()["min"],
            "max": self.signal_range()["max"],
            "range": self.signal_range()["range"],
            "p25": self.signal_percentile(25),
            "p50": self.signal_percentile(50),
            "p75": self.signal_percentile(75),
            "p90": self.signal_percentile(90),
            "p95": self.signal_percentile(95),
            "p99": self.signal_percentile(99),
        }

    # ── Channel distribution ───────────────────────────────────────────

    def channel_distribution(self) -> Dict[int, int]:
        """Return the number of APs per channel."""
        counter: Counter = Counter()
        for ap in self.scan_results:
            ch = ap.get("channel", 0)
            if ch > 0:
                counter[ch] += 1
        return dict(sorted(counter.items()))

    def channel_distribution_by_band(self) -> Dict[str, Dict[int, int]]:
        """Return AP counts per channel, split by 2.4 GHz and 5 GHz."""
        band_2g: Counter = Counter()
        band_5g: Counter = Counter()
        for ap in self.scan_results:
            ch = ap.get("channel", 0)
            if ch in CHANNELS_2GHZ:
                band_2g[ch] += 1
            elif ch in CHANNELS_5GHZ:
                band_5g[ch] += 1
        return {
            "2.4ghz": dict(sorted(band_2g.items())),
            "5ghz": dict(sorted(band_5g.items())),
        }

    def band_distribution(self) -> Dict[str, int]:
        """Return total AP counts per band."""
        g2 = g5 = 0
        for ap in self.scan_results:
            ch = ap.get("channel", 0)
            if ch in CHANNELS_2GHZ:
                g2 += 1
            elif ch in CHANNELS_5GHZ:
                g5 += 1
        return {"2.4ghz": g2, "5ghz": g5}

    # ── Security distribution ──────────────────────────────────────────

    def security_distribution(self) -> Dict[str, int]:
        """Return the number of APs per security type."""
        counter: Counter = Counter()
        for ap in self.scan_results:
            sec = ap.get("security", ap.get("encryption", "Unknown"))
            counter[sec] += 1
        return dict(counter.most_common())

    # ── SSID statistics ────────────────────────────────────────────────

    def ssid_stats(self) -> Dict[str, Dict[str, object]]:
        """Return per-SSID statistics (count, avg signal, channels)."""
        from collections import defaultdict
        per_ssid: Dict[str, List[Dict]] = defaultdict(list)
        for ap in self.scan_results:
            ssid = ap.get("ssid", "<hidden>")
            per_ssid[ssid].append(ap)

        result: Dict[str, Dict[str, object]] = {}
        for ssid, aps in sorted(per_ssid.items()):
            signals = [a["signal_dbm"] for a in aps if "signal_dbm" in a]
            channels = sorted(set(a.get("channel", 0) for a in aps))
            result[ssid] = {
                "count": len(aps),
                "avg_signal": round(sum(signals) / len(signals), 1) if signals else 0.0,
                "channels": channels,
            }
        return result

    # ── Full report ────────────────────────────────────────────────────

    def full_report(self) -> Dict[str, object]:
        """Return a combined statistical report."""
        return {
            "total_aps": len(self.scan_results),
            "signal_summary": self.signal_summary(),
            "channel_distribution": self.channel_distribution(),
            "channel_distribution_by_band": self.channel_distribution_by_band(),
            "band_distribution": self.band_distribution(),
            "security_distribution": self.security_distribution(),
        }

    # ── Internals ──────────────────────────────────────────────────────

    def _extract_signals(self) -> List[float]:
        """Pull signal_dbm values from scan results."""
        return [float(ap["signal_dbm"]) for ap in self.scan_results if "signal_dbm" in ap]
