"""ChannelAnalyzer – channel utilization, overlap detection, interference analysis.

Analyzes scan results to identify crowded channels, co-channel and
adjacent-channel interference, and recommends the least-congested
channel for deployment.
"""

from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set, Tuple

from wifi_aio.constants import CHANNELS_2GHZ, CHANNELS_5GHZ
from wifi_aio.exceptions import WiFiConnectionError
from wifi_aio.logger import get_logger

logger = get_logger("analysis.channel_analyzer")

# 2.4 GHz channel overlap map: each channel overlaps with these others
_OVERLAP_2GHZ: Dict[int, Set[int]] = {
    1: {1, 2, 3, 4, 5},
    2: {1, 2, 3, 4, 5, 6},
    3: {1, 2, 3, 4, 5, 6, 7},
    4: {2, 3, 4, 5, 6, 7, 8},
    5: {3, 4, 5, 6, 7, 8, 9},
    6: {4, 5, 6, 7, 8, 9, 10},
    7: {5, 6, 7, 8, 9, 10, 11},
    8: {6, 7, 8, 9, 10, 11, 12},
    9: {7, 8, 9, 10, 11, 12, 13},
    10: {8, 9, 10, 11, 12, 13},
    11: {9, 10, 11, 12, 13},
    12: {10, 11, 12, 13, 14},
    13: {11, 12, 13, 14},
    14: {12, 13, 14},
}

# 20 MHz non-overlapping channels in 2.4 GHz
_NON_OVERLAPPING_2GHZ = {1, 6, 11}


class ChannelAnalyzer:
    """Analyze WiFi channel utilization and interference.

    Parameters
    ----------
    scan_results:
        List of scan-result dicts.  Each dict must contain at least
        ``"channel"`` (int) and ``"signal_dbm"`` (int) keys.  Optional
        keys ``"ssid"``, ``"bssid"``, and ``"bandwidth"`` are used for
        richer reporting.
    """

    def __init__(self, scan_results: Optional[List[Dict]] = None) -> None:
        self.scan_results: List[Dict] = scan_results or []

    def set_scan_results(self, results: List[Dict]) -> None:
        """Replace the current scan data."""
        self.scan_results = results

    # ── Channel utilization ────────────────────────────────────────────

    def channel_utilization(self) -> Dict[int, Dict[str, object]]:
        """Calculate per-channel utilization metrics.

        Returns a dict keyed by channel number, each containing:

        * ``ap_count`` – number of APs on the channel
        * ``avg_signal`` – average signal strength (dBm)
        * ``max_signal`` – strongest signal (dBm)
        * ``min_signal`` – weakest signal (dBm)
        * ``ssids`` – list of SSIDs on the channel
        """
        per_channel: Dict[int, List[Dict]] = defaultdict(list)
        for ap in self.scan_results:
            ch = ap.get("channel", 0)
            if ch > 0:
                per_channel[ch].append(ap)

        result: Dict[int, Dict[str, object]] = {}
        for ch, aps in sorted(per_channel.items()):
            signals = [ap["signal_dbm"] for ap in aps if "signal_dbm" in ap]
            if not signals:
                signals = [0]
            result[ch] = {
                "ap_count": len(aps),
                "avg_signal": round(sum(signals) / len(signals), 1),
                "max_signal": max(signals),
                "min_signal": min(signals),
                "ssids": [ap.get("ssid", "<hidden>") for ap in aps],
            }
        return result

    # ── Overlap detection ──────────────────────────────────────────────

    def detect_overlap(self, channel: int) -> Dict[str, object]:
        """Detect channel overlap for the given channel.

        Returns a dict with:

        * ``overlapping_channels`` – set of channels that overlap
        * ``co_channel_aps`` – APs on the same channel
        * ``adjacent_channel_aps`` – APs on overlapping but different channels
        * ``overlap_score`` – weighted interference score (0–100)
        """
        overlapping = _OVERLAP_2GHZ.get(channel, {channel})
        co_channel: List[Dict] = []
        adjacent: List[Dict] = []

        for ap in self.scan_results:
            ap_ch = ap.get("channel", 0)
            if ap_ch == channel:
                co_channel.append(ap)
            elif ap_ch in overlapping:
                adjacent.append(ap)

        # Simple scoring: more APs and stronger signals → higher score
        total_interferers = len(co_channel) + len(adjacent) * 0.5
        score = min(100, round(total_interferers * 10))

        # Adjust for signal strength
        all_signals = [ap["signal_dbm"] for ap in co_channel + adjacent if "signal_dbm" in ap]
        if all_signals:
            avg_strength = sum(all_signals) / len(all_signals)
            # Stronger signals = more interference (less negative = stronger)
            signal_factor = max(0, (avg_strength + 90) / 90)  # 0 at -90, 1 at 0
            score = min(100, round(score * (0.5 + 0.5 * signal_factor)))

        return {
            "overlapping_channels": sorted(overlapping),
            "co_channel_aps": co_channel,
            "adjacent_channel_aps": adjacent,
            "overlap_score": score,
        }

    # ── Interference analysis ──────────────────────────────────────────

    def interference_analysis(self) -> Dict[str, object]:
        """Perform a full interference analysis across all channels.

        Returns:

        * ``channel_scores`` – dict of channel → interference score
        * ``worst_channels`` – top 3 most congested channels
        * ``best_channels`` – top 3 least congested channels
        * ``recommendation`` – best channel to use
        """
        scores: Dict[int, int] = {}
        for ch in list(CHANNELS_2GHZ.keys()):
            info = self.detect_overlap(ch)
            scores[ch] = info["overlap_score"]

        # Also score 5 GHz channels (no overlap, just count APs)
        for ch in list(CHANNELS_5GHZ.keys()):
            ap_count = sum(1 for ap in self.scan_results if ap.get("channel") == ch)
            scores[ch] = min(100, ap_count * 10)

        sorted_channels = sorted(scores.items(), key=lambda x: x[1])
        worst = sorted_channels[-3:][::-1] if len(sorted_channels) >= 3 else sorted_channels[::-1]
        best = sorted_channels[:3]

        # Prefer non-overlapping 2.4 GHz channels first, then any low-score channel
        recommendation = best[0][0] if best else 1
        for ch, score in sorted_channels:
            if ch in _NON_OVERLAPPING_2GHZ:
                recommendation = ch
                break

        return {
            "channel_scores": scores,
            "worst_channels": [{"channel": c, "score": s} for c, s in worst],
            "best_channels": [{"channel": c, "score": s} for c, s in best],
            "recommendation": recommendation,
        }

    # ── Channel summary ────────────────────────────────────────────────

    def channel_summary(self) -> Dict[str, object]:
        """Return a high-level summary of channel usage.

        Includes total APs per band, most/least used channels, and
        the number of unique channels in use.
        """
        channels_2g = [ap["channel"] for ap in self.scan_results
                       if ap.get("channel", 0) in CHANNELS_2GHZ]
        channels_5g = [ap["channel"] for ap in self.scan_results
                       if ap.get("channel", 0) in CHANNELS_5GHZ]

        counter_2g = Counter(channels_2g)
        counter_5g = Counter(channels_5g)

        return {
            "total_aps": len(self.scan_results),
            "aps_2ghz": len(channels_2g),
            "aps_5ghz": len(channels_5g),
            "unique_channels_2ghz": len(counter_2g),
            "unique_channels_5ghz": len(counter_5g),
            "most_used_2ghz": counter_2g.most_common(1)[0] if counter_2g else (0, 0),
            "most_used_5ghz": counter_5g.most_common(1)[0] if counter_5g else (0, 0),
            "least_used_2ghz": counter_2g.most_common()[-1] if counter_2g else (0, 0),
            "least_used_5ghz": counter_5g.most_common()[-1] if counter_5g else (0, 0),
        }
