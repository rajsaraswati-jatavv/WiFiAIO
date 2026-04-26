"""NetworkComparator – compare scans over time, detect new/changed/removed APs.

Compares two sets of scan results to identify networks that have been
added, removed, or modified between scans.
"""

from typing import Dict, List, Optional, Set

from wifi_aio.exceptions import WiFiConnectionError
from wifi_aio.logger import get_logger

logger = get_logger("analysis.network_comparator")


class NetworkComparator:
    """Compare WiFi scan results across time.

    Identify new, removed, and changed access points by comparing a
    previous scan snapshot against a current one.

    Each scan result dict should contain at least ``"bssid"`` and
    ``"ssid"`` keys.  Additional keys like ``"signal_dbm"``,
    ``"channel"``, ``"security"``, etc. are compared for changes.
    """

    def __init__(self) -> None:
        self._previous: Dict[str, Dict] = {}  # keyed by BSSID
        self._current: Dict[str, Dict] = {}
        self._diff: Optional[Dict[str, object]] = None

    # ── Loading scan data ──────────────────────────────────────────────

    def set_previous_scan(self, scan_results: List[Dict]) -> None:
        """Set the previous (baseline) scan results.

        Each entry must have a ``"bssid"`` key used as the unique
        identifier.
        """
        self._previous = {ap["bssid"].lower(): ap for ap in scan_results if "bssid" in ap}
        self._diff = None

    def set_current_scan(self, scan_results: List[Dict]) -> None:
        """Set the current scan results for comparison."""
        self._current = {ap["bssid"].lower(): ap for ap in scan_results if "bssid" in ap}
        self._diff = None

    # ── Comparison ─────────────────────────────────────────────────────

    def compare(self) -> Dict[str, object]:
        """Compare previous and current scans and return the diff.

        The returned dict contains:

        * ``new_aps`` – APs present in current but not in previous
        * ``removed_aps`` – APs present in previous but not in current
        * ``changed_aps`` – APs present in both with differing attributes
        * ``unchanged_aps`` – APs present in both with identical attributes
        * ``stats`` – summary counts
        """
        prev_keys: Set[str] = set(self._previous.keys())
        curr_keys: Set[str] = set(self._current.keys())

        new_bssids = curr_keys - prev_keys
        removed_bssids = prev_keys - curr_keys
        common_bssids = curr_keys & prev_keys

        new_aps = [self._current[b] for b in sorted(new_bssids)]
        removed_aps = [self._previous[b] for b in sorted(removed_bssids)]

        changed_aps: List[Dict] = []
        unchanged_aps: List[Dict] = []

        for bssid in sorted(common_bssids):
            prev = self._previous[bssid]
            curr = self._current[bssid]
            changes = self._detect_changes(prev, curr)

            if changes:
                changed_aps.append({
                    "bssid": bssid,
                    "ssid": curr.get("ssid", ""),
                    "changes": changes,
                    "previous": prev,
                    "current": curr,
                })
            else:
                unchanged_aps.append(curr)

        self._diff = {
            "new_aps": new_aps,
            "removed_aps": removed_aps,
            "changed_aps": changed_aps,
            "unchanged_aps": unchanged_aps,
            "stats": {
                "total_previous": len(self._previous),
                "total_current": len(self._current),
                "new_count": len(new_aps),
                "removed_count": len(removed_aps),
                "changed_count": len(changed_aps),
                "unchanged_count": len(unchanged_aps),
            },
        }
        return self._diff

    def _detect_changes(self, prev: Dict, curr: Dict) -> Dict[str, Dict[str, object]]:
        """Compare two AP records and return a dict of changed fields.

        Each entry is ``{field_name: {"previous": old, "current": new}}``.
        """
        changes: Dict[str, Dict[str, object]] = {}
        # Fields that are meaningful to compare
        tracked_fields = [
            "ssid", "signal_dbm", "channel", "security",
            "frequency", "bandwidth", "encryption", "wps",
        ]

        for field in tracked_fields:
            prev_val = prev.get(field)
            curr_val = curr.get(field)
            if prev_val != curr_val:
                changes[field] = {"previous": prev_val, "current": curr_val}

        return changes

    # ── Convenience methods ────────────────────────────────────────────

    def get_new_aps(self) -> List[Dict]:
        """Return APs added since the previous scan."""
        if self._diff is None:
            self.compare()
        return self._diff["new_aps"]  # type: ignore[index]

    def get_removed_aps(self) -> List[Dict]:
        """Return APs removed since the previous scan."""
        if self._diff is None:
            self.compare()
        return self._diff["removed_aps"]  # type: ignore[index]

    def get_changed_aps(self) -> List[Dict]:
        """Return APs with changed attributes."""
        if self._diff is None:
            self.compare()
        return self._diff["changed_aps"]  # type: ignore[index]

    def get_unchanged_aps(self) -> List[Dict]:
        """Return APs that have not changed."""
        if self._diff is None:
            self.compare()
        return self._diff["unchanged_aps"]  # type: ignore[index]

    # ── Trend analysis ─────────────────────────────────────────────────

    def signal_trends(self) -> Dict[str, Dict[str, float]]:
        """Compare signal strengths for APs present in both scans.

        Returns a dict keyed by BSSID, each with ``previous_signal``,
        ``current_signal``, and ``delta`` (positive = improved).
        """
        trends: Dict[str, Dict[str, float]] = {}
        for bssid in set(self._previous.keys()) & set(self._current.keys()):
            prev_sig = self._previous[bssid].get("signal_dbm")
            curr_sig = self._current[bssid].get("signal_dbm")
            if prev_sig is not None and curr_sig is not None:
                trends[bssid] = {
                    "previous_signal": prev_sig,
                    "current_signal": curr_sig,
                    "delta": round(curr_sig - prev_sig, 1),
                    "ssid": self._current[bssid].get("ssid", ""),
                }
        return trends

    # ── Export ─────────────────────────────────────────────────────────

    def summary(self) -> Dict[str, object]:
        """Return a comparison summary (runs compare if not yet done)."""
        if self._diff is None:
            self.compare()
        return self._diff  # type: ignore[return-value]
