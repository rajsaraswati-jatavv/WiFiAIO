"""AnomalyDetector – detect rogue APs, evil twins, and deauth floods.

Inspects scan results and captured frames for common wireless attack
patterns: rogue access points, evil-twin networks, and deauthentication
flood attacks.
"""

import time
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set

from wifi_aio.exceptions import WiFiConnectionError
from wifi_aio.logger import get_logger

logger = get_logger("analysis.anomaly_detector")


class AnomalyDetector:
    """Detect wireless security anomalies in scan and frame data.

    Parameters
    ----------
    deauth_threshold:
        Number of deauth frames within *deauth_window* seconds that
        triggers a deauth-flood alert.
    deauth_window:
        Time window (seconds) for deauth-flood detection.
    signal_delta_threshold:
        dBm difference that suggests a different physical device
        broadcasting the same BSSID (evil-twin indicator).
    """

    def __init__(
        self,
        deauth_threshold: int = 20,
        deauth_window: float = 10.0,
        signal_delta_threshold: float = 15.0,
    ) -> None:
        self.deauth_threshold = deauth_threshold
        self.deauth_window = deauth_window
        self.signal_delta_threshold = signal_delta_threshold
        self._known_networks: Dict[str, Dict] = {}  # bssid → baseline info
        self._deauth_events: List[float] = []       # timestamps of deauth frames
        self._anomalies: List[Dict] = []

    # ── Baseline management ────────────────────────────────────────────

    def set_baseline(self, scan_results: List[Dict]) -> None:
        """Set a trusted baseline of known networks.

        Each entry should contain ``"bssid"``, ``"ssid"``,
        ``"channel"``, ``"signal_dbm"``, and ``"security"``.
        """
        self._known_networks.clear()
        for ap in scan_results:
            bssid = ap.get("bssid", "").lower()
            if bssid:
                self._known_networks[bssid] = {
                    "ssid": ap.get("ssid", ""),
                    "channel": ap.get("channel", 0),
                    "signal_dbm": ap.get("signal_dbm", 0),
                    "security": ap.get("security", ap.get("encryption", "")),
                }
        logger.info("Baseline set with %d networks", len(self._known_networks))

    # ── Rogue AP detection ─────────────────────────────────────────────

    def detect_rogue_aps(self, scan_results: List[Dict]) -> List[Dict]:
        """Detect potentially rogue access points.

        A rogue AP is flagged when:

        1. A BSSID is seen that was **not** in the baseline.
        2. A known BSSID appears on a **different channel** than the baseline.
        3. A known BSSID advertises **different security** settings.

        Returns a list of anomaly dicts with ``type``, ``bssid``,
        ``ssid``, ``reason``, and ``details``.
        """
        anomalies: List[Dict] = []

        for ap in scan_results:
            bssid = ap.get("bssid", "").lower()
            ssid = ap.get("ssid", "")
            channel = ap.get("channel", 0)
            security = ap.get("security", ap.get("encryption", ""))

            if bssid not in self._known_networks:
                anomalies.append({
                    "type": "rogue_ap",
                    "bssid": bssid,
                    "ssid": ssid,
                    "reason": "Unknown BSSID not in baseline",
                    "details": {"channel": channel, "security": security},
                })
                continue

            baseline = self._known_networks[bssid]

            # Channel mismatch
            if baseline["channel"] != 0 and channel != 0 and baseline["channel"] != channel:
                anomalies.append({
                    "type": "rogue_ap",
                    "bssid": bssid,
                    "ssid": ssid,
                    "reason": "Channel mismatch with baseline",
                    "details": {
                        "baseline_channel": baseline["channel"],
                        "current_channel": channel,
                    },
                })

            # Security mismatch
            if baseline["security"] and security and baseline["security"] != security:
                anomalies.append({
                    "type": "rogue_ap",
                    "bssid": bssid,
                    "ssid": ssid,
                    "reason": "Security type mismatch with baseline",
                    "details": {
                        "baseline_security": baseline["security"],
                        "current_security": security,
                    },
                })

        self._anomalies.extend(anomalies)
        if anomalies:
            logger.warning("Detected %d potential rogue APs", len(anomalies))
        return anomalies

    # ── Evil twin detection ────────────────────────────────────────────

    def detect_evil_twins(self, scan_results: List[Dict]) -> List[Dict]:
        """Detect evil-twin access points.

        An evil twin is identified when:

        1. Two or more BSSIDs broadcast the **same SSID** on different
           channels with significantly different signal strengths.
        2. A known SSID appears with a **new BSSID** not in the baseline.

        Returns a list of anomaly dicts.
        """
        anomalies: List[Dict] = []

        # Group by SSID
        ssid_groups: Dict[str, List[Dict]] = defaultdict(list)
        for ap in scan_results:
            ssid = ap.get("ssid", "")
            if ssid:
                ssid_groups[ssid].append(ap)

        for ssid, aps in ssid_groups.items():
            if len(aps) < 2:
                continue

            bssids: Set[str] = set()
            signals: Dict[str, float] = {}
            channels: Dict[str, int] = {}

            for ap in aps:
                bssid = ap.get("bssid", "").lower()
                bssids.add(bssid)
                signals[bssid] = ap.get("signal_dbm", 0)
                channels[bssid] = ap.get("channel", 0)

            # Multiple BSSIDs for the same SSID
            if len(bssids) > 1:
                signal_values = list(signals.values())
                signal_range = max(signal_values) - min(signal_values)

                if signal_range > self.signal_delta_threshold:
                    anomalies.append({
                        "type": "evil_twin",
                        "ssid": ssid,
                        "bssids": sorted(bssids),
                        "reason": "Same SSID on multiple BSSIDs with large signal delta",
                        "details": {
                            "signal_range_dbm": round(signal_range, 1),
                            "bssid_details": {b: {"signal": signals[b], "channel": channels[b]} for b in bssids},
                        },
                    })
                else:
                    # Could be a legitimate multi-AP deployment, but flag if any BSSID is unknown
                    known_bssids = set(self._known_networks.keys())
                    unknown = bssids - known_bssids
                    if unknown and known_bssids & bssids:
                        anomalies.append({
                            "type": "evil_twin",
                            "ssid": ssid,
                            "bssids": sorted(bssids),
                            "reason": "Same SSID with known and unknown BSSIDs",
                            "details": {
                                "known_bssids": sorted(known_bssids & bssids),
                                "unknown_bssids": sorted(unknown),
                            },
                        })

        self._anomalies.extend(anomalies)
        if anomalies:
            logger.warning("Detected %d potential evil twins", len(anomalies))
        return anomalies

    # ── Deauth flood detection ─────────────────────────────────────────

    def record_deauth(self, timestamp: Optional[float] = None) -> None:
        """Record a deauthentication frame event.

        Parameters
        ----------
        timestamp:
            Epoch timestamp; defaults to current time.
        """
        now = timestamp or time.time()
        self._deauth_events.append(now)

    def detect_deauth_flood(self) -> Optional[Dict]:
        """Check if a deauthentication flood is in progress.

        Returns an anomaly dict if the deauth rate exceeds the
        threshold, or ``None`` otherwise.
        """
        now = time.time()
        cutoff = now - self.deauth_window

        # Prune old events
        self._deauth_events = [t for t in self._deauth_events if t >= cutoff]
        recent_count = len(self._deauth_events)

        if recent_count >= self.deauth_threshold:
            anomaly = {
                "type": "deauth_flood",
                "reason": f"{recent_count} deauth frames in {self.deauth_window}s window",
                "details": {
                    "frame_count": recent_count,
                    "window_seconds": self.deauth_window,
                    "threshold": self.deauth_threshold,
                },
            }
            self._anomalies.append(anomaly)
            logger.warning("Deauth flood detected: %d frames in %.0fs", recent_count, self.deauth_window)
            return anomaly

        return None

    # ── Combined scan analysis ─────────────────────────────────────────

    def analyze_scan(self, scan_results: List[Dict]) -> Dict[str, List[Dict]]:
        """Run all anomaly detections on a scan result set.

        Returns a dict with ``"rogue_aps"``, ``"evil_twins"``, and
        ``"all_anomalies"``.
        """
        rogue = self.detect_rogue_aps(scan_results)
        twins = self.detect_evil_twins(scan_results)
        deauth = self.detect_deauth_flood()

        all_anomalies = rogue + twins
        if deauth:
            all_anomalies.append(deauth)

        return {
            "rogue_aps": rogue,
            "evil_twins": twins,
            "deauth_flood": deauth,
            "all_anomalies": all_anomalies,
        }

    # ── Anomaly history ────────────────────────────────────────────────

    def get_anomalies(self) -> List[Dict]:
        """Return all accumulated anomalies."""
        return list(self._anomalies)

    def clear_anomalies(self) -> None:
        """Clear the anomaly history."""
        self._anomalies.clear()

    def clear_deauth_events(self) -> None:
        """Clear recorded deauth events."""
        self._deauth_events.clear()

    def summary(self) -> Dict[str, object]:
        """Return a summary of detected anomalies."""
        type_counts = Counter(a.get("type", "unknown") for a in self._anomalies)
        return {
            "total_anomalies": len(self._anomalies),
            "by_type": dict(type_counts),
            "baseline_size": len(self._known_networks),
            "deauth_events_buffered": len(self._deauth_events),
        }
