"""MLAnomalyDetector – Extended statistical & ML anomaly detection.

Applies Z-score / IQR statistical methods, Isolation Forest, DBSCAN
clustering, and a rolling statistical baseline to WiFi signal and
traffic data.  Falls back gracefully when numpy/scipy/sklearn are
not installed.
"""

import math
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

from wifi_aio.exceptions import WiFiConnectionError
from wifi_aio.logger import get_logger

logger = get_logger("analysis.ml_anomaly")

# ── Optional dependency guards ──────────────────────────────────────────

try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    np = None  # type: ignore[assignment]
    _HAS_NUMPY = False

try:
    from scipy import stats as scipy_stats
    _HAS_SCIPY = True
except ImportError:
    scipy_stats = None  # type: ignore[assignment]
    _HAS_SCIPY = False

try:
    from sklearn.ensemble import IsolationForest as _IsolationForest
    from sklearn.cluster import DBSCAN as _DBSCAN
    _HAS_SKLEARN = True
except ImportError:
    _IsolationForest = None  # type: ignore[assignment,misc]
    _DBSCAN = None  # type: ignore[assignment,misc]
    _HAS_SKLEARN = False


class MLAnomalyDetector:
    """Statistical anomaly detection for WiFi metrics.

    Uses Z-score, IQR, Isolation Forest, and DBSCAN methods to identify
    outlier data points in signal strength, frame counts, or any numeric
    metric series.  Maintains a rolling statistical baseline for
    comparison.

    Parameters
    ----------
    zscore_threshold:
        Number of standard deviations beyond which a value is
        considered anomalous (default 2.0).
    iqr_multiplier:
        Multiplier for the IQR range in outlier detection
        (default 1.5, same as box-plot whiskers).
    min_samples:
        Minimum number of data points required before anomaly
        detection is attempted (default 5).
    """

    def __init__(
        self,
        zscore_threshold: float = 2.0,
        iqr_multiplier: float = 1.5,
        min_samples: int = 5,
    ) -> None:
        self.zscore_threshold = zscore_threshold
        self.iqr_multiplier = iqr_multiplier
        self.min_samples = min_samples
        self._data_series: Dict[str, List[float]] = defaultdict(list)
        self._anomalies: List[Dict] = []

        # Rolling statistical baseline: maps feature name → {mean, std, count}
        self._baseline: Dict[str, Dict[str, float]] = {}

    # ── Data ingestion ─────────────────────────────────────────────────

    def add_value(self, series_name: str, value: float) -> None:
        """Add a value to a named data series.

        Parameters
        ----------
        series_name:
            Name of the metric (e.g. ``"signal_dbm"``, ``"frame_count"``).
        value:
            The observed numeric value.
        """
        self._data_series[series_name].append(value)

    def add_values(self, series_name: str, values: Sequence[float]) -> None:
        """Add multiple values to a named data series."""
        self._data_series[series_name].extend(values)

    def set_series(self, series_name: str, values: Sequence[float]) -> None:
        """Replace a data series entirely."""
        self._data_series[series_name] = list(values)

    def get_series(self, series_name: str) -> List[float]:
        """Return the current values in a named series."""
        return list(self._data_series.get(series_name, []))

    # ── Z-score detection ──────────────────────────────────────────────

    def zscore_detect(self, series_name: str) -> List[Dict]:
        """Detect anomalies in a series using Z-score analysis.

        Each value with |Z| > *zscore_threshold* is flagged.

        Returns a list of anomaly dicts with ``index``, ``value``,
        ``zscore``, and ``threshold``.
        """
        values = self._data_series.get(series_name, [])
        if len(values) < self.min_samples:
            return []

        mean = sum(values) / len(values)
        std = math.sqrt(sum((x - mean) ** 2 for x in values) / len(values))
        if std == 0:
            return []

        anomalies: List[Dict] = []
        for i, val in enumerate(values):
            z = (val - mean) / std
            if abs(z) > self.zscore_threshold:
                anomalies.append({
                    "series": series_name,
                    "method": "zscore",
                    "index": i,
                    "value": val,
                    "zscore": round(z, 3),
                    "mean": round(mean, 2),
                    "std": round(std, 2),
                    "threshold": self.zscore_threshold,
                })

        self._anomalies.extend(anomalies)
        return anomalies

    # ── IQR detection ──────────────────────────────────────────────────

    def iqr_detect(self, series_name: str) -> List[Dict]:
        """Detect anomalies in a series using the IQR method.

        A value is anomalous if it falls below Q1 − k·IQR or above
        Q3 + k·IQR, where k is *iqr_multiplier*.

        Returns a list of anomaly dicts.
        """
        values = self._data_series.get(series_name, [])
        if len(values) < self.min_samples:
            return []

        sorted_vals = sorted(values)
        q1, q3 = self._quartiles(sorted_vals)
        iqr = q3 - q1
        lower_bound = q1 - self.iqr_multiplier * iqr
        upper_bound = q3 + self.iqr_multiplier * iqr

        anomalies: List[Dict] = []
        for i, val in enumerate(values):
            if val < lower_bound or val > upper_bound:
                anomalies.append({
                    "series": series_name,
                    "method": "iqr",
                    "index": i,
                    "value": val,
                    "q1": round(q1, 2),
                    "q3": round(q3, 2),
                    "iqr": round(iqr, 2),
                    "lower_bound": round(lower_bound, 2),
                    "upper_bound": round(upper_bound, 2),
                })

        self._anomalies.extend(anomalies)
        return anomalies

    # ── Combined detection ─────────────────────────────────────────────

    def detect_all(self, series_name: Optional[str] = None) -> Dict[str, List[Dict]]:
        """Run both Z-score and IQR detection on one or all series.

        Parameters
        ----------
        series_name:
            If given, analyse only this series; otherwise analyse all.

        Returns ``{"zscore": [...], "iqr": [...]}``.
        """
        if series_name:
            names = [series_name]
        else:
            names = list(self._data_series.keys())

        zscore_anomalies: List[Dict] = []
        iqr_anomalies: List[Dict] = []

        for name in names:
            zscore_anomalies.extend(self.zscore_detect(name))
            iqr_anomalies.extend(self.iqr_detect(name))

        return {"zscore": zscore_anomalies, "iqr": iqr_anomalies}

    # ── Signal-specific detection ──────────────────────────────────────

    def detect_signal_anomalies(
        self,
        scan_results: List[Dict],
    ) -> List[Dict]:
        """Detect anomalous signal strengths in scan results.

        Compiles all signal_dbm values, then runs both detection methods.

        Returns a consolidated list of anomalies.
        """
        signals = [ap["signal_dbm"] for ap in scan_results if "signal_dbm" in ap]
        if len(signals) < self.min_samples:
            return []

        self.set_series("signal_dbm", signals)
        results = self.detect_all("signal_dbm")

        # Merge and deduplicate (same index may appear in both)
        seen_indices: set = set()
        combined: List[Dict] = []
        for anomaly in results["zscore"] + results["iqr"]:
            key = (anomaly.get("series"), anomaly.get("index"))
            if key not in seen_indices:
                seen_indices.add(key)
                # Add the BSSID/SSID if available
                idx = anomaly.get("index", -1)
                if 0 <= idx < len(scan_results):
                    anomaly["bssid"] = scan_results[idx].get("bssid", "")
                    anomaly["ssid"] = scan_results[idx].get("ssid", "")
                combined.append(anomaly)

        return combined

    # ── Channel load anomalies ─────────────────────────────────────────

    def detect_channel_anomalies(
        self,
        scan_results: List[Dict],
    ) -> List[Dict]:
        """Detect channels with abnormally high AP counts.

        Uses IQR on per-channel AP counts.
        """
        channel_counts = Counter(ap.get("channel", 0) for ap in scan_results)
        channels = sorted(channel_counts.keys())
        counts = [channel_counts[ch] for ch in channels]

        if len(counts) < self.min_samples:
            return []

        self.set_series("channel_ap_count", counts)
        iqr_results = self.iqr_detect("channel_ap_count")

        # Map back to channel numbers
        anomalies: List[Dict] = []
        for anomaly in iqr_results:
            idx = anomaly.get("index", -1)
            if 0 <= idx < len(channels):
                anomaly["channel"] = channels[idx]
                anomaly["ap_count"] = counts[idx]
                anomalies.append(anomaly)

        return anomalies

    # ── Isolation Forest ───────────────────────────────────────────────

    def detect_with_isolation_forest(
        self,
        networks: List[Dict],
        contamination: float = 0.1,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> List[Dict]:
        """Detect rogue APs and evil twins using Isolation Forest.

        Extracts per-network features (signal_delta, channel frequency,
        security encoding, BSSID entropy), fits an Isolation Forest,
        and returns the networks flagged as anomalous (label −1).

        Falls back to a pure-numpy / pure-Python implementation when
        sklearn is not available.

        Parameters
        ----------
        networks:
            List of network dicts, each containing at least
            ``signal_dbm``, ``channel``, ``security``, and ``bssid``.
        contamination:
            Expected proportion of outliers (default 0.1).
        n_estimators:
            Number of trees in the forest (default 100).
        random_state:
            Random seed for reproducibility (default 42).

        Returns
        -------
        List of dicts for networks flagged as anomalous, each
        containing the original network data plus ``anomaly_score``
        and ``method``.
        """
        if len(networks) < self.min_samples:
            return []

        feature_matrix, feature_names = self._extract_features(networks)
        if feature_matrix is None or len(feature_matrix) == 0:
            return []

        if _HAS_SKLEARN and _HAS_NUMPY:
            return self._isolation_forest_sklearn(
                networks, feature_matrix, feature_names,
                contamination, n_estimators, random_state,
            )

        # Fallback: pure-numpy z-score across features
        if _HAS_NUMPY:
            return self._isolation_forest_numpy_fallback(
                networks, feature_matrix, feature_names, contamination,
            )

        # Pure-Python fallback: use composite z-score
        return self._isolation_forest_python_fallback(
            networks, feature_matrix, feature_names, contamination,
        )

    def _isolation_forest_sklearn(
        self,
        networks: List[Dict],
        feature_matrix: "np.ndarray",
        feature_names: List[str],
        contamination: float,
        n_estimators: int,
        random_state: int,
    ) -> List[Dict]:
        """Isolation Forest using sklearn."""
        import numpy as _np  # guaranteed available here

        clf = _IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
        )
        labels = clf.fit_predict(feature_matrix)
        scores = clf.decision_function(feature_matrix)

        anomalous: List[Dict] = []
        for i, (label, score) in enumerate(zip(labels, scores)):
            if label == -1:
                entry = dict(networks[i])
                entry["method"] = "isolation_forest"
                entry["anomaly_score"] = float(score)
                entry["features"] = {
                    name: float(feature_matrix[i, j])
                    for j, name in enumerate(feature_names)
                }
                anomalous.append(entry)

        return anomalous

    def _isolation_forest_numpy_fallback(
        self,
        networks: List[Dict],
        feature_matrix: "np.ndarray",
        feature_names: List[str],
        contamination: float,
    ) -> List[Dict]:
        """Isolation Forest fallback using numpy z-score across features."""
        import numpy as _np

        mean = _np.mean(feature_matrix, axis=0)
        std = _np.std(feature_matrix, axis=0)
        std[std == 0] = 1.0  # avoid division by zero
        z_scores = _np.abs((feature_matrix - mean) / std)
        composite = _np.mean(z_scores, axis=1)

        threshold = _np.percentile(composite, (1 - contamination) * 100)
        anomalous: List[Dict] = []
        for i in range(len(networks)):
            if composite[i] > threshold:
                entry = dict(networks[i])
                entry["method"] = "isolation_forest"
                entry["anomaly_score"] = float(-composite[i])  # negative = more anomalous
                entry["features"] = {
                    name: float(feature_matrix[i, j])
                    for j, name in enumerate(feature_names)
                }
                anomalous.append(entry)
        return anomalous

    def _isolation_forest_python_fallback(
        self,
        networks: List[Dict],
        feature_matrix: List[List[float]],
        feature_names: List[str],
        contamination: float,
    ) -> List[Dict]:
        """Pure-Python fallback for Isolation Forest (composite z-score)."""
        n = len(feature_matrix)
        d = len(feature_names)
        # Compute per-column mean and std
        col_means = []
        col_stds = []
        for j in range(d):
            col = [feature_matrix[i][j] for i in range(n)]
            m = sum(col) / n
            s = math.sqrt(sum((x - m) ** 2 for x in col) / n) if n > 0 else 0
            col_means.append(m)
            col_stds.append(s if s > 0 else 1.0)

        composite_scores: List[float] = []
        for i in range(n):
            z_sum = 0.0
            for j in range(d):
                z_sum += abs((feature_matrix[i][j] - col_means[j]) / col_stds[j])
            composite_scores.append(z_sum / d)

        sorted_scores = sorted(composite_scores, reverse=True)
        cutoff_idx = max(1, int(n * contamination))
        threshold = sorted_scores[min(cutoff_idx, len(sorted_scores) - 1)]

        anomalous: List[Dict] = []
        for i, score in enumerate(composite_scores):
            if score >= threshold:
                entry = dict(networks[i])
                entry["method"] = "isolation_forest"
                entry["anomaly_score"] = float(-score)
                entry["features"] = {
                    name: feature_matrix[i][j]
                    for j, name in enumerate(feature_names)
                }
                anomalous.append(entry)
        return anomalous

    # ── DBSCAN clustering ──────────────────────────────────────────────

    def detect_with_dbscan(
        self,
        networks: List[Dict],
        eps: float = 0.5,
        min_samples: int = 3,
    ) -> List[Dict]:
        """Group similar APs with DBSCAN and return outlier networks.

        Networks assigned to cluster label −1 are considered outliers
        (not part of any dense cluster), which often indicates rogue
        APs, evil twins, or misconfigured equipment.

        Falls back to a simple distance-based approach when sklearn or
        numpy is not available.

        Parameters
        ----------
        networks:
            List of network dicts.
        eps:
            Maximum distance between two samples for them to be
            considered neighbours (default 0.5).
        min_samples:
            Minimum number of samples in a neighbourhood for a
            point to be a core point (default 3).

        Returns
        -------
        List of dicts for outlier networks (cluster label −1).
        """
        if len(networks) < self.min_samples:
            return []

        feature_matrix, feature_names = self._extract_features(networks)
        if feature_matrix is None or len(feature_matrix) == 0:
            return []

        if _HAS_SKLEARN and _HAS_NUMPY:
            return self._dbscan_sklearn(
                networks, feature_matrix, feature_names, eps, min_samples,
            )

        if _HAS_NUMPY:
            return self._dbscan_numpy_fallback(
                networks, feature_matrix, feature_names, eps, min_samples,
            )

        return self._dbscan_python_fallback(
            networks, feature_matrix, feature_names, eps, min_samples,
        )

    def _dbscan_sklearn(
        self,
        networks: List[Dict],
        feature_matrix: "np.ndarray",
        feature_names: List[str],
        eps: float,
        min_samples: int,
    ) -> List[Dict]:
        """DBSCAN using sklearn."""
        clf = _DBSCAN(eps=eps, min_samples=min_samples)
        labels = clf.fit_predict(feature_matrix)

        anomalous: List[Dict] = []
        for i, label in enumerate(labels):
            if label == -1:
                entry = dict(networks[i])
                entry["method"] = "dbscan"
                entry["cluster_label"] = -1
                entry["features"] = {
                    name: float(feature_matrix[i, j])
                    for j, name in enumerate(feature_names)
                }
                anomalous.append(entry)
        return anomalous

    def _dbscan_numpy_fallback(
        self,
        networks: List[Dict],
        feature_matrix: "np.ndarray",
        feature_names: List[str],
        eps: float,
        min_samples: int,
    ) -> List[Dict]:
        """DBSCAN fallback using numpy distance matrix."""
        import numpy as _np

        n = len(feature_matrix)
        # Normalise features to [0, 1]
        fmin = feature_matrix.min(axis=0)
        fmax = feature_matrix.max(axis=0)
        frange = fmax - fmin
        frange[frange == 0] = 1.0
        normed = (feature_matrix - fmin) / frange

        # Compute pairwise Euclidean distances
        diff = normed[:, _np.newaxis, :] - normed[_np.newaxis, :, :]
        dists = _np.sqrt(_np.sum(diff ** 2, axis=2))

        # Simple DBSCAN assignment
        labels = _np.full(n, -1)
        cluster_id = 0
        visited = set()

        for i in range(n):
            if i in visited:
                continue
            visited.add(i)
            neighbours = list(_np.where(dists[i] <= eps)[0])
            if len(neighbours) < min_samples:
                continue
            labels[i] = cluster_id
            seed_set = list(neighbours)
            seed_set = [s for s in seed_set if s != i]
            while seed_set:
                q = seed_set.pop(0)
                if q in visited:
                    continue
                visited.add(q)
                labels[q] = cluster_id
                q_neighbours = list(_np.where(dists[q] <= eps)[0])
                if len(q_neighbours) >= min_samples:
                    seed_set.extend(q_neighbours)
            cluster_id += 1

        anomalous: List[Dict] = []
        for i in range(n):
            if labels[i] == -1:
                entry = dict(networks[i])
                entry["method"] = "dbscan"
                entry["cluster_label"] = -1
                entry["features"] = {
                    name: float(feature_matrix[i, j])
                    for j, name in enumerate(feature_names)
                }
                anomalous.append(entry)
        return anomalous

    def _dbscan_python_fallback(
        self,
        networks: List[Dict],
        feature_matrix: List[List[float]],
        feature_names: List[str],
        eps: float,
        min_samples: int,
    ) -> List[Dict]:
        """Pure-Python DBSCAN fallback (simplified)."""
        n = len(feature_matrix)
        d = len(feature_names)

        # Normalise to [0, 1]
        col_mins = [min(feature_matrix[i][j] for i in range(n)) for j in range(d)]
        col_maxs = [max(feature_matrix[i][j] for i in range(n)) for j in range(d)]
        normed: List[List[float]] = []
        for i in range(n):
            row = []
            for j in range(d):
                rng = col_maxs[j] - col_mins[j]
                denom = rng if rng > 0 else 1.0
                row.append((feature_matrix[i][j] - col_mins[j]) / denom)
            normed.append(row)

        def euclidean(a: List[float], b: List[float]) -> float:
            return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

        labels = [-1] * n
        cluster_id = 0
        visited: set = set()

        for i in range(n):
            if i in visited:
                continue
            visited.add(i)
            neighbours = [j for j in range(n) if euclidean(normed[i], normed[j]) <= eps]
            if len(neighbours) < min_samples:
                continue
            labels[i] = cluster_id
            seed_set = [s for s in neighbours if s != i]
            while seed_set:
                q = seed_set.pop(0)
                if q in visited:
                    continue
                visited.add(q)
                labels[q] = cluster_id
                q_neighbours = [j for j in range(n) if euclidean(normed[q], normed[j]) <= eps]
                if len(q_neighbours) >= min_samples:
                    seed_set.extend(q_neighbours)
            cluster_id += 1

        anomalous: List[Dict] = []
        for i in range(n):
            if labels[i] == -1:
                entry = dict(networks[i])
                entry["method"] = "dbscan"
                entry["cluster_label"] = -1
                entry["features"] = {
                    name: feature_matrix[i][j]
                    for j, name in enumerate(feature_names)
                }
                anomalous.append(entry)
        return anomalous

    # ── Statistical baseline ───────────────────────────────────────────

    def update_baseline(self, networks: List[Dict]) -> None:
        """Update the rolling statistical baseline from observed networks.

        Computes per-feature mean and standard deviation, merging with
        any existing baseline using an exponential moving average.

        Parameters
        ----------
        networks:
            List of network dicts used to update the baseline.
        """
        features, names = self._extract_features(networks)
        if features is None or len(features) == 0:
            return

        alpha = 0.3  # EMA smoothing factor

        for j, name in enumerate(names):
            if _HAS_NUMPY:
                col = features[:, j]
                new_mean = float(col.mean())
                new_std = float(col.std())
            else:
                col = [features[i][j] for i in range(len(features))]
                new_mean = sum(col) / len(col)
                new_std = math.sqrt(sum((x - new_mean) ** 2 for x in col) / len(col)) if len(col) > 0 else 0.0

            if name in self._baseline:
                old = self._baseline[name]
                self._baseline[name] = {
                    "mean": old["mean"] * (1 - alpha) + new_mean * alpha,
                    "std": old["std"] * (1 - alpha) + new_std * alpha,
                    "count": old["count"] + len(col),
                }
            else:
                self._baseline[name] = {
                    "mean": new_mean,
                    "std": new_std,
                    "count": float(len(col)),
                }

    def get_baseline(self) -> Dict[str, Dict[str, float]]:
        """Return the current statistical baseline."""
        return dict(self._baseline)

    # ── Anomaly score ──────────────────────────────────────────────────

    def compute_anomaly_score(self, network: Dict) -> float:
        """Compute a 0.0–1.0 anomaly score for a single network.

        The score measures how much the network's features deviate
        from the established statistical baseline.  A score near 0
        means "normal"; near 1 means "highly anomalous".

        If no baseline has been established yet, returns 0.0.

        Parameters
        ----------
        network:
            A single network dict.

        Returns
        -------
        Float in [0.0, 1.0].
        """
        if not self._baseline:
            return 0.0

        features_single, names = self._extract_features([network])
        if features_single is None or len(features_single) == 0:
            return 0.0

        row = features_single[0] if _HAS_NUMPY else features_single[0]
        deviations: List[float] = []

        for j, name in enumerate(names):
            if name not in self._baseline:
                continue
            bl = self._baseline[name]
            val = float(row[j])
            std = bl["std"]
            if std == 0:
                continue
            dev = abs((val - bl["mean"]) / std)
            # Sigmoid mapping: 0 deviations → 0, 3+ deviations → ~1
            score = 1.0 / (1.0 + math.exp(-1.5 * (dev - 2.0)))
            deviations.append(score)

        if not deviations:
            return 0.0

        return float(sum(deviations) / len(deviations))

    # ── Feature engineering ────────────────────────────────────────────

    def _extract_features(
        self,
        networks: List[Dict],
    ) -> Tuple[Optional[object], List[str]]:
        """Extract numerical features from a list of network dicts.

        Features
        --------
        signal_dbm:
            Signal strength (negative dBm).
        channel:
            Channel number (normalised).
        security_mismatch_score:
            0 if security matches the dominant type, 1 otherwise.
        signal_delta:
            Deviation from mean signal across all networks.
        channel_switch_frequency:
            Fraction of networks on the same channel.
        beacon_interval_variance:
            Variance proxy for beacon interval anomalies (0 if unknown).
        bssid_entropy:
            Shannon entropy of the BSSID hex characters.

        Returns
        -------
        (feature_matrix, feature_names) where feature_matrix is either
        a numpy ndarray, a list of lists, or None (if no features could
        be extracted), and feature_names is a list of column labels.
        """
        if not networks:
            return None, []

        feature_names = [
            "signal_dbm",
            "channel",
            "security_mismatch_score",
            "signal_delta",
            "channel_switch_frequency",
            "beacon_interval_variance",
            "bssid_entropy",
        ]

        # Compute global statistics for delta features
        signals = [n.get("signal_dbm", -100) for n in networks]
        channels = [n.get("channel", 0) for n in networks]
        securities = [n.get("security", "OPEN") for n in networks]

        mean_signal = sum(signals) / len(signals) if signals else -100
        channel_counts = Counter(channels)
        total_networks = len(networks)

        # Dominant security type
        if securities:
            dominant_sec = Counter(securities).most_common(1)[0][0]
        else:
            dominant_sec = "OPEN"

        rows: List[List[float]] = []
        for net in networks:
            sig = float(net.get("signal_dbm", -100))
            ch = float(net.get("channel", 0))
            sec = net.get("security", "OPEN")
            bssid = net.get("bssid", "")

            sec_mismatch = 0.0 if sec == dominant_sec else 1.0
            sig_delta = abs(sig - mean_signal)
            ch_freq = channel_counts.get(int(ch), 0) / total_networks if total_networks > 0 else 0.0
            beacon_var = 0.0  # placeholder; real value from beacon data
            bssid_entropy = self._shannon_entropy(bssid)

            rows.append([sig, ch, sec_mismatch, sig_delta, ch_freq, beacon_var, bssid_entropy])

        if not rows:
            return None, feature_names

        if _HAS_NUMPY:
            import numpy as _np
            return _np.array(rows, dtype=_np.float64), feature_names

        return rows, feature_names

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Compute Shannon entropy of a string's characters.

        Parameters
        ----------
        s:
            Input string (e.g. a BSSID).

        Returns
        -------
        Entropy in bits (0.0 for empty or single-char strings).
        """
        if not s:
            return 0.0
        freq: Dict[str, int] = Counter(s)
        length = len(s)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    # ── Anomaly history ────────────────────────────────────────────────

    def get_anomalies(self) -> List[Dict]:
        """Return all accumulated anomalies."""
        return list(self._anomalies)

    def clear_anomalies(self) -> None:
        """Clear anomaly history."""
        self._anomalies.clear()

    def clear_data(self) -> None:
        """Clear all stored data series and anomalies."""
        self._data_series.clear()
        self._anomalies.clear()

    def summary(self) -> Dict[str, object]:
        """Return a summary of stored data and detected anomalies."""
        method_counts = Counter(a.get("method", "unknown") for a in self._anomalies)
        series_counts = Counter(a.get("series", "unknown") for a in self._anomalies)

        result: Dict[str, object] = {
            "series_count": len(self._data_series),
            "series_names": list(self._data_series.keys()),
            "total_data_points": sum(len(v) for v in self._data_series.values()),
            "total_anomalies": len(self._anomalies),
            "anomalies_by_method": dict(method_counts),
            "anomalies_by_series": dict(series_counts),
            "config": {
                "zscore_threshold": self.zscore_threshold,
                "iqr_multiplier": self.iqr_multiplier,
                "min_samples": self.min_samples,
            },
        }
        if self._baseline:
            result["baseline_features"] = list(self._baseline.keys())
        return result

    # ── Internals ──────────────────────────────────────────────────────

    @staticmethod
    def _quartiles(sorted_values: List[float]) -> Tuple[float, float]:
        """Compute Q1 and Q3 from a sorted list using linear interpolation."""
        n = len(sorted_values)

        def percentile(p: float) -> float:
            rank = p / 100 * (n - 1)
            lower = int(math.floor(rank))
            upper = int(math.ceil(rank))
            if lower == upper:
                return sorted_values[lower]
            frac = rank - lower
            return sorted_values[lower] + frac * (sorted_values[upper] - sorted_values[lower])

        return percentile(25), percentile(75)
