"""TrafficAnalyzer – protocol distribution, bandwidth, and frame-type analysis.

Analyses captured 802.11 frames to determine protocol distribution,
estimate bandwidth usage, and classify frame types encountered in the
capture.
"""

from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple

from wifi_aio.constants import FrameType
from wifi_aio.exceptions import WiFiConnectionError
from wifi_aio.logger import get_logger

logger = get_logger("analysis.traffic_analyzer")

# ── Frame classification helpers ──────────────────────────────────────

_FRAME_TYPE_NAMES: Dict[int, str] = {
    0: "Management",
    1: "Control",
    2: "Data",
    3: "Extension",
}

_MANAGEMENT_SUBTYPE_NAMES: Dict[int, str] = {
    0x0: "Association Request",
    0x1: "Association Response",
    0x2: "Reassociation Request",
    0x3: "Reassociation Response",
    0x4: "Probe Request",
    0x5: "Probe Response",
    0x8: "Beacon",
    0x9: "ATIM",
    0xA: "Disassociation",
    0xB: "Authentication",
    0xC: "Deauthentication",
    0xD: "Action",
}

_CONTROL_SUBTYPE_NAMES: Dict[int, str] = {
    0x1: "RTS",
    0x2: "CTS",
    0x3: "ACK",
    0x9: "Block ACK",
}

_DATA_SUBTYPE_NAMES: Dict[int, str] = {
    0x0: "Data",
    0x1: "Data + CF-ACK",
    0x2: "Data + CF-Poll",
    0x3: "Data + CF-ACK + CF-Poll",
    0x4: "Null",
    0x5: "CF-ACK (no data)",
    0x6: "CF-Poll (no data)",
    0x7: "CF-ACK + CF-Poll (no data)",
    0x8: "QoS Data",
    0x9: "QoS Data + CF-ACK",
    0xA: "QoS Data + CF-Poll",
    0xB: "QoS Data + CF-ACK + CF-Poll",
    0xC: "QoS Null",
    0xD: "Reserved",
    0xE: "QoS CF-Poll (no data)",
    0xF: "QoS CF-ACK + CF-Poll (no data)",
}


class TrafficAnalyzer:
    """Analyse WiFi traffic from a list of captured frame records.

    Parameters
    ----------
    frames:
        List of frame-record dicts.  Each dict should contain:
        ``"frame_type"`` (int 0–3), ``"frame_subtype"`` (int),
        ``"length"`` (bytes), and optionally ``"src"``, ``"dst"``,
        ``"bssid"``, ``"signal_dbm"``, ``"timestamp"``.
    """

    def __init__(self, frames: Optional[List[Dict]] = None) -> None:
        self.frames: List[Dict] = frames or []

    def set_frames(self, frames: List[Dict]) -> None:
        """Replace the current frame data."""
        self.frames = frames

    # ── Frame type distribution ────────────────────────────────────────

    def frame_type_distribution(self) -> Dict[str, Dict[str, int]]:
        """Count frames by type and subtype.

        Returns a nested dict: ``{type_name: {subtype_name: count}}``.
        """
        dist: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for frame in self.frames:
            ftype = frame.get("frame_type", -1)
            subtype = frame.get("frame_subtype", -1)
            type_name = _FRAME_TYPE_NAMES.get(ftype, f"Unknown({ftype})")

            if ftype == 0:
                sub_name = _MANAGEMENT_SUBTYPE_NAMES.get(subtype, f"Subtype({subtype})")
            elif ftype == 1:
                sub_name = _CONTROL_SUBTYPE_NAMES.get(subtype, f"Subtype({subtype})")
            elif ftype == 2:
                sub_name = _DATA_SUBTYPE_NAMES.get(subtype, f"Subtype({subtype})")
            else:
                sub_name = f"Subtype({subtype})"

            dist[type_name][sub_name] += 1

        # Convert inner defaultdicts to plain dicts
        return {k: dict(v) for k, v in dist.items()}

    # ── Protocol distribution ──────────────────────────────────────────

    def protocol_distribution(self) -> Dict[str, int]:
        """Count frames by 802.11 protocol category.

        Returns a dict like ``{"Management": 150, "Control": 80, "Data": 200}``.
        """
        counter: Counter = Counter()
        for frame in self.frames:
            ftype = frame.get("frame_type", -1)
            name = _FRAME_TYPE_NAMES.get(ftype, "Unknown")
            counter[name] += 1
        return dict(counter)

    # ── Bandwidth estimation ───────────────────────────────────────────

    def bandwidth_estimate(self, capture_duration: float = 1.0) -> Dict[str, float]:
        """Estimate bandwidth from captured frame lengths.

        Parameters
        ----------
        capture_duration:
            Duration of the capture in seconds.

        Returns a dict with ``total_bytes``, ``total_mbps``,
        ``management_bytes``, ``control_bytes``, ``data_bytes``, and
        per-type Mbps estimates.
        """
        if capture_duration <= 0:
            capture_duration = 1.0

        total_bytes = 0
        type_bytes: Dict[int, int] = defaultdict(int)

        for frame in self.frames:
            length = frame.get("length", 0)
            total_bytes += length
            ftype = frame.get("frame_type", -1)
            type_bytes[ftype] += length

        total_mbps = (total_bytes * 8) / (capture_duration * 1_000_000)
        mgmt_mbps = (type_bytes.get(0, 0) * 8) / (capture_duration * 1_000_000)
        ctrl_mbps = (type_bytes.get(1, 0) * 8) / (capture_duration * 1_000_000)
        data_mbps = (type_bytes.get(2, 0) * 8) / (capture_duration * 1_000_000)

        return {
            "total_bytes": total_bytes,
            "total_mbps": round(total_mbps, 4),
            "management_bytes": type_bytes.get(0, 0),
            "control_bytes": type_bytes.get(1, 0),
            "data_bytes": type_bytes.get(2, 0),
            "management_mbps": round(mgmt_mbps, 4),
            "control_mbps": round(ctrl_mbps, 4),
            "data_mbps": round(data_mbps, 4),
        }

    # ── Frame size statistics ──────────────────────────────────────────

    def frame_size_stats(self) -> Dict[str, float]:
        """Compute min/max/mean/median frame sizes."""
        sizes = [f.get("length", 0) for f in self.frames]
        if not sizes:
            return {"min": 0, "max": 0, "mean": 0, "median": 0, "total_frames": 0}

        sorted_sizes = sorted(sizes)
        mid = len(sorted_sizes) // 2
        median = (sorted_sizes[mid - 1] + sorted_sizes[mid]) / 2 if len(sorted_sizes) % 2 == 0 else sorted_sizes[mid]

        return {
            "min": sorted_sizes[0],
            "max": sorted_sizes[-1],
            "mean": round(sum(sizes) / len(sizes), 2),
            "median": round(median, 2),
            "total_frames": len(sizes),
        }

    # ── Top talkers ────────────────────────────────────────────────────

    def top_talkers(self, limit: int = 10) -> List[Dict[str, object]]:
        """Identify the most active source MAC addresses by frame count.

        Returns a list of dicts with ``mac``, ``frame_count``, and
        ``total_bytes``.
        """
        counter: Dict[str, Dict[str, int]] = defaultdict(lambda: {"frame_count": 0, "total_bytes": 0})

        for frame in self.frames:
            src = frame.get("src", "")
            if src:
                counter[src]["frame_count"] += 1
                counter[src]["total_bytes"] += frame.get("length", 0)

        sorted_talkers = sorted(counter.items(), key=lambda x: x[1]["frame_count"], reverse=True)[:limit]
        return [
            {"mac": mac, "frame_count": stats["frame_count"], "total_bytes": stats["total_bytes"]}
            for mac, stats in sorted_talkers
        ]

    # ── Retransmission detection ───────────────────────────────────────

    def detect_retransmissions(self) -> Dict[str, int]:
        """Estimate retransmission count from frame records.

        Looks for duplicate (src, sequence_number) pairs in data frames.

        Returns ``{"total_frames"``, ``"retransmissions"``, ``"retransmit_rate"}``.
        """
        seen_sequences: Dict[Tuple[str, int], int] = {}
        retransmissions = 0
        data_frames = 0

        for frame in self.frames:
            if frame.get("frame_type") != 2:
                continue
            data_frames += 1
            src = frame.get("src", "")
            seq = frame.get("sequence", -1)
            if seq < 0:
                continue
            key = (src, seq)
            if key in seen_sequences:
                retransmissions += 1
            else:
                seen_sequences[key] = 1

        rate = (retransmissions / data_frames * 100) if data_frames > 0 else 0.0
        return {
            "total_data_frames": data_frames,
            "retransmissions": retransmissions,
            "retransmit_rate": round(rate, 2),
        }

    # ── Summary ────────────────────────────────────────────────────────

    def summary(self, capture_duration: float = 1.0) -> Dict[str, object]:
        """Return a comprehensive analysis summary combining all metrics."""
        return {
            "total_frames": len(self.frames),
            "protocol_distribution": self.protocol_distribution(),
            "frame_type_distribution": self.frame_type_distribution(),
            "bandwidth": self.bandwidth_estimate(capture_duration),
            "frame_size_stats": self.frame_size_stats(),
            "top_talkers": self.top_talkers(),
            "retransmissions": self.detect_retransmissions(),
        }
