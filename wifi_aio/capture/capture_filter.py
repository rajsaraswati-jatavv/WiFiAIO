"""Capture filter engine for BPF and display filters.

Provides utilities for constructing Berkeley Packet Filter (BPF) strings
and applying display-style filters to captured packets.
"""

import re
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

from wifi_aio.constants import FrameType
from wifi_aio.exceptions import CaptureError


# ── BPF filter helpers ─────────────────────────────────────────────────

# Common 802.11 type/subtype BPF expressions
BPF_MGMT_FRAMES = "type mgt"
BPF_CTL_FRAMES = "type ctl"
BPF_DATA_FRAMES = "type data"
BPF_BEACON = "type mgt subtype beacon"
BPF_PROBE_REQUEST = "type mgt subtype probe-req"
BPF_PROBE_RESPONSE = "type mgt subtype probe-resp"
BPF_AUTHENTICATION = "type mgt subtype auth"
BPF_DEAUTHENTICATION = "type mgt subtype deauth"
BPF_ASSOCIATION_REQUEST = "type mgt subtype assoc-req"
BPF_ASSOCIATION_RESPONSE = "type mgt subtype assoc-resp"
BPF_REASSOCIATION_REQUEST = "type mgt subtype reassoc-req"
BPF_REASSOCIATION_RESPONSE = "type mgt subtype reassoc-resp"
BPF_DISASSOCIATION = "type mgt subtype disassoc"
BPF_ACTION = "type mgt subtype action"
BPF_EAPOL = "port 888e or (ether proto 0x888e)"
BPF_WPA_HANDSHAKE = "type data and (ether proto 0x888e)"


class CaptureFilter:
    """Build and apply BPF / display filters for packet capture.

    Supports two filter modes:

    * **BPF filter** – A string passed to the capture engine's kernel-level
      packet filter (e.g. ``"type mgt subtype beacon"``).
    * **Display filter** – A post-capture Python-level filter applied to
      each parsed frame before acceptance.

    Parameters
    ----------
    bpf_filter:
        Initial BPF filter expression.
    display_filter:
        Initial display filter expression.
    """

    def __init__(
        self,
        bpf_filter: Optional[str] = None,
        display_filter: Optional[str] = None,
    ) -> None:
        self._bpf_filter = bpf_filter or ""
        self._display_filter = display_filter or ""
        self._bpf_parts: List[str] = []
        self._display_rules: List[Callable] = []
        self._bssid_whitelist: Set[str] = set()
        self._bssid_blacklist: Set[str] = set()
        self._ssid_patterns: List[re.Pattern] = []
        self._frame_types: Set[int] = set()

        # Parse initial filters
        if self._bpf_filter:
            self._bpf_parts = [self._bpf_filter]
        if self._display_filter:
            self._parse_display_filter(self._display_filter)

    # ── BPF filter construction ────────────────────────────────────────

    @property
    def bpf_filter(self) -> str:
        """Return the composed BPF filter string."""
        if self._bpf_parts:
            return " and ".join(f"({p})" for p in self._bpf_parts)
        return ""

    def set_bpf(self, expression: str) -> "CaptureFilter":
        """Set the BPF filter to a fixed expression (replaces any previous)."""
        self._bpf_parts = [expression]
        return self

    def add_bpf(self, expression: str) -> "CaptureFilter":
        """Add a BPF expression (ANDed with existing)."""
        if expression not in self._bpf_parts:
            self._bpf_parts.append(expression)
        return self

    def add_bpf_or(self, expression: str) -> "CaptureFilter":
        """Add a BPF expression using OR logic.

        Wraps all existing parts and the new expression in an OR group.
        """
        existing = self.bpf_filter
        if existing:
            self._bpf_parts = [f"{existing} or ({expression})"]
        else:
            self._bpf_parts = [expression]
        return self

    # ── Frame type filters ─────────────────────────────────────────────

    def filter_beacons(self) -> "CaptureFilter":
        """Add a filter for beacon frames."""
        self.add_bpf(BPF_BEACON)
        self._frame_types.add(0x0008)
        return self

    def filter_probes(self) -> "CaptureFilter":
        """Add a filter for probe request/response frames."""
        self.add_bpf_or(BPF_PROBE_REQUEST)
        self.add_bpf_or(BPF_PROBE_RESPONSE)
        return self

    def filter_authentication(self) -> "CaptureFilter":
        """Add a filter for authentication frames."""
        self.add_bpf(BPF_AUTHENTICATION)
        self._frame_types.add(0x000B)
        return self

    def filter_deauthentication(self) -> "CaptureFilter":
        """Add a filter for deauthentication frames."""
        self.add_bpf(BPF_DEAUTHENTICATION)
        self._frame_types.add(0x000C)
        return self

    def filter_eapol(self) -> "CaptureFilter":
        """Add a filter for EAPOL frames (WPA handshake)."""
        self.add_bpf(BPF_EAPOL)
        return self

    def filter_handshake(self) -> "CaptureFilter":
        """Add a filter for WPA 4-way handshake frames."""
        self.add_bpf(BPF_WPA_HANDSHAKE)
        return self

    def filter_management(self) -> "CaptureFilter":
        """Add a filter for all management frames."""
        self.add_bpf(BPF_MGMT_FRAMES)
        return self

    def filter_data(self) -> "CaptureFilter":
        """Add a filter for data frames."""
        self.add_bpf(BPF_DATA_FRAMES)
        return self

    # ── Address filters ────────────────────────────────────────────────

    def filter_bssid(self, bssid: str) -> "CaptureFilter":
        """Filter to a specific BSSID."""
        bssid = bssid.lower()
        self._bssid_whitelist.add(bssid)
        # BPF for BSSID in addr3 (most common case)
        self.add_bpf(f"wlan addr3 {bssid}")
        return self

    def filter_bssid_list(self, bssids: List[str]) -> "CaptureFilter":
        """Filter to multiple BSSIDs."""
        for bssid in bssids:
            self.filter_bssid(bssid)
        return self

    def exclude_bssid(self, bssid: str) -> "CaptureFilter":
        """Exclude a specific BSSID."""
        self._bssid_blacklist.add(bssid.lower())
        return self

    def filter_source(self, mac: str) -> "CaptureFilter":
        """Filter by source MAC address."""
        self.add_bpf(f"wlan addr2 {mac}")
        return self

    def filter_destination(self, mac: str) -> "CaptureFilter":
        """Filter by destination MAC address."""
        self.add_bpf(f"wlan addr1 {mac}")
        return self

    def filter_broadcast(self) -> "CaptureFilter":
        """Filter for broadcast frames (destination ff:ff:ff:ff:ff:ff)."""
        self.add_bpf("wlan addr1 ff:ff:ff:ff:ff:ff")
        return self

    # ── SSID filters ───────────────────────────────────────────────────

    def filter_ssid(self, ssid: str) -> "CaptureFilter":
        """Add an SSID display filter.

        Since SSIDs are in the frame body, they can't be filtered at the
        BPF level in most capture engines.  This adds a display filter.
        """
        try:
            pattern = re.compile(re.escape(ssid), re.IGNORECASE)
            self._ssid_patterns.append(pattern)
        except re.error:
            raise CaptureError(f"Invalid SSID pattern: {ssid!r}")
        return self

    def filter_ssid_regex(self, pattern: str) -> "CaptureFilter":
        """Add a regex-based SSID display filter."""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            self._ssid_patterns.append(compiled)
        except re.error as exc:
            raise CaptureError(f"Invalid regex pattern: {pattern!r}") from exc
        return self

    # ── Display filter ─────────────────────────────────────────────────

    @property
    def display_filter(self) -> str:
        """Return the current display filter expression."""
        return self._display_filter

    def set_display_filter(self, expression: str) -> "CaptureFilter":
        """Set a display filter expression.

        Supported syntax::

            type=mgt          # frame type
            subtype=beacon    # frame subtype
            bssid=aa:bb:cc:dd:ee:ff
            ssid=MyNetwork
            protected=true
            signal>-70
        """
        self._display_filter = expression
        self._display_rules.clear()
        self._parse_display_filter(expression)
        return self

    def matches(self, frame_dict: Dict) -> bool:
        """Test whether a parsed frame (as a dict) passes all filters.

        Parameters
        ----------
        frame_dict:
            A dictionary as returned by :meth:`ParsedFrame.to_dict`.

        Returns
        -------
        bool
            ``True`` if the frame passes all filter rules.
        """
        # BSSID whitelist
        if self._bssid_whitelist:
            bssid = frame_dict.get("bssid", "").lower()
            if bssid not in self._bssid_whitelist:
                return False

        # BSSID blacklist
        bssid = frame_dict.get("bssid", "").lower()
        if bssid in self._bssid_blacklist:
            return False

        # SSID patterns
        if self._ssid_patterns:
            ssid = frame_dict.get("ssid", "")
            if not any(p.search(ssid) for p in self._ssid_patterns):
                return False

        # Display rules
        for rule in self._display_rules:
            if not rule(frame_dict):
                return False

        return True

    # ── Filter composition ─────────────────────────────────────────────

    def combine(self, other: "CaptureFilter", operator: str = "and") -> "CaptureFilter":
        """Combine two filters with the given operator.

        Parameters
        ----------
        other:
            Another CaptureFilter to combine with.
        operator:
            ``"and"`` or ``"or"``.
        """
        if operator == "and":
            new_bpf_parts = self._bpf_parts + other._bpf_parts
        elif operator == "or":
            left = self.bpf_filter
            right = other.bpf_filter
            new_bpf_parts = [f"({left}) or ({right})"] if left and right else (
                self._bpf_parts or other._bpf_parts
            )
        else:
            raise CaptureError(f"Unsupported operator: {operator!r}")

        result = CaptureFilter()
        result._bpf_parts = new_bpf_parts
        result._bssid_whitelist = self._bssid_whitelist | other._bssid_whitelist
        result._bssid_blacklist = self._bssid_blacklist | other._bssid_blacklist
        result._ssid_patterns = self._ssid_patterns + other._ssid_patterns
        result._display_rules = self._display_rules + other._display_rules
        return result

    def reset(self) -> "CaptureFilter":
        """Clear all filters."""
        self._bpf_parts.clear()
        self._display_rules.clear()
        self._bssid_whitelist.clear()
        self._bssid_blacklist.clear()
        self._ssid_patterns.clear()
        self._frame_types.clear()
        self._display_filter = ""
        return self

    # ── Display filter parsing ─────────────────────────────────────────

    def _parse_display_filter(self, expression: str) -> None:
        """Parse a display filter expression into rule callables."""
        for token in expression.split():
            if "=" not in token:
                continue

            key, value = token.split("=", 1)
            key = key.strip().lower()
            value = value.strip()

            if key == "type":
                rule = self._make_type_rule(value)
            elif key == "subtype":
                rule = self._make_subtype_rule(value)
            elif key == "bssid":
                rule = self._make_bssid_rule(value)
            elif key == "ssid":
                rule = self._make_ssid_rule(value)
            elif key == "protected":
                rule = self._make_bool_rule("protected", value)
            elif key == "retry":
                rule = self._make_bool_rule("retry", value)
            elif key == "signal":
                rule = self._make_signal_rule(value)
            else:
                continue  # skip unknown keys

            self._display_rules.append(rule)

    @staticmethod
    def _make_type_rule(value: str) -> Callable[[Dict], bool]:
        """Create a frame type filter rule."""
        type_map = {"mgt": 0, "management": 0, "ctl": 1, "control": 1, "data": 2}
        type_val = type_map.get(value.lower())
        if type_val is None:
            try:
                type_val = int(value)
            except ValueError:
                return lambda f: True

        return lambda f: f.get("type") == type_val

    @staticmethod
    def _make_subtype_rule(value: str) -> Callable[[Dict], bool]:
        """Create a frame subtype filter rule."""
        subtype_map = {
            "beacon": 8, "probe_req": 4, "probe_resp": 5,
            "auth": 11, "deauth": 12, "assoc_req": 0,
            "assoc_resp": 1, "reassoc_req": 2, "reassoc_resp": 3,
            "disassoc": 10, "action": 13,
        }
        subtype_val = subtype_map.get(value.lower())
        if subtype_val is None:
            try:
                subtype_val = int(value)
            except ValueError:
                return lambda f: True

        return lambda f: f.get("subtype") == subtype_val

    @staticmethod
    def _make_bssid_rule(value: str) -> Callable[[Dict], bool]:
        """Create a BSSID filter rule."""
        target = value.lower()
        return lambda f: f.get("bssid", "").lower() == target

    @staticmethod
    def _make_ssid_rule(value: str) -> Callable[[Dict], bool]:
        """Create an SSID filter rule."""
        pattern = re.compile(re.escape(value), re.IGNORECASE)
        return lambda f: bool(pattern.search(f.get("ssid", "")))

    @staticmethod
    def _make_bool_rule(key: str, value: str) -> Callable[[Dict], bool]:
        """Create a boolean field filter rule."""
        target = value.lower() in ("true", "1", "yes")
        return lambda f: f.get(key) == target

    @staticmethod
    def _make_signal_rule(value: str) -> Callable[[Dict], bool]:
        """Create a signal strength filter rule (e.g. signal>-70)."""
        match = re.match(r"([><=!]+)(-?\d+)", value)
        if not match:
            return lambda f: True

        op, threshold = match.group(1), int(match.group(2))
        ops = {
            ">": lambda a, b: a > b,
            ">=": lambda a, b: a >= b,
            "<": lambda a, b: a < b,
            "<=": lambda a, b: a <= b,
            "=": lambda a, b: a == b,
            "==": lambda a, b: a == b,
            "!=": lambda a, b: a != b,
        }
        compare = ops.get(op, lambda a, b: True)

        return lambda f: compare(f.get("signal_dbm", -100), threshold)

    # ── String representation ──────────────────────────────────────────

    def __repr__(self) -> str:
        parts = []
        if self._bpf_parts:
            parts.append(f"bpf={self.bpf_filter!r}")
        if self._display_filter:
            parts.append(f"display={self._display_filter!r}")
        if self._bssid_whitelist:
            parts.append(f"bssid_whitelist={self._bssid_whitelist}")
        return f"CaptureFilter({', '.join(parts)})"
