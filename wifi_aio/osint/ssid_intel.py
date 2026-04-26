"""SSID intelligence and analysis for WiFiAIO.

Analyzes SSID names to extract intelligence about the network,
including device identification, location hints, and security implications.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from wifi_aio.exceptions import OSINTError, WiFiTimeoutError

logger = logging.getLogger(__name__)


@dataclass
class SSIDAnalysis:
    """Result of SSID intelligence analysis."""
    ssid: str
    normalized_ssid: str = ""
    is_default: bool = False
    manufacturer: str = ""
    model: str = ""
    device_type: str = ""  # "router", "extender", "iot", "mobile_hotspot"
    location_hints: List[str] = field(default_factory=list)
    network_type: str = ""  # "home", "business", "public", "isp", "iot"
    encryption_hint: str = ""
    is_hidden: bool = False
    is_mesh: bool = False
    mesh_group: str = ""
    risk_indicators: List[str] = field(default_factory=list)
    confidence: str = "low"


# SSID patterns and their intelligence value
SSID_PATTERNS: List[Dict[str, Any]] = [
    # Default router SSIDs
    {"pattern": r"^NETGEAR\d*$", "manufacturer": "Netgear", "is_default": True, "device_type": "router"},
    {"pattern": r"^NETGEAR-\w+$", "manufacturer": "Netgear", "is_default": True, "device_type": "router"},
    {"pattern": r"^Linksys\d*$", "manufacturer": "Linksys", "is_default": True, "device_type": "router"},
    {"pattern": r"^linksys\w+$", "manufacturer": "Linksys", "is_default": True, "device_type": "router"},
    {"pattern": r"^dlink\w*$", "manufacturer": "D-Link", "is_default": True, "device_type": "router"},
    {"pattern": r"^DIR-\w+$", "manufacturer": "D-Link", "is_default": True, "device_type": "router", "model_prefix": "DIR"},
    {"pattern": r"^DAP-\w+$", "manufacturer": "D-Link", "is_default": True, "device_type": "access_point", "model_prefix": "DAP"},
    {"pattern": r"^Belkin\.\w+$", "manufacturer": "Belkin", "is_default": True, "device_type": "router"},
    {"pattern": r"^TP-LINK_\w+$", "manufacturer": "TP-Link", "is_default": True, "device_type": "router"},
    {"pattern": r"^TP-Link_\w+$", "manufacturer": "TP-Link", "is_default": True, "device_type": "router"},
    {"pattern": r"^ASUS_\w+$", "manufacturer": "ASUS", "is_default": True, "device_type": "router"},
    {"pattern": r"^RT-\w+$", "manufacturer": "ASUS", "is_default": True, "device_type": "router", "model_prefix": "RT"},
    {"pattern": r"^HUAWEI-\w+$", "manufacturer": "Huawei", "is_default": True, "device_type": "router"},
    {"pattern": r"^ZTE-\w+$", "manufacturer": "ZTE", "is_default": True, "device_type": "router"},
    {"pattern": r"^ZXHN-\w+$", "manufacturer": "ZTE", "is_default": True, "device_type": "router"},

    # ISP-provided gateways
    {"pattern": r"^xfinitywifi$", "manufacturer": "Comcast", "network_type": "isp", "device_type": "hotspot"},
    {"pattern": r"^XFINITY-\w+$", "manufacturer": "Comcast", "network_type": "isp", "device_type": "gateway"},
    {"pattern": r"^HOME-\w+$", "manufacturer": "Comcast", "network_type": "isp", "device_type": "gateway"},
    {"pattern": r"^ATT\w+$", "manufacturer": "AT&T", "network_type": "isp", "device_type": "gateway"},
    {"pattern": r"^2WIRE\d*$", "manufacturer": "AT&T/2Wire", "network_type": "isp", "device_type": "gateway"},
    {"pattern": r"^Pace-\w+$", "manufacturer": "AT&T/Pace", "network_type": "isp", "device_type": "gateway"},
    {"pattern": r"^BGW\d+", "manufacturer": "AT&T", "network_type": "isp", "device_type": "gateway"},
    {"pattern": r"^NVG\d+", "manufacturer": "AT&T/Netgear", "network_type": "isp", "device_type": "gateway"},
    {"pattern": r"^FIOS-\w+$", "manufacturer": "Verizon", "network_type": "isp", "device_type": "gateway"},
    {"pattern": r"^Verizon_\w+$", "manufacturer": "Verizon", "network_type": "isp", "device_type": "gateway"},
    {"pattern": r"^SpectrumSetup-\w+$", "manufacturer": "Charter", "network_type": "isp", "device_type": "gateway"},
    {"pattern": r"^MySpectrum\w+$", "manufacturer": "Charter", "network_type": "isp", "device_type": "gateway"},
    {"pattern": r"^Cox-\w+$", "manufacturer": "Cox", "network_type": "isp", "device_type": "gateway"},
    {"pattern": r"^CableWiFi$", "manufacturer": "Cable Providers", "network_type": "isp", "device_type": "hotspot"},

    # Mesh networks
    {"pattern": r"^.*[Ee]ero.*$", "manufacturer": "eero/Amazon", "device_type": "mesh", "is_mesh": True},
    {"pattern": r"^.*[Nn]est.*$", "manufacturer": "Google Nest", "device_type": "mesh", "is_mesh": True},
    {"pattern": r"^.*[Gg]oogle.*[Ff]iber.*$", "manufacturer": "Google", "device_type": "mesh", "is_mesh": True},
    {"pattern": r"^Orphi$", "manufacturer": "Netgear", "device_type": "mesh", "is_mesh": True},
    {"pattern": r"^Deco$", "manufacturer": "TP-Link", "device_type": "mesh", "is_mesh": True},
    {"pattern": r"^.*_5G$", "device_type": "router", "is_mesh": False},  # Dual-band indicator

    # WiFi extenders
    {"pattern": r"^.*[Ee]xtender.*$", "device_type": "extender"},
    {"pattern": r"^.*[Rr]epeater.*$", "device_type": "extender"},
    {"pattern": r"^.*_EXT$", "device_type": "extender"},
    {"pattern": r"^.*-EXT$", "device_type": "extender"},
    {"pattern": r"^RE\d+", "manufacturer": "TP-Link", "device_type": "extender"},

    # Mobile hotspots
    {"pattern": r"^.*[Hh]otspot.*$", "device_type": "mobile_hotspot"},
    {"pattern": r"^MiFi-\w+$", "manufacturer": "Novatel/Inseego", "device_type": "mobile_hotspot"},
    {"pattern": r"^iPhone$", "manufacturer": "Apple", "device_type": "mobile_hotspot"},
    {"pattern": r"^iPhone\s*\(\d+\)$", "manufacturer": "Apple", "device_type": "mobile_hotspot"},
    {"pattern": r"^AndroidAP\w*$", "manufacturer": "Android", "device_type": "mobile_hotspot"},
    {"pattern": r"^Galaxy-\w+$", "manufacturer": "Samsung", "device_type": "mobile_hotspot"},

    # IoT devices
    {"pattern": r"^.*[Rr]ing.*$", "manufacturer": "Ring/Amazon", "device_type": "iot", "network_type": "iot"},
    {"pattern": r"^.*[Nn]est.*$", "manufacturer": "Google Nest", "device_type": "iot", "network_type": "iot"},
    {"pattern": r"^.*[Hh]ue.*$", "manufacturer": "Philips Hue", "device_type": "iot", "network_type": "iot"},
    {"pattern": r"^.*[Aa]lexa.*$", "manufacturer": "Amazon", "device_type": "iot", "network_type": "iot"},
    {"pattern": r"^.*[Ss]mart.*$", "device_type": "iot", "network_type": "iot"},
    {"pattern": r"^.*[Tt]uya.*$", "manufacturer": "Tuya", "device_type": "iot", "network_type": "iot"},
    {"pattern": r"^ESP_\w+$", "manufacturer": "Espressif", "device_type": "iot", "network_type": "iot"},

    # Business/enterprise
    {"pattern": r"^.*[Cc]orporate.*$", "network_type": "business"},
    {"pattern": r"^.*[Gg]uest.*$", "network_type": "business"},
    {"pattern": r"^.*[Vv]isitor.*$", "network_type": "business"},
    {"pattern": r"^.*-Guest$", "network_type": "business"},
    {"pattern": r"^.*_Guest$", "network_type": "business"},
    {"pattern": r"^.*-CORP$", "network_type": "business"},
    {"pattern": r"^.*-SEC$", "network_type": "business"},

    # Public WiFi
    {"pattern": r"^.*[Ff]ree.*[Ww]i.*[Ff]i.*$", "network_type": "public"},
    {"pattern": r"^.*[Aa]irport.*$", "network_type": "public", "location_hints": ["airport"]},
    {"pattern": r"^.*[Hh]otel.*$", "network_type": "public", "location_hints": ["hotel"]},
    {"pattern": r"^.*[Cc]afe.*$", "network_type": "public", "location_hints": ["cafe"]},
    {"pattern": r"^.*[Ll]ibrary.*$", "network_type": "public", "location_hints": ["library"]},
    {"pattern": r"^.*[Mm]all.*$", "network_type": "public", "location_hints": ["shopping"]},
]

# Suffixes that indicate dual-band or mesh nodes
BAND_SUFFIXES = {
    "_5G": "5 GHz band",
    "_5GHz": "5 GHz band",
    "-5G": "5 GHz band",
    "_2.4G": "2.4 GHz band",
    "_2.4GHz": "2.4 GHz band",
    "-2.4G": "2.4 GHz band",
    "_EXT": "Extender/Repeater",
    "-EXT": "Extender/Repeater",
    "_Guest": "Guest network",
    "-Guest": "Guest network",
    "_IoT": "IoT network",
    "-IoT": "IoT network",
}


class SSIDIntel:
    """SSID intelligence and analysis.

    Analyzes SSID names to extract intelligence about the network,
    including device identification, security assessment, and
    location hints.

    Usage::

        intel = SSIDIntel()
        analysis = intel.analyze("NETGEAR-5G")
        print(f"Default: {analysis.is_default}, Manufacturer: {analysis.manufacturer}")

        analysis = intel.analyze("SmithFamily_Guest")
        print(f"Network type: {analysis.network_type}, Risks: {analysis.risk_indicators}")
    """

    def __init__(self) -> None:
        """Initialize the SSID intelligence analyzer."""
        self._compiled_patterns = [
            {**p, "compiled": re.compile(p["pattern"], re.IGNORECASE)}
            for p in SSID_PATTERNS
        ]
        logger.info("SSIDIntel initialized with %d patterns", len(self._compiled_patterns))

    def analyze(self, ssid: str) -> SSIDAnalysis:
        """Analyze an SSID for intelligence.

        Args:
            ssid: SSID to analyze.

        Returns:
            SSIDAnalysis with extracted intelligence.
        """
        analysis = SSIDAnalysis(
            ssid=ssid,
            normalized_ssid=ssid.strip(),
        )

        if not ssid:
            analysis.is_hidden = True
            analysis.risk_indicators.append("Hidden SSID - may indicate security-conscious or suspicious network")
            return analysis

        # Check for hidden network
        if ssid.strip() in ("", "\x00", "Hidden", "HIDDEN"):
            analysis.is_hidden = True
            analysis.risk_indicators.append("Hidden SSID")
            return analysis

        # Match against known patterns
        for pattern in self._compiled_patterns:
            compiled = pattern["compiled"]
            if compiled.search(ssid):
                if pattern.get("is_default") and not analysis.is_default:
                    analysis.is_default = True
                if pattern.get("manufacturer") and not analysis.manufacturer:
                    analysis.manufacturer = pattern["manufacturer"]
                if pattern.get("device_type") and not analysis.device_type:
                    analysis.device_type = pattern["device_type"]
                if pattern.get("network_type") and not analysis.network_type:
                    analysis.network_type = pattern["network_type"]
                if pattern.get("is_mesh"):
                    analysis.is_mesh = True
                if pattern.get("model_prefix") and not analysis.model:
                    # Extract model from SSID
                    match = compiled.search(ssid)
                    if match:
                        analysis.model = match.group()

                for hint in pattern.get("location_hints", []):
                    if hint not in analysis.location_hints:
                        analysis.location_hints.append(hint)

        # Analyze SSID suffixes
        self._analyze_suffixes(ssid, analysis)

        # Analyze for personal information leakage
        self._check_personal_info(ssid, analysis)

        # Determine confidence
        if analysis.manufacturer and analysis.is_default:
            analysis.confidence = "high"
        elif analysis.manufacturer or analysis.device_type:
            analysis.confidence = "medium"
        elif analysis.network_type:
            analysis.confidence = "medium"
        else:
            analysis.confidence = "low"

        return analysis

    def _analyze_suffixes(self, ssid: str, analysis: SSIDAnalysis) -> None:
        """Analyze SSID suffixes for band and network type information."""
        for suffix, description in BAND_SUFFIXES.items():
            if ssid.endswith(suffix):
                base_ssid = ssid[: -len(suffix)]
                analysis.encryption_hint = description

                if "Extender" in description and not analysis.device_type:
                    analysis.device_type = "extender"
                if "Guest" in description and not analysis.network_type:
                    analysis.network_type = "business"

                # Check if base SSID matches a pattern
                for pattern in self._compiled_patterns:
                    compiled = pattern["compiled"]
                    if compiled.search(base_ssid):
                        if pattern.get("manufacturer") and not analysis.manufacturer:
                            analysis.manufacturer = pattern["manufacturer"]
                        if pattern.get("is_default") and not analysis.is_default:
                            analysis.is_default = True
                        break

    def _check_personal_info(self, ssid: str, analysis: SSIDAnalysis) -> None:
        """Check if the SSID leaks personal information."""
        # Check for names
        name_patterns = [
            (r"^([A-Z][a-z]+)'s?\s", "possible personal name in SSID"),
            (r"^(The\s)?([A-Z][a-z]+)s?\s", "possible family name in SSID"),
            (r"^([A-Z][a-z]+)(Family|Home|House)", "family name in SSID"),
        ]

        for pattern, risk in name_patterns:
            if re.search(pattern, ssid):
                analysis.risk_indicators.append(risk)
                break

        # Check for addresses
        address_pattern = r"\d{1,5}\s+\w+\s+(St|Ave|Blvd|Dr|Ln|Rd|Ct|Way)"
        if re.search(address_pattern, ssid, re.IGNORECASE):
            analysis.risk_indicators.append("possible address in SSID")

        # Check for phone numbers
        phone_pattern = r"\d{3}[-.]?\d{3}[-.]?\d{4}"
        if re.search(phone_pattern, ssid):
            analysis.risk_indicators.append("possible phone number in SSID")

        # Default SSID risk
        if analysis.is_default:
            analysis.risk_indicators.append(
                "Default SSID indicates possible unconfigured device with default credentials"
            )

    def analyze_batch(self, ssids: List[str]) -> Dict[str, SSIDAnalysis]:
        """Analyze multiple SSIDs.

        Args:
            ssids: List of SSIDs to analyze.

        Returns:
            Dictionary mapping SSIDs to their analysis results.
        """
        results: Dict[str, SSIDAnalysis] = {}
        for ssid in ssids:
            results[ssid] = self.analyze(ssid)
        return results

    def find_related_ssids(
        self,
        ssid: str,
        available_ssids: List[str],
    ) -> List[Dict[str, Any]]:
        """Find SSIDs related to the target (e.g., same network, extenders).

        Args:
            ssid: Target SSID.
            available_ssids: All visible SSIDs.

        Returns:
            List of related SSID dictionaries with relationship info.
        """
        related: List[Dict[str, Any]] = []

        # Extract base SSID by removing known suffixes
        base_ssid = ssid
        for suffix in BAND_SUFFIXES:
            if base_ssid.endswith(suffix):
                base_ssid = base_ssid[: -len(suffix)]
                break

        for candidate in available_ssids:
            if candidate == ssid:
                continue

            # Check if candidate shares the same base
            candidate_base = candidate
            for suffix in BAND_SUFFIXES:
                if candidate_base.endswith(suffix):
                    candidate_base = candidate_base[: -len(suffix)]
                    break

            if candidate_base == base_ssid:
                related.append({
                    "ssid": candidate,
                    "relationship": "same_network",
                    "base_ssid": base_ssid,
                })
            elif candidate.startswith(base_ssid) or base_ssid.startswith(candidate):
                related.append({
                    "ssid": candidate,
                    "relationship": "related_prefix",
                    "base_ssid": base_ssid,
                })

        return related

    def generate_ssid_fingerprint(self, ssid: str) -> str:
        """Generate a fingerprint hash for an SSID.

        Useful for tracking SSIDs across scans without storing
        the actual SSID text.

        Args:
            ssid: SSID to fingerprint.

        Returns:
            SHA-256 hash string of the normalized SSID.
        """
        normalized = ssid.strip().lower()
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]

    def quick_check(self, ssid: str) -> Dict[str, Any]:
        """Quick intelligence check on an SSID.

        Args:
            ssid: SSID to check.

        Returns:
            Dictionary with key intelligence points.
        """
        analysis = self.analyze(ssid)
        return {
            "is_default": analysis.is_default,
            "manufacturer": analysis.manufacturer,
            "device_type": analysis.device_type,
            "network_type": analysis.network_type,
            "risk_count": len(analysis.risk_indicators),
            "confidence": analysis.confidence,
        }
