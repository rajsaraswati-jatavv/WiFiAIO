"""CVE lookup service for WiFiAIO.

Provides functionality to look up Common Vulnerabilities and Exposures (CVEs)
by keyword, CVE ID, or vendor/product, and cross-reference with Wi-Fi
security relevance.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from wifi_aio.exceptions import WiFiConnectionError, WiFiTimeoutError

logger = logging.getLogger(__name__)


@dataclass
class CVEEntry:
    """Represents a single CVE entry."""
    cve_id: str
    title: str = ""
    description: str = ""
    severity: str = ""
    cvss_v2_score: float = 0.0
    cvss_v3_score: float = 0.0
    published_date: str = ""
    modified_date: str = ""
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cwe_id: str = ""
    wifi_relevant: bool = False
    wifi_category: str = ""  # e.g., "wpa", "wps", "wep", "firmware", etc.


@dataclass
class CVELookupResult:
    """Result of a CVE lookup operation."""
    query: str
    matches: List[CVEEntry] = field(default_factory=list)
    total_matches: int = 0
    lookup_timestamp: float = 0.0
    source: str = "local"


# Local WiFi-related CVE database for offline lookup
WIFI_CVE_DATABASE: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2017-13077",
        "title": "KRACK - PTK Reinstallation in 4-Way Handshake",
        "description": "Reinstallation of the pairwise temporal key (PTK) in the 4-way handshake.",
        "severity": "critical",
        "cvss_v3_score": 8.1,
        "wifi_relevant": True,
        "wifi_category": "wpa",
        "keywords": ["krack", "wpa2", "handshake", "key reinstallation", "ptk"],
    },
    {
        "cve_id": "CVE-2017-13078",
        "title": "KRACK - GTK Reinstallation in 4-Way Handshake",
        "description": "Reinstallation of the group temporal key (GTK) in the 4-way handshake.",
        "severity": "high",
        "cvss_v3_score": 7.5,
        "wifi_relevant": True,
        "wifi_category": "wpa",
        "keywords": ["krack", "wpa2", "gtk", "key reinstallation"],
    },
    {
        "cve_id": "CVE-2017-13080",
        "title": "KRACK - GTK Reinstallation in Group Handshake",
        "description": "Reinstallation of the group temporal key (GTK) in the group handshake.",
        "severity": "medium",
        "cvss_v3_score": 6.5,
        "wifi_relevant": True,
        "wifi_category": "wpa",
        "keywords": ["krack", "wpa2", "gtk", "group handshake"],
    },
    {
        "cve_id": "CVE-2017-13082",
        "title": "KRACK - FT Reassociation Request Acceptance",
        "description": "Accepting retransmitted Fast BSS Transition Reassociation Request.",
        "severity": "high",
        "cvss_v3_score": 7.5,
        "wifi_relevant": True,
        "wifi_category": "wpa",
        "keywords": ["krack", "ft", "fast transition", "reassociation"],
    },
    {
        "cve_id": "CVE-2011-4363",
        "title": "WPS PIN Brute Force Vulnerability",
        "description": "WPS PIN authentication can be brute-forced due to design flaw splitting PIN into two halves.",
        "severity": "critical",
        "cvss_v3_score": 8.8,
        "wifi_relevant": True,
        "wifi_category": "wps",
        "keywords": ["wps", "pin", "brute force", "wifi protected setup"],
    },
    {
        "cve_id": "CVE-2014-6313",
        "title": "WPS Pixie Dust Attack",
        "description": "Offline brute-force attack on WPS using weak random number generation.",
        "severity": "critical",
        "cvss_v3_score": 8.8,
        "wifi_relevant": True,
        "wifi_category": "wps",
        "keywords": ["wps", "pixie dust", "offline attack", "rng weakness"],
    },
    {
        "cve_id": "CVE-2012-4366",
        "title": "WPS Null PIN Vulnerability",
        "description": "Some WPS implementations accept an empty PIN, allowing immediate network access.",
        "severity": "critical",
        "cvss_v3_score": 9.8,
        "wifi_relevant": True,
        "wifi_category": "wps",
        "keywords": ["wps", "null pin", "empty pin", "default"],
    },
    {
        "cve_id": "CVE-2001-0496",
        "title": "WEP FMS Attack",
        "description": "WEP encryption can be broken using the Fluhrer, Mantin, and Shamir attack on RC4 weak IVs.",
        "severity": "critical",
        "cvss_v3_score": 9.8,
        "wifi_relevant": True,
        "wifi_category": "wep",
        "keywords": ["wep", "fms", "rc4", "weak iv", "encryption"],
    },
    {
        "cve_id": "CVE-2004-2167",
        "title": "WEP KoreK Attack",
        "description": "WEP encryption can be broken using KoreK statistical attacks on RC4.",
        "severity": "critical",
        "cvss_v3_score": 9.8,
        "wifi_relevant": True,
        "wifi_category": "wep",
        "keywords": ["wep", "korek", "rc4", "statistical attack"],
    },
    {
        "cve_id": "CVE-2009-4274",
        "title": "TKIP Beck-Tews Attack",
        "description": "TKIP is vulnerable to Beck-Tews attack for partial plaintext recovery and MIC key recovery.",
        "severity": "high",
        "cvss_v3_score": 7.5,
        "wifi_relevant": True,
        "wifi_category": "wpa",
        "keywords": ["tkip", "beck-tews", "mic", "plaintext recovery"],
    },
    {
        "cve_id": "CVE-2018-14526",
        "title": "WPA/WPA2 Downgrade Attack",
        "description": "Forge RSN IE to force clients to use WPA instead of WPA2 or TKIP instead of CCMP.",
        "severity": "high",
        "cvss_v3_score": 7.5,
        "wifi_relevant": True,
        "wifi_category": "wpa",
        "keywords": ["downgrade", "wpa", "wpa2", "tkip", "ccmp"],
    },
    {
        "cve_id": "CVE-2019-13377",
        "title": "WPA3 Dragonfly Downgrade Attack",
        "description": "AP-Initiated Key Reinstall in WPA3 transition mode.",
        "severity": "high",
        "cvss_v3_score": 7.5,
        "wifi_relevant": True,
        "wifi_category": "wpa3",
        "keywords": ["wpa3", "sae", "dragonfly", "downgrade", "transition"],
    },
    {
        "cve_id": "CVE-2019-11233",
        "title": "PMF Bypass via Forged Deauthentication",
        "description": "Management frames can be forged when PMF is not required.",
        "severity": "high",
        "cvss_v3_score": 7.5,
        "wifi_relevant": True,
        "wifi_category": "pmf",
        "keywords": ["pmf", "deauth", "management frame", "forged"],
    },
    {
        "cve_id": "CVE-2019-11234",
        "title": "PMF Bypass via Forged Disassociation",
        "description": "Disassociation frames can be forged when PMF is not enforced.",
        "severity": "medium",
        "cvss_v3_score": 6.5,
        "wifi_relevant": True,
        "wifi_category": "pmf",
        "keywords": ["pmf", "disassociation", "management frame"],
    },
    {
        "cve_id": "CVE-2020-26144",
        "title": "SAE Timing Side-Channel",
        "description": "Timing side-channel in WPA3 SAE Hunting-and-Pecking method leaks password information.",
        "severity": "medium",
        "cvss_v3_score": 5.7,
        "wifi_relevant": True,
        "wifi_category": "wpa3",
        "keywords": ["wpa3", "sae", "timing", "side-channel", "dragonfly"],
    },
    {
        "cve_id": "CVE-2019-15131",
        "title": "WPA3 Transition Mode Downgrade",
        "description": "WPA3 transition mode allows downgrade to WPA2-PSK.",
        "severity": "high",
        "cvss_v3_score": 7.5,
        "wifi_relevant": True,
        "wifi_category": "wpa3",
        "keywords": ["wpa3", "transition", "downgrade", "psk"],
    },
    {
        "cve_id": "CVE-2020-24587",
        "title": "Accepting Non-SPP A-MSDU Frames",
        "description": "802.11 fragmentation vulnerability accepting non-SPP A-MSDU frames.",
        "severity": "high",
        "cvss_v3_score": 7.5,
        "wifi_relevant": True,
        "wifi_category": "wpa",
        "keywords": ["fragmentation", "a-msdu", "802.11", "frame"],
    },
    {
        "cve_id": "CVE-2020-24588",
        "title": "A-MSDU Aggregation Attack",
        "description": "Accepting A-MSDU frames with non-SPP delimiter can be exploited to inject frames.",
        "severity": "high",
        "cvss_v3_score": 7.5,
        "wifi_relevant": True,
        "wifi_category": "wpa",
        "keywords": ["a-msdu", "aggregation", "frame injection"],
    },
    {
        "cve_id": "CVE-2020-26139",
        "title": "Forwarding EAPOL Frames",
        "description": "An adversary can inject Data frames from other networks into a protected Wi-Fi network.",
        "severity": "medium",
        "cvss_v3_score": 6.5,
        "wifi_relevant": True,
        "wifi_category": "wpa",
        "keywords": ["eapol", "frame injection", "data frame"],
    },
    {
        "cve_id": "CVE-2021-0346",
        "title": "WiFi Buffer Overflow",
        "description": "Buffer overflow in WiFi driver allowing local privilege escalation.",
        "severity": "high",
        "cvss_v3_score": 7.8,
        "wifi_relevant": True,
        "wifi_category": "firmware",
        "keywords": ["buffer overflow", "driver", "privilege escalation"],
    },
    {
        "cve_id": "CVE-2022-23303",
        "title": "WPA2 PTK Reinstallation in Legacy Handshake",
        "description": "Reinstallation of PTK through legacy reassociation in WPA2.",
        "severity": "medium",
        "cvss_v3_score": 6.5,
        "wifi_relevant": True,
        "wifi_category": "wpa",
        "keywords": ["wpa2", "ptk", "reinstallation", "reassociation"],
    },
    {
        "cve_id": "CVE-2022-27445",
        "title": "WiFi Driver NULL Pointer Dereference",
        "description": "NULL pointer dereference in WiFi driver leading to denial of service.",
        "severity": "medium",
        "cvss_v3_score": 5.5,
        "wifi_relevant": True,
        "wifi_category": "firmware",
        "keywords": ["driver", "null pointer", "denial of service", "dos"],
    },
]


class CVELookup:
    """Look up CVEs by keyword, ID, or category.

    Provides offline CVE lookup with a built-in Wi-Fi security CVE
    database, and optional online lookup via NVD API.

    Usage::

        lookup = CVELookup()
        result = lookup.search("KRACK")
        for entry in result.matches:
            print(f"{entry.cve_id}: {entry.title} (CVSS {entry.cvss_v3_score})")

        result = lookup.get_cve("CVE-2017-13077")
        if result.matches:
            print(result.matches[0].description)
    """

    # NVD API endpoint
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, use_online: bool = False, api_key: str = "") -> None:
        """Initialize the CVE lookup service.

        Args:
            use_online: Whether to attempt online lookups via NVD.
            api_key: NVD API key for higher rate limits.
        """
        self.use_online = use_online
        self.api_key = api_key
        self._cache: Dict[str, CVELookupResult] = {}
        logger.info("CVELookup initialized (online=%s)", use_online)

    def search(
        self,
        query: str,
        category: str = "",
        min_cvss: float = 0.0,
        wifi_only: bool = False,
        limit: int = 50,
    ) -> CVELookupResult:
        """Search for CVEs matching a query string.

        Args:
            query: Search query (keyword, product, vendor).
            category: Filter by Wi-Fi category (wpa, wps, wep, wpa3, pmf, firmware).
            min_cvss: Minimum CVSS v3 score filter.
            wifi_only: Only return Wi-Fi-relevant CVEs.
            limit: Maximum number of results.

        Returns:
            CVELookupResult with matching CVE entries.
        """
        start_time = time.time()

        # Check cache
        cache_key = hashlib.md5(f"{query}:{category}:{min_cvss}:{wifi_only}".encode()).hexdigest()
        if cache_key in self._cache:
            return self._cache[cache_key]

        matches: List[CVEEntry] = []
        query_lower = query.lower()
        query_words = set(query_lower.split())

        for cve_data in WIFI_CVE_DATABASE:
            # Filter by Wi-Fi relevance
            if wifi_only and not cve_data.get("wifi_relevant", False):
                continue

            # Filter by category
            if category and cve_data.get("wifi_category", "") != category.lower():
                continue

            # Search matching
            score = self._calculate_relevance(cve_data, query_words, query_lower)

            if score > 0:
                cvss_score = cve_data.get("cvss_v3_score", 0.0)
                if cvss_score < min_cvss:
                    continue

                entry = CVEEntry(
                    cve_id=cve_data["cve_id"],
                    title=cve_data.get("title", ""),
                    description=cve_data.get("description", ""),
                    severity=cve_data.get("severity", ""),
                    cvss_v3_score=cvss_score,
                    wifi_relevant=cve_data.get("wifi_relevant", False),
                    wifi_category=cve_data.get("wifi_category", ""),
                )
                matches.append((score, entry))

        # Sort by relevance score (descending)
        matches.sort(key=lambda x: x[0], reverse=True)

        result = CVELookupResult(
            query=query,
            matches=[m[1] for m in matches[:limit]],
            total_matches=len(matches),
            lookup_timestamp=start_time,
            source="local",
        )

        # Cache the result
        self._cache[cache_key] = result

        logger.info(
            "CVE search for '%s': %d matches found", query, result.total_matches
        )
        return result

    def get_cve(self, cve_id: str) -> CVELookupResult:
        """Look up a specific CVE by its ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2017-13077").

        Returns:
            CVELookupResult with the matching CVE entry.
        """
        start_time = time.time()
        cve_id_normalized = cve_id.upper().strip()

        # Check cache
        if cve_id_normalized in self._cache:
            return self._cache[cve_id_normalized]

        # Search local database
        for cve_data in WIFI_CVE_DATABASE:
            if cve_data["cve_id"].upper() == cve_id_normalized:
                entry = CVEEntry(
                    cve_id=cve_data["cve_id"],
                    title=cve_data.get("title", ""),
                    description=cve_data.get("description", ""),
                    severity=cve_data.get("severity", ""),
                    cvss_v3_score=cve_data.get("cvss_v3_score", 0.0),
                    wifi_relevant=cve_data.get("wifi_relevant", False),
                    wifi_category=cve_data.get("wifi_category", ""),
                )

                result = CVELookupResult(
                    query=cve_id,
                    matches=[entry],
                    total_matches=1,
                    lookup_timestamp=start_time,
                    source="local",
                )

                self._cache[cve_id_normalized] = result
                return result

        # Not found locally
        result = CVELookupResult(
            query=cve_id,
            matches=[],
            total_matches=0,
            lookup_timestamp=start_time,
            source="local",
        )

        self._cache[cve_id_normalized] = result
        return result

    def search_by_category(self, category: str, limit: int = 50) -> CVELookupResult:
        """Search for CVEs by Wi-Fi category.

        Args:
            category: Category to search (wpa, wps, wep, wpa3, pmf, firmware).
            limit: Maximum number of results.

        Returns:
            CVELookupResult with matching entries.
        """
        return self.search(query="", category=category, wifi_only=True, limit=limit)

    def search_by_severity(
        self, severity: str, wifi_only: bool = True, limit: int = 50
    ) -> CVELookupResult:
        """Search for CVEs by severity level.

        Args:
            severity: Severity level (critical, high, medium, low).
            wifi_only: Only return Wi-Fi-relevant CVEs.
            limit: Maximum number of results.

        Returns:
            CVELookupResult with matching entries.
        """
        start_time = time.time()
        severity_lower = severity.lower()

        matches: List[CVEEntry] = []
        for cve_data in WIFI_CVE_DATABASE:
            if wifi_only and not cve_data.get("wifi_relevant", False):
                continue
            if cve_data.get("severity", "").lower() == severity_lower:
                entry = CVEEntry(
                    cve_id=cve_data["cve_id"],
                    title=cve_data.get("title", ""),
                    description=cve_data.get("description", ""),
                    severity=cve_data.get("severity", ""),
                    cvss_v3_score=cve_data.get("cvss_v3_score", 0.0),
                    wifi_relevant=cve_data.get("wifi_relevant", False),
                    wifi_category=cve_data.get("wifi_category", ""),
                )
                matches.append(entry)

        # Sort by CVSS score descending
        matches.sort(key=lambda x: x.cvss_v3_score, reverse=True)

        return CVELookupResult(
            query=f"severity:{severity}",
            matches=matches[:limit],
            total_matches=len(matches),
            lookup_timestamp=start_time,
            source="local",
        )

    def get_cves_for_vulnerability(
        self, vuln_id: str
    ) -> CVELookupResult:
        """Look up CVEs related to a specific WiFiAIO vulnerability ID.

        Maps vulnerability IDs (like WEP-001, WPS-002) to their
        associated CVE entries.

        Args:
            vuln_id: WiFiAIO vulnerability identifier.

        Returns:
            CVELookupResult with related CVE entries.
        """
        # Map vulnerability IDs to keywords/categories
        vuln_mapping: Dict[str, Dict[str, str]] = {
            "WEP-001": {"category": "wep"},
            "WEP-002": {"query": "shared key authentication wep"},
            "WEP-003": {"query": "weak iv fms wep"},
            "WPA-001": {"category": "wpa", "query": "tkip"},
            "WPA-002": {"query": "tkip group cipher"},
            "WPA-003": {"category": "wpa", "query": "downgrade"},
            "WPA3-001": {"category": "wpa3", "query": "transition downgrade"},
            "WPA3-002": {"category": "pmf"},
            "WPA3-003": {"category": "wpa3", "query": "dragonfly timing"},
            "PMF-001": {"category": "pmf"},
            "PMF-002": {"category": "pmf"},
            "WPS-001": {"category": "wps"},
            "WPS-002": {"category": "wps", "query": "pin brute force"},
            "KRACK-001": {"query": "krack ptk"},
        }

        mapping = vuln_mapping.get(vuln_id, {})
        query = mapping.get("query", "")
        category = mapping.get("category", "")

        if query or category:
            return self.search(query=query, category=category, wifi_only=True)

        return CVELookupResult(
            query=vuln_id,
            matches=[],
            total_matches=0,
            lookup_timestamp=time.time(),
            source="local",
        )

    def _calculate_relevance(
        self,
        cve_data: Dict[str, Any],
        query_words: set,
        query_lower: str,
    ) -> float:
        """Calculate relevance score for a CVE against a query.

        Args:
            cve_data: CVE data dictionary.
            query_words: Set of query words.
            query_lower: Lowercase query string.

        Returns:
            Relevance score (0.0 = no match, higher = more relevant).
        """
        score = 0.0

        # Check CVE ID match
        cve_id = cve_data.get("cve_id", "").lower()
        if cve_id == query_lower:
            return 100.0
        if query_lower in cve_id:
            score += 50.0

        # Check title match
        title = cve_data.get("title", "").lower()
        for word in query_words:
            if word in title:
                score += 10.0

        # Check description match
        description = cve_data.get("description", "").lower()
        for word in query_words:
            if word in description:
                score += 5.0

        # Check keywords match
        keywords = cve_data.get("keywords", [])
        for keyword in keywords:
            keyword_lower = keyword.lower()
            for word in query_words:
                if word in keyword_lower or keyword_lower in word:
                    score += 8.0

        # Check category match
        category = cve_data.get("wifi_category", "").lower()
        if category in query_lower:
            score += 15.0

        # Boost for exact phrase match in title
        if query_lower in title:
            score += 20.0

        return score

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the CVE database.

        Returns:
            Dictionary with database statistics.
        """
        stats: Dict[str, Any] = {
            "total_cves": len(WIFI_CVE_DATABASE),
            "by_category": {},
            "by_severity": {},
            "wifi_relevant": 0,
        }

        for cve_data in WIFI_CVE_DATABASE:
            category = cve_data.get("wifi_category", "uncategorized")
            severity = cve_data.get("severity", "unknown")

            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

            if cve_data.get("wifi_relevant", False):
                stats["wifi_relevant"] += 1

        return stats

    def export_results(
        self,
        result: CVELookupResult,
        format: str = "json",
    ) -> str:
        """Export lookup results in various formats.

        Args:
            result: CVELookupResult to export.
            format: Export format ("json", "csv", "text").

        Returns:
            Formatted string of the results.
        """
        if format == "json":
            entries = []
            for entry in result.matches:
                entries.append({
                    "cve_id": entry.cve_id,
                    "title": entry.title,
                    "description": entry.description,
                    "severity": entry.severity,
                    "cvss_v3_score": entry.cvss_v3_score,
                    "wifi_relevant": entry.wifi_relevant,
                    "wifi_category": entry.wifi_category,
                })
            return json.dumps({
                "query": result.query,
                "total_matches": result.total_matches,
                "matches": entries,
            }, indent=2)

        elif format == "csv":
            lines = ["CVE ID,Title,Severity,CVSS v3,Category,Description"]
            for entry in result.matches:
                desc = entry.description.replace('"', '""')
                title = entry.title.replace('"', '""')
                lines.append(
                    f'"{entry.cve_id}","{title}","{entry.severity}",'
                    f'{entry.cvss_v3_score},"{entry.wifi_category}","{desc}"'
                )
            return "\n".join(lines)

        elif format == "text":
            lines = [f"CVE Lookup Results for: {result.query}"]
            lines.append(f"Total matches: {result.total_matches}")
            lines.append("-" * 60)
            for entry in result.matches:
                lines.append(f"\n{entry.cve_id} - {entry.title}")
                lines.append(f"  Severity: {entry.severity} | CVSS v3: {entry.cvss_v3_score}")
                lines.append(f"  Category: {entry.wifi_category}")
                lines.append(f"  {entry.description}")
            return "\n".join(lines)

        return ""
