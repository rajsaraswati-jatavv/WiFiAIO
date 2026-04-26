"""Vulnerability report generator for WiFiAIO.

Generates comprehensive vulnerability assessment reports from scan results,
supporting multiple output formats and severity aggregation.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from wifi_aio.exceptions import WiFiConnectionError, WiFiTimeoutError
from wifi_aio.vuln.wep_checker import WEPScanResult, WEPVulnerability
from wifi_aio.vuln.wpa_checker import WPAScanResult, WPAVulnerability
from wifi_aio.vuln.wpa3_checker import WPA3ScanResult, WPA3Vulnerability
from wifi_aio.vuln.pmf_checker import PMFScanResult, PMFVulnerability
from wifi_aio.vuln.wps_checker import WPSScanResult, WPSVulnerability
from wifi_aio.vuln.krack_checker import KRACKScanResult, KRACKVulnerability
from wifi_aio.vuln.default_cred_checker import DefaultCredScanResult, DefaultCredVulnerability
from wifi_aio.vuln.dns_hijack_checker import DNSHijackScanResult, DNSHijackVulnerability
from wifi_aio.vuln.rogue_dhcp_checker import RogueDHCPScanResult, RogueDHCPVulnerability

logger = logging.getLogger(__name__)


# Severity levels ordered by impact
SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@dataclass
class VulnSummary:
    """Summary statistics for a vulnerability report."""
    total_targets: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    unique_cves: int = 0
    most_common_vuln: str = ""
    most_vulnerable_target: str = ""


@dataclass
class VulnReportEntry:
    """A single entry in the vulnerability report."""
    bssid: str
    ssid: str
    category: str  # e.g., "wep", "wpa", "wps", etc.
    vuln_id: str
    title: str
    description: str
    severity: str
    cve_ids: List[str] = field(default_factory=list)
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnReport:
    """Vulnerability report data structure."""
    report_id: str = ""
    title: str = ""
    generated_at: float = 0.0
    entries: List[VulnReportEntry] = field(default_factory=list)
    summary: VulnSummary = field(default_factory=VulnSummary)
    scan_results: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


def _vuln_to_entry(
    bssid: str, ssid: str, category: str, vuln: Any
) -> VulnReportEntry:
    """Convert a vulnerability object to a VulnReportEntry."""
    return VulnReportEntry(
        bssid=bssid,
        ssid=ssid,
        category=category,
        vuln_id=getattr(vuln, "vuln_id", ""),
        title=getattr(vuln, "title", ""),
        description=getattr(vuln, "description", ""),
        severity=getattr(vuln, "severity", "info"),
        cve_ids=getattr(vuln, "cve_ids", []),
        recommendation=getattr(vuln, "recommendation", ""),
        evidence=getattr(vuln, "evidence", {}),
    )


class VulnReportGenerator:
    """Generates vulnerability assessment reports.

    Aggregates results from multiple vulnerability checkers and produces
    comprehensive reports in various formats.

    Usage::

        report_gen = VulnReportGenerator()
        report_gen.add_wep_result(wep_result)
        report_gen.add_wpa_result(wpa_result)
        report_gen.add_wps_result(wps_result)
        report = report_gen.generate()
        print(report_gen.to_text(report))
    """

    def __init__(self) -> None:
        """Initialize the vulnerability report generator."""
        self._results: List[Dict[str, Any]] = []
        self._entries: List[VulnReportEntry] = []
        logger.info("VulnReportGenerator initialized")

    def add_wep_result(self, result: WEPScanResult) -> None:
        """Add WEP scan results to the report.

        Args:
            result: WEP scan result to add.
        """
        for vuln in result.vulnerabilities:
            self._entries.append(
                _vuln_to_entry(result.bssid, result.ssid, "wep", vuln)
            )
        self._results.append({"type": "wep", "bssid": result.bssid, "ssid": result.ssid})

    def add_wpa_result(self, result: WPAScanResult) -> None:
        """Add WPA/TKIP scan results to the report."""
        for vuln in result.vulnerabilities:
            self._entries.append(
                _vuln_to_entry(result.bssid, result.ssid, "wpa", vuln)
            )
        self._results.append({"type": "wpa", "bssid": result.bssid, "ssid": result.ssid})

    def add_wpa3_result(self, result: WPA3ScanResult) -> None:
        """Add WPA3/SAE scan results to the report."""
        for vuln in result.vulnerabilities:
            self._entries.append(
                _vuln_to_entry(result.bssid, result.ssid, "wpa3", vuln)
            )
        self._results.append({"type": "wpa3", "bssid": result.bssid, "ssid": result.ssid})

    def add_pmf_result(self, result: PMFScanResult) -> None:
        """Add PMF scan results to the report."""
        for vuln in result.vulnerabilities:
            self._entries.append(
                _vuln_to_entry(result.bssid, result.ssid, "pmf", vuln)
            )
        self._results.append({"type": "pmf", "bssid": result.bssid, "ssid": result.ssid})

    def add_wps_result(self, result: WPSScanResult) -> None:
        """Add WPS scan results to the report."""
        for vuln in result.vulnerabilities:
            self._entries.append(
                _vuln_to_entry(result.bssid, result.ssid, "wps", vuln)
            )
        self._results.append({"type": "wps", "bssid": result.bssid, "ssid": result.ssid})

    def add_krack_result(self, result: KRACKScanResult) -> None:
        """Add KRACK scan results to the report."""
        for vuln in result.vulnerabilities:
            self._entries.append(
                _vuln_to_entry(result.bssid, result.ssid, "krack", vuln)
            )
        self._results.append({"type": "krack", "bssid": result.bssid, "ssid": result.ssid})

    def add_default_cred_result(self, result: DefaultCredScanResult) -> None:
        """Add default credential scan results to the report."""
        for vuln in result.vulnerabilities:
            self._entries.append(
                _vuln_to_entry(result.bssid, result.ssid, "default_creds", vuln)
            )
        self._results.append({"type": "default_creds", "bssid": result.bssid, "ssid": result.ssid})

    def add_dns_hijack_result(self, result: DNSHijackScanResult) -> None:
        """Add DNS hijack scan results to the report."""
        for vuln in result.vulnerabilities:
            self._entries.append(
                _vuln_to_entry(bssid="", ssid="", category="dns_hijack", vuln=vuln)
            )
        self._results.append({"type": "dns_hijack"})

    def add_rogue_dhcp_result(self, result: RogueDHCPScanResult) -> None:
        """Add rogue DHCP scan results to the report."""
        for vuln in result.vulnerabilities:
            self._entries.append(
                _vuln_to_entry(bssid="", ssid="", category="rogue_dhcp", vuln=vuln)
            )
        self._results.append({"type": "rogue_dhcp"})

    def add_generic_vuln(
        self,
        bssid: str,
        ssid: str,
        category: str,
        vuln_id: str,
        title: str,
        description: str,
        severity: str,
        cve_ids: Optional[List[str]] = None,
        recommendation: str = "",
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a generic vulnerability entry to the report.

        Args:
            bssid: BSSID of the target.
            ssid: SSID of the network.
            category: Vulnerability category.
            vuln_id: Vulnerability identifier.
            title: Vulnerability title.
            description: Detailed description.
            severity: Severity level.
            cve_ids: Associated CVE identifiers.
            recommendation: Remediation recommendation.
            evidence: Supporting evidence.
        """
        self._entries.append(VulnReportEntry(
            bssid=bssid,
            ssid=ssid,
            category=category,
            vuln_id=vuln_id,
            title=title,
            description=description,
            severity=severity,
            cve_ids=cve_ids or [],
            recommendation=recommendation,
            evidence=evidence or {},
        ))

    def generate(
        self,
        title: str = "WiFiAIO Vulnerability Assessment Report",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VulnReport:
        """Generate the vulnerability report.

        Args:
            title: Report title.
            metadata: Additional metadata to include.

        Returns:
            Complete VulnReport with summary.
        """
        report_id = f"VA-{int(time.time())}"
        now = time.time()

        # Calculate summary statistics
        summary = self._calculate_summary()

        report = VulnReport(
            report_id=report_id,
            title=title,
            generated_at=now,
            entries=list(self._entries),
            summary=summary,
            scan_results={"scans_performed": len(self._results)},
            metadata=metadata or {},
        )

        logger.info(
            "Vulnerability report generated: %s (%d entries)",
            report_id,
            len(self._entries),
        )
        return report

    def _calculate_summary(self) -> VulnSummary:
        """Calculate summary statistics from collected entries."""
        summary = VulnSummary()
        summary.total_vulnerabilities = len(self._entries)

        # Count by severity
        for entry in self._entries:
            severity = entry.severity.lower()
            if severity == "critical":
                summary.critical_count += 1
            elif severity == "high":
                summary.high_count += 1
            elif severity == "medium":
                summary.medium_count += 1
            elif severity == "low":
                summary.low_count += 1
            else:
                summary.info_count += 1

        # Count unique targets
        targets: set = set()
        for entry in self._entries:
            if entry.bssid:
                targets.add(entry.bssid)
        summary.total_targets = len(targets)

        # Count unique CVEs
        all_cves: set = set()
        for entry in self._entries:
            all_cves.update(entry.cve_ids)
        summary.unique_cves = len(all_cves)

        # Find most common vulnerability
        vuln_counts: Dict[str, int] = {}
        for entry in self._entries:
            key = f"{entry.category}:{entry.vuln_id}"
            vuln_counts[key] = vuln_counts.get(key, 0) + 1

        if vuln_counts:
            summary.most_common_vuln = max(vuln_counts, key=vuln_counts.get)

        # Find most vulnerable target
        target_counts: Dict[str, int] = {}
        for entry in self._entries:
            key = entry.bssid or "network"
            target_counts[key] = target_counts.get(key, 0) + 1

        if target_counts:
            summary.most_vulnerable_target = max(target_counts, key=target_counts.get)

        return summary

    def to_json(self, report: VulnReport, indent: int = 2) -> str:
        """Convert report to JSON format.

        Args:
            report: VulnReport to convert.
            indent: JSON indentation level.

        Returns:
            JSON string.
        """
        data = {
            "report_id": report.report_id,
            "title": report.title,
            "generated_at": report.generated_at,
            "summary": {
                "total_targets": report.summary.total_targets,
                "total_vulnerabilities": report.summary.total_vulnerabilities,
                "critical": report.summary.critical_count,
                "high": report.summary.high_count,
                "medium": report.summary.medium_count,
                "low": report.summary.low_count,
                "info": report.summary.info_count,
                "unique_cves": report.summary.unique_cves,
                "most_common_vuln": report.summary.most_common_vuln,
                "most_vulnerable_target": report.summary.most_vulnerable_target,
            },
            "entries": [],
        }

        for entry in report.entries:
            data["entries"].append({
                "bssid": entry.bssid,
                "ssid": entry.ssid,
                "category": entry.category,
                "vuln_id": entry.vuln_id,
                "title": entry.title,
                "description": entry.description,
                "severity": entry.severity,
                "cve_ids": entry.cve_ids,
                "recommendation": entry.recommendation,
                "evidence": entry.evidence,
            })

        return json.dumps(data, indent=indent)

    def to_text(self, report: VulnReport) -> str:
        """Convert report to human-readable text format.

        Args:
            report: VulnReport to convert.

        Returns:
            Formatted text string.
        """
        lines: List[str] = []

        # Header
        lines.append("=" * 70)
        lines.append(f"  {report.title}")
        lines.append(f"  Report ID: {report.report_id}")
        lines.append(f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.generated_at))}")
        lines.append("=" * 70)

        # Summary
        lines.append("")
        lines.append("SUMMARY")
        lines.append("-" * 40)
        lines.append(f"  Total Targets Scanned:  {report.summary.total_targets}")
        lines.append(f"  Total Vulnerabilities:  {report.summary.total_vulnerabilities}")
        lines.append(f"  ┌─ Critical:  {report.summary.critical_count}")
        lines.append(f"  ├─ High:      {report.summary.high_count}")
        lines.append(f"  ├─ Medium:    {report.summary.medium_count}")
        lines.append(f"  ├─ Low:       {report.summary.low_count}")
        lines.append(f"  └─ Info:      {report.summary.info_count}")
        lines.append(f"  Unique CVEs:  {report.summary.unique_cves}")

        if report.summary.most_common_vuln:
            lines.append(f"  Most Common:  {report.summary.most_common_vuln}")
        if report.summary.most_vulnerable_target:
            lines.append(f"  Most Vulnerable Target: {report.summary.most_vulnerable_target}")

        # Risk level
        risk_level = self._calculate_risk_level(report)
        lines.append(f"  Overall Risk: {risk_level}")

        # Vulnerability details
        lines.append("")
        lines.append("FINDINGS")
        lines.append("-" * 70)

        # Sort by severity
        sorted_entries = sorted(
            report.entries,
            key=lambda e: SEVERITY_ORDER.get(e.severity.lower(), 0),
            reverse=True,
        )

        current_bssid = ""
        for entry in sorted_entries:
            if entry.bssid != current_bssid:
                current_bssid = entry.bssid
                lines.append("")
                lines.append(f"  Target: {entry.ssid} ({entry.bssid})")
                lines.append("  " + "-" * 50)

            severity_marker = {
                "critical": "[!!!]",
                "high": "[!! ]",
                "medium": "[!  ]",
                "low": "[   ]",
                "info": "[ - ]",
            }.get(entry.severity.lower(), "[ ? ]")

            lines.append(f"    {severity_marker} {entry.vuln_id} - {entry.title}")
            lines.append(f"         Category: {entry.category}")
            lines.append(f"         Severity: {entry.severity.upper()}")
            if entry.cve_ids:
                lines.append(f"         CVEs: {', '.join(entry.cve_ids)}")
            lines.append(f"         {entry.description[:120]}...")
            if entry.recommendation:
                lines.append(f"         Fix: {entry.recommendation[:100]}...")
            lines.append("")

        # Recommendations
        lines.append("")
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 70)
        recommendations = self._generate_recommendations(report)
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"  {i}. {rec}")

        lines.append("")
        lines.append("=" * 70)
        lines.append("  End of Report")
        lines.append("=" * 70)

        return "\n".join(lines)

    def to_csv(self, report: VulnReport) -> str:
        """Convert report to CSV format.

        Args:
            report: VulnReport to convert.

        Returns:
            CSV string.
        """
        lines = ["BSSID,SSID,Category,Vuln ID,Title,Severity,CVEs,Recommendation"]

        for entry in report.entries:
            cves = "; ".join(entry.cve_ids)
            title = entry.title.replace('"', '""')
            rec = entry.recommendation.replace('"', '""')
            lines.append(
                f'{entry.bssid},{entry.ssid},{entry.category},{entry.vuln_id},'
                f'"{title}",{entry.severity},"{cves}","{rec}"'
            )

        return "\n".join(lines)

    def to_html(self, report: VulnReport) -> str:
        """Convert report to HTML format.

        Args:
            report: VulnReport to convert.

        Returns:
            HTML string.
        """
        html_parts: List[str] = []

        html_parts.append("<!DOCTYPE html>")
        html_parts.append("<html><head><meta charset='utf-8'>")
        html_parts.append(f"<title>{report.title}</title>")
        html_parts.append("<style>")
        html_parts.append("body { font-family: Arial, sans-serif; margin: 20px; }")
        html_parts.append("table { border-collapse: collapse; width: 100%; }")
        html_parts.append("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
        html_parts.append("th { background-color: #4a90d9; color: white; }")
        html_parts.append(".critical { color: #cc0000; font-weight: bold; }")
        html_parts.append(".high { color: #ff6600; font-weight: bold; }")
        html_parts.append(".medium { color: #ffaa00; }")
        html_parts.append(".low { color: #339900; }")
        html_parts.append(".info { color: #666; }")
        html_parts.append(".summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 10px 0; }")
        html_parts.append("</style></head><body>")

        html_parts.append(f"<h1>{report.title}</h1>")
        html_parts.append(f"<p>Report ID: {report.report_id}</p>")

        # Summary
        html_parts.append("<div class='summary'>")
        html_parts.append("<h2>Summary</h2>")
        html_parts.append(f"<p>Total Vulnerabilities: {report.summary.total_vulnerabilities}</p>")
        html_parts.append("<ul>")
        html_parts.append(f"<li class='critical'>Critical: {report.summary.critical_count}</li>")
        html_parts.append(f"<li class='high'>High: {report.summary.high_count}</li>")
        html_parts.append(f"<li class='medium'>Medium: {report.summary.medium_count}</li>")
        html_parts.append(f"<li class='low'>Low: {report.summary.low_count}</li>")
        html_parts.append(f"<li class='info'>Info: {report.summary.info_count}</li>")
        html_parts.append("</ul>")
        html_parts.append("</div>")

        # Findings table
        html_parts.append("<h2>Findings</h2>")
        html_parts.append("<table>")
        html_parts.append("<tr><th>BSSID</th><th>SSID</th><th>Category</th>")
        html_parts.append("<th>Vuln ID</th><th>Title</th><th>Severity</th>")
        html_parts.append("<th>CVEs</th><th>Recommendation</th></tr>")

        sorted_entries = sorted(
            report.entries,
            key=lambda e: SEVERITY_ORDER.get(e.severity.lower(), 0),
            reverse=True,
        )

        for entry in sorted_entries:
            severity_class = entry.severity.lower()
            cves = ", ".join(entry.cve_ids) if entry.cve_ids else "-"
            html_parts.append(f"<tr>")
            html_parts.append(f"<td>{entry.bssid}</td>")
            html_parts.append(f"<td>{entry.ssid}</td>")
            html_parts.append(f"<td>{entry.category}</td>")
            html_parts.append(f"<td>{entry.vuln_id}</td>")
            html_parts.append(f"<td>{entry.title}</td>")
            html_parts.append(f"<td class='{severity_class}'>{entry.severity.upper()}</td>")
            html_parts.append(f"<td>{cves}</td>")
            html_parts.append(f"<td>{entry.recommendation}</td>")
            html_parts.append(f"</tr>")

        html_parts.append("</table>")
        html_parts.append("</body></html>")

        return "\n".join(html_parts)

    def _calculate_risk_level(self, report: VulnReport) -> str:
        """Calculate overall risk level from the report.

        Args:
            report: VulnReport to assess.

        Returns:
            Risk level string.
        """
        if report.summary.critical_count > 0:
            return "CRITICAL"
        if report.summary.high_count > 2:
            return "HIGH"
        if report.summary.high_count > 0:
            return "ELEVATED"
        if report.summary.medium_count > 3:
            return "MODERATE"
        if report.summary.medium_count > 0:
            return "LOW"
        return "MINIMAL"

    def _generate_recommendations(self, report: VulnReport) -> List[str]:
        """Generate prioritized remediation recommendations.

        Args:
            report: VulnReport to analyze.

        Returns:
            List of recommendation strings, ordered by priority.
        """
        recs: List[str] = []
        categories_seen: set = set()

        # Prioritize by severity
        for entry in sorted(
            report.entries,
            key=lambda e: SEVERITY_ORDER.get(e.severity.lower(), 0),
            reverse=True,
        ):
            if entry.category not in categories_seen and entry.recommendation:
                categories_seen.add(entry.category)
                recs.append(entry.recommendation)

        # Add generic recommendations based on findings
        if report.summary.critical_count > 0:
            recs.append(
                "CRITICAL: Address all critical findings immediately. "
                "These vulnerabilities can be exploited with minimal effort."
            )

        if any(e.category == "wep" for e in report.entries):
            recs.append(
                "Migrate all WEP networks to WPA2-AES or WPA3 immediately."
            )

        if any(e.category == "wps" for e in report.entries):
            recs.append("Disable WPS on all access points.")

        if any(e.category == "pmf" for e in report.entries):
            recs.append("Enable PMF in required mode on all WPA2/WPA3 networks.")

        if any(e.category == "krack" for e in report.entries):
            recs.append("Ensure all client devices have KRACK patches applied.")

        if any(e.category == "default_creds" for e in report.entries):
            recs.append("Change all default passwords on network devices.")

        # Deduplicate
        seen = set()
        unique_recs = []
        for rec in recs:
            if rec not in seen:
                seen.add(rec)
                unique_recs.append(rec)

        return unique_recs[:20]  # Limit to 20 recommendations

    def clear(self) -> None:
        """Clear all collected results and entries."""
        self._results.clear()
        self._entries.clear()
        logger.info("VulnReportGenerator cleared")
