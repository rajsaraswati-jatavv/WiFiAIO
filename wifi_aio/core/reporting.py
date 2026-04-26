"""Report generation for WiFi security assessments.

Supports scan reports, vulnerability reports, and compliance reports
in multiple formats (HTML, JSON, PDF-ready).
"""

import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Optional

from wifi_aio.exceptions import (
    WiFiConnectionError,
)

logger = logging.getLogger(__name__)


class Reporting:
    """Generate professional security assessment reports.

    Supports:
    - Scan reports (network discovery results)
    - Vulnerability reports (security findings)
    - Compliance reports (PCI-DSS, NIST, etc.)
    - Multiple output formats (HTML, JSON, text)
    """

    def __init__(self, organization: str = "WiFiAIO"):
        self.organization = organization
        self._templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")

    # ------------------------------------------------------------------
    # Scan Reports
    # ------------------------------------------------------------------

    def generate_scan_report(
        self,
        scan_data: List[Dict],
        output_path: str,
        format: str = "html",
        title: str = "WiFi Network Scan Report",
        metadata: Optional[Dict] = None,
    ) -> str:
        """Generate a network scan report.

        Args:
            scan_data: List of network dicts from scanning.
            output_path: Output file path.
            format: Output format ('html', 'json', 'text').
            title: Report title.
            metadata: Additional metadata dict.

        Returns:
            Path to the generated report.
        """
        meta = metadata or {}
        report_data = {
            "title": title,
            "organization": self.organization,
            "generated_at": datetime.now().isoformat(),
            "assessor": meta.get("assessor", "WiFiAIO"),
            "location": meta.get("location", "Unknown"),
            "scope": meta.get("scope", "WiFi network scan"),
            "total_networks": len(scan_data),
            "networks": scan_data,
            "summary": self._summarize_scan(scan_data),
        }

        if format == "html":
            content = self._render_scan_html(report_data)
        elif format == "json":
            content = json.dumps(report_data, indent=2, default=str)
        elif format == "text":
            content = self._render_scan_text(report_data)
        else:
            raise ValueError(f"Unsupported format: {format}")

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(content)

        logger.info("Scan report generated: %s", output_path)
        return output_path

    @staticmethod
    def _summarize_scan(networks: List[Dict]) -> Dict:
        """Generate summary statistics from scan data."""
        summary = {
            "total_networks": len(networks),
            "encryption_types": {},
            "channel_distribution": {},
            "signal_quality": {"strong": 0, "medium": 0, "weak": 0},
            "open_networks": 0,
            "wep_networks": 0,
            "wpa_networks": 0,
            "wpa2_networks": 0,
            "wpa3_networks": 0,
            "hidden_networks": 0,
        }

        for net in networks:
            enc = net.get("encryption", net.get("security", "unknown")).upper()
            summary["encryption_types"][enc] = summary["encryption_types"].get(enc, 0) + 1

            if "OPEN" in enc or enc == "NONE" or enc == "":
                summary["open_networks"] += 1
            elif "WEP" in enc:
                summary["wep_networks"] += 1
            elif "WPA3" in enc:
                summary["wpa3_networks"] += 1
            elif "WPA2" in enc:
                summary["wpa2_networks"] += 1
            elif "WPA" in enc:
                summary["wpa_networks"] += 1

            channel = str(net.get("channel", "unknown"))
            summary["channel_distribution"][channel] = (
                summary["channel_distribution"].get(channel, 0) + 1
            )

            signal = net.get("signal", net.get("rssi", ""))
            if isinstance(signal, (int, float)):
                if signal >= -50:
                    summary["signal_quality"]["strong"] += 1
                elif signal >= -70:
                    summary["signal_quality"]["medium"] += 1
                else:
                    summary["signal_quality"]["weak"] += 1
            elif isinstance(signal, str):
                try:
                    val = float(signal.replace(" dBm", "").replace("dBm", ""))
                    if val >= -50:
                        summary["signal_quality"]["strong"] += 1
                    elif val >= -70:
                        summary["signal_quality"]["medium"] += 1
                    else:
                        summary["signal_quality"]["weak"] += 1
                except ValueError:
                    pass

            ssid = net.get("ssid", "")
            if not ssid or ssid == "" or ssid == "\\x00":
                summary["hidden_networks"] += 1

        return summary

    def _render_scan_html(self, data: Dict) -> str:
        """Render scan report as HTML."""
        rows = ""
        for i, net in enumerate(data["networks"], 1):
            ssid = self._html_escape(net.get("ssid", "Hidden"))
            bssid = self._html_escape(net.get("bssid", ""))
            channel = net.get("channel", "N/A")
            signal = net.get("signal", net.get("rssi", "N/A"))
            encryption = self._html_escape(net.get("encryption", net.get("security", "Unknown")))
            enc_class = "danger" if "OPEN" in encryption.upper() or "WEP" in encryption.upper() else "success"

            rows += f"""
            <tr>
                <td>{i}</td>
                <td>{ssid}</td>
                <td><code>{bssid}</code></td>
                <td>{channel}</td>
                <td>{signal}</td>
                <td class="{enc_class}">{encryption}</td>
            </tr>"""

        summary = data["summary"]
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{self._html_escape(data['title'])}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
    .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
    h1 {{ color: #1a1a1a; border-bottom: 3px solid #2563eb; padding-bottom: 10px; }}
    h2 {{ color: #374151; margin-top: 30px; }}
    .metadata {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 20px 0; }}
    .meta-item {{ padding: 10px; background: #f8fafc; border-radius: 4px; }}
    .meta-label {{ font-weight: bold; color: #64748b; font-size: 0.85em; }}
    .meta-value {{ color: #1e293b; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
    .stat-card {{ background: #eff6ff; padding: 15px; border-radius: 6px; text-align: center; }}
    .stat-number {{ font-size: 2em; font-weight: bold; color: #2563eb; }}
    .stat-label {{ color: #64748b; font-size: 0.9em; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
    th {{ background: #1e40af; color: white; padding: 12px; text-align: left; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #e5e7eb; }}
    tr:hover {{ background: #f8fafc; }}
    .danger {{ color: #dc2626; font-weight: bold; }}
    .success {{ color: #16a34a; font-weight: bold; }}
    .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="container">
    <h1>{self._html_escape(data['title'])}</h1>
    <div class="metadata">
        <div class="meta-item"><div class="meta-label">Organization</div><div class="meta-value">{self._html_escape(data['organization'])}</div></div>
        <div class="meta-item"><div class="meta-label">Generated</div><div class="meta-value">{self._html_escape(data['generated_at'])}</div></div>
        <div class="meta-item"><div class="meta-label">Assessor</div><div class="meta-value">{self._html_escape(data['assessor'])}</div></div>
        <div class="meta-item"><div class="meta-label">Location</div><div class="meta-value">{self._html_escape(data['location'])}</div></div>
    </div>

    <h2>Summary</h2>
    <div class="summary-grid">
        <div class="stat-card"><div class="stat-number">{summary['total_networks']}</div><div class="stat-label">Total Networks</div></div>
        <div class="stat-card"><div class="stat-number" style="color:#dc2626">{summary['open_networks']}</div><div class="stat-label">Open Networks</div></div>
        <div class="stat-card"><div class="stat-number" style="color:#f59e0b">{summary['wep_networks']}</div><div class="stat-label">WEP Networks</div></div>
        <div class="stat-card"><div class="stat-number" style="color:#16a34a">{summary['wpa2_networks']}</div><div class="stat-label">WPA2 Networks</div></div>
        <div class="stat-card"><div class="stat-number" style="color:#2563eb">{summary['wpa3_networks']}</div><div class="stat-label">WPA3 Networks</div></div>
        <div class="stat-card"><div class="stat-number">{summary['hidden_networks']}</div><div class="stat-label">Hidden Networks</div></div>
    </div>

    <h2>Discovered Networks</h2>
    <table>
        <thead>
            <tr><th>#</th><th>SSID</th><th>BSSID</th><th>Channel</th><th>Signal</th><th>Encryption</th></tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>

    <div class="footer">
        <p>Generated by WiFiAIO Security Assessment Toolkit</p>
        <p>Report ID: {self._html_escape(data['generated_at'])}</p>
    </div>
</div>
</body>
</html>"""

    def _render_scan_text(self, data: Dict) -> str:
        """Render scan report as plain text."""
        lines = [
            "=" * 70,
            data["title"],
            "=" * 70,
            f"Organization: {data['organization']}",
            f"Generated:    {data['generated_at']}",
            f"Assessor:     {data['assessor']}",
            f"Location:     {data['location']}",
            "",
            "SUMMARY",
            "-" * 40,
            f"Total Networks:  {data['summary']['total_networks']}",
            f"Open Networks:   {data['summary']['open_networks']}",
            f"WEP Networks:    {data['summary']['wep_networks']}",
            f"WPA Networks:    {data['summary']['wpa_networks']}",
            f"WPA2 Networks:   {data['summary']['wpa2_networks']}",
            f"WPA3 Networks:   {data['summary']['wpa3_networks']}",
            f"Hidden Networks: {data['summary']['hidden_networks']}",
            "",
            "DISCOVERED NETWORKS",
            "-" * 40,
        ]

        for i, net in enumerate(data["networks"], 1):
            lines.append(f"  {i}. SSID: {net.get('ssid', 'Hidden')}")
            lines.append(f"     BSSID: {net.get('bssid', 'N/A')}")
            lines.append(f"     Channel: {net.get('channel', 'N/A')}")
            lines.append(f"     Signal: {net.get('signal', net.get('rssi', 'N/A'))}")
            lines.append(f"     Encryption: {net.get('encryption', net.get('security', 'Unknown'))}")
            lines.append("")

        lines.append("=" * 70)
        lines.append("Generated by WiFiAIO")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Vulnerability Reports
    # ------------------------------------------------------------------

    def generate_vulnerability_report(
        self,
        vulnerabilities: List[Dict],
        output_path: str,
        format: str = "html",
        title: str = "WiFi Vulnerability Assessment Report",
        metadata: Optional[Dict] = None,
    ) -> str:
        """Generate a vulnerability assessment report.

        Args:
            vulnerabilities: List of vulnerability dicts with keys:
                title, description, severity (critical/high/medium/low/info),
                affected_target, recommendation, cve_id (optional).
            output_path: Output file path.
            format: Output format ('html', 'json', 'text').
            title: Report title.
            metadata: Additional metadata.

        Returns:
            Path to the generated report.
        """
        meta = metadata or {}

        # Calculate risk score
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulnerabilities:
            sev = vuln.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        risk_score = (
            severity_counts["critical"] * 10
            + severity_counts["high"] * 7
            + severity_counts["medium"] * 4
            + severity_counts["low"] * 1
        )

        if risk_score >= 30:
            overall_risk = "Critical"
        elif risk_score >= 20:
            overall_risk = "High"
        elif risk_score >= 10:
            overall_risk = "Medium"
        elif risk_score > 0:
            overall_risk = "Low"
        else:
            overall_risk = "None"

        report_data = {
            "title": title,
            "organization": self.organization,
            "generated_at": datetime.now().isoformat(),
            "assessor": meta.get("assessor", "WiFiAIO"),
            "location": meta.get("location", "Unknown"),
            "scope": meta.get("scope", "WiFi vulnerability assessment"),
            "total_vulnerabilities": len(vulnerabilities),
            "severity_counts": severity_counts,
            "risk_score": risk_score,
            "overall_risk": overall_risk,
            "vulnerabilities": vulnerabilities,
            "executive_summary": self._generate_executive_summary(vulnerabilities, severity_counts, overall_risk),
        }

        if format == "html":
            content = self._render_vuln_html(report_data)
        elif format == "json":
            content = json.dumps(report_data, indent=2, default=str)
        elif format == "text":
            content = self._render_vuln_text(report_data)
        else:
            raise ValueError(f"Unsupported format: {format}")

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(content)

        logger.info("Vulnerability report generated: %s", output_path)
        return output_path

    @staticmethod
    def _generate_executive_summary(
        vulnerabilities: List[Dict],
        severity_counts: Dict[str, int],
        overall_risk: str,
    ) -> str:
        """Generate an executive summary paragraph."""
        total = len(vulnerabilities)
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)

        summary = (
            f"This assessment identified {total} vulnerabilities. "
            f"The overall risk level is {overall_risk}. "
        )

        if critical > 0:
            summary += f"There are {critical} critical-severity findings that require immediate attention. "
        if high > 0:
            summary += f"There are {high} high-severity findings that should be addressed promptly. "

        # Key findings
        key_findings = []
        for vuln in vulnerabilities:
            if vuln.get("severity") in ("critical", "high"):
                key_findings.append(vuln.get("title", "Untitled"))

        if key_findings:
            summary += "Key findings include: " + "; ".join(key_findings[:5]) + ". "

        summary += "Detailed findings and recommendations are provided in the report body."
        return summary

    def _render_vuln_html(self, data: Dict) -> str:
        """Render vulnerability report as HTML."""
        rows = ""
        for i, vuln in enumerate(data["vulnerabilities"], 1):
            severity = vuln.get("severity", "info").lower()
            sev_class = {
                "critical": "severity-critical",
                "high": "severity-high",
                "medium": "severity-medium",
                "low": "severity-low",
                "info": "severity-info",
            }.get(severity, "severity-info")

            title = self._html_escape(vuln.get("title", "Untitled"))
            description = self._html_escape(vuln.get("description", ""))
            target = self._html_escape(vuln.get("affected_target", ""))
            recommendation = self._html_escape(vuln.get("recommendation", ""))
            cve = self._html_escape(vuln.get("cve_id", ""))

            rows += f"""
            <tr class="{sev_class}">
                <td>{i}</td>
                <td>{title}</td>
                <td class="{sev_class}">{severity.upper()}</td>
                <td><code>{target}</code></td>
                <td>{description[:200]}{'...' if len(description) > 200 else ''}</td>
                <td>{recommendation[:150]}{'...' if len(recommendation) > 150 else ''}</td>
                <td>{cve}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{self._html_escape(data['title'])}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
    .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
    h1 {{ color: #1a1a1a; border-bottom: 3px solid #dc2626; padding-bottom: 10px; }}
    h2 {{ color: #374151; margin-top: 30px; }}
    .risk-banner {{ padding: 20px; border-radius: 8px; margin: 20px 0; text-align: center; font-size: 1.2em; font-weight: bold; }}
    .risk-Critical {{ background: #fef2f2; color: #991b1b; border: 2px solid #dc2626; }}
    .risk-High {{ background: #fff7ed; color: #9a3412; border: 2px solid #ea580c; }}
    .risk-Medium {{ background: #fefce8; color: #854d0e; border: 2px solid #ca8a04; }}
    .risk-Low {{ background: #f0fdf4; color: #166534; border: 2px solid #16a34a; }}
    .risk-None {{ background: #f0f9ff; color: #075985; border: 2px solid #0284c7; }}
    .summary {{ background: #f8fafc; padding: 20px; border-radius: 6px; margin: 20px 0; line-height: 1.6; }}
    .severity-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 20px 0; }}
    .sev-card {{ padding: 15px; border-radius: 6px; text-align: center; }}
    .sev-critical {{ background: #fef2f2; color: #dc2626; }}
    .sev-high {{ background: #fff7ed; color: #ea580c; }}
    .sev-medium {{ background: #fefce8; color: #ca8a04; }}
    .sev-low {{ background: #f0fdf4; color: #16a34a; }}
    .sev-info {{ background: #f0f9ff; color: #0284c7; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }}
    th {{ background: #1e293b; color: white; padding: 10px; text-align: left; }}
    td {{ padding: 8px 10px; border-bottom: 1px solid #e5e7eb; }}
    .severity-critical {{ color: #dc2626; font-weight: bold; }}
    .severity-high {{ color: #ea580c; font-weight: bold; }}
    .severity-medium {{ color: #ca8a04; font-weight: bold; }}
    .severity-low {{ color: #16a34a; }}
    .severity-info {{ color: #0284c7; }}
    .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="container">
    <h1>{self._html_escape(data['title'])}</h1>
    <div class="risk-banner risk-{data['overall_risk']}">
        Overall Risk: {data['overall_risk']} (Score: {data['risk_score']})
    </div>
    <div class="summary">
        <h3>Executive Summary</h3>
        <p>{self._html_escape(data['executive_summary'])}</p>
    </div>
    <div class="severity-grid">
        <div class="sev-card sev-critical"><div style="font-size:2em;font-weight:bold">{data['severity_counts']['critical']}</div>Critical</div>
        <div class="sev-card sev-high"><div style="font-size:2em;font-weight:bold">{data['severity_counts']['high']}</div>High</div>
        <div class="sev-card sev-medium"><div style="font-size:2em;font-weight:bold">{data['severity_counts']['medium']}</div>Medium</div>
        <div class="sev-card sev-low"><div style="font-size:2em;font-weight:bold">{data['severity_counts']['low']}</div>Low</div>
        <div class="sev-card sev-info"><div style="font-size:2em;font-weight:bold">{data['severity_counts']['info']}</div>Info</div>
    </div>
    <h2>Vulnerability Details</h2>
    <table>
        <thead><tr><th>#</th><th>Title</th><th>Severity</th><th>Target</th><th>Description</th><th>Recommendation</th><th>CVE</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
    <div class="footer">
        <p>Generated by WiFiAIO Security Assessment Toolkit</p>
        <p>Report ID: {self._html_escape(data['generated_at'])}</p>
    </div>
</div>
</body>
</html>"""

    def _render_vuln_text(self, data: Dict) -> str:
        """Render vulnerability report as plain text."""
        lines = [
            "=" * 70,
            data["title"],
            "=" * 70,
            f"Organization: {data['organization']}",
            f"Generated:    {data['generated_at']}",
            f"Overall Risk: {data['overall_risk']} (Score: {data['risk_score']})",
            "",
            "SEVERITY BREAKDOWN",
            "-" * 40,
            f"Critical: {data['severity_counts']['critical']}",
            f"High:     {data['severity_counts']['high']}",
            f"Medium:   {data['severity_counts']['medium']}",
            f"Low:      {data['severity_counts']['low']}",
            f"Info:     {data['severity_counts']['info']}",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 40,
            data["executive_summary"],
            "",
            "VULNERABILITY DETAILS",
            "-" * 40,
        ]

        for i, vuln in enumerate(data["vulnerabilities"], 1):
            lines.append(f"  [{vuln.get('severity', 'info').upper()}] {vuln.get('title', 'Untitled')}")
            lines.append(f"    Target: {vuln.get('affected_target', 'N/A')}")
            lines.append(f"    Description: {vuln.get('description', 'N/A')}")
            lines.append(f"    Recommendation: {vuln.get('recommendation', 'N/A')}")
            if vuln.get("cve_id"):
                lines.append(f"    CVE: {vuln['cve_id']}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Compliance Reports
    # ------------------------------------------------------------------

    def generate_compliance_report(
        self,
        compliance_results: Dict,
        output_path: str,
        format: str = "html",
        standard: str = "PCI-DSS",
        title: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> str:
        """Generate a compliance assessment report.

        Args:
            compliance_results: Dict from ComplianceChecker.
            output_path: Output file path.
            format: Output format.
            standard: Compliance standard name.
            title: Report title.
            metadata: Additional metadata.

        Returns:
            Path to generated report.
        """
        meta = metadata or {}
        report_title = title or f"{standard} WiFi Compliance Report"

        total_checks = compliance_results.get("total_checks", 0)
        passed = compliance_results.get("passed", 0)
        failed = compliance_results.get("failed", 0)
        warnings = compliance_results.get("warnings", 0)
        compliance_pct = (passed / total_checks * 100) if total_checks > 0 else 0

        report_data = {
            "title": report_title,
            "organization": self.organization,
            "generated_at": datetime.now().isoformat(),
            "standard": standard,
            "assessor": meta.get("assessor", "WiFiAIO"),
            "location": meta.get("location", "Unknown"),
            "total_checks": total_checks,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "compliance_percentage": round(compliance_pct, 1),
            "compliant": compliance_pct >= 80,
            "checks": compliance_results.get("checks", []),
            "metadata": meta,
        }

        if format == "html":
            content = self._render_compliance_html(report_data)
        elif format == "json":
            content = json.dumps(report_data, indent=2, default=str)
        elif format == "text":
            content = self._render_compliance_text(report_data)
        else:
            raise ValueError(f"Unsupported format: {format}")

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(content)

        logger.info("Compliance report generated: %s", output_path)
        return output_path

    def _render_compliance_html(self, data: Dict) -> str:
        """Render compliance report as HTML."""
        checks_rows = ""
        for check in data["checks"]:
            status = check.get("status", "unknown")
            status_class = {
                "pass": "status-pass",
                "fail": "status-fail",
                "warning": "status-warn",
            }.get(status, "")

            checks_rows += f"""
            <tr class="{status_class}">
                <td>{self._html_escape(check.get('id', ''))}</td>
                <td>{self._html_escape(check.get('requirement', ''))}</td>
                <td class="{status_class}">{status.upper()}</td>
                <td>{self._html_escape(check.get('description', ''))}</td>
                <td>{self._html_escape(check.get('recommendation', ''))}</td>
            </tr>"""

        compliant_class = "compliant" if data["compliant"] else "non-compliant"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{self._html_escape(data['title'])}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
    .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
    h1 {{ border-bottom: 3px solid #2563eb; padding-bottom: 10px; }}
    .compliance-banner {{ padding: 20px; border-radius: 8px; margin: 20px 0; text-align: center; font-size: 1.3em; font-weight: bold; }}
    .compliant {{ background: #f0fdf4; color: #166534; border: 2px solid #16a34a; }}
    .non-compliant {{ background: #fef2f2; color: #991b1b; border: 2px solid #dc2626; }}
    .progress-bar {{ background: #e5e7eb; border-radius: 8px; height: 30px; margin: 15px 0; overflow: hidden; }}
    .progress-fill {{ height: 100%; border-radius: 8px; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }}
    th {{ background: #1e293b; color: white; padding: 10px; text-align: left; }}
    td {{ padding: 8px 10px; border-bottom: 1px solid #e5e7eb; }}
    .status-pass {{ color: #16a34a; font-weight: bold; }}
    .status-fail {{ color: #dc2626; font-weight: bold; }}
    .status-warn {{ color: #ca8a04; font-weight: bold; }}
    .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="container">
    <h1>{self._html_escape(data['title'])}</h1>
    <div class="compliance-banner {compliant_class}">
        {data['compliance_percentage']}% Compliant - {"COMPLIANT" if data["compliant"] else "NON-COMPLIANT"}
    </div>
    <div class="progress-bar">
        <div class="progress-fill" style="width:{data['compliance_percentage']}%;background:{'#16a34a' if data['compliant'] else '#dc2626'}">{data['compliance_percentage']}%</div>
    </div>
    <p><strong>Standard:</strong> {self._html_escape(data['standard'])} | <strong>Passed:</strong> {data['passed']}/{data['total_checks']} | <strong>Failed:</strong> {data['failed']} | <strong>Warnings:</strong> {data['warnings']}</p>
    <h2>Compliance Checks</h2>
    <table>
        <thead><tr><th>ID</th><th>Requirement</th><th>Status</th><th>Description</th><th>Recommendation</th></tr></thead>
        <tbody>{checks_rows}</tbody>
    </table>
    <div class="footer">
        <p>Generated by WiFiAIO | {self._html_escape(data['generated_at'])}</p>
    </div>
</div>
</body>
</html>"""

    def _render_compliance_text(self, data: Dict) -> str:
        """Render compliance report as plain text."""
        lines = [
            "=" * 70,
            data["title"],
            "=" * 70,
            f"Standard: {data['standard']}",
            f"Generated: {data['generated_at']}",
            f"Compliance: {data['compliance_percentage']}% ({'COMPLIANT' if data['compliant'] else 'NON-COMPLIANT'})",
            f"Passed: {data['passed']}/{data['total_checks']}  Failed: {data['failed']}  Warnings: {data['warnings']}",
            "",
            "CHECKS",
            "-" * 40,
        ]
        for check in data["checks"]:
            status = check.get("status", "unknown").upper()
            lines.append(f"  [{status}] {check.get('id', '')} - {check.get('requirement', '')}")
            if check.get("description"):
                lines.append(f"         {check['description']}")
            if check.get("recommendation") and status != "PASS":
                lines.append(f"         Fix: {check['recommendation']}")
            lines.append("")
        lines.append("=" * 70)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _html_escape(text: str) -> str:
        """Escape HTML special characters."""
        import html
        return html.escape(str(text), quote=True)

    def generate_combined_report(
        self,
        scan_data: List[Dict],
        vulnerabilities: List[Dict],
        compliance_results: Optional[Dict] = None,
        output_path: str = "wifiaio_full_report.html",
        format: str = "html",
        metadata: Optional[Dict] = None,
    ) -> str:
        """Generate a comprehensive combined report.

        Includes scan results, vulnerability findings, and optionally
        compliance status in a single document.
        """
        meta = metadata or {}
        all_sections = []

        # Generate individual sections
        scan_report = self._summarize_scan(scan_data)
        all_sections.append(("Network Scan Results", scan_data, scan_report))

        if vulnerabilities:
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for v in vulnerabilities:
                sev = v.get("severity", "info").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            all_sections.append(("Vulnerability Findings", vulnerabilities, sev_counts))

        if compliance_results:
            all_sections.append(("Compliance Status", compliance_results.get("checks", []), compliance_results))

        if format == "json":
            combined = {
                "title": "WiFiAIO Comprehensive Security Report",
                "organization": self.organization,
                "generated_at": datetime.now().isoformat(),
                "scan_summary": scan_report,
                "vulnerabilities": vulnerabilities,
                "compliance": compliance_results,
                "metadata": meta,
            }
            content = json.dumps(combined, indent=2, default=str)
        else:
            # Build HTML
            content = self._render_combined_html(all_sections, meta)

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(content)

        return output_path

    def _render_combined_html(self, sections, metadata: Dict) -> str:
        """Render combined report as HTML."""
        body_content = ""
        for title, data, summary in sections:
            body_content += f"<h2>{self._html_escape(title)}</h2>"
            body_content += f"<pre>{self._html_escape(json.dumps(summary, indent=2, default=str))}</pre>"
            body_content += f"<pre>{self._html_escape(json.dumps(data[:20], indent=2, default=str))}</pre>"

        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>WiFiAIO Comprehensive Report</title>
<style>body{{font-family:sans-serif;margin:20px;}}pre{{background:#f5f5f5;padding:15px;overflow:auto;}}</style>
</head><body><h1>WiFiAIO Comprehensive Security Report</h1>
<p>Generated: {datetime.now().isoformat()}</p>
{body_content}
</body></html>"""
