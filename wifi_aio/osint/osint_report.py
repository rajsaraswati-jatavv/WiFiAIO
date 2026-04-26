"""OSINT report generator for WiFi intelligence data.

Generates comprehensive OSINT reports in JSON, HTML, and plain text
formats, aggregating data from WiGLE, Google Geolocation, OpenWiFi,
SSID analysis, ISP identification, and router fingerprinting.
"""

from __future__ import annotations

import html as html_module
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from wifi_aio.exceptions import OSINTError


@dataclass
class OSINTReportData:
    """Container for all OSINT data to be included in a report."""
    target_bssid: str = ""
    target_ssid: str = ""
    target_channel: int = 0
    target_encryption: str = ""
    target_signal_dbm: int = 0
    target_vendor: str = ""
    isp_info: Dict[str, Any] = None
    router_fingerprint: Dict[str, Any] = None
    wigle_data: Dict[str, Any] = None
    geolocation: Dict[str, Any] = None
    openwifi_data: Dict[str, Any] = None
    ssid_intel: Dict[str, Any] = None
    cve_matches: List[Dict[str, Any]] = None
    default_credentials: Dict[str, str] = None
    discovered_networks: List[Dict[str, Any]] = None
    scan_timestamp: str = ""
    notes: str = ""

    def __post_init__(self):
        if self.isp_info is None:
            self.isp_info = {}
        if self.router_fingerprint is None:
            self.router_fingerprint = {}
        if self.wigle_data is None:
            self.wigle_data = {}
        if self.geolocation is None:
            self.geolocation = {}
        if self.openwifi_data is None:
            self.openwifi_data = {}
        if self.ssid_intel is None:
            self.ssid_intel = {}
        if self.cve_matches is None:
            self.cve_matches = []
        if self.default_credentials is None:
            self.default_credentials = {}
        if self.discovered_networks is None:
            self.discovered_networks = []
        if not self.scan_timestamp:
            self.scan_timestamp = datetime.utcnow().isoformat()


from dataclasses import dataclass


class OSINTReport:
    """Generates OSINT reports from collected WiFi intelligence data.

    Supports JSON, HTML, and plain text output formats with
    customizable templates and severity-based formatting.
    """

    def __init__(self, data: Optional[OSINTReportData] = None):
        """Initialize the report generator.

        Args:
            data: OSINT report data container. Can be set later via set_data().
        """
        self._data = data

    def set_data(self, data: OSINTReportData) -> None:
        """Set the report data.

        Args:
            data: OSINT report data container.
        """
        self._data = data

    def generate(self, fmt: str = "json", output_path: Optional[str] = None) -> str:
        """Generate an OSINT report in the specified format.

        Args:
            fmt: Output format - "json", "html", or "text".
            output_path: Optional file path to write the report.

        Returns:
            Report content as a string.

        Raises:
            OSINTError: If no data is set or format is unsupported.
        """
        if self._data is None:
            raise OSINTError("No report data set. Call set_data() first.")

        fmt_lower = fmt.lower()
        if fmt_lower == "json":
            content = self._generate_json()
        elif fmt_lower == "html":
            content = self._generate_html()
        elif fmt_lower == "text":
            content = self._generate_text()
        else:
            raise OSINTError(f"Unsupported report format: {fmt}. Use 'json', 'html', or 'text'.")

        if output_path:
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(content)
            except OSError as e:
                raise OSINTError(f"Failed to write report to {output_path}: {e}")

        return content

    def _generate_json(self) -> str:
        """Generate a JSON format report.

        Returns:
            JSON string of the report data.
        """
        report = {
            "report_type": "WiFiAIO OSINT Report",
            "generated_at": datetime.utcnow().isoformat(),
            "target": {
                "bssid": self._data.target_bssid,
                "ssid": self._data.target_ssid,
                "channel": self._data.target_channel,
                "encryption": self._data.target_encryption,
                "signal_dbm": self._data.target_signal_dbm,
                "vendor": self._data.target_vendor,
            },
            "isp_identification": self._data.isp_info,
            "router_fingerprint": self._data.router_fingerprint,
            "geolocation": self._data.geolocation,
            "wigle_data": self._data.wigle_data,
            "openwifi_data": self._data.openwifi_data,
            "ssid_analysis": self._data.ssid_intel,
            "cve_matches": self._data.cve_matches,
            "default_credentials": self._data.default_credentials,
            "discovered_networks_count": len(self._data.discovered_networks),
            "discovered_networks": self._data.discovered_networks[:50],
            "scan_timestamp": self._data.scan_timestamp,
            "notes": self._data.notes,
            "summary": self._generate_summary(),
        }
        return json.dumps(report, indent=2, default=str, ensure_ascii=False)

    def _generate_html(self) -> str:
        """Generate an HTML format report.

        Returns:
            HTML string of the report.
        """
        d = self._data
        summary = self._generate_summary()

        severity_class = "info"
        if d.target_encryption in ("WEP", "Open"):
            severity_class = "critical"
        elif "WPA " in d.target_encryption and "WPA2" not in d.target_encryption:
            severity_class = "high"
        elif "WPA2" in d.target_encryption:
            severity_class = "medium"
        elif "WPA3" in d.target_encryption:
            severity_class = "low"

        cve_rows = ""
        for cve in d.cve_matches:
            cve_severity = cve.get("severity", "info").lower()
            cve_rows += (
                f'<tr class="{cve_severity}">'
                f'<td>{html_module.escape(cve.get("cve_id", ""))}</td>'
                f'<td>{html_module.escape(cve.get("description", ""))}</td>'
                f'<td>{html_module.escape(str(cve.get("cvss", "")))}</td>'
                f'<td>{html_module.escape(cve.get("severity", ""))}</td>'
                f'<td>{html_module.escape(cve.get("mitigation", ""))}</td>'
                f'</tr>\n'
            )

        network_rows = ""
        for net in d.discovered_networks[:30]:
            network_rows += (
                f'<tr>'
                f'<td>{html_module.escape(net.get("ssid", ""))}</td>'
                f'<td>{html_module.escape(net.get("bssid", ""))}</td>'
                f'<td>{html_module.escape(str(net.get("channel", "")))}</td>'
                f'<td>{html_module.escape(net.get("encryption", ""))}</td>'
                f'<td>{html_module.escape(str(net.get("signal_dbm", "")))}</td>'
                f'</tr>\n'
            )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFiAIO OSINT Report - {html_module.escape(d.target_ssid or d.target_bssid)}</title>
<style>
body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #e0e0e0; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
h2 {{ color: #4ecdc4; margin-top: 30px; }}
h3 {{ color: #45b7d1; }}
.header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
.severity-critical {{ background: #ff4444; color: white; padding: 3px 8px; border-radius: 3px; }}
.severity-high {{ background: #ff8800; color: white; padding: 3px 8px; border-radius: 3px; }}
.severity-medium {{ background: #ffcc00; color: black; padding: 3px 8px; border-radius: 3px; }}
.severity-low {{ background: #44bb44; color: white; padding: 3px 8px; border-radius: 3px; }}
.severity-info {{ background: #4488ff; color: white; padding: 3px 8px; border-radius: 3px; }}
.section {{ background: #16213e; padding: 15px; border-radius: 8px; margin-bottom: 15px; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th {{ background: #0f3460; padding: 10px; text-align: left; }}
td {{ padding: 8px; border-bottom: 1px solid #233554; }}
tr:hover {{ background: #1a3a5c; }}
.critical {{ background: rgba(255,68,68,0.2); }}
.high {{ background: rgba(255,136,0,0.2); }}
.medium {{ background: rgba(255,204,0,0.15); }}
.low {{ background: rgba(68,187,68,0.15); }}
.info {{ background: rgba(68,136,255,0.15); }}
.key-value {{ display: flex; margin: 5px 0; }}
.key {{ font-weight: bold; min-width: 200px; color: #4ecdc4; }}
.value {{ color: #e0e0e0; }}
.summary {{ background: #0f3460; padding: 20px; border-radius: 10px; border-left: 4px solid #00d4ff; }}
.footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 0.9em; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>WiFiAIO OSINT Report</h1>
<p>Generated: {html_module.escape(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))}</p>
<p>Target: <strong>{html_module.escape(d.target_ssid or "Unknown")}</strong> ({html_module.escape(d.target_bssid or "N/A")})</p>
<p>Security Assessment: <span class="severity-{severity_class}">{html_module.escape(d.target_encryption or "Unknown")}</span></p>
</div>

<div class="summary">
<h2>Executive Summary</h2>
<p>{html_module.escape(summary)}</p>
</div>

<div class="section">
<h2>Target Information</h2>
<div class="key-value"><span class="key">BSSID:</span><span class="value">{html_module.escape(d.target_bssid)}</span></div>
<div class="key-value"><span class="key">SSID:</span><span class="value">{html_module.escape(d.target_ssid)}</span></div>
<div class="key-value"><span class="key">Channel:</span><span class="value">{html_module.escape(str(d.target_channel))}</span></div>
<div class="key-value"><span class="key">Encryption:</span><span class="value">{html_module.escape(d.target_encryption)}</span></div>
<div class="key-value"><span class="key">Signal:</span><span class="value">{html_module.escape(str(d.target_signal_dbm))} dBm</span></div>
<div class="key-value"><span class="key">Vendor:</span><span class="value">{html_module.escape(d.target_vendor)}</span></div>
</div>

<div class="section">
<h2>ISP Identification</h2>
{_format_dict_html(d.isp_info)}
</div>

<div class="section">
<h2>Router Fingerprint</h2>
{_format_dict_html(d.router_fingerprint)}
</div>

<div class="section">
<h2>Geolocation</h2>
{_format_dict_html(d.geolocation)}
</div>

<div class="section">
<h2>WiGLE Data</h2>
{_format_dict_html(d.wigle_data)}
</div>

<div class="section">
<h2>SSID Analysis</h2>
{_format_dict_html(d.ssid_intel)}
</div>

<div class="section">
<h2>Default Credentials</h2>
{_format_dict_html(d.default_credentials)}
</div>

<div class="section">
<h2>CVE Matches ({len(d.cve_matches)})</h2>
<table>
<tr><th>CVE ID</th><th>Description</th><th>CVSS</th><th>Severity</th><th>Mitigation</th></tr>
{cve_rows}
</table>
</div>

<div class="section">
<h2>Discovered Networks ({len(d.discovered_networks)})</h2>
<table>
<tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>Encryption</th><th>Signal</th></tr>
{network_rows}
</table>
</div>

<div class="footer">
<p>WiFiAIO OSINT Report - For authorized security assessment use only</p>
<p>Report generated at {html_module.escape(datetime.utcnow().isoformat())}</p>
</div>
</div>
</body>
</html>"""
        return html_content

    def _generate_text(self) -> str:
        """Generate a plain text format report.

        Returns:
            Plain text string of the report.
        """
        d = self._data
        lines = [
            "=" * 72,
            "WiFiAIO OSINT REPORT",
            "=" * 72,
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "-" * 72,
            "TARGET INFORMATION",
            "-" * 72,
            f"  BSSID:       {d.target_bssid}",
            f"  SSID:        {d.target_ssid}",
            f"  Channel:     {d.target_channel}",
            f"  Encryption:  {d.target_encryption}",
            f"  Signal:      {d.target_signal_dbm} dBm",
            f"  Vendor:      {d.target_vendor}",
            "",
        ]

        if d.isp_info:
            lines.extend([
                "-" * 72,
                "ISP IDENTIFICATION",
                "-" * 72,
            ])
            lines.extend(_format_dict_text(d.isp_info))
            lines.append("")

        if d.router_fingerprint:
            lines.extend([
                "-" * 72,
                "ROUTER FINGERPRINT",
                "-" * 72,
            ])
            lines.extend(_format_dict_text(d.router_fingerprint))
            lines.append("")

        if d.geolocation:
            lines.extend([
                "-" * 72,
                "GEOLOCATION",
                "-" * 72,
            ])
            lines.extend(_format_dict_text(d.geolocation))
            lines.append("")

        if d.wigle_data:
            lines.extend([
                "-" * 72,
                "WIGLE DATA",
                "-" * 72,
            ])
            lines.extend(_format_dict_text(d.wigle_data))
            lines.append("")

        if d.ssid_intel:
            lines.extend([
                "-" * 72,
                "SSID ANALYSIS",
                "-" * 72,
            ])
            lines.extend(_format_dict_text(d.ssid_intel))
            lines.append("")

        if d.default_credentials:
            lines.extend([
                "-" * 72,
                "DEFAULT CREDENTIALS",
                "-" * 72,
            ])
            lines.extend(_format_dict_text(d.default_credentials))
            lines.append("")

        if d.cve_matches:
            lines.extend([
                "-" * 72,
                f"CVE MATCHES ({len(d.cve_matches)})",
                "-" * 72,
            ])
            for cve in d.cve_matches:
                lines.append(f"  [{cve.get('severity', 'INFO')}] {cve.get('cve_id', 'N/A')}")
                lines.append(f"    {cve.get('description', 'No description')}")
                lines.append(f"    CVSS: {cve.get('cvss', 'N/A')} | Mitigation: {cve.get('mitigation', 'N/A')}")
                lines.append("")

        if d.discovered_networks:
            lines.extend([
                "-" * 72,
                f"DISCOVERED NETWORKS ({len(d.discovered_networks)})",
                "-" * 72,
                f"  {'SSID':<24} {'BSSID':<18} {'CH':<4} {'Encryption':<16} {'Signal'}",
                f"  {'-'*23} {'-'*17} {'-'*3} {'-'*15} {'-'*6}",
            ])
            for net in d.discovered_networks[:50]:
                ssid = net.get("ssid", "")[:23]
                bssid = net.get("bssid", "")
                ch = str(net.get("channel", ""))
                enc = net.get("encryption", "")[:15]
                sig = str(net.get("signal_dbm", ""))
                lines.append(f"  {ssid:<24} {bssid:<18} {ch:<4} {enc:<16} {sig}")
            lines.append("")

        lines.extend([
            "-" * 72,
            "EXECUTIVE SUMMARY",
            "-" * 72,
            self._generate_summary(),
            "",
            "=" * 72,
            "WiFiAIO OSINT Report - For authorized security assessment use only",
            "=" * 72,
        ])

        return "\n".join(lines)

    def _generate_summary(self) -> str:
        """Generate an executive summary of the OSINT findings.

        Returns:
            Summary string.
        """
        d = self._data
        parts = []

        target_desc = f"Target network '{d.target_ssid}' (BSSID: {d.target_bssid})"
        if d.target_vendor:
            target_desc += f" using {d.target_vendor} hardware"
        parts.append(target_desc + ".")

        # Encryption assessment
        enc = d.target_encryption
        if enc == "Open" or not enc:
            parts.append("CRITICAL: The network is open (unencrypted) - all traffic is visible to attackers.")
        elif "WEP" in enc:
            parts.append("CRITICAL: WEP encryption is broken and can be cracked within minutes.")
        elif "WPA " in enc and "WPA2" not in enc:
            parts.append("HIGH: WPA1 is deprecated and vulnerable to multiple attacks.")
        elif "WPA2" in enc and "WPA3" not in enc:
            parts.append("MEDIUM: WPA2 is secure but lacks forward secrecy; consider upgrading to WPA3.")
        elif "WPA3" in enc:
            parts.append("LOW: WPA3 provides strong security with forward secrecy.")

        # ISP info
        if d.isp_info and d.isp_info.get("isp_name"):
            parts.append(f"ISP identified as {d.isp_info['isp_name']} ({d.isp_info.get('country', 'unknown country')}).")

        # Router fingerprint
        if d.router_fingerprint:
            if d.router_fingerprint.get("is_isp_issued"):
                parts.append("The router appears to be ISP-issued, which may have restricted firmware or known vulnerabilities.")
            if d.router_fingerprint.get("is_enterprise"):
                parts.append("The device appears to be enterprise-grade equipment.")

        # Default credentials
        if d.default_credentials:
            username = d.default_credentials.get("username", "")
            password = d.default_credentials.get("password", "")
            if username or password:
                cred_str = f"Default credentials found - username: '{username}', password: '{password}'"
                parts.append(f"HIGH: {cred_str}. If unchanged, the router is accessible to attackers.")

        # CVEs
        if d.cve_matches:
            critical_cves = [c for c in d.cve_matches if c.get("severity") == "Critical"]
            high_cves = [c for c in d.cve_matches if c.get("severity") == "High"]
            if critical_cves:
                parts.append(f"CRITICAL: {len(critical_cves)} critical-severity CVE(s) found affecting this target.")
            if high_cves:
                parts.append(f"HIGH: {len(high_cves)} high-severity CVE(s) found affecting this target.")
            parts.append(f"Total: {len(d.cve_matches)} CVE(s) identified.")

        return " ".join(parts) if parts else "Insufficient data for summary."


def _format_dict_html(data: Dict[str, Any]) -> str:
    """Format a dictionary as HTML key-value pairs.

    Args:
        data: Dictionary to format.

    Returns:
        HTML string.
    """
    if not data:
        return '<p><em>No data available</em></p>'
    lines = []
    for key, value in data.items():
        if isinstance(value, (dict, list)):
            value_str = html_module.escape(json.dumps(value, default=str, ensure_ascii=False))
        else:
            value_str = html_module.escape(str(value))
        lines.append(
            f'<div class="key-value">'
            f'<span class="key">{html_module.escape(str(key))}:</span>'
            f'<span class="value">{value_str}</span>'
            f'</div>'
        )
    return "\n".join(lines)


def _format_dict_text(data: Dict[str, Any], indent: int = 2) -> List[str]:
    """Format a dictionary as plain text lines.

    Args:
        data: Dictionary to format.
        indent: Number of spaces for indentation.

    Returns:
        List of formatted text lines.
    """
    if not data:
        return ["  No data available"]
    lines = []
    prefix = " " * indent
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            lines.extend(_format_dict_text(value, indent + 2))
        elif isinstance(value, list):
            lines.append(f"{prefix}{key}: {', '.join(str(v) for v in value)}")
        else:
            lines.append(f"{prefix}{key}: {value}")
    return lines
