"""Report generation engine for WiFiAIO — PDF and HTML reports."""

import io
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from wifi_aio.exceptions import WiFiAIOError
from wifi_aio.constants import Severity, SECURITY_RISK

logger = logging.getLogger(__name__)


class ReportEngine:
    """Generate PDF and HTML reports from scan/crack/audit data."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(
            os.path.expanduser(output_dir or "/tmp/wifi_aio/reports")
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        data: Dict,
        format: str = "html",
        filename: Optional[str] = None,
        title: str = "WiFiAIO Security Report",
        author: str = "WiFiAIO",
        **kwargs,
    ) -> str:
        """Generate a report from the provided data.

        Args:
            data: Report data dict with keys like 'networks', 'vulnerabilities',
                  'cracked', 'session_info', etc.
            format: 'html' or 'pdf'.
            filename: Output filename (without extension).
            title: Report title.
            author: Report author.

        Returns:
            Path to the generated report file.
        """
        format = format.lower().strip(".")

        if filename is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"wifi_aio_report_{ts}"

        if format == "pdf":
            return self._generate_pdf(data, filename, title, author, **kwargs)
        elif format == "html":
            return self._generate_html(data, filename, title, author, **kwargs)
        else:
            raise WiFiAIOError(f"Unsupported report format: '{format}'. Use 'html' or 'pdf'.")

    # ── HTML Report ───────────────────────────────────────────────────

    def _generate_html(
        self,
        data: Dict,
        filename: str,
        title: str,
        author: str,
        **kwargs,
    ) -> str:
        """Generate a styled HTML report."""
        filepath = self.output_dir / f"{filename}.html"
        now = datetime.now()

        networks = data.get("networks", [])
        vulnerabilities = data.get("vulnerabilities", [])
        cracked = data.get("cracked", [])
        session_info = data.get("session_info", {})
        statistics = data.get("statistics", {})

        # Summary counts
        total_networks = len(networks)
        total_vulns = len(vulnerabilities)
        total_cracked = len(cracked)
        critical_count = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "critical")
        high_count = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "high")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(title)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
         background: #0f0f1a; color: #e0e0e0; line-height: 1.6; padding: 2rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .header {{ background: linear-gradient(135deg, #1a1a3e, #2d2d5e);
             padding: 2rem; border-radius: 12px; margin-bottom: 2rem;
             border: 1px solid #3d3d6e; }}
  .header h1 {{ color: #89b4fa; font-size: 2rem; margin-bottom: 0.5rem; }}
  .header .meta {{ color: #6c7086; font-size: 0.9rem; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                   gap: 1rem; margin-bottom: 2rem; }}
  .summary-card {{ background: #1e1e2e; border: 1px solid #313244; border-radius: 8px;
                   padding: 1.5rem; text-align: center; }}
  .summary-card .number {{ font-size: 2.5rem; font-weight: bold; }}
  .summary-card .label {{ color: #6c7086; font-size: 0.9rem; margin-top: 0.5rem; }}
  .card {{ background: #1e1e2e; border: 1px solid #313244; border-radius: 8px;
           padding: 1.5rem; margin-bottom: 1.5rem; }}
  .card h2 {{ color: #89b4fa; margin-bottom: 1rem; border-bottom: 1px solid #313244;
              padding-bottom: 0.5rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
  th {{ background: #313244; color: #89b4fa; padding: 0.75rem; text-align: left;
        font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 0.75rem; border-bottom: 1px solid #313244; }}
  tr:hover {{ background: #252540; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.6rem; border-radius: 4px;
            font-size: 0.8rem; font-weight: 500; }}
  .critical {{ background: #f38ba8; color: #1e1e2e; }}
  .high {{ background: #fab387; color: #1e1e2e; }}
  .medium {{ background: #f9e2af; color: #1e1e2e; }}
  .low {{ background: #a6e3a1; color: #1e1e2e; }}
  .info {{ background: #89dceb; color: #1e1e2e; }}
  .minimal {{ background: #74c7ec; color: #1e1e2e; }}
  .signal-bar {{ display: inline-block; height: 10px; border-radius: 2px; }}
  .footer {{ text-align: center; color: #6c7086; margin-top: 2rem; padding-top: 1rem;
             border-top: 1px solid #313244; font-size: 0.85rem; }}
  @media print {{
    body {{ background: white; color: black; }}
    .header {{ background: #f0f0f0; }}
    .summary-card, .card {{ border: 1px solid #ddd; background: white; }}
    th {{ background: #f0f0f0; color: #333; }}
  }}
</style>
</head>
<body>
<div class="container">
<div class="header">
  <h1>{_esc(title)}</h1>
  <div class="meta">
    Generated: {now.strftime("%Y-%m-%d %H:%M:%S")} &bull;
    Author: {_esc(author)} &bull;
    Tool: WiFiAIO
  </div>
</div>

<div class="summary-grid">
  <div class="summary-card">
    <div class="number" style="color:#89b4fa">{total_networks}</div>
    <div class="label">Networks Scanned</div>
  </div>
  <div class="summary-card">
    <div class="number" style="color:#f38ba8">{critical_count}</div>
    <div class="label">Critical Vulnerabilities</div>
  </div>
  <div class="summary-card">
    <div class="number" style="color:#fab387">{high_count}</div>
    <div class="label">High Vulnerabilities</div>
  </div>
  <div class="summary-card">
    <div class="number" style="color:#a6e3a1">{total_cracked}</div>
    <div class="label">Passwords Cracked</div>
  </div>
</div>
"""

        # Networks table
        if networks:
            html += """<div class="card">
<h2>Discovered Networks</h2>
<table>
<thead><tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>Signal</th><th>Security</th><th>Risk</th></tr></thead>
<tbody>
"""
            for n in networks:
                ssid = _esc(str(n.get("ssid", "<hidden>")))
                bssid = _esc(str(n.get("bssid", "")))
                channel = _esc(str(n.get("channel", "")))
                signal = n.get("signal_dbm", -100)
                security = _esc(str(n.get("security", "")))
                risk = _esc(str(n.get("risk", SECURITY_RISK.get(n.get("security", ""), "info"))))
                risk_lower = risk.lower()
                # Signal bar
                sig_width = max(0, min(100, signal + 100))
                sig_color = "#a6e3a1" if signal >= -50 else "#f9e2af" if signal >= -60 else "#fab387" if signal >= -70 else "#f38ba8"
                html += f"""<tr>
<td><strong>{ssid}</strong></td>
<td>{bssid}</td>
<td>{channel}</td>
<td><span class="signal-bar" style="width:{sig_width}%;background:{sig_color}"></span> {signal} dBm</td>
<td>{security}</td>
<td><span class="badge {risk_lower}">{risk}</span></td>
</tr>\n"""
            html += "</tbody></table>\n</div>\n"

        # Vulnerabilities table
        if vulnerabilities:
            html += """<div class="card">
<h2>Vulnerabilities</h2>
<table>
<thead><tr><th>BSSID</th><th>SSID</th><th>Type</th><th>Severity</th><th>Description</th><th>Remediation</th></tr></thead>
<tbody>
"""
            for v in vulnerabilities:
                bssid = _esc(str(v.get("bssid", "")))
                ssid = _esc(str(v.get("ssid", "")))
                vtype = _esc(str(v.get("vuln_type", "")))
                severity = _esc(str(v.get("severity", "info")))
                desc = _esc(str(v.get("description", "")))
                remediation = _esc(str(v.get("remediation", "")))
                html += f"""<tr>
<td>{bssid}</td>
<td>{ssid}</td>
<td>{vtype}</td>
<td><span class="badge {severity.lower()}">{severity}</span></td>
<td>{desc}</td>
<td>{remediation}</td>
</tr>\n"""
            html += "</tbody></table>\n</div>\n"

        # Cracked passwords table
        if cracked:
            html += """<div class="card">
<h2>Cracked Passwords</h2>
<table>
<thead><tr><th>SSID</th><th>BSSID</th><th>Security</th><th>Password</th><th>Method</th></tr></thead>
<tbody>
"""
            for c in cracked:
                ssid = _esc(str(c.get("ssid", "")))
                bssid = _esc(str(c.get("bssid", "")))
                security = _esc(str(c.get("security", "")))
                password = _esc(str(c.get("password", "")))
                method = _esc(str(c.get("method", "")))
                html += f"""<tr>
<td>{ssid}</td>
<td>{bssid}</td>
<td>{security}</td>
<td><code>{password}</code></td>
<td>{method}</td>
</tr>\n"""
            html += "</tbody></table>\n</div>\n"

        # Session info
        if session_info:
            html += """<div class="card">
<h2>Session Information</h2>
<table>
"""
            for key, value in session_info.items():
                html += f"<tr><td><strong>{_esc(key)}</strong></td><td>{_esc(str(value))}</td></tr>\n"
            html += "</table>\n</div>\n"

        # Statistics
        if statistics:
            html += """<div class="card">
<h2>Statistics</h2>
<table>
"""
            for key, value in statistics.items():
                html += f"<tr><td><strong>{_esc(key)}</strong></td><td>{_esc(str(value))}</td></tr>\n"
            html += "</table>\n</div>\n"

        # Disclaimer
        html += f"""
<div class="footer">
  <p>Report generated by <strong>WiFiAIO</strong> on {now.strftime("%Y-%m-%d %H:%M:%S")}</p>
  <p><em>WARNING: This report contains sensitive security information. Handle responsibly and in compliance with applicable laws.</em></p>
</div>
</div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(html)

        logger.info("HTML report generated: %s", filepath)
        return str(filepath)

    # ── PDF Report ────────────────────────────────────────────────────

    def _generate_pdf(
        self,
        data: Dict,
        filename: str,
        title: str,
        author: str,
        **kwargs,
    ) -> str:
        """Generate a PDF report using ReportLab (if available) or HTML-to-PDF fallback.

        Falls back to HTML report if ReportLab is not installed.
        """
        filepath = self.output_dir / f"{filename}.pdf"

        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch, mm
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                PageBreak, HRFlowable,
            )
        except ImportError:
            logger.warning("ReportLab not installed; falling back to HTML report")
            return self._generate_html(data, filename, title, author, **kwargs)

        networks = data.get("networks", [])
        vulnerabilities = data.get("vulnerabilities", [])
        cracked = data.get("cracked", [])
        now = datetime.now()

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            rightMargin=25 * mm,
            leftMargin=25 * mm,
            topMargin=25 * mm,
            bottomMargin=25 * mm,
            title=title,
            author=author,
        )

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontSize=24,
            spaceAfter=12,
            textColor=colors.HexColor("#2c3e50"),
        ))
        styles.add(ParagraphStyle(
            name="SectionTitle",
            parent=styles["Heading2"],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=8,
            textColor=colors.HexColor("#2c3e50"),
        ))
        styles.add(ParagraphStyle(
            name="SmallText",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.grey,
        ))

        elements = []

        # Title
        elements.append(Paragraph(title, styles["ReportTitle"]))
        elements.append(Paragraph(
            f"Generated: {now.strftime('%Y-%m-%d %H:%M:%S')} &bull; Author: {author} &bull; WiFiAIO",
            styles["Normal"],
        ))
        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#bdc3c7")))
        elements.append(Spacer(1, 20))

        # Summary
        elements.append(Paragraph("Summary", styles["SectionTitle"]))
        summary_data = [
            ["Metric", "Value"],
            ["Networks Scanned", str(len(networks))],
            ["Vulnerabilities Found", str(len(vulnerabilities))],
            ["Passwords Cracked", str(len(cracked))],
            ["Critical Issues", str(sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "critical"))],
        ]
        summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ecf0f1")]),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))

        # Networks table
        if networks:
            elements.append(Paragraph("Discovered Networks", styles["SectionTitle"]))
            net_data = [["SSID", "BSSID", "Channel", "Signal (dBm)", "Security", "Risk"]]
            for n in networks:
                net_data.append([
                    str(n.get("ssid", "<hidden>")),
                    str(n.get("bssid", "")),
                    str(n.get("channel", "")),
                    str(n.get("signal_dbm", "")),
                    str(n.get("security", "")),
                    str(n.get("risk", "")),
                ])
            net_table = Table(net_data, colWidths=[1.5 * inch, 1.2 * inch, 0.6 * inch, 0.8 * inch, 1.2 * inch, 0.7 * inch])
            net_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ecf0f1")]),
            ]))
            elements.append(net_table)
            elements.append(Spacer(1, 20))

        # Vulnerabilities table
        if vulnerabilities:
            elements.append(Paragraph("Vulnerabilities", styles["SectionTitle"]))
            vuln_data = [["BSSID", "SSID", "Type", "Severity", "Description"]]
            for v in vulnerabilities:
                vuln_data.append([
                    str(v.get("bssid", "")),
                    str(v.get("ssid", "")),
                    str(v.get("vuln_type", "")),
                    str(v.get("severity", "")),
                    str(v.get("description", ""))[:80],
                ])
            vuln_table = Table(vuln_data, colWidths=[1.2 * inch, 1 * inch, 1 * inch, 0.8 * inch, 2 * inch])
            vuln_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ecf0f1")]),
            ]))
            elements.append(vuln_table)

        # Footer
        elements.append(Spacer(1, 40))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        elements.append(Paragraph(
            "Report generated by WiFiAIO. This report contains sensitive information — handle responsibly.",
            styles["SmallText"],
        ))

        doc.build(elements)
        logger.info("PDF report generated: %s", filepath)
        return str(filepath)


def _esc(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
