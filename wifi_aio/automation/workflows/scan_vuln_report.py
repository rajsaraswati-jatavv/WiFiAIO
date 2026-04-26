"""Scan → Vulnerability Check → Report workflow.

Scans for WiFi networks, runs a full vulnerability audit on each target,
and produces a consolidated security report.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from wifi_aio.automation.workflow_engine import (
    ErrorStrategy,
    WorkflowEngine,
    WorkflowResult,
    WorkflowStep,
)
from wifi_aio.exceptions import (
    AutomationError,
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


@dataclass
class ScanVulnReportConfig:
    """Configuration for the ScanVulnReport workflow.

    Attributes:
        interface: Wireless interface for scanning.
        scan_timeout: Seconds to spend scanning.
        scan_channel: Specific channel (0 = all).
        target_ssid: SSID to target (empty = audit all WPA networks).
        target_bssid: BSSID to target (overrides SSID).
        min_signal: Minimum signal strength in dBm.
        check_credentials: Test for default credentials.
        check_dns: Check for DNS hijacking.
        check_rogue: Check for rogue DHCP servers.
        report_file: Output path for the report.
        report_format: ``"json"`` or ``"html"``.
        max_targets: Maximum APs to audit (0 = all).
    """

    interface: str = "wlan0"
    scan_timeout: int = 30
    scan_channel: int = 0
    target_ssid: str = ""
    target_bssid: str = ""
    min_signal: int = -85
    check_credentials: bool = True
    check_dns: bool = True
    check_rogue: bool = True
    report_file: str = "/tmp/wifiaio_vuln_report.json"
    report_format: str = "json"
    max_targets: int = 0


@dataclass
class ScanVulnReportResult:
    """Outcome of the ScanVulnReport workflow.

    Attributes:
        success: Whether at least one audit completed.
        targets_scanned: Number of APs audited.
        total_vulnerabilities: Total vulns across all targets.
        critical_count: Number of critical-severity vulns.
        high_count: Number of high-severity vulns.
        audit_results: Per-target audit result dicts.
        report_file: Path to the written report.
        elapsed: Total wall-clock seconds.
    """

    success: bool = False
    targets_scanned: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    audit_results: list[dict[str, Any]] = field(default_factory=list)
    report_file: str = ""
    elapsed: float = 0.0


class ScanVulnReport:
    """Scan → Vulnerability Check → Report workflow.

    Steps:
      1. Scan for WiFi networks.
      2. Select targets for auditing.
      3. Run vulnerability audit on each target.
      4. Generate a consolidated report.

    Example::

        workflow = ScanVulnReport(
            config=ScanVulnReportConfig(
                interface="wlan0",
                target_ssid="MyNetwork",
                report_file="/tmp/my_audit.json",
            )
        )
        result = workflow.run()
        print(f"Found {result.total_vulnerabilities} vulnerabilities")
    """

    def __init__(self, config: Optional[ScanVulnReportConfig] = None) -> None:
        self.config = config or ScanVulnReportConfig()
        self._engine = WorkflowEngine(name="scan_vuln_report")

    def _build_engine(self) -> WorkflowEngine:
        engine = WorkflowEngine(name="scan_vuln_report")
        engine.set_context("config", self.config)

        # Step 1: Scan
        engine.add_step(WorkflowStep(
            name="scan",
            action=self._step_scan,
            on_error=ErrorStrategy.STOP,
            timeout=60.0,
        ))

        # Step 2: Select targets
        engine.add_step(WorkflowStep(
            name="select_targets",
            action=self._step_select_targets,
            condition=lambda ctx: bool(ctx.get("scan_results")),
            on_error=ErrorStrategy.STOP,
        ))

        # Step 3: Audit targets
        engine.add_step(WorkflowStep(
            name="audit",
            action=self._step_audit,
            condition=lambda ctx: bool(ctx.get("targets")),
            on_error=ErrorStrategy.CONTINUE,
            timeout=600.0,
        ))

        # Step 4: Generate report
        engine.add_step(WorkflowStep(
            name="report",
            action=self._step_report,
            on_error=ErrorStrategy.CONTINUE,
        ))

        return engine

    # ── Steps ──────────────────────────────────────────────────────────

    def _step_scan(self, ctx: dict[str, Any]) -> list[dict[str, Any]]:
        """Scan for WiFi networks."""
        from wifi_aio.core.network_scanner import NetworkScanner

        cfg: ScanVulnReportConfig = ctx["config"]
        scanner = NetworkScanner(interface=cfg.interface)

        try:
            aps = scanner.scan(timeout=cfg.scan_timeout)
        except (WiFiPermissionError, WiFiTimeoutError):
            aps = scanner.scan_airodump(timeout=cfg.scan_timeout)

        results = [ap.to_dict() for ap in aps]
        ctx["scan_results"] = results
        logger.info("Scan found %d access points", len(results))
        return results

    def _step_select_targets(self, ctx: dict[str, Any]) -> list[dict[str, Any]]:
        """Select which APs to audit."""
        cfg: ScanVulnReportConfig = ctx["config"]
        results = ctx.get("scan_results", [])

        targets: list[dict[str, Any]] = []

        # Specific BSSID
        if cfg.target_bssid:
            for ap in results:
                if ap.get("bssid", "").lower() == cfg.target_bssid.lower():
                    targets.append(ap)
                    break

        # Specific SSID
        if not targets and cfg.target_ssid:
            for ap in results:
                if ap.get("ssid") == cfg.target_ssid:
                    targets.append(ap)

        # All above-signal-threshold APs
        if not targets:
            candidates = [
                ap for ap in results
                if ap.get("signal_dbm", -100) >= cfg.min_signal
            ]
            # Prioritise encrypted networks (more interesting for vuln assessment)
            candidates.sort(
                key=lambda a: (
                    0 if "WPA" in a.get("security_type", a.get("security", "")).upper() else 1,
                    -a.get("signal_dbm", -100),
                )
            )
            targets = candidates

        # Apply max_targets limit
        if cfg.max_targets > 0:
            targets = targets[: cfg.max_targets]

        ctx["targets"] = targets
        logger.info("Selected %d targets for audit", len(targets))
        return targets

    def _step_audit(self, ctx: dict[str, Any]) -> list[dict[str, Any]]:
        """Run vulnerability audit on each target."""
        from wifi_aio.core.vuln_scanner import VulnScanner

        cfg: ScanVulnReportConfig = ctx["config"]
        targets = ctx.get("targets", [])

        scanner = VulnScanner(interface=cfg.interface)
        audit_results: list[dict[str, Any]] = []

        for target in targets:
            bssid = target.get("bssid", "")
            ssid = target.get("ssid", "")
            channel = target.get("channel", 0)

            logger.info("Auditing %s (%s) ch %d", ssid, bssid, channel)

            try:
                audit = scanner.full_audit(
                    bssid=bssid,
                    ssid=ssid,
                    channel=channel,
                    check_credentials=cfg.check_credentials,
                    check_dns=cfg.check_dns,
                    check_rogue=cfg.check_rogue,
                )
                audit_dict = audit.to_dict()
                audit_results.append(audit_dict)
                logger.info(
                    "Audit of %s: score %d, %d vulns",
                    ssid, audit.score, len(audit.vulnerabilities),
                )
            except (WiFiPermissionError, WiFiTimeoutError, Exception) as exc:
                logger.error("Audit failed for %s: %s", ssid, exc)
                audit_results.append({
                    "target_bssid": bssid,
                    "target_ssid": ssid,
                    "error": str(exc),
                    "vulnerabilities": [],
                    "score": 0,
                })

        ctx["audit_results"] = audit_results
        return audit_results

    def _step_report(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Generate the consolidated report."""
        cfg: ScanVulnReportConfig = ctx["config"]
        audit_results = ctx.get("audit_results", [])
        scan_results = ctx.get("scan_results", [])

        # Aggregate statistics
        total_vulns = 0
        critical_count = 0
        high_count = 0

        for audit in audit_results:
            vulns = audit.get("vulnerabilities", [])
            total_vulns += len(vulns)
            for v in vulns:
                sev = v.get("severity", "").lower()
                if sev == "critical":
                    critical_count += 1
                elif sev == "high":
                    high_count += 1

        report = {
            "generated_at": time.time(),
            "config": {
                "interface": cfg.interface,
                "scan_timeout": cfg.scan_timeout,
                "min_signal": cfg.min_signal,
            },
            "summary": {
                "networks_scanned": len(scan_results),
                "targets_audited": len(audit_results),
                "total_vulnerabilities": total_vulns,
                "critical_count": critical_count,
                "high_count": high_count,
            },
            "scan_results": scan_results,
            "audit_results": audit_results,
        }

        # Write report
        try:
            os.makedirs(os.path.dirname(cfg.report_file) or ".", exist_ok=True)
            with open(cfg.report_file, "w", encoding="utf-8") as f:
                if cfg.report_format == "html":
                    f.write(self._generate_html_report(report))
                else:
                    json.dump(report, f, indent=2, default=str)
            logger.info("Report written to %s", cfg.report_file)
        except OSError as exc:
            logger.error("Failed to write report: %s", exc)

        return {
            "report_file": cfg.report_file,
            "total_vulnerabilities": total_vulns,
            "critical_count": critical_count,
            "high_count": high_count,
        }

    @staticmethod
    def _generate_html_report(report: dict[str, Any]) -> str:
        """Generate an HTML vulnerability report."""
        summary = report.get("summary", {})
        audits = report.get("audit_results", [])

        html = """<!DOCTYPE html>
<html><head><title>WiFiAIO Vulnerability Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }
.header { background: #343a40; color: white; padding: 20px; border-radius: 5px; }
.summary { display: flex; gap: 20px; margin: 20px 0; }
.stat { background: white; padding: 15px; border-radius: 5px; text-align: center; flex: 1; }
.stat-number { font-size: 36px; font-weight: bold; }
.vuln { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 5px solid; }
.critical { border-left-color: #dc3545; }
.high { border-left-color: #fd7e14; }
.medium { border-left-color: #ffc107; }
.low { border-left-color: #28a745; }
</style></head><body>
<div class="header">
<h1>WiFiAIO Vulnerability Report</h1>
<p>Generated: """ + time.strftime("%Y-%m-%d %H:%M:%S") + """</p>
</div>
<div class="summary">
<div class="stat"><div class="stat-number">""" + str(summary.get("targets_audited", 0)) + """</div>Networks Audited</div>
<div class="stat"><div class="stat-number" style="color:#dc3545">""" + str(summary.get("critical_count", 0)) + """</div>Critical</div>
<div class="stat"><div class="stat-number" style="color:#fd7e14">""" + str(summary.get("high_count", 0)) + """</div>High</div>
<div class="stat"><div class="stat-number">""" + str(summary.get("total_vulnerabilities", 0)) + """</div>Total Vulns</div>
</div>
"""

        for audit in audits:
            ssid = audit.get("target_ssid", "Unknown")
            bssid = audit.get("target_bssid", "")
            score = audit.get("score", 0)
            vulns = audit.get("vulnerabilities", [])

            score_color = "#dc3545" if score < 50 else "#fd7e14" if score < 75 else "#28a745"
            html += f"""<h2>{ssid} ({bssid}) – Score: <span style="color:{score_color}">{score}/100</span></h2>"""

            for v in vulns:
                sev = v.get("severity", "info").lower()
                html += f"""
<div class="vuln {sev}">
<strong>{v.get('title', 'Unknown')}</strong> <span style="color:{'#dc3545' if sev=='critical' else '#fd7e14' if sev=='high' else '#ffc107' if sev=='medium' else '#28a745'}">[{sev.upper()}]</span>
<p>{v.get('description', '')}</p>
<p><em>Recommendation:</em> {v.get('recommendation', 'N/A')}</p>
{"<p><strong>CVE:</strong> " + v.get('cve', '') + "</p>" if v.get('cve') else ""}
</div>"""

        html += "</body></html>"
        return html

    # ── Public API ─────────────────────────────────────────────────────

    def run(self) -> ScanVulnReportResult:
        """Execute the full scan → vuln check → report pipeline.

        Returns:
            ScanVulnReportResult with the consolidated outcome.
        """
        start = time.time()
        self._engine = self._build_engine()
        wf_result: WorkflowResult = self._engine.run()

        audit_results = self._engine.get_context("audit_results", [])
        report_data = wf_result.step_results.get("report", {})

        result = ScanVulnReportResult(
            success=len(audit_results) > 0,
            targets_scanned=len(audit_results),
            total_vulnerabilities=report_data.get("total_vulnerabilities", 0) if isinstance(report_data, dict) else 0,
            critical_count=report_data.get("critical_count", 0) if isinstance(report_data, dict) else 0,
            high_count=report_data.get("high_count", 0) if isinstance(report_data, dict) else 0,
            audit_results=audit_results,
            report_file=self.config.report_file,
            elapsed=time.time() - start,
        )

        return result

    def __repr__(self) -> str:
        return (
            f"ScanVulnReport(interface={self.config.interface!r}, "
            f"target_ssid={self.config.target_ssid!r})"
        )
