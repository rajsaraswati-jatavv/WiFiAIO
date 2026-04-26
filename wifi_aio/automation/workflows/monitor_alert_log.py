"""Monitor → Detect Anomaly → Alert → Log workflow.

Continuously monitors WiFi networks for anomalies, generates alerts,
and persists detailed logs for forensic analysis.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

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


class AlertSeverity(Enum):
    """Severity level for alerts."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnomalyType(Enum):
    """Types of detectable anomalies."""
    SIGNAL_SPIKE = "signal_spike"
    SIGNAL_DROP = "signal_drop"
    NEW_AP_DETECTED = "new_ap_detected"
    AP_DISAPPEARED = "ap_disappeared"
    CHANNEL_CHANGE = "channel_change"
    SECURITY_CHANGE = "security_change"
    DEAUTH_STORM = "deauth_storm"
    ROGUE_AP = "rogue_ap"
    EVIL_TWIN = "evil_twin"
    UNUSUAL_TRAFFIC = "unusual_traffic"
    WPS_ANOMALY = "wps_anomaly"


@dataclass
class Alert:
    """An alert triggered by an anomaly detection.

    Attributes:
        timestamp: Epoch time when the alert was generated.
        severity: Alert severity level.
        anomaly_type: Category of anomaly.
        message: Human-readable description.
        details: Additional data about the anomaly.
        target_bssid: BSSID of the affected AP (if applicable).
        target_ssid: SSID of the affected network (if applicable).
    """

    timestamp: float
    severity: AlertSeverity
    anomaly_type: AnomalyType
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    target_bssid: str = ""
    target_ssid: str = ""


@dataclass
class MonitorAlertLogConfig:
    """Configuration for the MonitorAlertLog workflow.

    Attributes:
        interface: Wireless interface for monitoring.
        monitor_duration: Seconds to run the monitoring loop.
        scan_interval: Seconds between each scan cycle.
        signal_threshold_db: Signal change threshold for anomaly detection.
        alert_callback: Optional callback invoked when an alert fires.
        log_file: Path to the JSON log file.
        target_bssid: Specific BSSID to monitor (empty = all).
        detect_rogue_ap: Whether to run rogue AP detection.
        detect_deauth_storms: Whether to detect deauth storms.
        min_alert_severity: Minimum severity to include in alerts.
    """

    interface: str = "wlan0"
    monitor_duration: float = 300.0
    scan_interval: float = 10.0
    signal_threshold_db: int = 15
    alert_callback: Optional[Callable[[Alert], None]] = None
    log_file: str = "/tmp/wifiaio_monitor_log.json"
    target_bssid: str = ""
    detect_rogue_ap: bool = True
    detect_deauth_storms: bool = True
    min_alert_severity: AlertSeverity = AlertSeverity.MEDIUM


@dataclass
class MonitorAlertLogResult:
    """Outcome of the MonitorAlertLog workflow.

    Attributes:
        alerts: List of generated alerts.
        scan_cycles: Number of monitoring cycles completed.
        anomalies_detected: Total anomalies found.
        log_file: Path to the written log file.
        elapsed: Total wall-clock seconds.
    """

    alerts: list[Alert] = field(default_factory=list)
    scan_cycles: int = 0
    anomalies_detected: int = 0
    log_file: str = ""
    elapsed: float = 0.0


class MonitorAlertLog:
    """Monitor → Detect Anomaly → Alert → Log workflow.

    Steps:
      1. Start monitoring – capture initial baseline.
      2. Detect anomalies – compare current state to baseline.
      3. Generate alerts – create Alert objects for each anomaly.
      4. Log results – persist alerts and measurements to disk.

    Example::

        workflow = MonitorAlertLog(
            config=MonitorAlertLogConfig(
                interface="wlan0mon",
                monitor_duration=600,
                alert_callback=my_alert_handler,
            )
        )
        result = workflow.run()
        for alert in result.alerts:
            print(f"[{alert.severity.value}] {alert.message}")
    """

    def __init__(self, config: Optional[MonitorAlertLogConfig] = None) -> None:
        self.config = config or MonitorAlertLogConfig()
        self._engine = WorkflowEngine(name="monitor_alert_log")
        self._baseline: dict[str, dict[str, Any]] = {}
        self._alerts: list[Alert] = []
        self._measurements: list[dict[str, Any]] = []

    def _build_engine(self) -> WorkflowEngine:
        engine = WorkflowEngine(name="monitor_alert_log")
        engine.set_context("config", self.config)

        # Step 1: Establish baseline
        engine.add_step(WorkflowStep(
            name="baseline",
            action=self._step_baseline,
            on_error=ErrorStrategy.STOP,
            timeout=60.0,
        ))

        # Step 2: Monitor loop (detect + alert)
        engine.add_step(WorkflowStep(
            name="monitor",
            action=self._step_monitor,
            condition=lambda ctx: bool(ctx.get("baseline")),
            on_error=ErrorStrategy.CONTINUE,
            timeout=self.config.monitor_duration + 30,
        ))

        # Step 3: Log results
        engine.add_step(WorkflowStep(
            name="log",
            action=self._step_log,
            on_error=ErrorStrategy.CONTINUE,
        ))

        return engine

    # ── Steps ──────────────────────────────────────────────────────────

    def _step_baseline(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Capture the initial network baseline."""
        from wifi_aio.core.network_scanner import NetworkScanner

        cfg: MonitorAlertLogConfig = ctx["config"]
        scanner = NetworkScanner(interface=cfg.interface)

        try:
            aps = scanner.scan(timeout=30)
        except (WiFiPermissionError, WiFiTimeoutError):
            aps = []

        baseline: dict[str, dict[str, Any]] = {}
        for ap in aps:
            baseline[ap.bssid.lower()] = ap.to_dict()

        self._baseline = baseline
        ctx["baseline"] = baseline
        logger.info("Baseline established: %d APs", len(baseline))
        return {"ap_count": len(baseline)}

    def _step_monitor(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Run the monitoring loop, detecting anomalies and generating alerts."""
        from wifi_aio.core.network_scanner import NetworkScanner
        from wifi_aio.core.signal_analyzer import SignalAnalyzer

        cfg: MonitorAlertLogConfig = ctx["config"]
        scanner = NetworkScanner(interface=cfg.interface)
        analyzer = SignalAnalyzer(interface=cfg.interface)

        start = time.time()
        cycles = 0

        while (time.time() - start) < cfg.monitor_duration:
            cycles += 1
            current_aps: dict[str, dict[str, Any]] = {}

            # Scan current state
            try:
                aps = scanner.scan(timeout=min(cfg.scan_interval, 30))
                for ap in aps:
                    current_aps[ap.bssid.lower()] = ap.to_dict()
            except (WiFiPermissionError, WiFiTimeoutError):
                logger.warning("Scan failed in cycle %d", cycles)
                time.sleep(cfg.scan_interval)
                continue

            # If targeting a specific BSSID, filter
            if cfg.target_bssid:
                target = cfg.target_bssid.lower()
                current_aps = {k: v for k, v in current_aps.items() if k == target}

            # Detect anomalies
            new_alerts = self._detect_anomalies(current_aps, cfg)
            self._alerts.extend(new_alerts)

            # Fire alert callbacks
            for alert in new_alerts:
                if cfg.alert_callback:
                    try:
                        cfg.alert_callback(alert)
                    except Exception as exc:
                        logger.error("Alert callback error: %s", exc)
                logger.info(
                    "[%s] %s: %s", alert.severity.value,
                    alert.anomaly_type.value, alert.message,
                )

            # Record measurement snapshot
            self._measurements.append({
                "timestamp": time.time(),
                "cycle": cycles,
                "ap_count": len(current_aps),
                "alerts_this_cycle": len(new_alerts),
                "access_points": {
                    k: {"ssid": v.get("ssid", ""), "signal_dbm": v.get("signal_dbm", 0)}
                    for k, v in current_aps.items()
                },
            })

            # Update baseline with current state for drift tracking
            self._baseline.update(current_aps)

            time.sleep(cfg.scan_interval)

        ctx["alerts"] = self._alerts
        ctx["scan_cycles"] = cycles
        logger.info(
            "Monitoring complete: %d cycles, %d alerts",
            cycles, len(self._alerts),
        )
        return {"cycles": cycles, "alerts": len(self._alerts)}

    def _detect_anomalies(
        self, current: dict[str, dict[str, Any]], cfg: MonitorAlertLogConfig
    ) -> list[Alert]:
        """Compare current state to baseline and generate alerts."""
        alerts: list[Alert] = []
        now = time.time()

        # New APs detected
        for bssid, ap_data in current.items():
            if bssid not in self._baseline:
                alerts.append(Alert(
                    timestamp=now,
                    severity=AlertSeverity.MEDIUM,
                    anomaly_type=AnomalyType.NEW_AP_DETECTED,
                    message=f"New AP detected: {ap_data.get('ssid', '(hidden)')} ({bssid})",
                    details=ap_data,
                    target_bssid=bssid,
                    target_ssid=ap_data.get("ssid", ""),
                ))

                # Rogue AP detection
                if cfg.detect_rogue_ap:
                    ssid = ap_data.get("ssid", "")
                    for base_bssid, base_data in self._baseline.items():
                        if base_data.get("ssid") == ssid and base_bssid != bssid:
                            alerts.append(Alert(
                                timestamp=now,
                                severity=AlertSeverity.HIGH,
                                anomaly_type=AnomalyType.ROGUE_AP,
                                message=(
                                    f"Possible rogue AP: SSID '{ssid}' seen on "
                                    f"{bssid} (expected {base_bssid})"
                                ),
                                details={"expected_bssid": base_bssid, "observed_bssid": bssid},
                                target_bssid=bssid,
                                target_ssid=ssid,
                            ))
                            break

        # APs disappeared
        for bssid in list(self._baseline.keys()):
            if bssid not in current:
                base_data = self._baseline[bssid]
                alerts.append(Alert(
                    timestamp=now,
                    severity=AlertSeverity.LOW,
                    anomaly_type=AnomalyType.AP_DISAPPEARED,
                    message=(
                        f"AP disappeared: {base_data.get('ssid', '(unknown)')} ({bssid})"
                    ),
                    details=base_data,
                    target_bssid=bssid,
                    target_ssid=base_data.get("ssid", ""),
                ))

        # Signal anomalies for known APs
        for bssid, ap_data in current.items():
            if bssid in self._baseline:
                base_data = self._baseline[bssid]
                base_signal = base_data.get("signal_dbm", 0)
                current_signal = ap_data.get("signal_dbm", 0)
                delta = abs(current_signal - base_signal)

                if delta >= cfg.signal_threshold_db:
                    if current_signal > base_signal:
                        anomaly_type = AnomalyType.SIGNAL_SPIKE
                        severity = AlertSeverity.MEDIUM
                        msg = (
                            f"Signal spike for {ap_data.get('ssid', bssid)}: "
                            f"{base_signal} → {current_signal} dBm (+{delta})"
                        )
                    else:
                        anomaly_type = AnomalyType.SIGNAL_DROP
                        severity = AlertSeverity.LOW
                        msg = (
                            f"Signal drop for {ap_data.get('ssid', bssid)}: "
                            f"{base_signal} → {current_signal} dBm (-{delta})"
                        )
                    alerts.append(Alert(
                        timestamp=now,
                        severity=severity,
                        anomaly_type=anomaly_type,
                        message=msg,
                        details={"base_signal": base_signal, "current_signal": current_signal},
                        target_bssid=bssid,
                        target_ssid=ap_data.get("ssid", ""),
                    ))

                # Security change
                base_sec = base_data.get("security_type", base_data.get("security", ""))
                current_sec = ap_data.get("security_type", ap_data.get("security", ""))
                if base_sec != current_sec and base_sec and current_sec:
                    alerts.append(Alert(
                        timestamp=now,
                        severity=AlertSeverity.HIGH,
                        anomaly_type=AnomalyType.SECURITY_CHANGE,
                        message=(
                            f"Security change for {ap_data.get('ssid', bssid)}: "
                            f"{base_sec} → {current_sec}"
                        ),
                        details={"base_security": base_sec, "current_security": current_sec},
                        target_bssid=bssid,
                        target_ssid=ap_data.get("ssid", ""),
                    ))

                # Channel change
                base_ch = base_data.get("channel", 0)
                current_ch = ap_data.get("channel", 0)
                if base_ch != current_ch and base_ch > 0 and current_ch > 0:
                    alerts.append(Alert(
                        timestamp=now,
                        severity=AlertSeverity.LOW,
                        anomaly_type=AnomalyType.CHANNEL_CHANGE,
                        message=(
                            f"Channel change for {ap_data.get('ssid', bssid)}: "
                            f"{base_ch} → {current_ch}"
                        ),
                        details={"base_channel": base_ch, "current_channel": current_ch},
                        target_bssid=bssid,
                        target_ssid=ap_data.get("ssid", ""),
                    ))

        # Filter by minimum severity
        severity_order = {
            AlertSeverity.LOW: 0,
            AlertSeverity.MEDIUM: 1,
            AlertSeverity.HIGH: 2,
            AlertSeverity.CRITICAL: 3,
        }
        min_level = severity_order.get(cfg.min_alert_severity, 1)
        filtered = [a for a in alerts if severity_order.get(a.severity, 0) >= min_level]

        return filtered

    def _step_log(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Persist alerts and measurements to a JSON log file."""
        cfg: MonitorAlertLogConfig = ctx["config"]

        log_data = {
            "session_start": self._measurements[0]["timestamp"] if self._measurements else time.time(),
            "session_end": time.time(),
            "scan_cycles": ctx.get("scan_cycles", 0),
            "total_alerts": len(self._alerts),
            "alerts": [
                {
                    "timestamp": a.timestamp,
                    "severity": a.severity.value,
                    "anomaly_type": a.anomaly_type.value,
                    "message": a.message,
                    "details": a.details,
                    "target_bssid": a.target_bssid,
                    "target_ssid": a.target_ssid,
                }
                for a in self._alerts
            ],
            "measurements": self._measurements,
        }

        try:
            os.makedirs(os.path.dirname(cfg.log_file) or ".", exist_ok=True)
            with open(cfg.log_file, "w", encoding="utf-8") as f:
                json.dump(log_data, f, indent=2, default=str)
            logger.info("Log written to %s", cfg.log_file)
        except OSError as exc:
            logger.error("Failed to write log: %s", exc)

        return {"log_file": cfg.log_file, "total_alerts": len(self._alerts)}

    # ── Public API ─────────────────────────────────────────────────────

    def run(self) -> MonitorAlertLogResult:
        """Execute the full monitor → alert → log pipeline.

        Returns:
            MonitorAlertLogResult with all generated alerts.
        """
        start = time.time()
        self._alerts.clear()
        self._measurements.clear()
        self._baseline.clear()

        self._engine = self._build_engine()
        wf_result: WorkflowResult = self._engine.run()

        result = MonitorAlertLogResult(
            alerts=list(self._alerts),
            scan_cycles=self._engine.get_context("scan_cycles", 0),
            anomalies_detected=len(self._alerts),
            log_file=self.config.log_file,
            elapsed=time.time() - start,
        )

        return result

    def __repr__(self) -> str:
        return (
            f"MonitorAlertLog(interface={self.config.interface!r}, "
            f"duration={self.config.monitor_duration}s)"
        )
