"""Notification system for WiFiAIO — desktop and email notifications."""

import json
import logging
import os
import smtplib
import subprocess
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Dict, List, Optional

from wifi_aio.exceptions import WiFiAIOError

logger = logging.getLogger(__name__)


class NotificationManager:
    """Manage desktop and email notifications for WiFiAIO events."""

    def __init__(self, config: Optional[Dict] = None):
        self._config = config or {}
        self._smtp_host = self._config.get("smtp_host", "")
        self._smtp_port = self._config.get("smtp_port", 587)
        self._smtp_user = self._config.get("smtp_user", "")
        self._smtp_pass = self._config.get("smtp_pass", "")
        self._smtp_tls = self._config.get("smtp_tls", True)
        self._email_from = self._config.get("email_from", "")
        self._email_to = self._config.get("email_to", [])
        self._desktop_enabled = self._config.get("desktop_enabled", True)
        self._sound_enabled = self._config.get("sound_enabled", True)
        self._history: List[Dict] = []

    # ── Desktop Notifications ─────────────────────────────────────────

    def notify_desktop(
        self,
        title: str,
        message: str,
        urgency: str = "normal",
        icon: str = "network-wireless",
        timeout: int = 5000,
    ) -> bool:
        """Send a desktop notification.

        Tries notify-send (Linux), osascript (macOS), or falls back to logging.

        Args:
            title: Notification title.
            message: Notification body.
            urgency: 'low', 'normal', or 'critical'.
            icon: Icon name or path.
            timeout: Timeout in milliseconds.

        Returns:
            True if the notification was sent successfully.
        """
        if not self._desktop_enabled:
            return False

        self._record("desktop", title, message, urgency)

        # Try notify-send (Linux)
        result = self._notify_send(title, message, urgency, icon, timeout)
        if result:
            return True

        # Try osascript (macOS)
        result = self._notify_osascript(title, message)
        if result:
            return True

        # Fallback: log the notification
        logger.info("[Notification] %s: %s", title, message)
        return True

    def _notify_send(self, title: str, message: str, urgency: str,
                     icon: str, timeout: int) -> bool:
        """Send notification via notify-send (Linux)."""
        try:
            cmd = [
                "notify-send",
                "-u", urgency,
                "-i", icon,
                "-t", str(timeout),
                title,
                message,
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _notify_osascript(self, title: str, message: str) -> bool:
        """Send notification via osascript (macOS)."""
        try:
            script = f'display notification "{message}" with title "{title}"'
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    # ── Email Notifications ───────────────────────────────────────────

    def notify_email(
        self,
        subject: str,
        body: str,
        html: bool = False,
        to: Optional[List[str]] = None,
    ) -> bool:
        """Send an email notification.

        Args:
            subject: Email subject.
            body: Email body (plain text or HTML).
            html: If True, body is HTML.
            to: List of recipient addresses. Defaults to configured addresses.

        Returns:
            True if sent successfully.
        """
        recipients = to or self._email_to
        if not recipients:
            logger.warning("No email recipients configured")
            return False

        if not self._smtp_host:
            logger.warning("SMTP host not configured; cannot send email")
            return False

        self._record("email", subject, body[:200], "normal")

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[WiFiAIO] {subject}"
            msg["From"] = self._email_from or self._smtp_user
            msg["To"] = ", ".join(recipients)

            if html:
                msg.attach(MIMEText(body, "html", "utf-8"))
                # Also attach a plain text version
                import re
                plain = re.sub(r"<[^>]+>", "", body)
                msg.attach(MIMEText(plain, "plain", "utf-8"))
            else:
                msg.attach(MIMEText(body, "plain", "utf-8"))

            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=30) as server:
                if self._smtp_tls:
                    server.starttls()
                if self._smtp_user and self._smtp_pass:
                    server.login(self._smtp_user, self._smtp_pass)
                server.sendmail(msg["From"], recipients, msg.as_string())

            logger.info("Email notification sent to %s", recipients)
            return True

        except smtplib.SMTPException as exc:
            logger.error("Failed to send email notification: %s", exc)
            return False
        except Exception as exc:
            logger.error("Email notification error: %s", exc)
            return False

    # ── Convenience Methods ───────────────────────────────────────────

    def notify(self, title: str, message: str, severity: str = "normal",
               email: bool = False) -> bool:
        """Send a notification via the best available method.

        Args:
            title: Notification title.
            message: Notification body.
            severity: Severity level (maps to desktop urgency).
            email: Also send an email notification.

        Returns:
            True if at least one notification was sent.
        """
        urgency_map = {
            "critical": "critical",
            "high": "critical",
            "medium": "normal",
            "low": "low",
            "info": "low",
        }
        urgency = urgency_map.get(severity, "normal")

        desktop_ok = self.notify_desktop(title, message, urgency)
        email_ok = False
        if email:
            email_ok = self.notify_email(title, message)

        return desktop_ok or email_ok

    def notify_handshake_captured(self, bssid: str, ssid: str) -> bool:
        """Notify that a WPA handshake was captured."""
        return self.notify(
            "Handshake Captured!",
            f"WPA handshake captured for {ssid} ({bssid})",
            severity="high",
        )

    def notify_password_cracked(self, ssid: str, password: str) -> bool:
        """Notify that a password was cracked."""
        return self.notify(
            "Password Cracked!",
            f"Password for '{ssid}': {password}",
            severity="critical",
            email=True,
        )

    def notify_vulnerability_found(self, bssid: str, vuln_type: str, severity: str) -> bool:
        """Notify that a vulnerability was found."""
        return self.notify(
            "Vulnerability Found",
            f"{vuln_type} on {bssid} (severity: {severity})",
            severity=severity,
        )

    def notify_scan_complete(self, count: int) -> bool:
        """Notify that a scan is complete."""
        return self.notify(
            "Scan Complete",
            f"Found {count} networks",
            severity="info",
        )

    def notify_update_available(self, version: str) -> bool:
        """Notify that an update is available."""
        return self.notify(
            "Update Available",
            f"WiFiAIO {version} is available",
            severity="low",
        )

    def notify_error(self, error_message: str) -> bool:
        """Notify about an error."""
        return self.notify(
            "Error",
            error_message,
            severity="high",
        )

    # ── History ───────────────────────────────────────────────────────

    def get_history(self, limit: int = 50) -> List[Dict]:
        """Get notification history."""
        return self._history[-limit:]

    def clear_history(self) -> None:
        """Clear notification history."""
        self._history.clear()

    def _record(self, channel: str, title: str, message: str, severity: str) -> None:
        """Record a notification in history."""
        from datetime import datetime
        self._history.append({
            "channel": channel,
            "title": title,
            "message": message[:500],
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
        })
        # Keep last 500 entries
        if len(self._history) > 500:
            self._history = self._history[-500:]
