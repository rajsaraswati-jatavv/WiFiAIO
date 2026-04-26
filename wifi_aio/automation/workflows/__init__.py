"""WiFiAIO workflow definitions sub-package.

Pre-built workflow classes that chain common WiFi security operations
into automated pipelines.
"""

from wifi_aio.automation.workflows.scan_capture_crack import ScanCaptureCrack
from wifi_aio.automation.workflows.deauth_eviltwin_capture import DeauthEvilTwinCapture
from wifi_aio.automation.workflows.monitor_alert_log import MonitorAlertLog
from wifi_aio.automation.workflows.scan_vuln_report import ScanVulnReport

__all__ = [
    "ScanCaptureCrack",
    "DeauthEvilTwinCapture",
    "MonitorAlertLog",
    "ScanVulnReport",
]
