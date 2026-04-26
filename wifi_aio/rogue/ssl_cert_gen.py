"""SSLCertGenerator – generate self-signed SSL certificates using openssl.

Creates a self-signed X.509 certificate and corresponding RSA private
key suitable for the HTTPS captive-portal server.  All work is done
via the ``openssl`` command-line tool.
"""

import os
import subprocess
from typing import Dict, Optional

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
)
from wifi_aio.logger import get_logger

logger = get_logger("rogue.ssl_cert_gen")


class SSLCertGenerator:
    """Generate self-signed SSL certificates for the HTTPS captive portal.

    Parameters
    ----------
    cert_path:
        Output path for the PEM-encoded certificate.
    key_path:
        Output path for the PEM-encoded private key.
    common_name:
        Common Name (CN) for the certificate subject.
    organization:
        Organisation (O) field.
    country:
        Country (C) field (two-letter code).
    validity_days:
        Number of days the certificate is valid.
    key_size:
        RSA key size in bits.
    san:
        Optional Subject Alternative Name extension string
        (e.g. ``"DNS:*.local,IP:10.0.0.1"``).
    openssl_bin:
        Path to the ``openssl`` binary.
    """

    def __init__(
        self,
        cert_path: str = "/tmp/wifiaio/rogue/server.pem",
        key_path: str = "/tmp/wifiaio/rogue/server-key.pem",
        common_name: str = "WiFiAIO",
        organization: str = "WiFiAIO",
        country: str = "US",
        validity_days: int = 365,
        key_size: int = 2048,
        san: Optional[str] = None,
        openssl_bin: str = "openssl",
    ) -> None:
        self.cert_path = cert_path
        self.key_path = key_path
        self.common_name = common_name
        self.organization = organization
        self.country = country
        self.validity_days = validity_days
        self.key_size = key_size
        self.san = san
        self.openssl_bin = openssl_bin

    # ── Certificate generation ─────────────────────────────────────────

    def generate(self) -> Dict[str, str]:
        """Generate a self-signed certificate and private key.

        Returns a dict with ``cert_path`` and ``key_path``.

        Raises
        ------
        WiFiConnectionError
            If openssl fails or is not installed.
        """
        cert_dir = os.path.dirname(self.cert_path)
        key_dir = os.path.dirname(self.key_path)
        os.makedirs(cert_dir, exist_ok=True)
        os.makedirs(key_dir, exist_ok=True)

        # Build subject string
        subject = (
            f"/C={self.country}"
            f"/O={self.organization}"
            f"/CN={self.common_name}"
        )

        cmd = [
            self.openssl_bin, "req",
            "-x509",
            "-newkey", f"rsa:{self.key_size}",
            "-keyout", self.key_path,
            "-out", self.cert_path,
            "-days", str(self.validity_days),
            "-nodes",           # no passphrase on the key
            "-subj", subject,
        ]

        # Add SAN extension if specified
        if self.san:
            cmd.extend(["-addext", f"subjectAltName={self.san}"])

        logger.info("Generating self-signed cert: CN=%s, key=%d bits, days=%d",
                     self.common_name, self.key_size, self.validity_days)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError as exc:
            raise WiFiConnectionError(
                f"openssl binary not found: {self.openssl_bin}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise WiFiTimeoutError("openssl certificate generation timed out") from exc

        if result.returncode != 0:
            raise WiFiConnectionError(
                f"openssl failed (rc={result.returncode}): {result.stderr.strip()}"
            )

        # Verify the files were created
        if not os.path.isfile(self.cert_path):
            raise WiFiConnectionError("Certificate file was not created")
        if not os.path.isfile(self.key_path):
            raise WiFiConnectionError("Key file was not created")

        logger.info("Certificate written to %s", self.cert_path)
        logger.info("Private key written to %s", self.key_path)

        return {"cert_path": self.cert_path, "key_path": self.key_path}

    # ── Certificate inspection ─────────────────────────────────────────

    def get_cert_info(self) -> Dict[str, str]:
        """Parse the generated certificate and return its details.

        Returns a dict with keys: ``subject``, ``issuer``, ``not_before``,
        ``not_after``, ``serial``.
        """
        if not os.path.isfile(self.cert_path):
            return {}

        cmd = [self.openssl_bin, "x509", "-in", self.cert_path, "-noout", "-text"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {}

        if result.returncode != 0:
            return {}

        text = result.stdout
        info: Dict[str, str] = {}

        # Extract key fields with simple string parsing
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("Subject:"):
                info["subject"] = line.split("Subject:", 1)[1].strip()
            elif line.startswith("Issuer:"):
                info["issuer"] = line.split("Issuer:", 1)[1].strip()
            elif "Not Before" in line:
                info["not_before"] = line.split("Not Before:", 1)[1].strip() if "Not Before:" in line else ""
            elif "Not After" in line:
                info["not_after"] = line.split("Not After:", 1)[1].strip() if "Not After:" in line else ""
            elif line.startswith("Serial Number:"):
                info["serial"] = line.split("Serial Number:", 1)[1].strip()

        return info

    def is_valid(self) -> bool:
        """Check whether the certificate file exists and is within its validity period."""
        if not os.path.isfile(self.cert_path):
            return False

        cmd = [
            self.openssl_bin, "x509",
            "-in", self.cert_path,
            "-noout",
            "-checkend", "0",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def fingerprint(self, hash_alg: str = "sha256") -> str:
        """Return the certificate fingerprint using the given hash algorithm.

        Common values: ``"sha256"``, ``"sha1"``, ``"md5"``.
        """
        if not os.path.isfile(self.cert_path):
            return ""

        cmd = [
            self.openssl_bin, "x509",
            "-in", self.cert_path,
            "-noout",
            f"-{hash_alg}",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.strip().split("=", 1)[-1].strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return ""

    def delete(self) -> None:
        """Remove the certificate and key files from disk."""
        for path in (self.cert_path, self.key_path):
            if os.path.isfile(path):
                os.remove(path)
                logger.debug("Removed %s", path)
