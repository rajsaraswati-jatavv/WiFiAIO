"""WiFiAIO database sub-package.

Provides data models, schema migrations, backup/restore, and
repository classes for all persistent data operations.
"""

from wifi_aio.db.models import (
    Scan,
    AccessPoint,
    Client,
    Handshake,
    CrackingSession,
    Credential,
    Vulnerability,
    Config,
)
from wifi_aio.db.migrations import DatabaseMigrator
from wifi_aio.db.backup import DatabaseBackup
from wifi_aio.db.repositories.scan_repo import ScanRepository
from wifi_aio.db.repositories.network_repo import NetworkRepository
from wifi_aio.db.repositories.credential_repo import CredentialRepository
from wifi_aio.db.repositories.session_repo import SessionRepository
from wifi_aio.db.repositories.config_repo import ConfigRepository

__all__ = [
    "Scan",
    "AccessPoint",
    "Client",
    "Handshake",
    "CrackingSession",
    "Credential",
    "Vulnerability",
    "Config",
    "DatabaseMigrator",
    "DatabaseBackup",
    "ScanRepository",
    "NetworkRepository",
    "CredentialRepository",
    "SessionRepository",
    "ConfigRepository",
]
