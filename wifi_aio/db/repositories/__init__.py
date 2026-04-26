"""Database repositories sub-package.

Provides repository classes for CRUD operations on each data model.
"""

from wifi_aio.db.repositories.scan_repo import ScanRepository
from wifi_aio.db.repositories.network_repo import NetworkRepository
from wifi_aio.db.repositories.credential_repo import CredentialRepository
from wifi_aio.db.repositories.session_repo import SessionRepository
from wifi_aio.db.repositories.config_repo import ConfigRepository

__all__ = [
    "ScanRepository",
    "NetworkRepository",
    "CredentialRepository",
    "SessionRepository",
    "ConfigRepository",
]
