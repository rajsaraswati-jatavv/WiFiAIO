"""pytest fixtures for WiFiAIO test suite.

Provides shared fixtures for database connections, temporary directories,
mock interfaces, and test data used across the test suite.
"""

import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

from wifi_aio.db.models import (
    AccessPoint,
    Client,
    Config,
    CrackingSession,
    Credential,
    Handshake,
    Scan,
    Vulnerability,
)
from wifi_aio.db.migrations import DatabaseMigrator


# ── Temporary Directory Fixtures ─────────────────────────────────────────

@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory for test files."""
    return tmp_path


@pytest.fixture
def capture_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory for capture files."""
    d = tmp_path / "captures"
    d.mkdir()
    return d


@pytest.fixture
def report_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory for report output."""
    d = tmp_path / "reports"
    d.mkdir()
    return d


# ── Database Fixtures ────────────────────────────────────────────────────

@pytest.fixture
def db_path(tmp_path: Path) -> str:
    """Provide a path to a temporary SQLite database."""
    return str(tmp_path / "test_wifiaio.db")


@pytest.fixture
def db_connection(db_path: str) -> Generator[sqlite3.Connection, None, None]:
    """Provide a migrated SQLite database connection.

    Yields a connection with all tables created and populated with
    the current schema. The database is cleaned up after the test.
    """
    migrator = DatabaseMigrator(db_path)
    migrator.migrate()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    yield conn
    conn.close()
    migrator.close()


@pytest.fixture
def migrator(db_path: str) -> DatabaseMigrator:
    """Provide a DatabaseMigrator instance for the test database."""
    m = DatabaseMigrator(db_path)
    m.migrate()
    yield m
    m.close()


# ── Model Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def sample_scan() -> Scan:
    """Provide a sample Scan model instance."""
    return Scan(
        interface="wlan0",
        scan_type="active",
        band="both",
        status="completed",
        access_point_count=5,
    )


@pytest.fixture
def sample_access_point() -> AccessPoint:
    """Provide a sample AccessPoint model instance."""
    return AccessPoint(
        scan_id="test-scan-id",
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="TestNetwork",
        channel=6,
        frequency=2437,
        band="2.4GHz",
        signal_dbm=-45,
        signal_quality=85,
        encryption="WPA2",
        cipher="CCMP",
        authentication="PSK",
        wps=True,
        wps_version="2.0",
        pmf="capable",
        vendor="TestVendor",
        beacon_interval=100,
        clients_count=3,
    )


@pytest.fixture
def sample_client() -> Client:
    """Provide a sample Client model instance."""
    return Client(
        scan_id="test-scan-id",
        ap_id="test-ap-id",
        mac_address="11:22:33:44:55:66",
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="TestNetwork",
        signal_dbm=-55,
        channel=6,
        vendor="TestClient",
        associated=True,
        probes=["HomeNetwork", "Office"],
    )


@pytest.fixture
def sample_handshake() -> Handshake:
    """Provide a sample Handshake model instance."""
    return Handshake(
        ap_id="test-ap-id",
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="TestNetwork",
        capture_file="/tmp/test_capture.pcap",
        capture_type="4way",
        quality="complete",
        channel=6,
        encryption="WPA2",
    )


@pytest.fixture
def sample_cracking_session() -> CrackingSession:
    """Provide a sample CrackingSession model instance."""
    return CrackingSession(
        handshake_id="test-handshake-id",
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="TestNetwork",
        method="dictionary",
        wordlist="/usr/share/wordlists/rockyou.txt",
        tool="hashcat",
        gpu_used=True,
    )


@pytest.fixture
def sample_credential() -> Credential:
    """Provide a sample Credential model instance."""
    return Credential(
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="TestNetwork",
        password="testpassword123",
        encryption="WPA2",
        source="cracking",
        verified=True,
    )


@pytest.fixture
def sample_vulnerability() -> Vulnerability:
    """Provide a sample Vulnerability model instance."""
    return Vulnerability(
        ap_id="test-ap-id",
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="TestNetwork",
        vulnerability_type="WEP Encryption",
        severity="critical",
        cve_id="CVE-2022-23303",
        description="WEP encryption is broken and can be cracked within minutes",
        recommendation="Upgrade to WPA2 or WPA3 encryption",
    )


@pytest.fixture
def sample_config() -> Config:
    """Provide a sample Config model instance."""
    return Config(
        key="test.key",
        value="test_value",
        category="test",
        description="Test configuration entry",
    )


# ── Mock Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def mock_interface():
    """Provide a mock wireless interface."""
    mock = MagicMock()
    mock.name = "wlan0"
    mock.is_monitor = False
    mock.is_up = True
    mock.driver = "nl80211"
    return mock


@pytest.fixture
def mock_monitor_interface():
    """Provide a mock monitor mode interface."""
    mock = MagicMock()
    mock.name = "wlan0mon"
    mock.is_monitor = True
    mock.is_up = True
    mock.driver = "nl80211"
    mock.channel = 6
    return mock


@pytest.fixture
def mock_scapy():
    """Mock scapy to avoid actual packet operations during tests."""
    with patch.dict("sys.modules", {"scapy": MagicMock(), "scapy.all": MagicMock()}):
        yield MagicMock()


@pytest.fixture
def mock_subprocess():
    """Mock subprocess to avoid running external commands during tests."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        yield mock_run


# ── Test Data Fixtures ──────────────────────────────────────────────────

@pytest.fixture
def sample_scan_results() -> list:
    """Provide sample scan results for testing."""
    return [
        {
            "bssid": "AA:BB:CC:DD:EE:01",
            "ssid": "TestNet1",
            "channel": 1,
            "frequency": 2412,
            "signal_dbm": -40,
            "encryption": "WPA2",
            "cipher": "CCMP",
            "authentication": "PSK",
            "wps": True,
            "vendor": "TP-Link",
        },
        {
            "bssid": "AA:BB:CC:DD:EE:02",
            "ssid": "TestNet2",
            "channel": 6,
            "frequency": 2437,
            "signal_dbm": -55,
            "encryption": "WPA3",
            "cipher": "CCMP",
            "authentication": "SAE",
            "wps": False,
            "vendor": "Netgear",
        },
        {
            "bssid": "AA:BB:CC:DD:EE:03",
            "ssid": "TestNet3",
            "channel": 11,
            "frequency": 2462,
            "signal_dbm": -70,
            "encryption": "WEP",
            "cipher": "WEP40",
            "authentication": "",
            "wps": False,
            "vendor": "D-Link",
        },
        {
            "bssid": "AA:BB:CC:DD:EE:04",
            "ssid": "",
            "channel": 36,
            "frequency": 5180,
            "signal_dbm": -60,
            "encryption": "WPA2",
            "cipher": "CCMP",
            "authentication": "PSK",
            "wps": False,
            "vendor": "ASUS",
        },
        {
            "bssid": "AA:BB:CC:DD:EE:05",
            "ssid": "OpenNet",
            "channel": 6,
            "frequency": 2437,
            "signal_dbm": -50,
            "encryption": "Open",
            "cipher": "",
            "authentication": "",
            "wps": False,
            "vendor": "Unknown",
        },
    ]


@pytest.fixture
def sample_bssid_list() -> list:
    """Provide a list of sample BSSIDs for testing."""
    return [
        "AA:BB:CC:DD:EE:01",
        "AA:BB:CC:DD:EE:02",
        "AA:BB:CC:DD:EE:03",
        "00:27:19:AA:BB:01",  # TP-Link OUI
        "00:09:5B:AA:BB:02",  # Netgear OUI
        "00:05:5D:AA:BB:03",  # D-Link OUI
    ]


# ── Environment Fixtures ────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolate_env(tmp_path: Path):
    """Isolate test environment from real system config.

    Redirects config and data directories to temp paths to prevent
    tests from reading or modifying real user data.
    """
    with patch.dict(os.environ, {
        "WIFAIO_CONFIG_DIR": str(tmp_path / "config"),
        "WIFAIO_DATA_DIR": str(tmp_path / "data"),
        "WIFAIO_CACHE_DIR": str(tmp_path / "cache"),
    }):
        yield
