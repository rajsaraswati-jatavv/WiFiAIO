"""Tests for wifi_aio.database – Thread-safe SQLite wrapper.

Covers insert_ap, get_ap, insert_scan (start_session), thread safety,
SQL injection protection (column whitelisting), and backup/restore.
"""

import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List

import pytest

from wifi_aio.database import Database, VALID_AP_COLUMNS
from wifi_aio.exceptions import DatabaseError


# ── Fixtures ────────────────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path: Path) -> Database:
    """Provide a fresh Database pointing at a temp file."""
    path = str(tmp_path / "test.db")
    database = Database(db_path=path)
    yield database
    database.close()


@pytest.fixture
def db_with_ap(db: Database) -> Database:
    """Database with one AP record inserted."""
    db.insert_ap({
        "bssid": "aa:bb:cc:dd:ee:ff",
        "ssid": "TestNet",
        "channel": 6,
        "signal_dbm": -45,
        "security": "WPA2",
        "vendor": "TestVendor",
    })
    return db


# ── insert_ap / get_ap ───────────────────────────────────────────────────

class TestInsertGetAp:
    """Insert and retrieve access-point records."""

    def test_insert_and_get(self, db: Database) -> None:
        row_id = db.insert_ap({
            "bssid": "11:22:33:44:55:66",
            "ssid": "MyNetwork",
            "channel": 1,
        })
        assert isinstance(row_id, int)

        ap = db.get_ap("11:22:33:44:55:66")
        assert ap is not None
        assert ap["ssid"] == "MyNetwork"
        assert ap["channel"] == 1

    def test_get_nonexistent_returns_none(self, db: Database) -> None:
        assert db.get_ap("ff:ff:ff:ff:ff:ff") is None

    def test_insert_requires_bssid(self, db: Database) -> None:
        with pytest.raises(DatabaseError, match="bssid"):
            db.insert_ap({"ssid": "NoBSSID"})

    def test_insert_or_replace(self, db: Database) -> None:
        """Inserting the same BSSID twice should replace the record."""
        db.insert_ap({"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "First"})
        db.insert_ap({"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "Second"})
        ap = db.get_ap("aa:bb:cc:dd:ee:ff")
        assert ap["ssid"] == "Second"

    def test_update_ap(self, db_with_ap: Database) -> None:
        rows = db_with_ap.update_ap("aa:bb:cc:dd:ee:ff", {"ssid": "Updated"})
        assert rows == 1
        assert db_with_ap.get_ap("aa:bb:cc:dd:ee:ff")["ssid"] == "Updated"

    def test_delete_ap(self, db_with_ap: Database) -> None:
        rows = db_with_ap.delete_ap("aa:bb:cc:dd:ee:ff")
        assert rows == 1
        assert db_with_ap.get_ap("aa:bb:cc:dd:ee:ff") is None


# ── Scan sessions ────────────────────────────────────────────────────────

class TestScanSessions:
    """start_session / end_session."""

    def test_start_and_end_session(self, db: Database) -> None:
        sid = db.start_session(interface="wlan0", notes="test")
        assert isinstance(sid, int)
        db.end_session(sid)

    def test_count_aps(self, db_with_ap: Database) -> None:
        assert db_with_ap.count_aps() == 1


# ── Thread safety ────────────────────────────────────────────────────────

class TestThreadSafety:
    """Concurrent inserts must not corrupt the database."""

    def test_concurrent_inserts(self, db: Database) -> None:
        """100 concurrent inserts should all succeed without errors."""
        errors: List[Exception] = []

        def insert(i: int) -> None:
            try:
                db.insert_ap({
                    "bssid": f"00:00:00:00:{i:02x}:{i:02x}",
                    "ssid": f"Net{i}",
                    "channel": (i % 13) + 1,
                })
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=insert, args=(i,)) for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert db.count_aps() == 100


# ── SQL injection protection (column whitelisting) ───────────────────────

class TestSqlInjection:
    """Column whitelisting prevents SQL injection via user-supplied keys."""

    def test_invalid_column_ignored_on_insert(self, db: Database) -> None:
        """Keys not in VALID_AP_COLUMNS should be silently dropped."""
        row_id = db.insert_ap({
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "Safe",
            "evil_column": "DROP TABLE access_points;--",
        })
        # The AP should still exist with only whitelisted columns
        ap = db.get_ap("aa:bb:cc:dd:ee:ff")
        assert ap is not None
        assert ap["ssid"] == "Safe"

    def test_invalid_filter_column_raises(self, db: Database) -> None:
        with pytest.raises(DatabaseError, match="Invalid filter column"):
            db.list_aps(filter_col="evil_column", filter_val="pwned")

    def test_execute_rejects_non_select(self, db: Database) -> None:
        with pytest.raises(DatabaseError, match="Only SELECT"):
            db.execute("DROP TABLE access_points")

    def test_invalid_order_by_falls_back(self, db: Database) -> None:
        """An invalid order-by column should fall back to signal_dbm DESC."""
        results = db.list_aps(order_by="evil_col ASC")
        # Should not raise – just use the default ordering
        assert isinstance(results, list)


# ── Backup / Restore ─────────────────────────────────────────────────────

class TestBackupRestore:
    """Database backup and restore."""

    def test_backup_creates_file(self, db_with_ap: Database, tmp_path: Path) -> None:
        dest = str(tmp_path / "backup.db")
        result = db_with_ap.backup(dest)
        assert os.path.isfile(result)

    def test_restore_replaces_data(self, db_with_ap: Database, tmp_path: Path) -> None:
        """Back up, clear, then restore should bring data back."""
        dest = str(tmp_path / "backup.db")
        db_with_ap.backup(dest)

        # Delete the AP
        db_with_ap.delete_ap("aa:bb:cc:dd:ee:ff")
        assert db_with_ap.get_ap("aa:bb:cc:dd:ee:ff") is None

        # Restore
        db_with_ap.restore(dest)
        ap = db_with_ap.get_ap("aa:bb:cc:dd:ee:ff")
        assert ap is not None
        assert ap["ssid"] == "TestNet"

    def test_restore_missing_file_raises(self, db: Database) -> None:
        with pytest.raises(DatabaseError, match="not found"):
            db.restore("/nonexistent/path.db")
