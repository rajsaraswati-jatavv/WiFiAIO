"""Network repository for CRUD operations on access points and clients.

Provides create, read, update, delete, and query operations
for WiFi network (access point and client) data.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

from wifi_aio.db.models import AccessPoint, Client
from wifi_aio.exceptions import DatabaseError


class NetworkRepository:
    """Repository for AccessPoint and Client model CRUD operations."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    # ── Access Points ───────────────────────────────────────────────────

    def create_ap(self, ap: AccessPoint) -> AccessPoint:
        """Create a new access point record.

        Args:
            ap: AccessPoint model instance to persist.

        Returns:
            The created AccessPoint instance.

        Raises:
            DatabaseError: If the insert fails.
        """
        try:
            self.conn.execute(
                """INSERT INTO access_points
                   (id, scan_id, bssid, ssid, channel, frequency, band,
                    signal_dbm, signal_quality, encryption, cipher, authentication,
                    wps, wps_version, wps_pin, wps_locked, pmf, vendor,
                    first_seen, last_seen, beacon_interval, max_bitrate,
                    ht_capabilities, vht_capabilities, he_capabilities,
                    clients_count, is_hidden)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ap.id, ap.scan_id, ap.bssid, ap.ssid, ap.channel, ap.frequency, ap.band,
                    ap.signal_dbm, ap.signal_quality, ap.encryption, ap.cipher, ap.authentication,
                    int(ap.wps), ap.wps_version, ap.wps_pin, int(ap.wps_locked), ap.pmf, ap.vendor,
                    ap.first_seen.isoformat() if ap.first_seen else None,
                    ap.last_seen.isoformat() if ap.last_seen else None,
                    ap.beacon_interval, ap.max_bitrate,
                    ap.ht_capabilities, ap.vht_capabilities, ap.he_capabilities,
                    ap.clients_count, int(ap.is_hidden),
                ),
            )
            self.conn.commit()
            return ap
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to create access point: {e}", details=str(e))

    def get_ap_by_id(self, ap_id: str) -> Optional[AccessPoint]:
        """Get an access point by ID."""
        cursor = self.conn.execute("SELECT * FROM access_points WHERE id = ?", (ap_id,))
        row = cursor.fetchone()
        return self._row_to_ap(row) if row else None

    def get_ap_by_bssid(self, bssid: str, scan_id: Optional[str] = None) -> List[AccessPoint]:
        """Get access points by BSSID, optionally filtered by scan."""
        if scan_id:
            cursor = self.conn.execute(
                "SELECT * FROM access_points WHERE bssid = ? AND scan_id = ? ORDER BY last_seen DESC",
                (bssid, scan_id),
            )
        else:
            cursor = self.conn.execute(
                "SELECT * FROM access_points WHERE bssid = ? ORDER BY last_seen DESC",
                (bssid,),
            )
        return [self._row_to_ap(row) for row in cursor.fetchall()]

    def get_aps_by_scan(self, scan_id: str) -> List[AccessPoint]:
        """Get all access points for a scan."""
        cursor = self.conn.execute(
            "SELECT * FROM access_points WHERE scan_id = ? ORDER BY signal_dbm DESC",
            (scan_id,),
        )
        return [self._row_to_ap(row) for row in cursor.fetchall()]

    def search_aps(self, keyword: str, limit: int = 100) -> List[AccessPoint]:
        """Search access points by keyword in SSID, BSSID, or vendor."""
        pattern = f"%{keyword}%"
        cursor = self.conn.execute(
            """SELECT * FROM access_points
               WHERE ssid LIKE ? OR bssid LIKE ? OR vendor LIKE ?
               ORDER BY signal_dbm DESC LIMIT ?""",
            (pattern, pattern, pattern, limit),
        )
        return [self._row_to_ap(row) for row in cursor.fetchall()]

    def get_aps_by_encryption(self, encryption: str) -> List[AccessPoint]:
        """Get access points by encryption type."""
        cursor = self.conn.execute(
            "SELECT * FROM access_points WHERE encryption = ? ORDER BY signal_dbm DESC",
            (encryption,),
        )
        return [self._row_to_ap(row) for row in cursor.fetchall()]

    def get_aps_with_wps(self) -> List[AccessPoint]:
        """Get all access points with WPS enabled."""
        cursor = self.conn.execute(
            "SELECT * FROM access_points WHERE wps = 1 ORDER BY signal_dbm DESC"
        )
        return [self._row_to_ap(row) for row in cursor.fetchall()]

    def update_ap(self, ap: AccessPoint) -> AccessPoint:
        """Update an access point record."""
        try:
            self.conn.execute(
                """UPDATE access_points SET
                   ssid = ?, channel = ?, frequency = ?, band = ?,
                   signal_dbm = ?, signal_quality = ?, encryption = ?,
                   cipher = ?, authentication = ?, wps = ?, wps_version = ?,
                   wps_pin = ?, wps_locked = ?, pmf = ?, vendor = ?,
                   last_seen = ?, beacon_interval = ?, max_bitrate = ?,
                   ht_capabilities = ?, vht_capabilities = ?, he_capabilities = ?,
                   clients_count = ?, is_hidden = ?
                   WHERE id = ?""",
                (
                    ap.ssid, ap.channel, ap.frequency, ap.band,
                    ap.signal_dbm, ap.signal_quality, ap.encryption,
                    ap.cipher, ap.authentication, int(ap.wps), ap.wps_version,
                    ap.wps_pin, int(ap.wps_locked), ap.pmf, ap.vendor,
                    ap.last_seen.isoformat() if ap.last_seen else None,
                    ap.beacon_interval, ap.max_bitrate,
                    ap.ht_capabilities, ap.vht_capabilities, ap.he_capabilities,
                    ap.clients_count, int(ap.is_hidden), ap.id,
                ),
            )
            self.conn.commit()
            return ap
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to update access point: {e}", details=str(e))

    def delete_ap(self, ap_id: str) -> bool:
        """Delete an access point by ID."""
        try:
            self.conn.execute("DELETE FROM clients WHERE ap_id = ?", (ap_id,))
            cursor = self.conn.execute("DELETE FROM access_points WHERE id = ?", (ap_id,))
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to delete access point: {e}", details=str(e))

    def count_aps(self, scan_id: Optional[str] = None) -> int:
        """Count access points, optionally filtered by scan."""
        if scan_id:
            cursor = self.conn.execute("SELECT COUNT(*) FROM access_points WHERE scan_id = ?", (scan_id,))
        else:
            cursor = self.conn.execute("SELECT COUNT(*) FROM access_points")
        return cursor.fetchone()[0]

    # ── Clients ─────────────────────────────────────────────────────────

    def create_client(self, client: Client) -> Client:
        """Create a new client record."""
        try:
            import json
            self.conn.execute(
                """INSERT INTO clients
                   (id, scan_id, ap_id, mac_address, bssid, ssid,
                    signal_dbm, signal_quality, channel, frequency, vendor,
                    first_seen, last_seen, associated, probes, ip_address, hostname)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    client.id, client.scan_id, client.ap_id, client.mac_address,
                    client.bssid, client.ssid, client.signal_dbm, client.signal_quality,
                    client.channel, client.frequency, client.vendor,
                    client.first_seen.isoformat() if client.first_seen else None,
                    client.last_seen.isoformat() if client.last_seen else None,
                    int(client.associated), json.dumps(client.probes),
                    client.ip_address, client.hostname,
                ),
            )
            self.conn.commit()
            return client
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to create client: {e}", details=str(e))

    def get_clients_by_ap(self, ap_id: str) -> List[Client]:
        """Get all clients for an access point."""
        cursor = self.conn.execute(
            "SELECT * FROM clients WHERE ap_id = ? ORDER BY signal_dbm DESC",
            (ap_id,),
        )
        return [self._row_to_client(row) for row in cursor.fetchall()]

    def get_clients_by_scan(self, scan_id: str) -> List[Client]:
        """Get all clients for a scan."""
        cursor = self.conn.execute(
            "SELECT * FROM clients WHERE scan_id = ? ORDER BY signal_dbm DESC",
            (scan_id,),
        )
        return [self._row_to_client(row) for row in cursor.fetchall()]

    def search_clients(self, keyword: str, limit: int = 100) -> List[Client]:
        """Search clients by MAC, vendor, hostname, or IP."""
        pattern = f"%{keyword}%"
        cursor = self.conn.execute(
            """SELECT * FROM clients
               WHERE mac_address LIKE ? OR vendor LIKE ? OR hostname LIKE ? OR ip_address LIKE ?
               ORDER BY last_seen DESC LIMIT ?""",
            (pattern, pattern, pattern, pattern, limit),
        )
        return [self._row_to_client(row) for row in cursor.fetchall()]

    def delete_client(self, client_id: str) -> bool:
        """Delete a client by ID."""
        try:
            cursor = self.conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f"Failed to delete client: {e}", details=str(e))

    # ── Conversion Helpers ──────────────────────────────────────────────

    @staticmethod
    def _row_to_ap(row: sqlite3.Row) -> AccessPoint:
        """Convert a database row to an AccessPoint instance."""
        import json
        data = dict(row)
        for dt_field in ("first_seen", "last_seen"):
            if dt_field in data and data[dt_field] and isinstance(data[dt_field], str):
                try:
                    data[dt_field] = datetime.fromisoformat(data[dt_field])
                except (ValueError, TypeError):
                    pass
        for bool_field in ("wps", "wps_locked", "is_hidden"):
            if bool_field in data:
                data[bool_field] = bool(data[bool_field])
        return AccessPoint(**{k: v for k, v in data.items() if k in AccessPoint.__dataclass_fields__})

    @staticmethod
    def _row_to_client(row: sqlite3.Row) -> Client:
        """Convert a database row to a Client instance."""
        import json
        data = dict(row)
        for dt_field in ("first_seen", "last_seen"):
            if dt_field in data and data[dt_field] and isinstance(data[dt_field], str):
                try:
                    data[dt_field] = datetime.fromisoformat(data[dt_field])
                except (ValueError, TypeError):
                    pass
        if "associated" in data:
            data["associated"] = bool(data["associated"])
        if "probes" in data and isinstance(data["probes"], str):
            try:
                data["probes"] = json.loads(data["probes"])
            except (json.JSONDecodeError, TypeError):
                data["probes"] = []
        return Client(**{k: v for k, v in data.items() if k in Client.__dataclass_fields__})
