"""PMK (Pairwise Master Key) pre-computation and table management.

Pre-computes PMK values for a given SSID and a list of passwords,
storing them in lookup tables for faster cracking.  PMK computation
is the most expensive step in WPA verification (4096 PBKDF2-SHA1
iterations per password).
"""

import hashlib
import hmac
import os
import sqlite3
import struct
import time
from typing import Dict, Generator, List, Optional, Tuple

from wifi_aio.exceptions import CrackingError


# ── Constants ──────────────────────────────────────────────────────────

PBKDF2_ITERATIONS = 4096
PMK_LENGTH = 32
PTK_LENGTH = 64


class PMKTable:
    """In-memory PMK lookup table for a single SSID."""

    def __init__(self, ssid: str) -> None:
        self.ssid = ssid
        self._ssid_bytes = ssid.encode("utf-8")
        self._table: Dict[str, bytes] = {}  # password -> PMK
        self._creation_time = time.time()

    def compute(self, password: str) -> bytes:
        """Compute and store the PMK for a password."""
        pmk = hashlib.pbkdf2_hmac(
            "sha1",
            password.encode("utf-8"),
            self._ssid_bytes,
            PBKDF2_ITERATIONS,
            dklen=PMK_LENGTH,
        )
        self._table[password] = pmk
        return pmk

    def lookup(self, password: str) -> Optional[bytes]:
        """Look up a pre-computed PMK.  Returns None if not found."""
        return self._table.get(password)

    def get_or_compute(self, password: str) -> bytes:
        """Get the PMK from the table, computing it if needed."""
        pmk = self._table.get(password)
        if pmk is None:
            pmk = self.compute(password)
        return pmk

    def precompute_wordlist(self, wordlist_path: str, callback=None) -> int:
        """Pre-compute PMKs for all words in a wordlist file.

        Returns the number of PMKs computed.
        """
        count = 0
        with open(wordlist_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                password = line.strip()
                if not password or len(password) < 8 or len(password) > 63:
                    continue
                if password not in self._table:
                    self.compute(password)
                    count += 1
                if callback and count % 100 == 0:
                    callback(count)
        return count

    def batch_compute(self, passwords: List[str]) -> int:
        """Compute PMKs for a list of passwords.

        Returns the number of newly computed PMKs.
        """
        count = 0
        for pwd in passwords:
            if pwd not in self._table:
                self.compute(pwd)
                count += 1
        return count

    def iter_items(self) -> Generator[Tuple[str, bytes], None, None]:
        """Yield all (password, pmk) pairs in the table."""
        yield from self._table.items()

    @property
    def size(self) -> int:
        """Number of entries in the table."""
        return len(self._table)

    @property
    def memory_mb(self) -> float:
        """Estimated memory usage in MB."""
        # Each entry: password string + 32-byte PMK + dict overhead
        avg_pwd_len = 10  # rough average
        bytes_per_entry = avg_pwd_len + PMK_LENGTH + 100  # dict overhead
        return (self.size * bytes_per_entry) / (1024 * 1024)

    def clear(self) -> None:
        """Clear all entries."""
        self._table.clear()


class PMKCalculator:
    """Pre-compute and manage PMK tables for WPA cracking.

    Supports both in-memory and SQLite-backed tables for large
    wordlists.

    Parameters
    ----------
    ssid:
        The target SSID for PMK computation.
    backend:
        Storage backend: ``"memory"`` or ``"sqlite"``.
    db_path:
        Path for the SQLite database (required if backend is ``"sqlite"``).
    """

    def __init__(
        self,
        ssid: str,
        backend: str = "memory",
        db_path: Optional[str] = None,
    ) -> None:
        self.ssid = ssid
        self.backend = backend
        self.db_path = db_path

        self._table = PMKTable(ssid)
        self._db: Optional[sqlite3.Connection] = None
        self._computed = 0
        self._start_time: Optional[float] = None

        if backend == "sqlite":
            if db_path is None:
                db_path = os.path.join(
                    "/tmp/wifiaio", f"pmk_{ssid.replace(' ', '_')}.db"
                )
            self.db_path = db_path
            self._init_db()

    # ── Public API ─────────────────────────────────────────────────────

    def compute_pmk(self, password: str) -> bytes:
        """Compute the PMK for a single password."""
        if self.backend == "sqlite":
            return self._compute_pmk_sqlite(password)
        return self._table.compute(password)

    def lookup_pmk(self, password: str) -> Optional[bytes]:
        """Look up a pre-computed PMK."""
        if self.backend == "sqlite":
            return self._lookup_pmk_sqlite(password)
        return self._table.lookup(password)

    def precompute_wordlist(
        self,
        wordlist_path: str,
        callback=None,
    ) -> int:
        """Pre-compute PMKs for all passwords in a wordlist.

        Returns the number of PMKs computed.
        """
        self._computed = 0
        self._start_time = time.time()

        if self.backend == "sqlite":
            return self._precompute_sqlite(wordlist_path, callback)
        return self._table.precompute_wordlist(wordlist_path, callback)

    def batch_compute(self, passwords: List[str]) -> int:
        """Compute PMKs for a batch of passwords."""
        if self.backend == "sqlite":
            return self._batch_compute_sqlite(passwords)
        return self._table.batch_compute(passwords)

    def derive_ptk(
        self,
        password: str,
        anonce: bytes,
        snonce: bytes,
        ap_mac: bytes,
        client_mac: bytes,
    ) -> bytes:
        """Derive the full PTK from a password and handshake parameters."""
        pmk = self.lookup_pmk(password)
        if pmk is None:
            pmk = self.compute_pmk(password)

        if ap_mac < client_mac:
            mac_min, mac_max = ap_mac, client_mac
        else:
            mac_min, mac_max = client_mac, ap_mac

        if anonce < snonce:
            nonce_min, nonce_max = anonce, snonce
        else:
            nonce_min, nonce_max = snonce, anonce

        a = b"Pairwise key expansion"
        b = mac_min + mac_max + nonce_min + nonce_max

        ptk = b""
        for i in range(4):
            ptk += hmac.new(pmk, a + b"\x00" + b + bytes([i]), hashlib.sha1).digest()
        return ptk[:PTK_LENGTH]

    def verify_password(
        self,
        password: str,
        anonce: bytes,
        snonce: bytes,
        ap_mac: bytes,
        client_mac: bytes,
        target_mic: bytes,
        eapol_frame: bytes,
    ) -> bool:
        """Verify a password against a captured handshake."""
        ptk = self.derive_ptk(password, anonce, snonce, ap_mac, client_mac)

        frame_copy = bytearray(eapol_frame)
        if len(frame_copy) >= 97:
            frame_copy[81:97] = b"\x00" * 16

        computed_mic = hmac.new(ptk[:16], bytes(frame_copy), hashlib.sha1).digest()[:16]
        return hmac.compare_digest(computed_mic, target_mic)

    @property
    def size(self) -> int:
        """Number of PMKs in the table."""
        if self.backend == "sqlite":
            return self._sqlite_count()
        return self._table.size

    @property
    def computed(self) -> int:
        """Number of PMKs computed in the last precompute_wordlist run."""
        return self._computed

    @property
    def elapsed(self) -> float:
        """Time elapsed in the last precompute run."""
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time

    @property
    def speed(self) -> float:
        """PMKs computed per second."""
        e = self.elapsed
        return self._computed / e if e > 0 else 0.0

    def stats(self) -> Dict:
        """Return statistics about the PMK table."""
        return {
            "ssid": self.ssid,
            "backend": self.backend,
            "size": self.size,
            "computed": self._computed,
            "elapsed": self.elapsed,
            "speed": self.speed,
            "memory_mb": self._table.memory_mb if self.backend == "memory" else 0,
            "db_path": self.db_path,
        }

    def close(self) -> None:
        """Close the database connection (if using SQLite)."""
        if self._db is not None:
            self._db.close()
            self._db = None

    # ── SQLite backend ─────────────────────────────────────────────────

    def _init_db(self) -> None:
        """Initialize the SQLite database."""
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        self._db = sqlite3.connect(self.db_path)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS pmks ("
            "password TEXT PRIMARY KEY, "
            "pmk BLOB NOT NULL)"
        )
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_password ON pmks(password)")
        self._db.commit()

    def _compute_pmk_sqlite(self, password: str) -> bytes:
        """Compute and store a PMK in SQLite."""
        pmk = hashlib.pbkdf2_hmac(
            "sha1",
            password.encode("utf-8"),
            self.ssid.encode("utf-8"),
            PBKDF2_ITERATIONS,
            dklen=PMK_LENGTH,
        )
        try:
            self._db.execute(
                "INSERT OR REPLACE INTO pmks (password, pmk) VALUES (?, ?)",
                (password, pmk),
            )
            self._db.commit()
        except sqlite3.Error:
            pass
        return pmk

    def _lookup_pmk_sqlite(self, password: str) -> Optional[bytes]:
        """Look up a PMK from SQLite."""
        cursor = self._db.execute(
            "SELECT pmk FROM pmks WHERE password = ?", (password,)
        )
        row = cursor.fetchone()
        return row[0] if row else None

    def _precompute_sqlite(self, wordlist_path: str, callback=None) -> int:
        """Pre-compute PMKs for a wordlist using SQLite backend."""
        ssid_bytes = self.ssid.encode("utf-8")
        count = 0
        batch = []

        with open(wordlist_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                password = line.strip()
                if not password or len(password) < 8 or len(password) > 63:
                    continue

                # Check if already computed
                if self._lookup_pmk_sqlite(password) is not None:
                    continue

                pmk = hashlib.pbkdf2_hmac(
                    "sha1",
                    password.encode("utf-8"),
                    ssid_bytes,
                    PBKDF2_ITERATIONS,
                    dklen=PMK_LENGTH,
                )
                batch.append((password, pmk))
                count += 1

                # Batch insert every 100 entries
                if len(batch) >= 100:
                    self._db.executemany(
                        "INSERT OR REPLACE INTO pmks (password, pmk) VALUES (?, ?)",
                        batch,
                    )
                    self._db.commit()
                    batch.clear()

                if callback and count % 100 == 0:
                    callback(count)

        # Insert remaining
        if batch:
            self._db.executemany(
                "INSERT OR REPLACE INTO pmks (password, pmk) VALUES (?, ?)",
                batch,
            )
            self._db.commit()

        self._computed = count
        return count

    def _batch_compute_sqlite(self, passwords: List[str]) -> int:
        """Batch compute PMKs in SQLite."""
        count = 0
        ssid_bytes = self.ssid.encode("utf-8")
        batch = []

        for pwd in passwords:
            if self._lookup_pmk_sqlite(pwd) is not None:
                continue
            pmk = hashlib.pbkdf2_hmac(
                "sha1", pwd.encode("utf-8"), ssid_bytes,
                PBKDF2_ITERATIONS, dklen=PMK_LENGTH,
            )
            batch.append((pwd, pmk))
            count += 1

            if len(batch) >= 100:
                self._db.executemany(
                    "INSERT OR REPLACE INTO pmks (password, pmk) VALUES (?, ?)",
                    batch,
                )
                self._db.commit()
                batch.clear()

        if batch:
            self._db.executemany(
                "INSERT OR REPLACE INTO pmks (password, pmk) VALUES (?, ?)",
                batch,
            )
            self._db.commit()

        return count

    def _sqlite_count(self) -> int:
        """Count entries in the SQLite database."""
        cursor = self._db.execute("SELECT COUNT(*) FROM pmks")
        return cursor.fetchone()[0]

    # ── Import/Export ──────────────────────────────────────────────────

    def export_cowpatty(self, output_path: str) -> int:
        """Export the PMK table in cowpatty/genpmk format.

        Returns the number of entries exported.
        """
        count = 0
        with open(output_path, "wb") as fh:
            # cowpatty header: magic(4), ssid_len(4), ssid, reserved(4)
            ssid_bytes = self.ssid.encode("utf-8")
            fh.write(struct.pack("<I", 0x43575041))  # 'CPWA' magic
            fh.write(struct.pack("<I", len(ssid_bytes)))
            fh.write(ssid_bytes)
            fh.write(b"\x00" * 32)  # reserved

            if self.backend == "memory":
                for password, pmk in self._table.iter_items():
                    pwd_bytes = password.encode("utf-8")
                    fh.write(struct.pack("<I", len(pwd_bytes)))
                    fh.write(pwd_bytes)
                    fh.write(pmk)
                    count += 1
            else:
                cursor = self._db.execute("SELECT password, pmk FROM pmks")
                for password, pmk in cursor:
                    pwd_bytes = password.encode("utf-8")
                    fh.write(struct.pack("<I", len(pwd_bytes)))
                    fh.write(pwd_bytes)
                    fh.write(pmk)
                    count += 1

        return count

    def import_cowpatty(self, input_path: str) -> int:
        """Import a cowpatty/genpmk PMK table.

        Returns the number of entries imported.
        """
        count = 0
        with open(input_path, "rb") as fh:
            # Read header
            magic = struct.unpack("<I", fh.read(4))[0]
            if magic != 0x43575041:
                raise CrackingError("Not a valid cowpatty PMK file")

            ssid_len = struct.unpack("<I", fh.read(4))[0]
            ssid = fh.read(ssid_len).decode("utf-8", errors="replace")
            fh.read(32)  # reserved

            if ssid != self.ssid:
                raise CrackingError(
                    f"PMK file is for SSID {ssid!r}, expected {self.ssid!r}"
                )

            while True:
                len_data = fh.read(4)
                if len(len_data) < 4:
                    break

                pwd_len = struct.unpack("<I", len_data)[0]
                if pwd_len == 0 or pwd_len > 64:
                    break

                password = fh.read(pwd_len).decode("utf-8", errors="replace")
                pmk = fh.read(PMK_LENGTH)

                if len(pmk) != PMK_LENGTH:
                    break

                if self.backend == "memory":
                    self._table._table[password] = pmk
                else:
                    self._db.execute(
                        "INSERT OR REPLACE INTO pmks (password, pmk) VALUES (?, ?)",
                        (password, pmk),
                    )
                count += 1

            if self.backend == "sqlite" and count > 0:
                self._db.commit()

        return count
