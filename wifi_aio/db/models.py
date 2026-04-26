"""Data models for WiFiAIO database.

Defines SQLAlchemy-style dataclass models for scans, access points,
clients, handshakes, cracking sessions, credentials, vulnerabilities,
and configuration entries.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


def _generate_id() -> str:
    """Generate a unique identifier string."""
    return str(uuid.uuid4())


def _now() -> datetime:
    """Return current UTC datetime."""
    return datetime.utcnow()


@dataclass
class Scan:
    """Represents a WiFi network scan operation."""
    id: str = field(default_factory=_generate_id)
    interface: str = ""
    scan_type: str = "active"  # active, passive
    band: str = "both"  # 2.4GHz, 5GHz, 6GHz, both
    start_time: datetime = field(default_factory=_now)
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    status: str = "pending"  # pending, running, completed, failed
    access_point_count: int = 0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "interface": self.interface,
            "scan_type": self.scan_type,
            "band": self.band,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "access_point_count": self.access_point_count,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Scan":
        """Create a Scan from a dictionary."""
        if "start_time" in data and isinstance(data["start_time"], str):
            data["start_time"] = datetime.fromisoformat(data["start_time"])
        if "end_time" in data and isinstance(data["end_time"], str):
            data["end_time"] = datetime.fromisoformat(data["end_time"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def complete(self, ap_count: int = 0) -> None:
        """Mark the scan as completed."""
        self.status = "completed"
        self.end_time = _now()
        self.access_point_count = ap_count
        if self.start_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()

    def fail(self, reason: str = "") -> None:
        """Mark the scan as failed."""
        self.status = "failed"
        self.end_time = _now()
        self.notes = reason


@dataclass
class AccessPoint:
    """Represents a discovered WiFi access point."""
    id: str = field(default_factory=_generate_id)
    scan_id: str = ""
    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    frequency: int = 0
    band: str = ""
    signal_dbm: int = 0
    signal_quality: int = 0
    encryption: str = ""
    cipher: str = ""
    authentication: str = ""
    wps: bool = False
    wps_version: str = ""
    wps_pin: str = ""
    wps_locked: bool = False
    pmf: str = "disabled"  # disabled, capable, required
    vendor: str = ""
    first_seen: datetime = field(default_factory=_now)
    last_seen: datetime = field(default_factory=_now)
    beacon_interval: int = 100
    max_bitrate: int = 0
    ht_capabilities: str = ""
    vht_capabilities: str = ""
    he_capabilities: str = ""
    clients_count: int = 0
    is_hidden: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "frequency": self.frequency,
            "band": self.band,
            "signal_dbm": self.signal_dbm,
            "signal_quality": self.signal_quality,
            "encryption": self.encryption,
            "cipher": self.cipher,
            "authentication": self.authentication,
            "wps": self.wps,
            "wps_version": self.wps_version,
            "wps_pin": self.wps_pin,
            "wps_locked": self.wps_locked,
            "pmf": self.pmf,
            "vendor": self.vendor,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "beacon_interval": self.beacon_interval,
            "max_bitrate": self.max_bitrate,
            "ht_capabilities": self.ht_capabilities,
            "vht_capabilities": self.vht_capabilities,
            "he_capabilities": self.he_capabilities,
            "clients_count": self.clients_count,
            "is_hidden": self.is_hidden,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccessPoint":
        """Create an AccessPoint from a dictionary."""
        for dt_field in ("first_seen", "last_seen"):
            if dt_field in data and isinstance(data[dt_field], str):
                data[dt_field] = datetime.fromisoformat(data[dt_field])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @property
    def display_bssid(self) -> str:
        """Return formatted BSSID for display."""
        return self.bssid.upper()

    @property
    def security_summary(self) -> str:
        """Return a summary string of the AP security configuration."""
        parts = [self.encryption] if self.encryption else []
        if self.cipher:
            parts.append(self.cipher)
        if self.authentication:
            parts.append(self.authentication)
        if self.pmf == "required":
            parts.append("PMF")
        return "/".join(parts) if parts else "Open"


@dataclass
class Client:
    """Represents a WiFi client station."""
    id: str = field(default_factory=_generate_id)
    scan_id: str = ""
    ap_id: str = ""
    mac_address: str = ""
    bssid: str = ""
    ssid: str = ""
    signal_dbm: int = 0
    signal_quality: int = 0
    channel: int = 0
    frequency: int = 0
    vendor: str = ""
    first_seen: datetime = field(default_factory=_now)
    last_seen: datetime = field(default_factory=_now)
    associated: bool = False
    probes: List[str] = field(default_factory=list)
    ip_address: str = ""
    hostname: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "ap_id": self.ap_id,
            "mac_address": self.mac_address,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "signal_dbm": self.signal_dbm,
            "signal_quality": self.signal_quality,
            "channel": self.channel,
            "frequency": self.frequency,
            "vendor": self.vendor,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "associated": self.associated,
            "probes": self.probes,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Client":
        """Create a Client from a dictionary."""
        for dt_field in ("first_seen", "last_seen"):
            if dt_field in data and isinstance(data[dt_field], str):
                data[dt_field] = datetime.fromisoformat(data[dt_field])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Handshake:
    """Represents a captured WiFi handshake."""
    id: str = field(default_factory=_generate_id)
    ap_id: str = ""
    bssid: str = ""
    ssid: str = ""
    capture_file: str = ""
    capture_type: str = "4way"  # 4way, pmkid, both
    quality: str = "unknown"  # unknown, partial, complete
    channel: int = 0
    encryption: str = ""
    captured_at: datetime = field(default_factory=_now)
    file_size: int = 0
    verified: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "ap_id": self.ap_id,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "capture_file": self.capture_file,
            "capture_type": self.capture_type,
            "quality": self.quality,
            "channel": self.channel,
            "encryption": self.encryption,
            "captured_at": self.captured_at.isoformat() if self.captured_at else None,
            "file_size": self.file_size,
            "verified": self.verified,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Handshake":
        """Create a Handshake from a dictionary."""
        if "captured_at" in data and isinstance(data["captured_at"], str):
            data["captured_at"] = datetime.fromisoformat(data["captured_at"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class CrackingSession:
    """Represents a password cracking session."""
    id: str = field(default_factory=_generate_id)
    handshake_id: str = ""
    bssid: str = ""
    ssid: str = ""
    method: str = "dictionary"  # dictionary, brute_force, mask, rule, hybrid
    wordlist: str = ""
    rules: str = ""
    mask: str = ""
    status: str = "pending"  # pending, running, completed, failed, stopped
    progress: float = 0.0
    speed: int = 0  # hashes per second
    tried: int = 0
    total: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    cracked: bool = False
    password: str = ""
    tool: str = ""  # aircrack, hashcat, john, cowpatty
    gpu_used: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "handshake_id": self.handshake_id,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "method": self.method,
            "wordlist": self.wordlist,
            "rules": self.rules,
            "mask": self.mask,
            "status": self.status,
            "progress": self.progress,
            "speed": self.speed,
            "tried": self.tried,
            "total": self.total,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "cracked": self.cracked,
            "password": self.password,
            "tool": self.tool,
            "gpu_used": self.gpu_used,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CrackingSession":
        """Create a CrackingSession from a dictionary."""
        for dt_field in ("start_time", "end_time"):
            if dt_field in data and isinstance(data[dt_field], str):
                data[dt_field] = datetime.fromisoformat(data[dt_field])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def start(self) -> None:
        """Mark the session as running."""
        self.status = "running"
        self.start_time = _now()

    def complete_cracked(self, password: str) -> None:
        """Mark the session as successfully cracked."""
        self.status = "completed"
        self.cracked = True
        self.password = password
        self.progress = 1.0
        self.end_time = _now()
        if self.start_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()

    def complete_failed(self) -> None:
        """Mark the session as completed without cracking."""
        self.status = "completed"
        self.cracked = False
        self.progress = 1.0
        self.end_time = _now()
        if self.start_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()

    def stop(self) -> None:
        """Stop a running session."""
        self.status = "stopped"
        self.end_time = _now()
        if self.start_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()


@dataclass
class Credential:
    """Represents a discovered WiFi credential."""
    id: str = field(default_factory=_generate_id)
    bssid: str = ""
    ssid: str = ""
    password: str = ""
    encryption: str = ""
    source: str = ""  # cracking, default, osint, manual
    session_id: str = ""
    discovered_at: datetime = field(default_factory=_now)
    verified: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "password": self.password,
            "encryption": self.encryption,
            "source": self.source,
            "session_id": self.session_id,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "verified": self.verified,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Credential":
        """Create a Credential from a dictionary."""
        if "discovered_at" in data and isinstance(data["discovered_at"], str):
            data["discovered_at"] = datetime.fromisoformat(data["discovered_at"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    id: str = field(default_factory=_generate_id)
    ap_id: str = ""
    bssid: str = ""
    ssid: str = ""
    vulnerability_type: str = ""
    severity: str = "info"  # info, low, medium, high, critical
    cve_id: str = ""
    description: str = ""
    recommendation: str = ""
    discovered_at: datetime = field(default_factory=_now)
    verified: bool = False
    false_positive: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "ap_id": self.ap_id,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "cve_id": self.cve_id,
            "description": self.description,
            "recommendation": self.recommendation,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "verified": self.verified,
            "false_positive": self.false_positive,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Vulnerability":
        """Create a Vulnerability from a dictionary."""
        if "discovered_at" in data and isinstance(data["discovered_at"], str):
            data["discovered_at"] = datetime.fromisoformat(data["discovered_at"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Config:
    """Represents a configuration key-value entry."""
    id: str = field(default_factory=_generate_id)
    key: str = ""
    value: str = ""
    category: str = "general"
    description: str = ""
    created_at: datetime = field(default_factory=_now)
    updated_at: datetime = field(default_factory=_now)
    is_sensitive: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "id": self.id,
            "key": self.key,
            "value": "***" if self.is_sensitive else self.value,
            "category": self.category,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "is_sensitive": self.is_sensitive,
        }
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Create a Config from a dictionary."""
        for dt_field in ("created_at", "updated_at"):
            if dt_field in data and isinstance(data[dt_field], str):
                data[dt_field] = datetime.fromisoformat(data[dt_field])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def update_value(self, new_value: str) -> None:
        """Update the config value and timestamp."""
        self.value = new_value
        self.updated_at = _now()
