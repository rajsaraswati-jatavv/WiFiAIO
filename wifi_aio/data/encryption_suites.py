"""Encryption suite definitions for WiFi security.

Defines cipher suites, AKM suites, and integrity suites used in
802.11 RSN (Robust Security Network) IE parsing and validation.
"""

from __future__ import annotations

from typing import Dict, List, Optional

# ── Cipher (Data Encryption) Suites ─────────────────────────────────────

ENCRYPTION_SUITES: Dict[str, Dict] = {
    # WEP suites
    "WEP40": {
        "oui": "00-0F-AC",
        "suite_type": 1,
        "key_length": 40,
        "algorithm": "RC4",
        "description": "WEP with 40-bit key (aka WEP-64)",
        "deprecated": True,
        "weakness": "Broken - recoverable within minutes",
    },
    "WEP104": {
        "oui": "00-0F-AC",
        "suite_type": 5,
        "key_length": 104,
        "algorithm": "RC4",
        "description": "WEP with 104-bit key (aka WEP-128)",
        "deprecated": True,
        "weakness": "Broken - recoverable within minutes",
    },
    # TKIP
    "TKIP": {
        "oui": "00-0F-AC",
        "suite_type": 2,
        "key_length": 128,
        "algorithm": "RC4+Michael",
        "description": "Temporal Key Integrity Protocol",
        "deprecated": True,
        "weakness": "Beacon Michael attack, key recovery possible",
    },
    # CCMP (AES)
    "CCMP": {
        "oui": "00-0F-AC",
        "suite_type": 4,
        "key_length": 128,
        "algorithm": "AES-CCM",
        "description": "Counter Mode CBC-MAC Protocol (WPA2)",
        "deprecated": False,
        "weakness": None,
    },
    # GCMP
    "GCMP-128": {
        "oui": "00-0F-AC",
        "suite_type": 6,
        "key_length": 128,
        "algorithm": "AES-GCM",
        "description": "Galois/Counter Mode Protocol 128-bit (WPA3)",
        "deprecated": False,
        "weakness": None,
    },
    "GCMP-256": {
        "oui": "00-0F-AC",
        "suite_type": 7,
        "key_length": 256,
        "algorithm": "AES-GCM",
        "description": "Galois/Counter Mode Protocol 256-bit (WPA3)",
        "deprecated": False,
        "weakness": None,
    },
    # BIP (Management Frame Integrity)
    "BIP-CMAC-128": {
        "oui": "00-0F-AC",
        "suite_type": 8,
        "key_length": 128,
        "algorithm": "AES-CMAC",
        "description": "Broadcast/Multicast Integrity Protocol CMAC-128 (PMF)",
        "deprecated": False,
        "weakness": None,
    },
    "BIP-CMAC-256": {
        "oui": "00-0F-AC",
        "suite_type": 13,
        "key_length": 256,
        "algorithm": "AES-CMAC",
        "description": "Broadcast/Multicast Integrity Protocol CMAC-256",
        "deprecated": False,
        "weakness": None,
    },
    "BIP-GMAC-128": {
        "oui": "00-0F-AC",
        "suite_type": 11,
        "key_length": 128,
        "algorithm": "AES-GMAC",
        "description": "Broadcast/Multicast Integrity Protocol GMAC-128",
        "deprecated": False,
        "weakness": None,
    },
    "BIP-GMAC-256": {
        "oui": "00-0F-AC",
        "suite_type": 12,
        "key_length": 256,
        "algorithm": "AES-GMAC",
        "description": "Broadcast/Multicast Integrity Protocol GMAC-256",
        "deprecated": False,
        "weakness": None,
    },
    # CCMP-256
    "CCMP-256": {
        "oui": "00-0F-AC",
        "suite_type": 10,
        "key_length": 256,
        "algorithm": "AES-CCM-256",
        "description": "CCMP with 256-bit key",
        "deprecated": False,
        "weakness": None,
    },
}

# ── AKM (Authentication and Key Management) Suites ──────────────────────

AKM_SUITES: Dict[str, Dict] = {
    "AKM_PSK": {
        "oui": "00-0F-AC",
        "suite_type": 2,
        "description": "Pre-Shared Key (WPA-Personal)",
        "key_derivation": "PBKDF2-SHA1",
        "deprecated": False,
    },
    "AKM_8021X": {
        "oui": "00-0F-AC",
        "suite_type": 1,
        "description": "802.1X/EAP (WPA-Enterprise)",
        "key_derivation": "PBKDF2-SHA1",
        "deprecated": False,
    },
    "AKM_FT_PSK": {
        "oui": "00-0F-AC",
        "suite_type": 3,
        "description": "FT Pre-Shared Key",
        "key_derivation": "PBKDF2-SHA1+FT",
        "deprecated": False,
    },
    "AKM_FT_8021X": {
        "oui": "00-0F-AC",
        "suite_type": 4,
        "description": "FT 802.1X/EAP",
        "key_derivation": "PBKDF2-SHA1+FT",
        "deprecated": False,
    },
    "AKM_SAE": {
        "oui": "00-0F-AC",
        "suite_type": 8,
        "description": "SAE (WPA3-Personal)",
        "key_derivation": "ECVRF-SHA256",
        "deprecated": False,
    },
    "AKM_FT_SAE": {
        "oui": "00-0F-AC",
        "suite_type": 9,
        "description": "FT SAE (WPA3-Personal with FT)",
        "key_derivation": "ECVRF-SHA256+FT",
        "deprecated": False,
    },
    "AKM_SUITE_B_8021X": {
        "oui": "00-0F-AC",
        "suite_type": 11,
        "description": "Suite B 802.1X (WPA3-Enterprise 192-bit)",
        "key_derivation": "ECDH+SHA384",
        "deprecated": False,
    },
    "AKM_SUITE_B_192": {
        "oui": "00-0F-AC",
        "suite_type": 12,
        "description": "Suite B 192-bit (WPA3-Enterprise)",
        "key_derivation": "ECDH+SHA384",
        "deprecated": False,
    },
    "AKM_OWE": {
        "oui": "00-0F-AC",
        "suite_type": 18,
        "description": "Opportunistic Wireless Encryption (OWE)",
        "key_derivation": "ECDH+HKDF-SHA256",
        "deprecated": False,
    },
    "AKM_FT_PSK_SHA256": {
        "oui": "00-0F-AC",
        "suite_type": 5,
        "description": "FT PSK SHA-256",
        "key_derivation": "PBKDF2-SHA256+FT",
        "deprecated": False,
    },
    "AKM_PSK_SHA256": {
        "oui": "00-0F-AC",
        "suite_type": 6,
        "description": "PSK SHA-256 (WPA2 with SHA-256 KDF)",
        "key_derivation": "PBKDF2-SHA256",
        "deprecated": False,
    },
    "AKM_8021X_SHA256": {
        "oui": "00-0F-AC",
        "suite_type": 7,
        "description": "802.1X SHA-256 KDF",
        "key_derivation": "PBKDF2-SHA256",
        "deprecated": False,
    },
    "AKM_FILS_SHA256": {
        "oui": "00-0F-AC",
        "suite_type": 14,
        "description": "FILS with SHA-256",
        "key_derivation": "HKDF-SHA256",
        "deprecated": False,
    },
    "AKM_FILS_SHA384": {
        "oui": "00-0F-AC",
        "suite_type": 15,
        "description": "FILS with SHA-384",
        "key_derivation": "HKDF-SHA384",
        "deprecated": False,
    },
    "AKM_FT_FILS_SHA256": {
        "oui": "00-0F-AC",
        "suite_type": 16,
        "description": "FT FILS with SHA-256",
        "key_derivation": "HKDF-SHA256+FT",
        "deprecated": False,
    },
    "AKM_FT_FILS_SHA384": {
        "oui": "00-0F-AC",
        "suite_type": 17,
        "description": "FT FILS with SHA-384",
        "key_derivation": "HKDF-SHA384+FT",
        "deprecated": False,
    },
}

# ── RSN Capabilities Bits ───────────────────────────────────────────────

RSN_CAPABILITIES: Dict[str, Dict] = {
    "preauth":          {"bit": 0,  "description": "Pre-authentication supported"},
    "no_pairwise":      {"bit": 1,  "description": "No pairwise key (group only)"},
    "ptksa_rc1":        {"bit": 2,  "description": "PTKSA Replay Counter 1"},
    "ptksa_rc2":        {"bit": 3,  "description": "PTKSA Replay Counter 2"},
    "ptksa_rc4":        {"bit": 4,  "description": "PTKSA Replay Counter 4"},
    "ptksa_rc16":       {"bit": 5,  "description": "PTKSA Replay Counter 16"},
    "gtksa_rc1":        {"bit": 6,  "description": "GTKSA Replay Counter 1"},
    "gtksa_rc2":        {"bit": 7,  "description": "GTKSA Replay Counter 2"},
    "gtksa_rc4":        {"bit": 8,  "description": "GTKSA Replay Counter 4"},
    "gtksa_rc16":       {"bit": 9,  "description": "GTKSA Replay Counter 16"},
    "mfpr":             {"bit": 10, "description": "Management Frame Protection Required"},
    "mfpc":             {"bit": 11, "description": "Management Frame Protection Capable"},
    "joint_multicast":  {"bit": 12, "description": "Joint Multi-band RSNA"},
    "peerkey":          {"bit": 13, "description": "PeerKey handshake enabled"},
    "extended_iv":      {"bit": 14, "description": "Extended Key ID support"},
    "ocv":              {"bit": 15, "description": "Operating Channel Validation"},
}


def get_encryption_suite(name: str) -> Optional[Dict]:
    """Get encryption suite definition by name.

    Args:
        name: Suite name (e.g., "CCMP", "GCMP-256", "BIP-CMAC-128").

    Returns:
        Suite definition dict, or None if not found.
    """
    return ENCRYPTION_SUITES.get(name)


def get_suite_by_type(suite_type: int) -> Optional[str]:
    """Get encryption suite name by IANA suite type number.

    Args:
        suite_type: IANA suite type number.

    Returns:
        Suite name string, or None if not found.
    """
    for name, info in ENCRYPTION_SUITES.items():
        if info.get("suite_type") == suite_type:
            return name
    return None


def get_akm_suite(akm_name: str) -> Optional[Dict]:
    """Get AKM suite definition by name.

    Args:
        akm_name: AKM suite name.

    Returns:
        AKM suite definition dict, or None if not found.
    """
    return AKM_SUITES.get(akm_name)


def get_deprecated_suites() -> List[str]:
    """Return list of deprecated encryption suite names."""
    return [name for name, info in ENCRYPTION_SUITES.items() if info.get("deprecated")]


def get_secure_suites() -> List[str]:
    """Return list of non-deprecated, non-broken encryption suite names."""
    return [
        name for name, info in ENCRYPTION_SUITES.items()
        if not info.get("deprecated") and not info.get("weakness")
    ]


def assess_security(cipher_suites: List[str], akm_suites: List[str]) -> Dict:
    """Assess the security level of a given cipher/AKM combination.

    Args:
        cipher_suites: List of cipher suite names.
        akm_suites: List of AKM suite names.

    Returns:
        Assessment dict with level, score (0-100), issues list.
    """
    score = 100
    issues = []

    # Check cipher suites
    for cipher in cipher_suites:
        suite = ENCRYPTION_SUITES.get(cipher)
        if not suite:
            issues.append(f"Unknown cipher suite: {cipher}")
            score -= 10
        elif suite.get("deprecated"):
            issues.append(f"Deprecated cipher: {cipher} - {suite.get('weakness', 'No longer secure')}")
            score -= 30
        elif suite.get("weakness"):
            issues.append(f"Weakness in {cipher}: {suite['weakness']}")
            score -= 15

    # Check AKM suites
    has_wpa3 = any("SAE" in a or "OWE" in a or "Suite_B" in a for a in akm_suites)
    has_psk = any("PSK" in a and "SAE" not in a for a in akm_suites)

    if not akm_suites:
        issues.append("No AKM suite specified - open network")
        score = 0
    elif has_psk and not has_wpa3:
        issues.append("WPA2-PSK without WPA3 - consider upgrading")
        score -= 10

    # Determine security level
    score = max(0, min(100, score))
    if score >= 80:
        level = "Strong"
    elif score >= 60:
        level = "Moderate"
    elif score >= 30:
        level = "Weak"
    else:
        level = "Critical"

    return {"level": level, "score": score, "issues": issues}
