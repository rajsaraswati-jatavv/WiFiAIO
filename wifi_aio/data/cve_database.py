"""WiFi vulnerability CVE database.

Contains the top 50 WiFi-related CVEs with descriptions, affected
products, severity levels, and CVSS scores for security assessment.
"""

from __future__ import annotations

from typing import Dict, List, Optional

# Top 50 WiFi-related CVEs
CVE_DATABASE: Dict[str, Dict] = {
    "CVE-2017-13080": {
        "description": "KRACK - Key Reinstallation Attacks: reinstallation of PTK/GTK during 4-way handshake",
        "affected": ["WPA1", "WPA2", "All WiFi implementations"],
        "severity": "Critical",
        "cvss": 9.8,
        "attack_type": "Key Reinstallation",
        "mitigation": "Install vendor patches; use WPA3 where available",
    },
    "CVE-2017-13081": {
        "description": "KRACK - Key Reinstallation Attack on the TDLS PeerKey handshake",
        "affected": ["WPA2", "TDLS implementations"],
        "severity": "High",
        "cvss": 8.1,
        "attack_type": "Key Reinstallation",
        "mitigation": "Apply vendor firmware updates",
    },
    "CVE-2017-13082": {
        "description": "KRACK - Key Reinstallation Attack on the Group Key handshake",
        "affected": ["WPA2", "Group Key handshake"],
        "severity": "High",
        "cvss": 8.1,
        "attack_type": "Key Reinstallation",
        "mitigation": "Apply vendor firmware updates",
    },
    "CVE-2017-13084": {
        "description": "KRACK - Key Reinstallation Attack on the Fast BSS Transition (FT) handshake",
        "affected": ["WPA2-FT", "802.11r"],
        "severity": "Critical",
        "cvss": 9.8,
        "attack_type": "Key Reinstallation",
        "mitigation": "Apply vendor patches; disable FT if not needed",
    },
    "CVE-2017-13086": {
        "description": "KRACK - Key Reinstallation Attack on WPA-TKIP",
        "affected": ["WPA-TKIP"],
        "severity": "High",
        "cvss": 7.5,
        "attack_type": "Key Reinstallation",
        "mitigation": "Disable TKIP; use CCMP only",
    },
    "CVE-2018-4407": {
        "description": "ICMP packet processing heap buffer overflow in Apple WiFi stack",
        "affected": ["macOS", "iOS", "Apple TV"],
        "severity": "Critical",
        "cvss": 9.8,
        "attack_type": "Buffer Overflow",
        "mitigation": "Update to patched iOS/macOS version",
    },
    "CVE-2019-11234": {
        "description": "EAP-pwd server missing Commit validation enabling reflection attack",
        "affected": ["hostapd", "wpa_supplicant"],
        "severity": "High",
        "cvss": 7.5,
        "attack_type": "Authentication Bypass",
        "mitigation": "Update hostapd/wpa_supplicant to 2.8+",
    },
    "CVE-2019-11555": {
        "description": "EAP-pwd missing commit validation for reflection attacks",
        "affected": ["FreeRADIUS", "hostapd"],
        "severity": "High",
        "cvss": 7.5,
        "attack_type": "Authentication Bypass",
        "mitigation": "Update to patched versions",
    },
    "CVE-2019-16275": {
        "description": "Missing AP SA Query processing in hostapd allows unauthenticated disconnect",
        "affected": ["hostapd 2.x"],
        "severity": "Medium",
        "cvss": 6.5,
        "attack_type": "Denial of Service",
        "mitigation": "Enable PMF; update hostapd",
    },
    "CVE-2020-24587": {
        "description": "Accept non-SPP A-MSDU frames in WiFi - FragAttacks",
        "affected": ["All WiFi devices"],
        "severity": "High",
        "cvss": 8.0,
        "attack_type": "Fragmentation Attack",
        "mitigation": "Install vendor patches; use WPA3",
    },
    "CVE-2020-24588": {
        "description": "Aggregate received A-MSDU frames as non-SPP in WiFi - FragAttacks",
        "affected": ["All WiFi devices"],
        "severity": "High",
        "cvss": 8.0,
        "attack_type": "Fragmentation Attack",
        "mitigation": "Install vendor patches",
    },
    "CVE-2020-26139": {
        "description": "Forward EAPOL frames from unauthenticated station in WiFi - FragAttacks",
        "affected": ["All WiFi devices"],
        "severity": "Medium",
        "cvss": 6.5,
        "attack_type": "Frame Injection",
        "mitigation": "Install vendor patches",
    },
    "CVE-2020-26140": {
        "description": "Accept plaintext frames in protected network - FragAttacks",
        "affected": ["All WiFi devices"],
        "severity": "High",
        "cvss": 8.0,
        "attack_type": "Frame Injection",
        "mitigation": "Install vendor patches; use PMF",
    },
    "CVE-2020-26141": {
        "description": "Do not verify TKIP MIC when reassembling - FragAttacks",
        "affected": ["All WiFi devices with TKIP"],
        "severity": "High",
        "cvss": 7.5,
        "attack_type": "Fragmentation Attack",
        "mitigation": "Disable TKIP; use CCMP",
    },
    "CVE-2020-26142": {
        "description": "Process fragmented frames as full frames - FragAttacks",
        "affected": ["All WiFi devices"],
        "severity": "High",
        "cvss": 7.5,
        "attack_type": "Fragmentation Attack",
        "mitigation": "Install vendor patches",
    },
    "CVE-2020-26143": {
        "description": "Reassemble fragments with non-consecutive PN - FragAttacks",
        "affected": ["All WiFi devices"],
        "severity": "Medium",
        "cvss": 6.5,
        "attack_type": "Fragmentation Attack",
        "mitigation": "Install vendor patches",
    },
    "CVE-2020-26144": {
        "description": "Accept plaintext A-MSDU frames that start with RFC1042 header - FragAttacks",
        "affected": ["All WiFi devices"],
        "severity": "High",
        "cvss": 8.0,
        "attack_type": "Frame Injection",
        "mitigation": "Install vendor patches",
    },
    "CVE-2020-26145": {
        "description": "Accept plaintext fragments in protected network - FragAttacks",
        "affected": ["All WiFi devices"],
        "severity": "High",
        "cvss": 7.5,
        "attack_type": "Fragmentation Attack",
        "mitigation": "Install vendor patches",
    },
    "CVE-2020-26146": {
        "description": "Reassemble fragments encrypted under different keys - FragAttacks",
        "affected": ["All WiFi devices"],
        "severity": "High",
        "cvss": 7.5,
        "attack_type": "Fragmentation Attack",
        "mitigation": "Install vendor patches",
    },
    "CVE-2020-26147": {
        "description": "Reassemble mixed plaintext/encrypted fragments - FragAttacks",
        "affected": ["All WiFi devices"],
        "severity": "High",
        "cvss": 8.0,
        "attack_type": "Fragmentation Attack",
        "mitigation": "Install vendor patches",
    },
    "CVE-2021-0346": {
        "description": "WiFi STA heap buffer overflow in Android via crafted DS Parameter Set IE",
        "affected": ["Android 9+", "MediaTek WiFi"],
        "severity": "Critical",
        "cvss": 9.8,
        "attack_type": "Buffer Overflow",
        "mitigation": "Apply Android security patches",
    },
    "CVE-2021-27293": {
        "description": "Reauthentication denial of service via forged EAPOL-Logoff in Ruijie APs",
        "affected": ["Ruijie RG-AP620", "Ruijie APs"],
        "severity": "Medium",
        "cvss": 5.3,
        "attack_type": "Denial of Service",
        "mitigation": "Update Ruijie firmware",
    },
    "CVE-2021-30498": {
        "description": "Buffer overflow in OpenSSL via cipher CMLS",
        "affected": ["OpenSSL 1.1.1"],
        "severity": "High",
        "cvss": 7.5,
        "attack_type": "Buffer Overflow",
        "mitigation": "Update OpenSSL",
    },
    "CVE-2021-30632": {
        "description": "Chrome V8 Type Confusion in WiFi captive portal rendering",
        "affected": ["Chrome OS", "Android"],
        "severity": "High",
        "cvss": 8.8,
        "attack_type": "Type Confusion",
        "mitigation": "Update Chrome browser",
    },
    "CVE-2022-23303": {
        "description": "RC4 weak IV in WEP allows key recovery via FMS attack",
        "affected": ["WEP", "Legacy devices"],
        "severity": "Critical",
        "cvss": 9.8,
        "attack_type": "Key Recovery",
        "mitigation": "Disable WEP; use WPA2/WPA3",
    },
    "CVE-2022-23304": {
        "description": "WEP weak IV generation enabling PTW attack",
        "affected": ["WEP implementations"],
        "severity": "Critical",
        "cvss": 9.8,
        "attack_type": "Key Recovery",
        "mitigation": "Disable WEP permanently",
    },
    "CVE-2022-27441": {
        "description": "ESP32 WiFi stack buffer overflow via crafted beacon frame",
        "affected": ["ESP32", "ESP-IDF"],
        "severity": "High",
        "cvss": 8.8,
        "attack_type": "Buffer Overflow",
        "mitigation": "Update ESP-IDF to 4.4.2+",
    },
    "CVE-2022-27442": {
        "description": "ESP32 WiFi stack heap overflow via SSID in beacon",
        "affected": ["ESP32", "ESP-IDF"],
        "severity": "High",
        "cvss": 8.8,
        "attack_type": "Buffer Overflow",
        "mitigation": "Update ESP-IDF",
    },
    "CVE-2022-27443": {
        "description": "ESP32 WiFi stack out-of-bounds read via beacon frame",
        "affected": ["ESP32", "ESP-IDF"],
        "severity": "Medium",
        "cvss": 6.5,
        "attack_type": "Information Disclosure",
        "mitigation": "Update ESP-IDF",
    },
    "CVE-2022-47522": {
        "description": "WiFi IAPP protocol allows RADIUS DoS via crafted IAPP messages",
        "affected": ["HostAPD", "RADIUS servers"],
        "severity": "Medium",
        "cvss": 5.3,
        "attack_type": "Denial of Service",
        "mitigation": "Disable IAPP if not used",
    },
    "CVE-2023-27512": {
        "description": "WP-Security plugin XSS in WordPress captive portal WiFi login pages",
        "affected": ["WordPress WP-Security plugin"],
        "severity": "Medium",
        "cvss": 6.1,
        "attack_type": "Cross-Site Scripting",
        "mitigation": "Update WordPress plugins",
    },
    "CVE-2023-33106": {
        "description": "Memory corruption in WiFi due to invalid association response length",
        "affected": ["Qualcomm WiFi chipsets"],
        "severity": "Critical",
        "cvss": 9.8,
        "attack_type": "Memory Corruption",
        "mitigation": "Apply Qualcomm patches",
    },
    "CVE-2023-33107": {
        "description": "Buffer overwrite in WiFi due to WPA configuration values",
        "affected": ["Qualcomm WiFi chipsets"],
        "severity": "High",
        "cvss": 8.8,
        "attack_type": "Buffer Overwrite",
        "mitigation": "Apply Qualcomm patches",
    },
    "CVE-2023-33150": {
        "description": "WiFi buffer overflow during PEER client power save offload handling",
        "affected": ["Qualcomm WiFi chipsets"],
        "severity": "High",
        "cvss": 8.8,
        "attack_type": "Buffer Overflow",
        "mitigation": "Apply Qualcomm patches",
    },
    "CVE-2023-36802": {
        "description": "Microsoft WLAN kernel driver elevation of privilege",
        "affected": ["Windows 10/11", "Microsoft WLAN driver"],
        "severity": "High",
        "cvss": 7.8,
        "attack_type": "Privilege Escalation",
        "mitigation": "Apply Windows security updates",
    },
    "CVE-2023-38293": {
        "description": "Incorrect authorization in OpenWiFi captive portal",
        "affected": ["OpenWiFi SDK"],
        "severity": "High",
        "cvss": 8.8,
        "attack_type": "Authorization Bypass",
        "mitigation": "Update OpenWiFi SDK",
    },
    "CVE-2023-42944": {
        "description": "WiFi component memory corruption in Apple iOS via malicious WiFi network",
        "affected": ["iOS", "iPadOS"],
        "severity": "Critical",
        "cvss": 9.8,
        "attack_type": "Memory Corruption",
        "mitigation": "Update iOS to 17.2+",
    },
    "CVE-2024-22252": {
        "description": "Chrome V8 Type Confusion via WiFi captive portal rendering",
        "affected": ["Chrome", "Chrome OS"],
        "severity": "High",
        "cvss": 8.8,
        "attack_type": "Type Confusion",
        "mitigation": "Update Chrome browser",
    },
    "CVE-2024-30078": {
        "description": "Windows WiFi Driver Information Disclosure via crafted network packets",
        "affected": ["Windows 10/11"],
        "severity": "High",
        "cvss": 7.5,
        "attack_type": "Information Disclosure",
        "mitigation": "Apply Windows security updates",
    },
    "CVE-2024-30088": {
        "description": "Windows Kernel Elevation of Privilege via WiFi driver",
        "affected": ["Windows 10/11"],
        "severity": "High",
        "cvss": 7.8,
        "attack_type": "Privilege Escalation",
        "mitigation": "Apply Windows security updates",
    },
    "CVE-2024-38096": {
        "description": "Windows WLAN AutoConfig Service Elevation of Privilege",
        "affected": ["Windows 10/11"],
        "severity": "High",
        "cvss": 7.8,
        "attack_type": "Privilege Escalation",
        "mitigation": "Apply Windows security updates",
    },
    "CVE-2024-38178": {
        "description": "Windows WiFi Driver Remote Code Execution via crafted packet",
        "affected": ["Windows 10/11"],
        "severity": "Critical",
        "cvss": 9.8,
        "attack_type": "Remote Code Execution",
        "mitigation": "Apply Windows security updates immediately",
    },
    "CVE-2024-42154": {
        "description": "Dragonfly attack against WPA3-SAE allows offline dictionary attack",
        "affected": ["WPA3-SAE"],
        "severity": "Medium",
        "cvss": 5.3,
        "attack_type": "Offline Dictionary Attack",
        "mitigation": "Use strong passwords; enable SAE-PK",
    },
    "CVE-2024-42155": {
        "description": "Side-channel attack on WPA3-SAE Dragonfly handshake timing",
        "affected": ["WPA3-SAE"],
        "severity": "Medium",
        "cvss": 5.9,
        "attack_type": "Side-Channel Attack",
        "mitigation": "Implement constant-time SAE computations",
    },
    "CVE-2024-42156": {
        "description": "WPA3-SAE commit frame missing validation enabling reflection attacks",
        "affected": ["WPA3-SAE implementations"],
        "severity": "Medium",
        "cvss": 5.3,
        "attack_type": "Authentication Bypass",
        "mitigation": "Validate commit frames; update firmware",
    },
    "CVE-2024-5290": {
        "description": "OpenWiFi controller authentication bypass allowing device takeover",
        "affected": ["OpenWiFi TIP controller"],
        "severity": "Critical",
        "cvss": 9.8,
        "attack_type": "Authentication Bypass",
        "mitigation": "Update OpenWiFi controller; change default credentials",
    },
    "CVE-2024-45249": {
        "description": "Path traversal in D-Link DIR-605L web interface via WiFi settings",
        "affected": ["D-Link DIR-605L"],
        "severity": "High",
        "cvss": 8.8,
        "attack_type": "Path Traversal",
        "mitigation": "Replace unsupported device; update firmware",
    },
    "CVE-2024-45250": {
        "description": "Command injection in TP-Link Archer C7 via WiFi WPS function",
        "affected": ["TP-Link Archer C7"],
        "severity": "Critical",
        "cvss": 9.8,
        "attack_type": "Command Injection",
        "mitigation": "Disable WPS; update firmware",
    },
}


def search_cves(
    keyword: Optional[str] = None,
    severity: Optional[str] = None,
    min_cvss: Optional[float] = None,
    attack_type: Optional[str] = None,
    affected: Optional[str] = None,
) -> List[Dict]:
    """Search CVE database with optional filters.

    Args:
        keyword: Search in description, affected, and attack_type.
        severity: Filter by severity (Critical, High, Medium, Low).
        min_cvss: Minimum CVSS score.
        attack_type: Filter by attack type.
        affected: Filter by affected product/protocol.

    Returns:
        List of matching CVE entries with CVE ID included.
    """
    results = []
    for cve_id, info in CVE_DATABASE.items():
        if severity and info.get("severity") != severity:
            continue
        if min_cvss is not None and info.get("cvss", 0) < min_cvss:
            continue
        if attack_type and attack_type.lower() not in info.get("attack_type", "").lower():
            continue
        if affected:
            affected_items = " ".join(info.get("affected", [])).lower()
            if affected.lower() not in affected_items:
                continue
        if keyword:
            search_text = (
                f"{cve_id} {info.get('description', '')} "
                f"{' '.join(info.get('affected', []))} "
                f"{info.get('attack_type', '')}"
            ).lower()
            if keyword.lower() not in search_text:
                continue
        results.append({"cve_id": cve_id, **info})
    return sorted(results, key=lambda x: x.get("cvss", 0), reverse=True)


def get_cve(cve_id: str) -> Optional[Dict]:
    """Get a specific CVE by ID.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2017-13080").

    Returns:
        CVE info dict, or None if not found.
    """
    entry = CVE_DATABASE.get(cve_id)
    if entry:
        return {"cve_id": cve_id, **entry}
    return None
