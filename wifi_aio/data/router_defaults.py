"""Default credentials for common router models.

Contains default usernames, passwords, and SSID prefixes for 100+
router models from major manufacturers. This data is intended solely
for authorized security testing.
"""

from __future__ import annotations

from typing import Dict, List, Optional

# Default credentials database: model -> {username, password, ssid_prefix}
ROUTER_DEFAULTS: Dict[str, Dict[str, str]] = {
    # ── TP-Link ─────────────────────────────────────────────────────────
    "TP-Link Archer C7": {"username": "admin", "password": "admin", "ssid_prefix": "TP-LINK"},
    "TP-Link Archer C9": {"username": "admin", "password": "admin", "ssid_prefix": "TP-LINK"},
    "TP-Link Archer A7": {"username": "admin", "password": "admin", "ssid_prefix": "TP-LINK"},
    "TP-Link Archer C1200": {"username": "admin", "password": "admin", "ssid_prefix": "TP-LINK"},
    "TP-Link Archer C20": {"username": "admin", "password": "admin", "ssid_prefix": "TP-LINK"},
    "TP-Link Archer C50": {"username": "admin", "password": "admin", "ssid_prefix": "TP-LINK"},
    "TP-Link Archer C60": {"username": "admin", "password": "admin", "ssid_prefix": "TP-LINK"},
    "TP-Link Archer AX50": {"username": "admin", "password": "admin", "ssid_prefix": "TP-LINK"},
    "TP-Link Archer AX73": {"username": "admin", "password": "admin", "ssid_prefix": "TP-LINK"},
    "TP-Link Deco M5": {"username": "admin", "password": "admin", "ssid_prefix": "Deco"},
    "TP-Link Deco M9": {"username": "admin", "password": "admin", "ssid_prefix": "Deco"},
    "TP-Link WR841N": {"username": "admin", "password": "admin", "ssid_prefix": "TP-LINK"},
    "TP-Link WR940N": {"username": "admin", "password": "admin", "ssid_prefix": "TP-LINK"},
    "TP-Link WR1043ND": {"username": "admin", "password": "admin", "ssid_prefix": "TP-LINK"},
    # ── Netgear ─────────────────────────────────────────────────────────
    "Netgear Nighthawk R7000": {"username": "admin", "password": "password", "ssid_prefix": "NETGEAR"},
    "Netgear Nighthawk R8000": {"username": "admin", "password": "password", "ssid_prefix": "NETGEAR"},
    "Netgear Nighthawk AX12": {"username": "admin", "password": "password", "ssid_prefix": "NETGEAR"},
    "Netgear R6700": {"username": "admin", "password": "password", "ssid_prefix": "NETGEAR"},
    "Netgear R6900": {"username": "admin", "password": "password", "ssid_prefix": "NETGEAR"},
    "Netgear R7000P": {"username": "admin", "password": "password", "ssid_prefix": "NETGEAR"},
    "Netgear Orbi RBK50": {"username": "admin", "password": "password", "ssid_prefix": "ORBI"},
    "Netgear Orbi RBK752": {"username": "admin", "password": "password", "ssid_prefix": "ORBI"},
    "Netgear WNR2000": {"username": "admin", "password": "password", "ssid_prefix": "NETGEAR"},
    "Netgear WNDR3700": {"username": "admin", "password": "password", "ssid_prefix": "NETGEAR"},
    "Netgear WNDR4300": {"username": "admin", "password": "password", "ssid_prefix": "NETGEAR"},
    "Netgear DGN1000": {"username": "admin", "password": "password", "ssid_prefix": "NETGEAR"},
    # ── D-Link ──────────────────────────────────────────────────────────
    "D-Link DIR-615": {"username": "admin", "password": "", "ssid_prefix": "dlink"},
    "D-Link DIR-825": {"username": "admin", "password": "", "ssid_prefix": "dlink"},
    "D-Link DIR-868L": {"username": "admin", "password": "", "ssid_prefix": "dlink"},
    "D-Link DIR-882": {"username": "admin", "password": "", "ssid_prefix": "dlink"},
    "D-Link DIR-3060": {"username": "admin", "password": "", "ssid_prefix": "dlink"},
    "D-Link DIR-895L": {"username": "admin", "password": "", "ssid_prefix": "dlink"},
    "D-Link DAP-1360": {"username": "admin", "password": "", "ssid_prefix": "dlink"},
    "D-Link DSL-2750U": {"username": "admin", "password": "admin", "ssid_prefix": "dlink"},
    "D-Link DSL-2888A": {"username": "admin", "password": "admin", "ssid_prefix": "dlink"},
    "D-Link COVR-C1203": {"username": "admin", "password": "", "ssid_prefix": "COVR"},
    # ── Linksys ─────────────────────────────────────────────────────────
    "Linksys WRT54G": {"username": "", "password": "admin", "ssid_prefix": "linksys"},
    "Linksys WRT1900AC": {"username": "admin", "password": "admin", "ssid_prefix": "Linksys"},
    "Linksys WRT3200ACM": {"username": "admin", "password": "admin", "ssid_prefix": "Linksys"},
    "Linksys EA7500": {"username": "admin", "password": "admin", "ssid_prefix": "Linksys"},
    "Linksys EA8300": {"username": "admin", "password": "admin", "ssid_prefix": "Linksys"},
    "Linksys EA9500": {"username": "admin", "password": "admin", "ssid_prefix": "Linksys"},
    "Linksys MR8300": {"username": "admin", "password": "admin", "ssid_prefix": "Linksys"},
    "Linksys MX10": {"username": "admin", "password": "admin", "ssid_prefix": "Linksys"},
    "Linksys E1200": {"username": "admin", "password": "admin", "ssid_prefix": "linksys"},
    "Linksys E2500": {"username": "admin", "password": "admin", "ssid_prefix": "linksys"},
    # ── ASUS ────────────────────────────────────────────────────────────
    "ASUS RT-AC68U": {"username": "admin", "password": "admin", "ssid_prefix": "ASUS"},
    "ASUS RT-AC88U": {"username": "admin", "password": "admin", "ssid_prefix": "ASUS"},
    "ASUS RT-AC5300": {"username": "admin", "password": "admin", "ssid_prefix": "ASUS"},
    "ASUS RT-AX88U": {"username": "admin", "password": "admin", "ssid_prefix": "ASUS"},
    "ASUS RT-AX92U": {"username": "admin", "password": "admin", "ssid_prefix": "ASUS"},
    "ASUS ZenWiFi AX": {"username": "admin", "password": "admin", "ssid_prefix": "ASUS"},
    "ASUS RT-N66U": {"username": "admin", "password": "admin", "ssid_prefix": "ASUS"},
    "ASUS RT-N12": {"username": "admin", "password": "admin", "ssid_prefix": "ASUS"},
    "ASUS Blue Cave": {"username": "admin", "password": "admin", "ssid_prefix": "ASUS"},
    # ── Cisco ───────────────────────────────────────────────────────────
    "Cisco Linksys E1000": {"username": "admin", "password": "admin", "ssid_prefix": "Cisco"},
    "Cisco RV340W": {"username": "cisco", "password": "cisco", "ssid_prefix": "Cisco"},
    "Cisco RV260W": {"username": "cisco", "password": "cisco", "ssid_prefix": "Cisco"},
    "Cisco WRVS4400N": {"username": "admin", "password": "admin", "ssid_prefix": "Cisco"},
    "Cisco WAP371": {"username": "cisco", "password": "cisco", "ssid_prefix": "Cisco"},
    # ── Belkin ──────────────────────────────────────────────────────────
    "Belkin F9K1002": {"username": "", "password": "", "ssid_prefix": "belkin"},
    "Belkin F9K1102": {"username": "", "password": "", "ssid_prefix": "belkin"},
    "Belkin F9K1118": {"username": "", "password": "", "ssid_prefix": "belkin"},
    "Belkin F9K1123": {"username": "", "password": "", "ssid_prefix": "belkin"},
    # ── Huawei ──────────────────────────────────────────────────────────
    "Huawei HG532e": {"username": "admin", "password": "admin", "ssid_prefix": "HUAWEI"},
    "Huawei HG8245H": {"username": "telecomadmin", "password": "admintelecom", "ssid_prefix": "HUAWEI"},
    "Huawei WS5200": {"username": "admin", "password": "admin", "ssid_prefix": "HUAWEI"},
    "Huawei AX3 Pro": {"username": "admin", "password": "admin", "ssid_prefix": "HUAWEI"},
    "Huawei B525": {"username": "admin", "password": "admin", "ssid_prefix": "HUAWEI"},
    "Huawei E5186": {"username": "admin", "password": "admin", "ssid_prefix": "HUAWEI"},
    # ── Xiaomi ──────────────────────────────────────────────────────────
    "Xiaomi Mi Router 4A": {"username": "admin", "password": "admin", "ssid_prefix": "Xiaomi"},
    "Xiaomi Mi Router 4C": {"username": "admin", "password": "admin", "ssid_prefix": "Xiaomi"},
    "Xiaomi AX3600": {"username": "admin", "password": "admin", "ssid_prefix": "Xiaomi"},
    "Xiaomi AX9000": {"username": "admin", "password": "admin", "ssid_prefix": "Xiaomi"},
    "Xiaomi AX6000": {"username": "admin", "password": "admin", "ssid_prefix": "Xiaomi"},
    # ── MikroTik ────────────────────────────────────────────────────────
    "MikroTik hAP ac2": {"username": "admin", "password": "", "ssid_prefix": "MikroTik"},
    "MikroTik hAP ac3": {"username": "admin", "password": "", "ssid_prefix": "MikroTik"},
    "MikroTik RB4011": {"username": "admin", "password": "", "ssid_prefix": "MikroTik"},
    "MikroTik cAP ac": {"username": "admin", "password": "", "ssid_prefix": "MikroTik"},
    "MikroTik wAP ac": {"username": "admin", "password": "", "ssid_prefix": "MikroTik"},
    # ── Ubiquiti ────────────────────────────────────────────────────────
    "Ubiquiti EdgeRouter X": {"username": "ubnt", "password": "ubnt", "ssid_prefix": "Ubiquiti"},
    "Ubiquiti UniFi AP AC Pro": {"username": "ubnt", "password": "ubnt", "ssid_prefix": "Ubiquiti"},
    "Ubiquiti UniFi AP AC LR": {"username": "ubnt", "password": "ubnt", "ssid_prefix": "Ubiquiti"},
    "Ubiquiti UniFi 6 Lite": {"username": "ubnt", "password": "ubnt", "ssid_prefix": "Ubiquiti"},
    "Ubiquiti UniFi 6 Pro": {"username": "ubnt", "password": "ubnt", "ssid_prefix": "Ubiquiti"},
    "Ubiquiti AmpliFi HD": {"username": "ubnt", "password": "ubnt", "ssid_prefix": "AmpliFi"},
    # ── ZTE ─────────────────────────────────────────────────────────────
    "ZTE F660": {"username": "admin", "password": "admin", "ssid_prefix": "ZTE"},
    "ZTE F670L": {"username": "admin", "password": "admin", "ssid_prefix": "ZTE"},
    "ZTE H368N": {"username": "admin", "password": "admin", "ssid_prefix": "ZTE"},
    "ZTE MF286D": {"username": "admin", "password": "admin", "ssid_prefix": "ZTE"},
    # ── Tenda ───────────────────────────────────────────────────────────
    "Tenda AC10U": {"username": "admin", "password": "admin", "ssid_prefix": "Tenda"},
    "Tenda AC15": {"username": "admin", "password": "admin", "ssid_prefix": "Tenda"},
    "Tenda AC23": {"username": "admin", "password": "admin", "ssid_prefix": "Tenda"},
    "Tenda F3": {"username": "admin", "password": "admin", "ssid_prefix": "Tenda"},
    "Tenda N300": {"username": "admin", "password": "admin", "ssid_prefix": "Tenda"},
    # ── Ruckus ──────────────────────────────────────────────────────────
    "Ruckus R510": {"username": "super", "password": "sp-admin", "ssid_prefix": "Ruckus"},
    "Ruckus R610": {"username": "super", "password": "sp-admin", "ssid_prefix": "Ruckus"},
    "Ruckus R710": {"username": "super", "password": "sp-admin", "ssid_prefix": "Ruckus"},
    "Ruckus Unleashed": {"username": "super", "password": "sp-admin", "ssid_prefix": "Ruckus"},
    # ── Aruba / HPE ─────────────────────────────────────────────────────
    "Aruba AP-315": {"username": "admin", "password": "admin", "ssid_prefix": "Aruba"},
    "Aruba AP-515": {"username": "admin", "password": "admin", "ssid_prefix": "Aruba"},
    "Aruba AP-535": {"username": "admin", "password": "admin", "ssid_prefix": "Aruba"},
    "Aruba IAP-207": {"username": "admin", "password": "admin", "ssid_prefix": "Aruba"},
    # ── Fortinet ────────────────────────────────────────────────────────
    "Fortinet FortiGate 50E": {"username": "admin", "password": "", "ssid_prefix": "Fortinet"},
    "Fortinet FortiGate 60F": {"username": "admin", "password": "", "ssid_prefix": "Fortinet"},
    "Fortinet FortiAP 231F": {"username": "admin", "password": "", "ssid_prefix": "Fortinet"},
    # ── Juniper ─────────────────────────────────────────────────────────
    "Juniper SRX300": {"username": "root", "password": "", "ssid_prefix": "Juniper"},
    "Juniper Mist AP43": {"username": "admin", "password": "admin", "ssid_prefix": "Mist"},
    # ── Other common routers ────────────────────────────────────────────
    "Billion Bipac 8900AX": {"username": "admin", "password": "password", "ssid_prefix": "Billion"},
    "DrayTek Vigor 2860": {"username": "admin", "password": "admin", "ssid_prefix": "DrayTek"},
    "Synology RT2600ac": {"username": "admin", "password": "admin", "ssid_prefix": "Synology"},
    "Synology MR2200ac": {"username": "admin", "password": "admin", "ssid_prefix": "Synology"},
    "Amped Wireless RTA2600": {"username": "admin", "password": "admin", "ssid_prefix": "Amped"},
    "Arris SBG8300": {"username": "admin", "password": "password", "ssid_prefix": "ARRIS"},
    "Arris TG1682G": {"username": "admin", "password": "password", "ssid_prefix": "ARRIS"},
    "Motorola MG7550": {"username": "admin", "password": "motorola", "ssid_prefix": "Motorola"},
    "Motorola MG8702": {"username": "admin", "password": "motorola", "ssid_prefix": "Motorola"},
    "Sagemcom Fast 5260": {"username": "admin", "password": "admin", "ssid_prefix": "Sagemcom"},
    "Sagemcom Fast 5280": {"username": "admin", "password": "admin", "ssid_prefix": "Sagemcom"},
    "Technicolor TC8717T": {"username": "admin", "password": "admin", "ssid_prefix": "Technicolor"},
    "Ubee DDW365": {"username": "admin", "password": "admin", "ssid_prefix": "Ubee"},
    "Hitron CGNVM-3582": {"username": "admin", "password": "password", "ssid_prefix": "Hitron"},
}


def get_router_defaults(model: str) -> Optional[Dict[str, str]]:
    """Get default credentials for a router model.

    Args:
        model: Router model name (case-insensitive partial match).

    Returns:
        Dict with username, password, ssid_prefix or None if not found.
    """
    model_lower = model.lower()
    for key, value in ROUTER_DEFAULTS.items():
        if model_lower in key.lower():
            return dict(value)
    return None


def get_defaults_by_vendor(vendor: str) -> List[Dict[str, str]]:
    """Get all default credentials for a vendor.

    Args:
        vendor: Vendor name (case-insensitive partial match).

    Returns:
        List of dicts with model, username, password, ssid_prefix.
    """
    vendor_lower = vendor.lower()
    results = []
    for key, value in ROUTER_DEFAULTS.items():
        if vendor_lower in key.lower():
            results.append({"model": key, **value})
    return results


def get_defaults_by_ssid(ssid: str) -> List[Dict[str, str]]:
    """Find router defaults by SSID prefix.

    Args:
        ssid: SSID or SSID prefix to search for.

    Returns:
        List of matching router default entries.
    """
    ssid_lower = ssid.lower()
    results = []
    for key, value in ROUTER_DEFAULTS.items():
        if ssid_lower in value.get("ssid_prefix", "").lower():
            results.append({"model": key, **value})
    return results
