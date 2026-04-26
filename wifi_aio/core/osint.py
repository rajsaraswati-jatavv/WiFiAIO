"""Open Source Intelligence (OSINT) for WiFi networks.

Provides WiGLE database search, SSID intelligence gathering,
ISP lookup, and router fingerprinting capabilities.
"""

import json
import logging
import re
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

import requests

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiTimeoutError,
)

logger = logging.getLogger(__name__)

# OUI database URL (IEEE)
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

# Router fingerprint database (built-in common signatures)
ROUTER_SIGNATURES = {
    "AA:BB:CC": {"vendor": "Cisco", "default_ssids": ["Cisco", "Linksys"], "default_creds": [("admin", "admin")]},
    "00:14:BF": {"vendor": "Netgear", "default_ssids": ["NETGEAR", "NETGEAR-5G"], "default_creds": [("admin", "password")]},
    "00:1A:2B": {"vendor": "TP-Link", "default_ssids": ["TP-LINK", "TP-LINK_5G"], "default_creds": [("admin", "admin")]},
    "00:26:5E": {"vendor": "ASUS", "default_ssids": ["ASUS", "ASUS_5G"], "default_creds": [("admin", "admin")]},
    "B0:4E:26": {"vendor": "D-Link", "default_ssids": ["D-Link", "D-Link_5G"], "default_creds": [("admin", "")]},
    "DC:A6:32": {"vendor": "Raspberry Pi", "default_ssids": ["raspberrypi"], "default_creds": [("pi", "raspberry")]},
    "A0:EC:F9": {"vendor": "Huawei", "default_ssids": ["HUAWEI", "HUAWEI-5G"], "default_creds": [("admin", "admin")]},
    "78:8C:B5": {"vendor": "ZTE", "default_ssids": ["ZTE", "ZTE-5G"], "default_creds": [("admin", "admin")]},
    "F8:1E:DF": {"vendor": "Ubiquiti", "default_ssids": ["Ubiquiti", "UniFi"], "default_creds": [("ubnt", "ubnt")]},
    "24:5A:4C": {"vendor": "MikroTik", "default_ssids": ["MikroTik"], "default_creds": [("admin", "")]},
    "C0:56:E3": {"vendor": "Arris", "default_ssids": ["ARRIS", "ARRIS-5G"], "default_creds": [("admin", "password")]},
    "E0:46:9A": {"vendor": "Technicolor", "default_ssids": ["Technicolor"], "default_creds": [("admin", "admin")]},
}

# ISP lookup services
ISP_LOOKUP_SERVICES = [
    "https://ipinfo.io/{ip}/json",
    "https://ip-api.com/json/{ip}",
]


class Osint:
    """Open Source Intelligence for WiFi network investigation."""

    def __init__(
        self,
        wigle_api_key: Optional[str] = None,
    ):
        """Initialize Osint module.

        Args:
            wigle_api_key: WiGLE API key for database searches.
        """
        self.wigle_api_key = wigle_api_key
        self._oui_cache: Dict[str, str] = {}
        self._ssid_intel_cache: Dict[str, Dict] = {}

    # ------------------------------------------------------------------
    # WiGLE Search
    # ------------------------------------------------------------------

    def wigle_search(
        self,
        ssid: Optional[str] = None,
        bssid: Optional[str] = None,
        lat_range: Optional[Tuple[float, float]] = None,
        lon_range: Optional[Tuple[float, float]] = None,
        encryption: Optional[str] = None,
        results_per_page: int = 100,
    ) -> List[Dict]:
        """Search the WiGLE database for wireless networks.

        Args:
            ssid: SSID to search for.
            bssid: BSSID/MAC to search for.
            lat_range: Latitude range (min, max).
            lon_range: Longitude range (min, max).
            encryption: Encryption type filter.
            results_per_page: Max results per page.

        Returns:
            List of network result dicts.
        """
        if not self.wigle_api_key:
            raise WiFiConnectionError("WiGLE API key required (osint.wigle_api_key)")

        params: Dict[str, str] = {}
        if ssid:
            params["ssid"] = ssid
        if bssid:
            params["netid"] = bssid.replace(":", "")
        if lat_range:
            params["latrange1"] = str(lat_range[0])
            params["latrange2"] = str(lat_range[1])
        if lon_range:
            params["lonrange1"] = str(lon_range[0])
            params["lonrange2"] = str(lon_range[1])
        if encryption:
            params["encryption"] = encryption

        headers = {"Authorization": f"Bearer {self.wigle_api_key}"}

        try:
            resp = requests.get(
                "https://api.wigle.net/api/v2/network/search",
                params=params,
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.Timeout:
            raise WiFiTimeoutError("WiGLE search timed out")
        except requests.RequestException as exc:
            raise WiFiConnectionError(f"WiGLE search error: {exc}")

        results = data.get("results", [])
        total = data.get("totalResults", 0)
        logger.info("WiGLE search: %d/%d results", len(results), total)
        return results

    def wigle_stats(self) -> Dict:
        """Get WiGLE account statistics.

        Returns:
            Dict with API usage stats.
        """
        if not self.wigle_api_key:
            raise WiFiConnectionError("WiGLE API key required")

        headers = {"Authorization": f"Bearer {self.wigle_api_key}"}
        try:
            resp = requests.get(
                "https://api.wigle.net/api/v2/network/stats",
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.Timeout:
            raise WiFiTimeoutError("WiGLE stats request timed out")
        except requests.RequestException as exc:
            raise WiFiConnectionError(f"WiGLE stats error: {exc}")

    # ------------------------------------------------------------------
    # SSID Intelligence
    # ------------------------------------------------------------------

    def ssid_intelligence(self, ssid: str) -> Dict:
        """Gather intelligence on an SSID.

        Analyzes SSID naming patterns, default credentials, and
        searches for the SSID in public databases.

        Args:
            ssid: The SSID to analyze.

        Returns:
            Dict with intelligence findings.
        """
        if ssid in self._ssid_intel_cache:
            return self._ssid_intel_cache[ssid]

        intel: Dict = {
            "ssid": ssid,
            "is_default": False,
            "likely_vendor": None,
            "naming_pattern": None,
            "risk_level": "low",
            "findings": [],
            "wigle_results": None,
        }

        # Check if SSID matches a known default pattern
        for oui, sig in ROUTER_SIGNATURES.items():
            for default_ssid in sig.get("default_ssids", []):
                if ssid == default_ssid:
                    intel["is_default"] = True
                    intel["likely_vendor"] = sig["vendor"]
                    intel["findings"].append(
                        f"Default SSID for {sig['vendor']} - likely using default configuration"
                    )
                    if sig.get("default_creds"):
                        creds_str = ", ".join(
                            f"{u}/{p}" for u, p in sig["default_creds"]
                        )
                        intel["findings"].append(
                            f"Known default credentials: {creds_str}"
                        )
                    intel["risk_level"] = "high"
                    break

        # Detect naming patterns
        if re.match(r".*[_-]5[Gg]$", ssid):
            intel["naming_pattern"] = "5G_band_suffix"
            intel["findings"].append("5GHz band indicator in SSID")
        elif re.match(r".*[_-]2\.4[Gg]$", ssid):
            intel["naming_pattern"] = "2.4G_band_suffix"
            intel["findings"].append("2.4GHz band indicator in SSID")
        elif re.match(r"^[A-Fa-f0-9]{6,}$", ssid):
            intel["naming_pattern"] = "hex_mac_suffix"
            intel["is_default"] = True
            intel["findings"].append("SSID appears to be hex MAC suffix (default config)")
            intel["risk_level"] = "medium"
        elif re.match(r".*_Guest$", ssid):
            intel["naming_pattern"] = "guest_network"
            intel["findings"].append("Guest network detected")
        elif re.match(r".*_EXT$", ssid, re.IGNORECASE):
            intel["naming_pattern"] = "range_extender"
            intel["findings"].append("WiFi range extender network")
        elif re.match(r"^[A-Z][a-z]+\d*$", ssid):
            intel["naming_pattern"] = "personal_name"
            intel["findings"].append("SSID appears to use a personal name pattern")

        # Check for common weak SSIDs
        weak_ssids = [
            "FREE_WIFI", "FreeWifi", "wifi", "Wireless", "WLAN",
            "Internet", "Net", "HOME", "default",
        ]
        if ssid in weak_ssids:
            intel["risk_level"] = "high"
            intel["findings"].append("Common/generic SSID - potential honeypot or misconfigured AP")

        # Search WiGLE if key available
        if self.wigle_api_key:
            try:
                results = self.wigle_search(ssid=ssid)
                if results:
                    intel["wigle_results"] = {
                        "count": len(results),
                        "first_seen": results[0].get("firsttime", "unknown") if results else None,
                        "last_seen": results[0].get("lasttime", "unknown") if results else None,
                        "encryption_types": list(set(
                            r.get("encryption", "unknown") for r in results[:20]
                        )),
                    }
                    intel["findings"].append(f"Found in WiGLE database: {len(results)} entries")
            except (WiFiConnectionError, WiFiTimeoutError):
                intel["findings"].append("WiGLE lookup unavailable")

        self._ssid_intel_cache[ssid] = intel
        return intel

    # ------------------------------------------------------------------
    # ISP Lookup
    # ------------------------------------------------------------------

    def isp_lookup(self, ip_address: Optional[str] = None) -> Dict:
        """Look up ISP information for an IP address.

        Args:
            ip_address: IP address to look up. If None, uses current public IP.

        Returns:
            Dict with ISP, organization, location info.
        """
        for service_url in ISP_LOOKUP_SERVICES:
            url = service_url.format(ip=ip_address or "")
            try:
                resp = requests.get(url, timeout=15)
                resp.raise_for_status()
                data = resp.json()

                # Normalize response from different services
                result = self._normalize_isp_response(data)
                return result
            except requests.Timeout:
                continue
            except requests.RequestException:
                continue

        raise WiFiConnectionError("All ISP lookup services failed")

    @staticmethod
    def _normalize_isp_response(data: Dict) -> Dict:
        """Normalize ISP lookup response from different APIs."""
        result = {}

        # ipinfo.io format
        if "org" in data:
            result["isp"] = data.get("org", "")
            result["country"] = data.get("country", "")
            result["region"] = data.get("region", "")
            result["city"] = data.get("city", "")
            result["ip"] = data.get("ip", "")
            loc = data.get("loc", "").split(",")
            result["latitude"] = float(loc[0]) if len(loc) >= 1 else 0.0
            result["longitude"] = float(loc[1]) if len(loc) >= 2 else 0.0
            result["hostname"] = data.get("hostname", "")
            result["asn"] = data.get("asn", "")

        # ip-api.com format
        elif "isp" in data:
            result["isp"] = data.get("isp", "")
            result["country"] = data.get("country", "")
            result["region"] = data.get("regionName", "")
            result["city"] = data.get("city", "")
            result["ip"] = data.get("query", "")
            result["latitude"] = data.get("lat", 0.0)
            result["longitude"] = data.get("lon", 0.0)
            result["hostname"] = data.get("reverse", "")
            result["asn"] = data.get("as", "")
            result["organization"] = data.get("org", "")
            result["timezone"] = data.get("timezone", "")
        else:
            result = data

        return result

    def get_public_ip(self) -> str:
        """Get the current public IP address.

        Returns:
            Public IP address string.
        """
        try:
            resp = requests.get("https://api.ipify.org?format=json", timeout=10)
            resp.raise_for_status()
            return resp.json().get("ip", "")
        except requests.RequestException:
            try:
                resp = requests.get("https://ifconfig.me/ip", timeout=10)
                resp.raise_for_status()
                return resp.text.strip()
            except requests.RequestException:
                raise WiFiConnectionError("Could not determine public IP")

    def reverse_dns(self, ip_address: str) -> str:
        """Perform reverse DNS lookup.

        Args:
            ip_address: IP to look up.

        Returns:
            Hostname or empty string.
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""

    # ------------------------------------------------------------------
    # Router Fingerprinting
    # ------------------------------------------------------------------

    def fingerprint_router(
        self,
        bssid: str,
        ssid: Optional[str] = None,
        encryption: Optional[str] = None,
        channel: Optional[int] = None,
    ) -> Dict:
        """Fingerprint a router based on available information.

        Uses OUI lookup, SSID patterns, and known signatures to identify
        the router make/model and assess security posture.

        Args:
            bssid: Router BSSID (MAC address).
            ssid: Router SSID.
            encryption: Encryption type.
            channel: Operating channel.

        Returns:
            Dict with fingerprint findings.
        """
        fingerprint: Dict = {
            "bssid": bssid,
            "ssid": ssid,
            "vendor": "unknown",
            "model": "unknown",
            "default_credentials": [],
            "known_vulnerabilities": [],
            "risk_assessment": "low",
            "findings": [],
        }

        # OUI lookup (first 3 octets)
        oui = ":".join(bssid.split(":")[:3]).upper()
        vendor = self._lookup_oui(oui)
        if vendor:
            fingerprint["vendor"] = vendor
            fingerprint["findings"].append(f"OUI vendor: {vendor}")

        # Check against known signatures
        if oui in ROUTER_SIGNATURES:
            sig = ROUTER_SIGNATURES[oui]
            fingerprint["vendor"] = sig["vendor"]
            fingerprint["default_credentials"] = sig.get("default_creds", [])

            # Check if SSID matches default
            if ssid and ssid in sig.get("default_ssids", []):
                fingerprint["findings"].append(
                    f"Default SSID detected - {ssid} is default for {sig['vendor']}"
                )
                fingerprint["risk_assessment"] = "high"

        # SSID-based fingerprinting
        if ssid:
            ssid_lower = ssid.lower()
            if "linksys" in ssid_lower:
                fingerprint["vendor"] = "Linksys (Cisco)"
                fingerprint["default_credentials"] = [("admin", "admin")]
            elif "netgear" in ssid_lower:
                fingerprint["vendor"] = "Netgear"
                fingerprint["default_credentials"] = [("admin", "password")]
            elif "dlink" in ssid_lower or "d-link" in ssid_lower:
                fingerprint["vendor"] = "D-Link"
                fingerprint["default_credentials"] = [("admin", "")]
            elif "asus" in ssid_lower:
                fingerprint["vendor"] = "ASUS"
                fingerprint["default_credentials"] = [("admin", "admin")]
            elif "tplink" in ssid_lower or "tp-link" in ssid_lower:
                fingerprint["vendor"] = "TP-Link"
                fingerprint["default_credentials"] = [("admin", "admin")]
            elif "huawei" in ssid_lower:
                fingerprint["vendor"] = "Huawei"
                fingerprint["default_credentials"] = [("admin", "admin")]
            elif "xfinity" in ssid_lower or "xfinit" in ssid_lower:
                fingerprint["vendor"] = "Comcast/Xfinity"
                fingerprint["findings"].append("ISP-provided router")
            elif "attwifi" in ssid_lower or "att-" in ssid_lower:
                fingerprint["vendor"] = "AT&T"
                fingerprint["findings"].append("ISP-provided router")
            elif "fios" in ssid_lower:
                fingerprint["vendor"] = "Verizon FiOS"
                fingerprint["findings"].append("ISP-provided router")

        # Encryption analysis
        if encryption:
            enc_lower = encryption.lower()
            if enc_lower in ("wep", "wpa"):
                fingerprint["findings"].append(f"Weak encryption detected: {encryption}")
                fingerprint["risk_assessment"] = "high"
            elif enc_lower == "wpa2":
                fingerprint["findings"].append("WPA2 encryption - acceptable")
            elif enc_lower == "wpa3":
                fingerprint["findings"].append("WPA3 encryption - strong")
            elif "open" in enc_lower or enc_lower == "none":
                fingerprint["findings"].append("Open network - no encryption")
                fingerprint["risk_assessment"] = "critical"

        # Channel-based hints
        if channel:
            if channel > 14:
                fingerprint["findings"].append(f"5GHz operation on channel {channel}")
            else:
                fingerprint["findings"].append(f"2.4GHz operation on channel {channel}")
            # Check for overlapping channels
            if 1 <= channel <= 13 and channel not in (1, 6, 11):
                fingerprint["findings"].append(
                    f"Non-standard channel {channel} may cause overlap"
                )

        # Known vulnerabilities
        fingerprint["known_vulnerabilities"] = self._get_known_vulns(fingerprint["vendor"])

        if fingerprint["default_credentials"]:
            fingerprint["findings"].append(
                "Default credentials may be in use"
            )
            fingerprint["risk_assessment"] = "high"

        return fingerprint

    def _lookup_oui(self, oui: str) -> str:
        """Look up vendor from OUI (first 3 octets of MAC).

        Args:
            oui: OUI string like 'AA:BB:CC'.

        Returns:
            Vendor name or 'unknown'.
        """
        if oui in self._oui_cache:
            return self._oui_cache[oui]

        # Check built-in signatures first
        if oui in ROUTER_SIGNATURES:
            vendor = ROUTER_SIGNATURES[oui]["vendor"]
            self._oui_cache[oui] = vendor
            return vendor

        # Try IEEE online lookup
        try:
            resp = requests.get(OUI_URL, timeout=30)
            if resp.status_code == 200:
                oui_hex = oui.replace(":", "")
                for line in resp.text.splitlines():
                    if oui_hex in line.upper() and "(hex)" in line:
                        vendor = line.split("(hex)")[-1].strip()
                        self._oui_cache[oui] = vendor
                        return vendor
        except requests.RequestException:
            pass

        # Try MAC vendors API
        try:
            resp = requests.get(
                f"https://api.macvendors.com/{oui}",
                timeout=10,
            )
            if resp.status_code == 200:
                vendor = resp.text.strip()
                self._oui_cache[oui] = vendor
                return vendor
        except requests.RequestException:
            pass

        self._oui_cache[oui] = "unknown"
        return "unknown"

    @staticmethod
    def _get_known_vulns(vendor: str) -> List[str]:
        """Get known vulnerabilities for a router vendor."""
        vulns = {
            "Netgear": [
                "CVE-2017-5521: Authentication bypass on some models",
                "CVE-2019-20631: Pre-authentication buffer overflow",
                "CVE-2020-27868: Command injection vulnerability",
            ],
            "D-Link": [
                "CVE-2019-16920: Unauthenticated RCE on multiple models",
                "CVE-2020-25078: Information disclosure via device name",
                "CVE-2021-29379: Command injection in management interface",
            ],
            "Linksys (Cisco)": [
                "CVE-2014-6241: Authentication bypass",
                "CVE-2020-3330: Arbitrary code execution",
            ],
            "TP-Link": [
                "CVE-2021-41653: Authentication bypass on some models",
                "CVE-2022-30024: Buffer overflow in httpd",
            ],
            "ASUS": [
                "CVE-2018-17064: Authentication bypass",
                "CVE-2021-32030: Command injection",
            ],
            "Huawei": [
                "CVE-2017-17309: Buffer overflow in some models",
                "CVE-2021-37226: Authentication bypass",
            ],
            "Ubiquiti": [
                "CVE-2021-44228: Log4j vulnerability in some management software",
            ],
        }
        return vulns.get(vendor, [])

    # ------------------------------------------------------------------
    # Batch operations
    # ------------------------------------------------------------------

    def batch_ssid_intel(self, ssids: List[str]) -> Dict[str, Dict]:
        """Gather intelligence on multiple SSIDs.

        Args:
            ssids: List of SSIDs to analyze.

        Returns:
            Dict mapping SSID -> intelligence dict.
        """
        results = {}
        for ssid in ssids:
            try:
                results[ssid] = self.ssid_intelligence(ssid)
            except Exception as exc:
                logger.warning("SSID intel failed for %s: %s", ssid, exc)
                results[ssid] = {"error": str(exc)}
        return results

    def batch_isp_lookup(self, ip_addresses: List[str]) -> Dict[str, Dict]:
        """Look up ISP information for multiple IP addresses.

        Args:
            ip_addresses: List of IPs to look up.

        Returns:
            Dict mapping IP -> ISP info dict.
        """
        results = {}
        for ip in ip_addresses:
            try:
                results[ip] = self.isp_lookup(ip)
                time.sleep(0.5)  # Rate limiting
            except Exception as exc:
                logger.warning("ISP lookup failed for %s: %s", ip, exc)
                results[ip] = {"error": str(exc)}
        return results

    def load_oui_database(self, filepath: str) -> int:
        """Load an OUI database from a local file.

        Args:
            filepath: Path to IEEE OUI text file.

        Returns:
            Number of entries loaded.
        """
        count = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if "(hex)" in line:
                        parts = line.split("(hex)")
                        if len(parts) >= 2:
                            oui = parts[0].strip().replace("-", ":").upper()
                            vendor = parts[1].strip()
                            self._oui_cache[oui] = vendor
                            count += 1
        except OSError as exc:
            logger.error("Failed to load OUI database: %s", exc)
        logger.info("Loaded %d OUI entries", count)
        return count
