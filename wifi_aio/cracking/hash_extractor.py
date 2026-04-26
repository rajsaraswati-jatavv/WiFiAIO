"""Hash extractor for WPA handshakes.

Extracts authentication hashes from captured WPA/WPA2 handshakes for
use with hashcat, John the Ripper, and cowpatty.  Supports the modern
hashcat 22000 format as well as legacy formats.
"""

import os
import struct
import tempfile
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import HashExtractionError, PCAPError


# ── Format constants ───────────────────────────────────────────────────

FORMAT_HASHCAT_22000 = "22000"
FORMAT_HASHCAT_PMKID = "16800"
FORMAT_HASHCAT_EAPOL = "2500"
FORMAT_JOHN = "john"
FORMAT_COWPATTY = "cowpatty"


class HashExtractor:
    """Extract WPA/WPA2 authentication hashes from handshake data.

    Supports extraction to multiple output formats for compatibility
    with different cracking tools.
    """

    def __init__(self) -> None:
        self._extracted: List[Dict] = []

    # ── Public API ─────────────────────────────────────────────────────

    def extract(
        self,
        handshake: Dict,
        format: str = FORMAT_HASHCAT_22000,
    ) -> str:
        """Extract a hash string from handshake data.

        Parameters
        ----------
        handshake:
            Dict with keys: ``ssid``, ``ap_mac``, ``client_mac``,
            ``anonce``, ``snonce``, ``mic``, ``eapol_frame``.
        format:
            Output format: ``"22000"``, ``"16800"``, ``"2500"``,
            ``"john"``, or ``"cowpatty"``.

        Returns
        -------
        str
            The formatted hash string.
        """
        self._validate_handshake(handshake)

        if format == FORMAT_HASHCAT_22000:
            return self._format_22000(handshake)
        elif format == FORMAT_HASHCAT_PMKID:
            return self._format_16800(handshake)
        elif format == FORMAT_HASHCAT_EAPOL:
            return self._format_2500(handshake)
        elif format == FORMAT_JOHN:
            return self._format_john(handshake)
        elif format == FORMAT_COWPATTY:
            return self._format_cowpatty(handshake)
        else:
            raise HashExtractionError(f"Unsupported hash format: {format!r}")

    def extract_to_file(
        self,
        handshake: Dict,
        format: str = FORMAT_HASHCAT_22000,
        output_path: Optional[str] = None,
    ) -> str:
        """Extract a hash and write it to a file.

        Returns the path to the output file.
        """
        hash_string = self.extract(handshake, format)

        if output_path is None:
            fd, output_path = tempfile.mkstemp(
                suffix=f".{format}", prefix="wifiaio_hash_"
            )
            os.close(fd)

        with open(output_path, "w") as fh:
            fh.write(hash_string + "\n")

        return output_path

    def extract_from_pcap(
        self,
        pcap_path: str,
        format: str = FORMAT_HASHCAT_22000,
        target_bssid: Optional[str] = None,
    ) -> List[str]:
        """Extract all hashes from a PCAP file.

        Returns a list of hash strings.
        """
        from wifi_aio.capture.handshake_extractor import HandshakeExtractor

        extractor = HandshakeExtractor(pcap_path, target_bssid=target_bssid)
        result = extractor.extract()

        hashes = []
        for hs in result["handshakes"]:
            # Build handshake dict from extracted data
            messages = hs["messages"]
            bssid = hs["bssid"]

            # Need at least M1 and M2 for a crackable hash
            if "1" not in messages and "2" not in messages:
                # Try PMKID-based
                if "2" in messages and "3" in messages:
                    pass  # M2+M3 is also usable
                else:
                    continue

            handshake_dict = self._build_handshake_dict(hs)
            if handshake_dict:
                try:
                    h = self.extract(handshake_dict, format)
                    hashes.append(h)
                except HashExtractionError:
                    continue

        # Also extract PMKID hashes
        for pmkid_info in result["pmkids"]:
            handshake_dict = {
                "ssid": "",
                "ap_mac": pmkid_info.bssid,
                "client_mac": pmkid_info.client_mac,
                "pmkid": pmkid_info.pmkid.hex(),
                "anonce": pmkid_info.anonce.hex(),
            }
            try:
                h = self.extract(handshake_dict, FORMAT_HASHCAT_PMKID)
                hashes.append(h)
            except HashExtractionError:
                continue

        return hashes

    def list_formats(self) -> List[Dict]:
        """Return a list of supported hash formats."""
        return [
            {
                "id": FORMAT_HASHCAT_22000,
                "name": "hashcat 22000",
                "description": "Modern hashcat format (PMKID + EAPOL)",
            },
            {
                "id": FORMAT_HASHCAT_PMKID,
                "name": "hashcat 16800",
                "description": "Legacy PMKID format",
            },
            {
                "id": FORMAT_HASHCAT_EAPOL,
                "name": "hashcat 2500",
                "description": "Legacy EAPOL format (.hc22000 container)",
            },
            {
                "id": FORMAT_JOHN,
                "name": "John the Ripper",
                "description": "JtR WPAPSK format",
            },
            {
                "id": FORMAT_COWPATTY,
                "name": "cowpatty",
                "description": "Genpmk/cowpatty format",
            },
        ]

    # ── Format implementations ─────────────────────────────────────────

    def _format_22000(self, hs: Dict) -> str:
        """Format as hashcat 22000.

        Format: ``MAC_AP*MAC_CLIENT*PMKID*ANONCE*EAPOL_HASH*MIC*SSID_HEX``
        or for EAPOL-only:
        ``MAC_AP*MAC_CLIENT*...*ANONCE*EAPOL_HASH*MIC*SSID_HEX``
        """
        ap_mac = self._normalize_mac(hs["ap_mac"])
        client_mac = self._normalize_mac(hs["client_mac"])
        ssid_hex = hs.get("ssid", "").encode("utf-8").hex()

        # PMKID-based hash
        if "pmkid" in hs and hs["pmkid"]:
            pmkid = hs["pmkid"]
            if isinstance(pmkid, str) and ":" in pmkid:
                pmkid = pmkid.replace(":", "")
            return f"{ap_mac}*{client_mac}*{pmkid}*{ssid_hex}"

        # EAPOL-based hash
        anonce = hs.get("anonce", "")
        snonce = hs.get("snonce", "")
        mic = hs.get("mic", "")
        eapol_frame = hs.get("eapol_frame", "")

        if isinstance(anonce, str) and ":" in anonce:
            anonce = anonce.replace(":", "")
        if isinstance(snonce, str) and ":" in snonce:
            snonce = snonce.replace(":", "")
        if isinstance(mic, str) and ":" in mic:
            mic = mic.replace(":", "")

        # Clean hex strings
        anonce = self._clean_hex(anonce)
        snonce = self._clean_hex(snonce)
        mic = self._clean_hex(mic)

        eapol_hex = self._clean_hex(eapol_frame) if isinstance(eapol_frame, str) else eapol_frame.hex() if eapol_frame else ""

        # Compute EAPOL length for hashcat
        eapol_len = len(eapol_hex) // 2
        keyver = 1  # HMAC-SHA1 (WPA2)

        # hashcat 22000 EAPOL format:
        # MAC_AP*MAC_CLIENT*keyver*MIC*nonce_ap*nonce_client*eapol_len*eapol*SSID
        return (
            f"{ap_mac}*{client_mac}*{keyver}*{mic}*"
            f"{anonce}*{snonce}*{eapol_len}*{eapol_hex}*{ssid_hex}"
        )

    def _format_16800(self, hs: Dict) -> str:
        """Format as hashcat 16800 (PMKID only)."""
        if "pmkid" not in hs or not hs["pmkid"]:
            raise HashExtractionError("PMKID not available for 16800 format")

        ap_mac = self._normalize_mac(hs["ap_mac"])
        client_mac = self._normalize_mac(hs["client_mac"])
        pmkid = self._clean_hex(hs["pmkid"])
        ssid_hex = hs.get("ssid", "").encode("utf-8").hex()

        return f"{ap_mac}:{client_mac}:{pmkid}:{ssid_hex}"

    def _format_2500(self, hs: Dict) -> str:
        """Format as hashcat 2500 (legacy EAPOL)."""
        # 2500 uses a binary format, we return the text representation
        ap_mac = self._normalize_mac(hs["ap_mac"])
        client_mac = self._normalize_mac(hs["client_mac"])
        anonce = self._clean_hex(hs.get("anonce", ""))
        snonce = self._clean_hex(hs.get("snonce", ""))
        mic = self._clean_hex(hs.get("mic", ""))
        ssid_hex = hs.get("ssid", "").encode("utf-8").hex()

        return f"{ap_mac}:{client_mac}:{anonce}:{snonce}:{mic}:{ssid_hex}"

    def _format_john(self, hs: Dict) -> str:
        """Format as John the Ripper WPAPSK."""
        ssid = hs.get("ssid", "")
        ap_mac = self._normalize_mac(hs["ap_mac"])
        client_mac = self._normalize_mac(hs["client_mac"])

        # JtR format: $WPAPSK$SSID#hashdata
        # For PMKID
        if "pmkid" in hs and hs["pmkid"]:
            pmkid = self._clean_hex(hs["pmkid"])
            return f"$WPAPSK${ssid}#{pmkid}"

        # For EAPOL
        anonce = self._clean_hex(hs.get("anonce", ""))
        snonce = self._clean_hex(hs.get("snonce", ""))
        mic = self._clean_hex(hs.get("mic", ""))

        return f"$WPAPSK${ssid}#{ap_mac}{client_mac}{anonce}{snonce}{mic}"

    def _format_cowpatty(self, hs: Dict) -> str:
        """Format for cowpatty/genpmk.

        Cowpatty uses a binary format; we return the textual representation
        that can be converted by HashConverter.
        """
        ssid = hs.get("ssid", "")
        ap_mac = self._normalize_mac(hs["ap_mac"])
        client_mac = self._normalize_mac(hs["client_mac"])
        anonce = self._clean_hex(hs.get("anonce", ""))
        snonce = self._clean_hex(hs.get("snonce", ""))
        mic = self._clean_hex(hs.get("mic", ""))

        return f"cowpatty:{ssid}:{ap_mac}:{client_mac}:{anonce}:{snonce}:{mic}"

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _validate_handshake(hs: Dict) -> None:
        """Validate that the handshake dict contains required fields."""
        required = ["ap_mac", "client_mac"]
        for field in required:
            if field not in hs:
                raise HashExtractionError(
                    f"Missing required field: {field!r}"
                )

        # Must have either PMKID or EAPOL data
        has_pmkid = "pmkid" in hs and hs["pmkid"]
        has_eapol = "mic" in hs and hs["mic"]

        if not has_pmkid and not has_eapol:
            raise HashExtractionError(
                "Handshake must contain either 'pmkid' or 'mic' (EAPOL data)"
            )

    @staticmethod
    def _normalize_mac(mac: str) -> str:
        """Normalize a MAC address to hex without separators."""
        if isinstance(mac, bytes):
            return mac.hex()
        return mac.replace(":", "").replace("-", "").replace(".", "").lower()

    @staticmethod
    def _clean_hex(s: str) -> str:
        """Clean a hex string by removing separators and whitespace."""
        if isinstance(s, bytes):
            return s.hex()
        return s.replace(":", "").replace("-", "").replace(" ", "").replace("0x", "").lower()

    def _build_handshake_dict(self, hs_data: Dict) -> Optional[Dict]:
        """Build a handshake dict from HandshakeExtractor output."""
        messages = hs_data.get("messages", {})
        bssid = hs_data.get("bssid", "")

        # Try to get M1 (ANonce) and M2 (SNonce + MIC)
        anonce = ""
        snonce = ""
        mic = ""
        eapol_frame = ""

        if "1" in messages:
            anonce = messages["1"].get("nonce", "")
        if "2" in messages:
            snonce = messages["2"].get("nonce", "")
            mic = messages["2"].get("mic", "")
        elif "4" in messages:
            mic = messages["4"].get("mic", "")

        if not mic:
            return None

        return {
            "ssid": "",  # SSID would need to come from beacon analysis
            "ap_mac": bssid,
            "client_mac": "",
            "anonce": anonce,
            "snonce": snonce,
            "mic": mic,
            "eapol_frame": eapol_frame,
        }
