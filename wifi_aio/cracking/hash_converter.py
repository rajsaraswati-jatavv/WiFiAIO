"""Hash format converter for WPA handshake hashes.

Converts between different hash formats used by cracking tools:
hashcat (22000, 16800, 2500), John the Ripper, and cowpatty.
"""

import re
import struct
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import HashExtractionError


class HashConverter:
    """Convert WPA handshake hashes between cracking tool formats.

    Supported formats:
    - hashcat 22000 (modern combined PMKID+EAPOL)
    - hashcat 16800 (PMKID only)
    - hashcat 2500 (legacy EAPOL binary)
    - John the Ripper WPAPSK
    - cowpatty text
    """

    def __init__(self) -> None:
        pass

    # ── Public API ─────────────────────────────────────────────────────

    def convert(
        self,
        hash_string: str,
        source_format: str,
        target_format: str,
    ) -> str:
        """Convert a hash from one format to another.

        Parameters
        ----------
        hash_string:
            The hash string to convert.
        source_format:
            Current format: ``"22000"``, ``"16800"``, ``"2500"``,
            ``"john"``, or ``"cowpatty"``.
        target_format:
            Desired output format.

        Returns
        -------
        str
            The converted hash string.
        """
        if source_format == target_format:
            return hash_string

        # Parse source to intermediate representation
        parsed = self._parse(hash_string, source_format)
        if parsed is None:
            raise HashExtractionError(
                f"Failed to parse hash as {source_format} format"
            )

        # Render to target format
        return self._render(parsed, target_format)

    def convert_file(
        self,
        input_path: str,
        output_path: str,
        source_format: str,
        target_format: str,
    ) -> int:
        """Convert all hashes in a file.

        Returns the number of hashes converted.
        """
        count = 0
        with open(input_path, "r", encoding="utf-8", errors="replace") as fin:
            with open(output_path, "w") as fout:
                for line in fin:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        converted = self.convert(line, source_format, target_format)
                        fout.write(converted + "\n")
                        count += 1
                    except HashExtractionError:
                        continue
        return count

    def detect_format(self, hash_string: str) -> Optional[str]:
        """Auto-detect the format of a hash string.

        Returns the format identifier or ``None`` if unrecognized.
        """
        hash_string = hash_string.strip()

        # hashcat 22000 (uses * as separator)
        if re.match(r"^[0-9a-f]{12}\*[0-9a-f]{12}\*", hash_string, re.I):
            # Check for PMKID-only (3 fields) vs EAPOL (9 fields)
            parts = hash_string.split("*")
            if len(parts) == 4:
                return "22000"  # PMKID variant
            elif len(parts) >= 9:
                return "22000"  # EAPOL variant
            return "22000"

        # hashcat 16800 (uses : as separator, 4 fields)
        if re.match(r"^[0-9a-f]{12}:[0-9a-f]{12}:[0-9a-f]{32}:[0-9a-f]*$", hash_string, re.I):
            return "16800"

        # hashcat 2500 (uses : as separator, 6 fields)
        if re.match(r"^[0-9a-f]{12}:[0-9a-f]{12}:[0-9a-f]{64}:[0-9a-f]{64}:[0-9a-f]{32}:[0-9a-f]*$", hash_string, re.I):
            return "2500"

        # John the Ripper
        if hash_string.startswith("$WPAPSK$"):
            return "john"

        # cowpatty text
        if hash_string.startswith("cowpatty:"):
            return "cowpatty"

        return None

    def batch_convert(
        self,
        hashes: List[str],
        source_format: str,
        target_format: str,
    ) -> List[Tuple[str, str]]:
        """Convert multiple hashes.

        Returns list of ``(original, converted)`` tuples.  Failed
        conversions have an empty string as the converted value.
        """
        results = []
        for h in hashes:
            try:
                converted = self.convert(h, source_format, target_format)
                results.append((h, converted))
            except HashExtractionError:
                results.append((h, ""))
        return results

    # ── Parsing ────────────────────────────────────────────────────────

    def _parse(self, hash_string: str, fmt: str) -> Optional[Dict]:
        """Parse a hash string into a normalized intermediate dict."""
        try:
            if fmt == "22000":
                return self._parse_22000(hash_string)
            elif fmt == "16800":
                return self._parse_16800(hash_string)
            elif fmt == "2500":
                return self._parse_2500(hash_string)
            elif fmt == "john":
                return self._parse_john(hash_string)
            elif fmt == "cowpatty":
                return self._parse_cowpatty(hash_string)
        except (ValueError, IndexError):
            return None
        return None

    def _parse_22000(self, h: str) -> Dict:
        """Parse hashcat 22000 format."""
        parts = h.strip().split("*")

        if len(parts) == 4:
            # PMKID variant: MAC_AP*MAC_CLIENT*PMKID*SSID_HEX
            return {
                "ap_mac": parts[0],
                "client_mac": parts[1],
                "pmkid": parts[2],
                "ssid_hex": parts[3],
                "type": "pmkid",
            }
        elif len(parts) >= 9:
            # EAPOL variant: MAC_AP*MAC_CLIENT*keyver*MIC*ANONCE*SNONCE*eapol_len*eapol*SSID_HEX
            return {
                "ap_mac": parts[0],
                "client_mac": parts[1],
                "key_version": int(parts[2]),
                "mic": parts[3],
                "anonce": parts[4],
                "snonce": parts[5],
                "eapol_length": int(parts[6]),
                "eapol": parts[7],
                "ssid_hex": parts[8],
                "type": "eapol",
            }
        else:
            raise ValueError(f"Invalid 22000 hash: expected 4 or 9+ fields, got {len(parts)}")

    def _parse_16800(self, h: str) -> Dict:
        """Parse hashcat 16800 format: MAC_AP:MAC_CLIENT:PMKID:SSID_HEX"""
        parts = h.strip().split(":")
        if len(parts) != 4:
            raise ValueError(f"Invalid 16800 hash: expected 4 fields, got {len(parts)}")

        return {
            "ap_mac": parts[0],
            "client_mac": parts[1],
            "pmkid": parts[2],
            "ssid_hex": parts[3],
            "type": "pmkid",
        }

    def _parse_2500(self, h: str) -> Dict:
        """Parse hashcat 2500 format: MAC_AP:MAC_CLIENT:ANONCE:SNONCE:MIC:SSID_HEX"""
        parts = h.strip().split(":")
        if len(parts) != 6:
            raise ValueError(f"Invalid 2500 hash: expected 6 fields, got {len(parts)}")

        return {
            "ap_mac": parts[0],
            "client_mac": parts[1],
            "anonce": parts[2],
            "snonce": parts[3],
            "mic": parts[4],
            "ssid_hex": parts[5],
            "type": "eapol",
        }

    def _parse_john(self, h: str) -> Dict:
        """Parse John the Ripper WPAPSK format."""
        if not h.startswith("$WPAPSK$"):
            raise ValueError("Not a JtR WPAPSK hash")

        rest = h[len("$WPAPSK$"):]
        # Format: $WPAPSK$SSID#hashdata
        if "#" not in rest:
            raise ValueError("Missing # separator in JtR hash")

        ssid, hashdata = rest.split("#", 1)

        # Try to parse hashdata as PMKID (32 hex chars)
        if len(hashdata) == 32 and all(c in "0123456789abcdefABCDEF" for c in hashdata):
            return {
                "ssid": ssid,
                "pmkid": hashdata.lower(),
                "ssid_hex": ssid.encode("utf-8").hex(),
                "type": "pmkid",
            }

        # EAPOL hashdata: MACAP(12)MACCLIENT(12)ANONCE(64)SNONCE(64)MIC(32)
        if len(hashdata) >= 172:
            ap_mac = hashdata[0:12]
            client_mac = hashdata[12:24]
            anonce = hashdata[24:88]
            snonce = hashdata[88:152]
            mic = hashdata[152:184]

            return {
                "ssid": ssid,
                "ap_mac": ap_mac,
                "client_mac": client_mac,
                "anonce": anonce,
                "snonce": snonce,
                "mic": mic,
                "ssid_hex": ssid.encode("utf-8").hex(),
                "type": "eapol",
            }

        raise ValueError("Cannot parse JtR hashdata")

    def _parse_cowpatty(self, h: str) -> Dict:
        """Parse cowpatty text format: cowpatty:SSID:MAC_AP:MAC_CLIENT:ANONCE:SNONCE:MIC"""
        if not h.startswith("cowpatty:"):
            raise ValueError("Not a cowpatty hash")

        parts = h[len("cowpatty:"):].split(":")
        if len(parts) != 6:
            raise ValueError(f"Invalid cowpatty hash: expected 6 fields, got {len(parts)}")

        return {
            "ssid": parts[0],
            "ap_mac": parts[1],
            "client_mac": parts[2],
            "anonce": parts[3],
            "snonce": parts[4],
            "mic": parts[5],
            "ssid_hex": parts[0].encode("utf-8").hex(),
            "type": "eapol",
        }

    # ── Rendering ──────────────────────────────────────────────────────

    def _render(self, parsed: Dict, fmt: str) -> str:
        """Render a parsed hash dict to the target format."""
        if fmt == "22000":
            return self._render_22000(parsed)
        elif fmt == "16800":
            return self._render_16800(parsed)
        elif fmt == "2500":
            return self._render_2500(parsed)
        elif fmt == "john":
            return self._render_john(parsed)
        elif fmt == "cowpatty":
            return self._render_cowpatty(parsed)
        else:
            raise HashExtractionError(f"Unsupported target format: {fmt!r}")

    def _render_22000(self, p: Dict) -> str:
        """Render as hashcat 22000."""
        if p["type"] == "pmkid":
            ssid_hex = p.get("ssid_hex", "")
            pmkid = p.get("pmkid", "")
            return f"{p['ap_mac']}*{p['client_mac']}*{pmkid}*{ssid_hex}"
        else:
            ssid_hex = p.get("ssid_hex", "")
            keyver = p.get("key_version", 1)
            eapol_len = p.get("eapol_length", len(p.get("eapol", "")) // 2)
            return (
                f"{p['ap_mac']}*{p['client_mac']}*{keyver}*"
                f"{p.get('mic', '')}*{p.get('anonce', '')}*"
                f"{p.get('snonce', '')}*{eapol_len}*"
                f"{p.get('eapol', '')}*{ssid_hex}"
            )

    def _render_16800(self, p: Dict) -> str:
        """Render as hashcat 16800."""
        if p["type"] != "pmkid":
            raise HashExtractionError(
                "Cannot convert EAPOL hash to 16800 (PMKID-only) format"
            )
        ssid_hex = p.get("ssid_hex", "")
        return f"{p['ap_mac']}:{p['client_mac']}:{p['pmkid']}:{ssid_hex}"

    def _render_2500(self, p: Dict) -> str:
        """Render as hashcat 2500."""
        if p["type"] != "eapol":
            raise HashExtractionError(
                "Cannot convert PMKID hash to 2500 (EAPOL-only) format"
            )
        ssid_hex = p.get("ssid_hex", "")
        return (
            f"{p['ap_mac']}:{p['client_mac']}:"
            f"{p.get('anonce', '')}:{p.get('snonce', '')}:"
            f"{p.get('mic', '')}:{ssid_hex}"
        )

    def _render_john(self, p: Dict) -> str:
        """Render as John the Ripper WPAPSK."""
        ssid = ""
        if "ssid" in p:
            ssid = p["ssid"]
        elif "ssid_hex" in p:
            try:
                ssid = bytes.fromhex(p["ssid_hex"]).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                ssid = p["ssid_hex"]

        if p["type"] == "pmkid":
            return f"$WPAPSK${ssid}#{p['pmkid']}"
        else:
            hashdata = (
                f"{p['ap_mac']}{p['client_mac']}"
                f"{p.get('anonce', '')}{p.get('snonce', '')}"
                f"{p.get('mic', '')}"
            )
            return f"$WPAPSK${ssid}#{hashdata}"

    def _render_cowpatty(self, p: Dict) -> str:
        """Render as cowpatty text format."""
        ssid = ""
        if "ssid" in p:
            ssid = p["ssid"]
        elif "ssid_hex" in p:
            try:
                ssid = bytes.fromhex(p["ssid_hex"]).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                ssid = p["ssid_hex"]

        return (
            f"cowpatty:{ssid}:{p['ap_mac']}:{p['client_mac']}:"
            f"{p.get('anonce', '')}:{p.get('snonce', '')}:{p.get('mic', '')}"
        )
