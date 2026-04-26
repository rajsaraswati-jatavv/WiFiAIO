"""PMKID extractor from beacon frames using hcxdumptool.

Provides both a pure-Python PMKID parser for PCAP files and an
interface to hcxdumptool for live PMKID capture from access points.
"""

import os
import struct
import tempfile
from typing import Dict, List, Optional, Tuple

from wifi_aio.exceptions import (
    CaptureError,
    PCAPError,
    WiFiPermissionError,
    WiFiTimeoutError,
)
from wifi_aio.utils import run_command


class PMKIDResult:
    """A single PMKID extraction result."""

    def __init__(
        self,
        bssid: str,
        client_mac: str,
        pmkid: bytes,
        anonce: bytes,
        ssid: str = "",
        timestamp: float = 0.0,
        source: str = "pcap",
    ) -> None:
        self.bssid = bssid
        self.client_mac = client_mac
        self.pmkid = pmkid
        self.anonce = anonce
        self.ssid = ssid
        self.timestamp = timestamp
        self.source = source

    @property
    def pmkid_hex(self) -> str:
        return self.pmkid.hex()

    @property
    def anonce_hex(self) -> str:
        return self.anonce.hex()

    def to_hashcat_line(self) -> str:
        """Format as a hashcat 22000 hash line.

        Format: ``MAC_AP*MAC_CLIENT*PMKID*ANONCE*SSID_HEX``
        """
        ap_hex = self.bssid.replace(":", "")
        client_hex = self.client_mac.replace(":", "")
        pmkid_hex = self.pmkid.hex()
        anonce_hex = self.anonce.hex()
        ssid_hex = self.ssid.encode("utf-8").hex() if self.ssid else ""
        return f"{ap_hex}*{client_hex}*{pmkid_hex}*{anonce_hex}*{ssid_hex}"

    def __repr__(self) -> str:
        return (
            f"PMKIDResult(bssid={self.bssid}, ssid={self.ssid!r}, "
            f"pmkid={self.pmkid_hex[:16]}...)"
        )


class PMKIDExtractor:
    """Extract PMKID from beacon/EAPOL frames.

    Two modes of operation:

    1. **PCAP mode** – parse an existing capture file for PMKIDs in
       EAPOL msg 1/assoc frames.
    2. **Live mode** – use ``hcxdumptool`` to actively request PMKIDs
       from nearby access points.

    Parameters
    ----------
    interface:
        Wireless interface (required for live mode).
    target_bssid:
        If set, filter results to this BSSID only.
    timeout:
        Timeout in seconds for live capture.
    """

    def __init__(
        self,
        interface: str = "wlan0mon",
        target_bssid: Optional[str] = None,
        timeout: int = 60,
    ) -> None:
        self.interface = interface
        self.target_bssid = target_bssid.lower() if target_bssid else None
        self.timeout = timeout

        self._results: List[PMKIDResult] = []

    # ── Public API ─────────────────────────────────────────────────────

    def extract_from_pcap(self, pcap_path: str) -> List[PMKIDResult]:
        """Extract PMKIDs from an existing PCAP file.

        Parameters
        ----------
        pcap_path:
            Path to the PCAP/PCAPNG capture file.

        Returns
        -------
        list of PMKIDResult
        """
        from wifi_aio.capture.pcap_reader import PCAPReader

        self._results.clear()

        reader = PCAPReader(pcap_path)
        with reader:
            for pkt in reader.iter_packets():
                self._process_pcap_packet(pkt.data, pkt.timestamp)

        return self._results

    def extract_live(
        self,
        output_path: Optional[str] = None,
        filter_list: Optional[str] = None,
    ) -> List[PMKIDResult]:
        """Run hcxdumptool to capture PMKIDs from nearby APs.

        Parameters
        ----------
        output_path:
            Path to save the raw PCAP output.  If ``None``, a temp file
            is used and deleted after parsing.
        filter_list:
            Path to a filter file (BSSID list) for hcxdumptool.

        Returns
        -------
        list of PMKIDResult
        """
        if os.geteuid() != 0:
            raise WiFiPermissionError(
                "Root privileges required for live PMKID capture"
            )

        self._check_hcxdumptool()

        temp_file = output_path is None
        if temp_file:
            fd, output_path = tempfile.mkstemp(suffix=".pcapng")
            os.close(fd)

        try:
            self._run_hcxdumptool(output_path, filter_list)
            self._results = self.extract_from_pcap(output_path)
        finally:
            if temp_file:
                try:
                    os.unlink(output_path)
                except OSError:
                    pass

        return self._results

    @property
    def results(self) -> List[PMKIDResult]:
        return self._results

    def to_hashcat_file(self, path: str) -> int:
        """Write all extracted PMKIDs to a hashcat 22000 format file.

        Returns the number of hashes written.
        """
        lines = set()
        for r in self._results:
            lines.add(r.to_hashcat_line())

        with open(path, "w") as fh:
            for line in sorted(lines):
                fh.write(line + "\n")

        return len(lines)

    # ── PCAP packet processing ─────────────────────────────────────────

    def _process_pcap_packet(self, raw: bytes, timestamp: float) -> None:
        """Process a single raw packet for PMKID."""
        frame = self._strip_radiotap(raw)
        if frame is None:
            return

        # Check for EAPOL-Key frames (data frames)
        if self._is_data_frame(frame):
            self._process_eapol_frame(frame, timestamp)

    @staticmethod
    def _strip_radiotap(raw: bytes) -> Optional[bytes]:
        """Strip radiotap header."""
        if len(raw) < 4:
            return None
        version = raw[0]
        if version != 0:
            return raw
        hdr_len = struct.unpack("<H", raw[2:4])[0]
        if hdr_len < 4 or hdr_len > len(raw):
            return raw
        return raw[hdr_len:]

    @staticmethod
    def _is_data_frame(frame: bytes) -> bool:
        """Check if the frame is a data frame."""
        if len(frame) < 2:
            return False
        fc = struct.unpack("<H", frame[0:2])[0]
        return (fc & 0x000C) == 0x0008

    def _process_eapol_frame(self, frame: bytes, timestamp: float) -> None:
        """Process a data frame for EAPOL-Key with PMKID."""
        if len(frame) < 26:
            return

        # Parse MAC addresses
        addrs = self._parse_addresses(frame)
        if addrs is None:
            return

        bssid, src, dst = addrs
        if self.target_bssid and bssid.lower() != self.target_bssid:
            return

        # Extract EAPOL data
        eapol = self._extract_eapol(frame)
        if eapol is None:
            return

        # Check for EAPOL-Key
        if len(eapol) < 6 or eapol[1] != 3:
            return

        # Parse key info
        if len(eapol) < 99:
            return

        key_info = struct.unpack("!H", eapol[5:7])[0]
        nonce = eapol[17:49]
        key_data_length = struct.unpack("!H", eapol[97:99])[0]
        key_data = eapol[99: 99 + key_data_length] if key_data_length > 0 else b""

        # Look for PMKID KDE in key data
        pmkid = self._find_pmkid_kde(key_data)
        if pmkid is not None:
            result = PMKIDResult(
                bssid=bssid.lower(),
                client_mac=dst.lower(),
                pmkid=pmkid,
                anonce=nonce,
                timestamp=timestamp,
                source="pcap",
            )
            # Avoid duplicates
            if not any(
                r.bssid == result.bssid and r.pmkid == result.pmkid
                for r in self._results
            ):
                self._results.append(result)

    @staticmethod
    def _parse_addresses(frame: bytes) -> Optional[Tuple[str, str, str]]:
        """Parse BSSID, source, and destination from a data frame."""
        if len(frame) < 24:
            return None

        fc = struct.unpack("<H", frame[0:2])[0]
        to_ds = (fc >> 8) & 0x01
        from_ds = (fc >> 8) & 0x02

        addr1 = ":".join(f"{b:02x}" for b in frame[4:10])
        addr2 = ":".join(f"{b:02x}" for b in frame[10:16])
        addr3 = ":".join(f"{b:02x}" for b in frame[16:22])

        if to_ds and not from_ds:
            return addr1, addr2, addr3
        elif from_ds and not to_ds:
            return addr2, addr3, addr1
        else:
            return addr3, addr2, addr1

    @staticmethod
    def _extract_eapol(frame: bytes) -> Optional[bytes]:
        """Extract EAPOL payload from a data frame."""
        if len(frame) < 30:
            return None

        fc = struct.unpack("<H", frame[0:2])[0]
        subtype = (fc >> 4) & 0x0F
        offset = 24
        if subtype & 0x08:
            offset += 2

        if len(frame) < offset + 8:
            return None

        llc = frame[offset: offset + 8]
        if llc[0:3] != b"\xaa\xaa\x03":
            return None

        ethertype = struct.unpack("!H", llc[5:7])[0]
        if ethertype != 0x888E:
            return None

        return frame[offset + 8:]

    @staticmethod
    def _find_pmkid_kde(key_data: bytes) -> Optional[bytes]:
        """Search for a PMKID KDE in the key data field.

        KDE format: type(1)=0xDD, length(1), OUI(3)=00:0F:AC, type(1)=01, PMKID(16)
        """
        offset = 0
        while offset + 6 <= len(key_data):
            kde_type = key_data[offset]
            kde_len = key_data[offset + 1]

            if kde_type == 0xDD:
                oui = key_data[offset + 2: offset + 5]
                data_type = key_data[offset + 5]
                if oui == b"\x00\x0f\xac" and data_type == 0x01:
                    if offset + 22 <= len(key_data):
                        return key_data[offset + 6: offset + 22]

            # Move to next KDE
            next_offset = offset + 2 + kde_len
            if next_offset <= offset:
                break
            offset = next_offset

        return None

    # ── hcxdumptool integration ────────────────────────────────────────

    @staticmethod
    def _check_hcxdumptool() -> None:
        """Verify hcxdumptool is available."""
        try:
            rc, stdout, _ = run_command(["hcxdumptool", "--version"])
            if rc != 0:
                raise CaptureError("hcxdumptool not found or not working")
        except FileNotFoundError:
            raise CaptureError(
                "hcxdumptool is not installed. "
                "Install it with: apt install hcxdumptool"
            )

    def _run_hcxdumptool(
        self,
        output_path: str,
        filter_list: Optional[str] = None,
    ) -> None:
        """Execute hcxdumptool for live PMKID capture."""
        cmd = [
            "hcxdumptool",
            "-i", self.interface,
            "-w", output_path,
            "--active_beacon",
            "--essid_list=any",
        ]

        if filter_list:
            cmd.extend(["--filterlist_ap", filter_list])

        try:
            rc, stdout, stderr = run_command(
                cmd, timeout=self.timeout, sudo=True
            )
        except WiFiTimeoutError:
            pass  # Timeout is expected; hcxdumptool runs until killed

        # Parse the output for BSSID/SSID info
        self._parse_hcxdumptool_output(stdout)

    @staticmethod
    def _parse_hcxdumptool_output(output: str) -> Dict[str, str]:
        """Parse hcxdumptool stdout for BSSID→SSID mapping."""
        ssid_map: Dict[str, str] = {}
        for line in output.splitlines():
            # hcxdumptool outputs lines like: EAPOL: ... or BEACON: ...
            if "BEACON" in line or "PROBERESPONSE" in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.startswith("ESSID="):
                        ssid = part.split("=", 1)[1].strip('"')
                        # Try to find the MAC in the same line
                        for p in parts:
                            if ":" in p and len(p) == 17:
                                ssid_map[p.lower()] = ssid
        return ssid_map
