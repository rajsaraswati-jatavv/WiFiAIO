"""
WiFiAIO Password Cracker Module

Supports dictionary, brute-force, mask, hybrid, and rule-based attacks
against captured WiFi handshakes using hashcat and CPU-based cracking.
"""

import os
import re
import time
import logging
import subprocess
import hashlib
import hmac
import struct
from typing import List, Dict, Optional, Any, Generator, Tuple
from dataclasses import dataclass, field
from enum import Enum

from wifi_aio.exceptions import (
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    WiFiCrackerError,
    HandshakeError,
)

logger = logging.getLogger(__name__)


class AttackMode(Enum):
    """Hashcat attack modes."""
    DICTIONARY = 0
    COMBINATOR = 1
    BRUTE_FORCE = 3
    MASK = 3
    HYBRID_DICT_MASK = 6
    HYBRID_MASK_DICT = 7
    RULE_BASED = 0  # Dictionary with rules


class HashType(Enum):
    """WiFi hash types for hashcat."""
    WPA_EAPOL = 22000
    WPA_PMKID = 16800
    WPA_EAPOL_OLD = 2500


@dataclass
class CrackResult:
    """Result of a cracking attempt."""
    found: bool = False
    password: str = ""
    hash_type: str = ""
    attack_mode: str = ""
    time_elapsed: float = 0.0
    speed: float = 0.0  # Hashes per second
    tried: int = 0
    total: int = 0
    potfile_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "found": self.found,
            "password": self.password,
            "hash_type": self.hash_type,
            "attack_mode": self.attack_mode,
            "time_elapsed": self.time_elapsed,
            "speed": self.speed,
            "tried": self.tried,
            "total": self.total,
        }


@dataclass
class HandshakeData:
    """Parsed handshake data for CPU cracking."""
    anonce: bytes = b""
    snonce: bytes = b""
    ap_mac: bytes = b""
    client_mac: bytes = b""
    eapol_data: bytes = b""
    mic: bytes = b""
    key_version: int = 1
    ssid: str = ""


class PasswordCracker:
    """
    WiFi password cracker supporting multiple attack modes.

    Uses hashcat for GPU-accelerated cracking and a CPU fallback
    for environments without GPU support.
    """

    def __init__(self, hashcat_path: str = "hashcat",
                 potfile_dir: str = "/tmp/wifiaio_potfiles"):
        """
        Initialize PasswordCracker.

        Args:
            hashcat_path: Path to hashcat binary.
            potfile_dir: Directory for potfile storage.
        """
        self.hashcat_path = hashcat_path
        self.potfile_dir = potfile_dir
        self._running = False
        self._process: Optional[subprocess.Popen] = None
        self._hashcat_available: Optional[bool] = None

        os.makedirs(potfile_dir, exist_ok=True)

    def _check_hashcat(self) -> bool:
        """Check if hashcat is available."""
        if self._hashcat_available is not None:
            return self._hashcat_available
        try:
            result = subprocess.run(
                [self.hashcat_path, "--version"],
                capture_output=True, text=True, timeout=10
            )
            self._hashcat_available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._hashcat_available = False
        return self._hashcat_available

    def _extract_hash(self, capture_file: str) -> HandshakeData:
        """
        Extract handshake data from hc22000 format capture file.

        FIX: Properly parses hc22000 format to extract anonce, snonce,
        ap_mac, client_mac, eapol_data, mic for CPU cracking.

        Args:
            capture_file: Path to .hc22000 hash file.

        Returns:
            HandshakeData with parsed fields.
        """
        data = HandshakeData()

        try:
            with open(capture_file, "r") as f:
                content = f.read().strip()
        except OSError as e:
            raise HandshakeError(f"Failed to read capture file: {e}")

        # hc22000 format:
        # hc22000*key_version*ap_mac*client_mac*ssid*anonce*snonce*eapol_data*mic
        # or as a single line with fields separated by *
        lines = content.splitlines()
        if not lines:
            raise HandshakeError("Empty capture file")

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("hc22000"):
                parts = line.split("*")
                if len(parts) < 9:
                    raise HandshakeError(
                        f"Invalid hc22000 format: expected 9+ fields, got {len(parts)}"
                    )

                try:
                    # Parse key version
                    data.key_version = int(parts[1])

                    # Parse AP MAC (remove colons, convert to bytes)
                    ap_mac_str = parts[2].replace(":", "")
                    data.ap_mac = bytes.fromhex(ap_mac_str)

                    # Parse client MAC
                    client_mac_str = parts[3].replace(":", "")
                    data.client_mac = bytes.fromhex(client_mac_str)

                    # Parse SSID (hex encoded)
                    ssid_hex = parts[4]
                    if ssid_hex:
                        try:
                            data.ssid = bytes.fromhex(ssid_hex).decode("utf-8", errors="replace")
                        except ValueError:
                            data.ssid = ssid_hex
                    else:
                        data.ssid = ""

                    # Parse ANONCE (32 bytes = 64 hex chars)
                    anonce_hex = parts[5]
                    if len(anonce_hex) == 64:
                        data.anonce = bytes.fromhex(anonce_hex)

                    # Parse SNONCE (32 bytes = 64 hex chars)
                    snonce_hex = parts[6]
                    if len(snonce_hex) == 64:
                        data.snonce = bytes.fromhex(snonce_hex)

                    # Parse EAPOL data
                    eapol_hex = parts[7]
                    if eapol_hex:
                        data.eapol_data = bytes.fromhex(eapol_hex)

                    # Parse MIC (16 bytes = 32 hex chars, or 32 bytes = 64 for some formats)
                    mic_hex = parts[8]
                    if len(mic_hex) >= 32:
                        data.mic = bytes.fromhex(mic_hex[:32])

                    logger.debug(
                        "Extracted handshake: key_ver=%d, ssid=%s, "
                        "anonce_len=%d, snonce_len=%d, mic_len=%d",
                        data.key_version, data.ssid,
                        len(data.anonce), len(data.snonce), len(data.mic)
                    )
                    break

                except (ValueError, IndexError) as e:
                    raise HandshakeError(f"Failed to parse hc22000 fields: {e}")

            # Also try legacy hccapx or pcap formats with tshark
            elif line and not line.startswith("#"):
                # Try to parse as raw hex hash line
                parts = line.split("*")
                if len(parts) >= 5:
                    try:
                        data.key_version = int(parts[0])
                        ap_mac_str = parts[1].replace(":", "")
                        data.ap_mac = bytes.fromhex(ap_mac_str)
                        client_mac_str = parts[2].replace(":", "")
                        data.client_mac = bytes.fromhex(client_mac_str)
                        if len(parts) > 4 and len(parts[4]) == 64:
                            data.anonce = bytes.fromhex(parts[4])
                        if len(parts) > 5 and len(parts[5]) == 64:
                            data.snonce = bytes.fromhex(parts[5])
                    except (ValueError, IndexError):
                        pass
                    break

        if not data.anonce or not data.snonce:
            raise HandshakeError(
                "Failed to extract complete handshake data (missing anonce/snonce)"
            )

        return data

    def _pbkdf2_sha1(self, password: str, ssid: str, iterations: int = 4096) -> bytes:
        """Derive PSK from passphrase using PBKDF2-SHA1."""
        return hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"),
                                   ssid.encode("utf-8"), iterations, 32)

    def _prf_512(self, key: bytes, a: str, b: str) -> bytes:
        """PRF-512 function for PTK derivation."""
        result = b""
        for i in range(4):  # 4 * 160 bits = 640 bits, we need 512
            hmac_data = a.encode("ascii") + b"\0" + b.encode("ascii") + struct.pack(">B", i)
            result += hmac.new(key, hmac_data, hashlib.sha1).digest()
        return result[:64]

    def _derive_ptk(self, pmk: bytes, anonce: bytes, snonce: bytes,
                    ap_mac: bytes, client_mac: bytes) -> bytes:
        """Derive PTK from PMK and handshake nonces/MACs."""
        # Determine nonce ordering: smaller MAC first
        if ap_mac < client_mac:
            mac1, nonce1 = ap_mac, anonce
            mac2, nonce2 = client_mac, snonce
        else:
            mac1, nonce1 = client_mac, snonce
            mac2, nonce2 = ap_mac, anonce

        pke = b"Pairwise key expansion\0" + mac1 + mac2 + \
              min(nonce1, nonce2) + max(nonce1, nonce2)

        ptk = b""
        for i in range(4):
            hmac_data = pke + struct.pack(">B", i)
            ptk += hmac.new(pmk, hmac_data, hashlib.sha1).digest()

        return ptk[:64]

    def _verify_mic(self, ptk: bytes, eapol_data: bytes, mic: bytes,
                    key_version: int) -> bool:
        """Verify MIC against derived PTK."""
        # Zero out MIC in EAPOL frame for calculation
        eapol_for_mic = bytearray(eapol_data)
        # MIC field offset is typically at byte 81 (after EAPOL header + key info)
        mic_offset = 81
        if len(eapol_for_mic) > mic_offset + 16:
            eapol_for_mic[mic_offset:mic_offset + 16] = b"\x00" * 16

        if key_version == 1:
            calculated_mic = hmac.new(ptk[:16], bytes(eapol_for_mic), hashlib.sha1).digest()[:16]
        elif key_version == 2:
            calculated_mic = hmac.new(ptk[:16], bytes(eapol_for_mic), hashlib.sha256).digest()[:16]
        else:
            calculated_mic = hmac.new(ptk[:16], bytes(eapol_for_mic), hashlib.sha256).digest()[:16]

        return calculated_mic == mic

    def _cpu_crack(self, handshake: HandshakeData, passwords: Generator[str, None, None],
                   callback=None) -> CrackResult:
        """
        CPU-based password cracking.

        Args:
            handshake: Parsed handshake data.
            passwords: Generator yielding password candidates.
            callback: Optional callback with progress info.

        Returns:
            CrackResult with outcome.
        """
        result = CrackResult(
            hash_type="WPA-EAPOL",
            attack_mode="cpu-dictionary",
        )
        start_time = time.time()
        tried = 0

        for password in passwords:
            if not self._running:
                break

            tried += 1

            # Derive PMK
            pmk = self._pbkdf2_sha1(password, handshake.ssid)

            # Derive PTK
            ptk = self._derive_ptk(
                pmk, handshake.anonce, handshake.snonce,
                handshake.ap_mac, handshake.client_mac
            )

            # Verify MIC
            if self._verify_mic(ptk, handshake.eapol_data, handshake.mic, handshake.key_version):
                result.found = True
                result.password = password
                result.tried = tried
                result.time_elapsed = time.time() - start_time
                result.speed = tried / result.time_elapsed if result.time_elapsed > 0 else 0
                logger.info("Password found: %s", password)
                return result

            if callback and tried % 1000 == 0:
                elapsed = time.time() - start_time
                callback(tried=tried, speed=tried / elapsed if elapsed > 0 else 0)

        result.tried = tried
        result.time_elapsed = time.time() - start_time
        result.speed = tried / result.time_elapsed if result.time_elapsed > 0 else 0
        return result

    def _run_hashcat(self, hash_file: str, attack_mode: int,
                     wordlist: Optional[str] = None,
                     mask: Optional[str] = None,
                     rule_file: Optional[str] = None,
                     hash_type: int = 22000,
                     extra_args: Optional[List[str]] = None,
                     timeout: int = 0) -> CrackResult:
        """
        Run hashcat with specified parameters.

        Args:
            hash_file: Path to hash file.
            attack_mode: Hashcat attack mode number.
            wordlist: Path to wordlist file.
            mask: Hashcat mask pattern.
            rule_file: Path to rule file.
            hash_type: Hashcat hash type number.
            extra_args: Additional hashcat arguments.
            timeout: Maximum runtime in seconds (0 = no limit).

        Returns:
            CrackResult with outcome.
        """
        potfile = os.path.join(self.potfile_dir, f"potfile_{int(time.time())}")

        cmd = [
            self.hashcat_path,
            "-m", str(hash_type),
            "-a", str(attack_mode),
            "--potfile-path", potfile,
            "--force",
            hash_file,
        ]

        if wordlist:
            cmd.append(wordlist)
        if mask:
            cmd.append(mask)
        if rule_file:
            cmd.extend(["-r", rule_file])
        if extra_args:
            cmd.extend(extra_args)

        logger.info("Running hashcat: %s", " ".join(cmd))

        result = CrackResult(hash_type=str(hash_type), attack_mode=str(attack_mode))
        start_time = time.time()
        self._running = True

        try:
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            stdout, stderr = "", ""
            try:
                if timeout > 0:
                    stdout, stderr = self._process.communicate(timeout=timeout)
                else:
                    stdout, stderr = self._process.communicate()
            except subprocess.TimeoutExpired:
                self._process.kill()
                stdout, stderr = self._process.communicate()

            output = stdout + stderr

            # Check for cracked password in output
            # Parse hashcat status output
            status_match = re.search(r"([a-f0-9]+):(.+)", output)
            if status_match:
                result.found = True
                result.password = status_match.group(2).strip()

            # Check potfile
            if not result.found and os.path.isfile(potfile):
                try:
                    with open(potfile, "r") as f:
                        for line in f:
                            if ":" in line:
                                result.found = True
                                result.password = line.split(":")[-1].strip()
                                break
                except OSError:
                    pass

            # Parse speed from output
            speed_match = re.search(r"(\d+(?:\.\d+)?)\s*H/s", output)
            if speed_match:
                result.speed = float(speed_match.group(1))

        except FileNotFoundError:
            raise WiFiCrackerError("hashcat not found")
        finally:
            self._running = False
            self._process = None

        result.time_elapsed = time.time() - start_time
        return result

    def dictionary_attack(self, hash_file: str, wordlist: str,
                          hash_type: int = 22000,
                          rule_file: Optional[str] = None,
                          timeout: int = 0,
                          use_cpu: bool = False,
                          callback=None) -> CrackResult:
        """
        Perform a dictionary attack.

        Args:
            hash_file: Path to hash file (hc22000 format).
            wordlist: Path to wordlist file.
            hash_type: Hash type number.
            rule_file: Optional rule file to apply.
            timeout: Maximum runtime in seconds.
            use_cpu: Use CPU-based cracking instead of hashcat.
            callback: Optional progress callback.

        Returns:
            CrackResult with outcome.
        """
        self._running = True

        if use_cpu:
            handshake = self._extract_hash(hash_file)
            def password_generator():
                try:
                    with open(wordlist, "r", errors="ignore") as f:
                        for line in f:
                            if not self._running:
                                break
                            pw = line.strip()
                            if pw:
                                yield pw
                except OSError as e:
                    raise WiFiCrackerError(f"Failed to read wordlist: {e}")
            return self._cpu_crack(handshake, password_generator(), callback)

        if not self._check_hashcat():
            # Fallback to CPU
            logger.warning("hashcat not available, falling back to CPU cracking")
            return self.dictionary_attack(
                hash_file, wordlist, hash_type, rule_file,
                timeout, use_cpu=True, callback=callback
            )

        return self._run_hashcat(
            hash_file, 0, wordlist=wordlist,
            rule_file=rule_file, hash_type=hash_type,
            timeout=timeout
        )

    def brute_force_attack(self, hash_file: str, charset: str = "abcdef0123456789",
                           min_length: int = 8, max_length: int = 8,
                           hash_type: int = 22000,
                           use_cpu: bool = False,
                           callback=None) -> CrackResult:
        """
        Perform a brute-force attack.

        Args:
            hash_file: Path to hash file.
            charset: Characters to try.
            min_length: Minimum password length.
            max_length: Maximum password length.
            hash_type: Hash type number.
            use_cpu: Use CPU-based cracking.
            callback: Optional progress callback.

        Returns:
            CrackResult with outcome.
        """
        self._running = True

        if use_cpu:
            handshake = self._extract_hash(hash_file)
            def brute_generator():
                for length in range(min_length, max_length + 1):
                    for combo in self._generate_combinations(charset, length):
                        if not self._running:
                            return
                        yield combo
            return self._cpu_crack(handshake, brute_generator(), callback)

        if not self._check_hashcat():
            logger.warning("hashcat not available, falling back to CPU cracking")
            return self.brute_force_attack(
                hash_file, charset, min_length, max_length,
                hash_type, use_cpu=True, callback=callback
            )

        # Convert charset to hashcat mask
        mask_map = {
            "lower": "?l", "upper": "?u", "digits": "?d",
            "hex": "?h", "all": "?a", "printable": "?a",
        }
        mask_charset = mask_map.get(charset, f"?1")
        extra = ["-1", charset] if charset not in mask_map else []

        masks = []
        for length in range(min_length, max_length + 1):
            if charset in mask_map:
                masks.append(mask_map.get(charset, "?a") * length)
            else:
                masks.append("?1" * length)

        # Run for each mask length
        for mask in masks:
            if not self._running:
                break
            result = self._run_hashcat(
                hash_file, 3, mask=mask, hash_type=hash_type,
                extra_args=extra if extra else None
            )
            if result.found:
                return result

        return result

    def _generate_combinations(self, charset: str, length: int) -> Generator[str, None, None]:
        """Generate all combinations of charset of given length."""
        if length == 0:
            yield ""
            return
        for char in charset:
            for rest in self._generate_combinations(charset, length - 1):
                yield char + rest

    def mask_attack(self, hash_file: str, mask: str,
                    hash_type: int = 22000,
                    timeout: int = 0,
                    custom_charsets: Optional[Dict[str, str]] = None) -> CrackResult:
        """
        Perform a mask-based attack.

        Mask syntax follows hashcat conventions:
        ?l = abcdefghijklmnopqrstuvwxyz
        ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
        ?d = 0123456789
        ?h = 0123456789abcdef
        ?a = all printable

        Args:
            hash_file: Path to hash file.
            mask: Hashcat mask pattern (e.g., "?u?l?l?l?d?d?d?d").
            hash_type: Hash type number.
            timeout: Maximum runtime in seconds.
            custom_charsets: Custom charset mappings ({"1": "abc", "2": "xyz"}).

        Returns:
            CrackResult with outcome.
        """
        if not self._check_hashcat():
            raise WiFiCrackerError("Mask attack requires hashcat (GPU)")

        extra_args = []
        if custom_charsets:
            for idx, chars in custom_charsets.items():
                extra_args.extend([f"-{idx}", chars])

        return self._run_hashcat(
            hash_file, 3, mask=mask, hash_type=hash_type,
            extra_args=extra_args if extra_args else None,
            timeout=timeout
        )

    def hybrid_attack(self, hash_file: str, wordlist: str, mask: str,
                      mode: str = "dict_mask",
                      hash_type: int = 22000,
                      timeout: int = 0) -> CrackResult:
        """
        Perform a hybrid attack (dictionary + mask or mask + dictionary).

        Args:
            hash_file: Path to hash file.
            wordlist: Path to wordlist file.
            mask: Hashcat mask for appending/prepending.
            mode: "dict_mask" (append mask to words) or "mask_dict" (prepend mask to words).
            hash_type: Hash type number.
            timeout: Maximum runtime in seconds.

        Returns:
            CrackResult with outcome.
        """
        if not self._check_hashcat():
            raise WiFiCrackerError("Hybrid attack requires hashcat (GPU)")

        if mode == "mask_dict":
            attack_mode = 7
        else:
            attack_mode = 6

        return self._run_hashcat(
            hash_file, attack_mode, wordlist=wordlist,
            mask=mask, hash_type=hash_type, timeout=timeout
        )

    def rule_attack(self, hash_file: str, wordlist: str, rule_file: str,
                    hash_type: int = 22000,
                    timeout: int = 0) -> CrackResult:
        """
        Perform a rule-based dictionary attack.

        Args:
            hash_file: Path to hash file.
            wordlist: Path to wordlist file.
            rule_file: Path to rule file.
            hash_type: Hash type number.
            timeout: Maximum runtime in seconds.

        Returns:
            CrackResult with outcome.
        """
        if not self._check_hashcat():
            raise WiFiCrackerError("Rule attack requires hashcat (GPU)")

        return self._run_hashcat(
            hash_file, 0, wordlist=wordlist,
            rule_file=rule_file, hash_type=hash_type,
            timeout=timeout
        )

    def check_cracked(self, hash_file: str, hash_type: int = 22000) -> Optional[str]:
        """
        Check if a hash has already been cracked (in potfile).

        Args:
            hash_file: Path to hash file.
            hash_type: Hash type number.

        Returns:
            Cracked password or None.
        """
        potfile_path = os.path.expanduser("~/.hashcat/hashcat.potfile")
        if not os.path.isfile(potfile_path):
            return None

        try:
            with open(hash_file, "r") as f:
                hash_line = f.readline().strip()
        except OSError:
            return None

        try:
            with open(potfile_path, "r") as f:
                for line in f:
                    if hash_line in line and ":" in line:
                        return line.split(":")[-1].strip()
        except OSError:
            pass

        return None

    def convert_pcap_to_hc22000(self, pcap_file: str, output_file: Optional[str] = None) -> str:
        """
        Convert a .pcap capture file to hc22000 format.

        Args:
            pcap_file: Path to input pcap file.
            output_file: Path to output hash file.

        Returns:
            Path to the generated hash file.
        """
        if output_file is None:
            output_file = pcap_file.rsplit(".", 1)[0] + ".hc22000"

        # Try using hcxpcapngtool
        try:
            result = subprocess.run(
                ["hcxpcapngtool", "-o", output_file, pcap_file],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and os.path.isfile(output_file):
                logger.info("Converted %s to hc22000 format", pcap_file)
                return output_file
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            raise WiFiCrackerError("hcxpcapngtool timed out")

        # Fallback: try tshark + manual parsing
        try:
            result = subprocess.run(
                ["tshark", "-r", pcap_file, "-Y", "eapol",
                 "-T", "fields", "-e", "wlan.sa", "-e", "wlan.da",
                 "-e", "wlan_mgt.ssid", "-e", "eapol.keydes.mic"],
                capture_output=True, text=True, timeout=30
            )
            if result.stdout.strip():
                # Write basic hash format (simplified - real implementation needs full EAPOL)
                with open(output_file, "w") as f:
                    f.write(result.stdout)
                return output_file
        except FileNotFoundError:
            raise WiFiCrackerError("Neither hcxpcapngtool nor tshark available for conversion")
        except subprocess.TimeoutExpired:
            raise WiFiCrackerError("tshark conversion timed out")

        raise WiFiCrackerError(f"Failed to convert {pcap_file} to hc22000 format")

    def stop(self) -> None:
        """Stop the cracking process."""
        self._running = False
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
        self._process = None
        logger.info("Password cracker stopped")

    def is_running(self) -> bool:
        """Check if a cracking session is running."""
        return self._running
