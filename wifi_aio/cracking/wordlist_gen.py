"""Targeted wordlist generator for WPA cracking.

Generates wordlists based on target-specific information such as SSID,
network type, geographic data, and common patterns.  Supports multiple
generation strategies and custom rules.
"""

import itertools
import os
import random
import re
import string
import time
from typing import Dict, Generator, List, Optional, Set, TextIO


class WordlistGenerator:
    """Generate targeted wordlists for WPA/WPA2 cracking.

    Uses information about the target (SSID, known patterns, etc.) to
    create focused wordlists that are more likely to contain the
    password than generic wordlists.

    Parameters
    ----------
    target_info:
        Dict with target information like ``ssid``, ``location``,
        ``network_type``, ``keywords``, etc.
    min_length:
        Minimum password length (default 8 for WPA).
    max_length:
        Maximum password length (default 63 for WPA).
    """

    # Common password patterns
    MONTHS = [
        "january", "february", "march", "april", "may", "june",
        "july", "august", "september", "october", "november", "december",
    ]

    SEASONS = ["spring", "summer", "autumn", "winter"]

    COMMON_WORDS = [
        "password", "admin", "welcome", "letmein", "monkey", "dragon",
        "master", "qwerty", "login", "princess", "football", "shadow",
        "sunshine", "trustno1", "iloveyou", "batman", "access", "hello",
        "charlie", "donald", "secret", "internet", "computer", "gateway",
        "network", "wireless", "router", "connect", "online",
    ]

    LEET_MAP = {
        "a": ["4", "@"],
        "e": ["3"],
        "i": ["1", "!"],
        "o": ["0"],
        "s": ["5", "$"],
        "t": ["7"],
        "l": ["1"],
        "g": ["9"],
    }

    def __init__(
        self,
        target_info: Optional[Dict] = None,
        min_length: int = 8,
        max_length: int = 63,
    ) -> None:
        self.target_info = target_info or {}
        self.min_length = max(8, min_length)
        self.max_length = min(63, max_length)

        self._ssid = self.target_info.get("ssid", "")
        self._keywords = self.target_info.get("keywords", [])
        self._location = self.target_info.get("location", "")
        self._network_type = self.target_info.get("network_type", "")
        self._language = self.target_info.get("language", "en")

    # ── Public API ─────────────────────────────────────────────────────

    def generate(
        self,
        strategies: Optional[List[str]] = None,
        count: Optional[int] = None,
    ) -> List[str]:
        """Generate a wordlist using the specified strategies.

        Parameters
        ----------
        strategies:
            List of strategy names.  If ``None``, all strategies are used.
            Available: ``"ssid_based"``, ``"keyword"``, ``"common"``,
            ``"dates"``, ``"phone"``, ``"leet"``, ``"combinations"``.
        count:
            Maximum number of passwords to generate.  ``None`` = no limit.

        Returns
        -------
        list of str
        """
        all_strategies = [
            "ssid_based", "keyword", "common", "dates",
            "phone", "leet", "combinations",
        ]
        active = strategies or all_strategies

        passwords: Set[str] = set()

        for strategy in active:
            if count is not None and len(passwords) >= count:
                break

            method = getattr(self, f"_gen_{strategy}", None)
            if method is None:
                continue

            for pwd in method():
                if self.min_length <= len(pwd) <= self.max_length:
                    passwords.add(pwd)
                if count is not None and len(passwords) >= count:
                    break

        return sorted(passwords)

    def generate_to_file(
        self,
        output_path: str,
        strategies: Optional[List[str]] = None,
        count: Optional[int] = None,
    ) -> int:
        """Generate a wordlist and write it directly to a file.

        Returns the number of passwords written.
        """
        passwords = self.generate(strategies=strategies, count=count)
        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as fh:
            for pwd in passwords:
                fh.write(pwd + "\n")

        return len(passwords)

    def iter_generate(
        self,
        strategies: Optional[List[str]] = None,
    ) -> Generator[str, None, None]:
        """Yield passwords one at a time (memory-efficient)."""
        all_strategies = [
            "ssid_based", "keyword", "common", "dates",
            "phone", "leet", "combinations",
        ]
        active = strategies or all_strategies
        seen: Set[str] = set()

        for strategy in active:
            method = getattr(self, f"_gen_{strategy}", None)
            if method is None:
                continue

            for pwd in method():
                if self.min_length <= len(pwd) <= self.max_length:
                    if pwd not in seen:
                        seen.add(pwd)
                        yield pwd

    def estimate_count(
        self,
        strategies: Optional[List[str]] = None,
    ) -> int:
        """Estimate the number of passwords that will be generated."""
        count = 0
        for _ in self.iter_generate(strategies):
            count += 1
        return count

    # ── Strategy implementations ───────────────────────────────────────

    def _gen_ssid_based(self) -> Generator[str, None, None]:
        """Generate passwords based on the target SSID."""
        if not self._ssid:
            return

        ssid = self._ssid
        ssid_lower = ssid.lower()
        ssid_upper = ssid.upper()
        ssid_cap = ssid.capitalize()

        # Base variations
        base_variants = [
            ssid, ssid_lower, ssid_upper, ssid_cap,
            ssid_lower + "1", ssid_lower + "123",
            ssid_lower + "1234", ssid_lower + "12345",
            ssid_cap + "1", ssid_cap + "123",
            ssid_cap + "1234", ssid_cap + "12345",
            ssid_lower + "!", ssid_lower + "@",
            ssid_lower + "#", ssid_lower + "$",
            ssid + "2024", ssid + "2025", ssid + "2026",
            ssid_lower + "wifi", ssid_lower + "net",
            ssid_lower + "pass", ssid_lower + "pwd",
        ]
        yield from base_variants

        # SSID with appended years
        for year in range(2015, 2027):
            yield ssid_lower + str(year)
            yield ssid_cap + str(year)

        # SSID with common suffixes
        suffixes = [
            "admin", "password", "pass", "wifi", "net", "network",
            "12345", "54321", "123456", "654321", "12345678",
            "123456789", "00000000", "11111111", "99999999",
        ]
        for suffix in suffixes:
            yield ssid_lower + suffix
            yield ssid_cap + suffix

        # SSID with common prefixes
        prefixes = ["pass", "pwd", "wifi", "net", "admin", "key"]
        for prefix in prefixes:
            yield prefix + ssid_lower
            yield prefix + ssid_cap

        # SSID digits only (if applicable)
        digits = re.sub(r"[^0-9]", "", ssid)
        if digits and len(digits) >= 8:
            yield digits

        # SSID with common special character patterns
        for sep in ["_", ".", "-", "@", "#"]:
            yield ssid_lower + sep + "1234"
            yield ssid_lower + sep + "wifi"
            yield ssid_lower + sep + "pass"

    def _gen_keyword(self) -> Generator[str, None, None]:
        """Generate passwords based on target keywords."""
        keywords = list(self._keywords)
        if self._location:
            keywords.append(self._location.lower())
        if self._network_type:
            keywords.append(self._network_type.lower())

        if not keywords:
            return

        for keyword in keywords:
            kw_lower = keyword.lower()
            kw_cap = keyword.capitalize()
            kw_upper = keyword.upper()

            # Basic variations
            yield kw_lower
            yield kw_cap
            yield kw_upper

            # With numbers
            yield kw_lower + "1"
            yield kw_lower + "123"
            yield kw_lower + "1234"
            yield kw_cap + "1"
            yield kw_cap + "123"
            yield kw_cap + "1234"

            # With special characters
            yield kw_lower + "!"
            yield kw_lower + "@"
            yield kw_lower + "#"
            yield kw_lower + "$"

            # With years
            for year in range(2018, 2027):
                yield kw_lower + str(year)
                yield kw_cap + str(year)

            # Combinations of two keywords
            for kw2 in keywords:
                if kw2 != keyword:
                    yield kw_lower + kw2.capitalize()
                    yield kw_cap + kw2.lower()

    def _gen_common(self) -> Generator[str, None, None]:
        """Generate common password patterns."""
        # Common words with number suffixes
        for word in self.COMMON_WORDS:
            yield word
            yield word.capitalize()
            yield word.upper()
            for i in range(10):
                yield word + str(i)
            for suffix in ["123", "1234", "12345", "123456", "!", "@", "#"]:
                yield word + suffix
                yield word.capitalize() + suffix

        # Simple number sequences
        for length in range(8, 17):
            yield "0" * length
            yield "1" * length
            yield "9" * length
            yield "1234567890"[:length]

        # Keyboard patterns
        keyboard_patterns = [
            "qwertyui", "qwertyuiop", "asdfghjkl", "zxcvbnm",
            "qazwsxedc", "1qaz2wsx", "1q2w3e4r", "1q2w3e4r5t",
            "q1w2e3r4", "zaq1xsw2", "!qaz2wsx",
        ]
        yield from keyboard_patterns

    def _gen_dates(self) -> Generator[str, None, None]:
        """Generate date-based passwords."""
        # Full dates in various formats
        for year in range(1970, 2027):
            for month in range(1, 13):
                # MMDDYYYY
                yield f"{month:02d}{1:02d}{year}"
                # DDMMYYYY
                yield f"{1:02d}{month:02d}{year}"

                # Month name + year
                month_name = self.MONTHS[month - 1]
                yield month_name + str(year)
                yield month_name.capitalize() + str(year)

        # Season + year
        for season in self.SEASONS:
            for year in range(2015, 2027):
                yield season + str(year)
                yield season.capitalize() + str(year)

    def _gen_phone(self) -> Generator[str, None, None]:
        """Generate phone-number-based passwords."""
        # US phone number patterns (10 digits, no separators)
        # Area codes
        common_area_codes = [
            "212", "310", "415", "512", "617", "702", "808", "917",
            "202", "305", "404", "503", "602", "713", "818", "949",
            "201", "303", "410", "510", "614", "703", "832", "954",
        ]
        for area in common_area_codes:
            # Area code + 7 digits pattern
            for prefix in ["555", "123", "000", "999", "100", "200"]:
                yield area + prefix + "0000"
                yield area + prefix + "1111"
                yield area + prefix + "1234"
                yield area + prefix + "4321"

    def _gen_leet(self) -> Generator[str, None, None]:
        """Generate leet-speak variations of known words."""
        # Apply leet speak to SSID and common words
        base_words = list(self.COMMON_WORDS[:20])
        if self._ssid:
            base_words.append(self._ssid.lower())
        for kw in self._keywords:
            base_words.append(kw.lower())

        for word in base_words:
            # Generate leet variations
            leet_vars = self._leet_variations(word, max_variants=10)
            yield from leet_vars

    def _gen_combinations(self) -> Generator[str, None, None]:
        """Generate word + number + special character combinations."""
        small_words = self.COMMON_WORDS[:10]
        if self._ssid:
            small_words.append(self._ssid.lower())

        digits = ["1", "12", "123", "1234", "12345", "0", "00", "0000"]
        specials = ["!", "@", "#", "$", ".", "_"]

        for word in small_words:
            for d in digits:
                candidate = word + d
                if self.min_length <= len(candidate) <= self.max_length:
                    yield candidate
                candidate = word.capitalize() + d
                if self.min_length <= len(candidate) <= self.max_length:
                    yield candidate

                for s in specials:
                    candidate = word + d + s
                    if self.min_length <= len(candidate) <= self.max_length:
                        yield candidate

    # ── Leet speak ─────────────────────────────────────────────────────

    def _leet_variations(self, word: str, max_variants: int = 10) -> List[str]:
        """Generate leet-speak variations of a word."""
        if not word:
            return []

        # Find positions that can be leet-ified
        leet_positions = []
        for i, ch in enumerate(word.lower()):
            if ch in self.LEET_MAP:
                leet_positions.append((i, ch, self.LEET_MAP[ch]))

        if not leet_positions:
            return []

        results = set()
        # Try single substitutions first
        for pos, ch, replacements in leet_positions:
            for rep in replacements:
                variant = word[:pos] + rep + word[pos + 1:]
                results.add(variant)

        # Try double substitutions
        if len(leet_positions) >= 2:
            for i in range(len(leet_positions)):
                for j in range(i + 1, len(leet_positions)):
                    pos1, ch1, reps1 = leet_positions[i]
                    pos2, ch2, reps2 = leet_positions[j]
                    for r1 in reps1:
                        for r2 in reps2:
                            if pos1 < pos2:
                                variant = word[:pos1] + r1 + word[pos1 + 1:pos2] + r2 + word[pos2 + 1:]
                            else:
                                variant = word[:pos2] + r2 + word[pos2 + 1:pos1] + r1 + word[pos1 + 1:]
                            results.add(variant)
                            if len(results) >= max_variants:
                                return list(results)

        return list(results)[:max_variants]
