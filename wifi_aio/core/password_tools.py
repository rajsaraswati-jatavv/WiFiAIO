"""Password generation, analysis, and mutation tools.

Provides password generation, strength analysis, common password checking,
password mutation for auditing, and WPA passphrase generation.
"""

import hashlib
import logging
import math
import os
import re
import string
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Common password lists (top 100 most common passwords)
TOP_COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "iloveyou", "trustno1", "sunshine",
    "master", "1234567890", "shadow", "ashley", "abc123",
    "654321", "superman", "qazwsx", "michael", "football",
    "password1", "password123", "admin", "admin123", "root",
    "letmein", "welcome", "monkey", "batman", "login",
    "princess", "qwerty123", "passw0rd", "123qwe", "access",
    "hello", "charlie", "donald", "test", "pass",
    "mustang", "pepper", "hunter", "hunter2", "changeme",
}

# Common word lists for mutation
COMMON_WORDS = [
    "password", "admin", "welcome", "letmein", "monkey",
    "dragon", "master", "qwerty", "login", "princess",
    "shadow", "sunshine", "trustno", "iloveyou", "batman",
    "football", "baseball", "superman", "hello", "charlie",
]


class PasswordTools:
    """Generate, analyze, and mutate passwords for security auditing."""

    def __init__(self):
        self._common_passwords: Set[str] = set(TOP_COMMON_PASSWORDS)
        self._custom_wordlist: Set[str] = set()

    # ------------------------------------------------------------------
    # Password Generation
    # ------------------------------------------------------------------

    @staticmethod
    def generate_password(
        length: int = 16,
        uppercase: bool = True,
        lowercase: bool = True,
        digits: bool = True,
        special: bool = True,
        exclude_ambiguous: bool = False,
    ) -> str:
        """Generate a random password.

        Args:
            length: Password length (minimum 4).
            uppercase: Include uppercase letters.
            lowercase: Include lowercase letters.
            digits: Include digits.
            special: Include special characters.
            exclude_ambiguous: Exclude ambiguous chars (0O1lI|).

        Returns:
            Generated password string.
        """
        if length < 4:
            length = 4

        charset = ""
        required_chars: List[str] = []

        if lowercase:
            chars = string.ascii_lowercase
            if exclude_ambiguous:
                chars = chars.replace("l", "")
            charset += chars
            required_chars.append(chars)

        if uppercase:
            chars = string.ascii_uppercase
            if exclude_ambiguous:
                chars = chars.replace("O", "").replace("I", "")
            charset += chars
            required_chars.append(chars)

        if digits:
            chars = string.digits
            if exclude_ambiguous:
                chars = chars.replace("0", "").replace("1", "")
            charset += chars
            required_chars.append(chars)

        if special:
            chars = string.punctuation
            if exclude_ambiguous:
                chars = chars.replace("|", "")
            charset += chars
            required_chars.append(chars)

        if not charset:
            charset = string.ascii_lowercase
            required_chars = [charset]

        # Ensure at least one character from each required set
        password_chars = []
        for req_set in required_chars:
            password_chars.append(req_set[ord(os.urandom(1)) % len(req_set)])

        # Fill remaining length with random choices from full charset
        remaining = length - len(password_chars)
        for _ in range(remaining):
            password_chars.append(charset[ord(os.urandom(1)) % len(charset)])

        # Shuffle using os.urandom-based Fisher-Yates
        for i in range(len(password_chars) - 1, 0, -1):
            j = ord(os.urandom(1)) % (i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

        return "".join(password_chars)

    @staticmethod
    def generate_passphrase(
        num_words: int = 4,
        separator: str = "-",
        capitalize: bool = True,
        word_list: Optional[List[str]] = None,
    ) -> str:
        """Generate a Diceware-style passphrase.

        Args:
            num_words: Number of words in the passphrase.
            separator: Word separator character.
            capitalize: Whether to capitalize each word.
            word_list: Custom word list. Uses EFF short list if None.

        Returns:
            Generated passphrase string.
        """
        # EFF short word list (subset)
        eff_words = word_list or [
            "acid", "aged", "also", "area", "army", "away", "baby", "back",
            "ball", "band", "bank", "base", "bath", "bear", "beat", "been",
            "beer", "bell", "belt", "best", "bill", "bird", "blow", "blue",
            "boat", "body", "bomb", "bond", "bone", "book", "boom", "born",
            "boss", "both", "bowl", "bulk", "burn", "bush", "busy", "call",
            "calm", "came", "camp", "card", "care", "case", "cash", "cast",
            "cell", "chat", "chip", "city", "club", "coal", "coat", "code",
            "cold", "come", "cook", "cool", "cope", "copy", "core", "cost",
            "crew", "crop", "dark", "data", "date", "dawn", "dead", "deal",
            "dear", "debt", "deep", "desk", "dial", "diet", "disc", "disk",
            "dock", "door", "dose", "down", "draw", "drew", "drop", "drug",
            "drum", "dual", "dull", "dust", "duty", "each", "earn", "ease",
            "east", "easy", "edge", "else", "even", "ever", "evil", "exit",
            "face", "fact", "fail", "fair", "fall", "farm", "fast", "fate",
            "fear", "feed", "feel", "file", "fill", "film", "find", "fine",
            "fire", "firm", "fish", "flag", "flat", "flee", "flow", "folk",
            "food", "foot", "ford", "form", "fort", "four", "free", "from",
            "fuel", "full", "fund", "gain", "game", "gate", "gave", "gear",
            "gene", "gift", "girl", "give", "glad", "goal", "goes", "gold",
            "golf", "gone", "good", "grab", "gray", "grew", "grey", "grow",
            "gulf", "guys", "hack", "hair", "half", "hall", "hand", "hang",
            "hard", "harm", "hate", "have", "head", "hear", "heat", "held",
            "hell", "help", "here", "hero", "high", "hill", "hire", "hold",
            "hole", "home", "hope", "host", "hour", "huge", "hung", "hunt",
            "hurt", "idea", "inch", "into", "iron", "item", "jack", "jane",
            "jean", "jobs", "john", "join", "jump", "jury", "just", "keen",
            "keep", "kent", "kept", "kick", "kill", "kind", "king", "knee",
            "knew", "know", "lack", "lady", "laid", "lake", "land", "lane",
            "last", "late", "lawn", "lead", "left", "less", "life", "lift",
            "like", "line", "link", "list", "live", "loan", "lock", "logo",
            "long", "look", "lord", "lose", "loss", "lost", "love", "luck",
        ]

        words = []
        for _ in range(num_words):
            idx = int.from_bytes(os.urandom(2), "big") % len(eff_words)
            word = eff_words[idx]
            if capitalize:
                word = word.capitalize()
            words.append(word)

        return separator.join(words)

    # ------------------------------------------------------------------
    # Strength Analysis
    # ------------------------------------------------------------------

    def analyze_strength(self, password: str) -> Dict:
        """Analyze password strength.

        Args:
            password: Password to analyze.

        Returns:
            Dict with: score (0-100), entropy, crack_time_seconds,
            crack_time_display, strength_level, suggestions, is_common.
        """
        if not password:
            return {
                "score": 0,
                "entropy": 0,
                "crack_time_seconds": 0,
                "crack_time_display": "instant",
                "strength_level": "very_weak",
                "suggestions": ["Password is empty"],
                "is_common": False,
            }

        # Check if common
        is_common = password.lower() in self._common_passwords

        # Calculate character space
        charset_size = 0
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 33

        if charset_size == 0:
            charset_size = 26

        # Calculate entropy
        entropy = len(password) * math.log2(charset_size) if charset_size > 1 else 0

        # Adjust entropy for patterns
        adjusted_entropy = entropy
        suggestions: List[str] = []

        # Penalize repeated characters
        if re.search(r"(.)\1{2,}", password):
            adjusted_entropy -= 10
            suggestions.append("Avoid repeated characters")

        # Penalize sequential characters
        if self._has_sequential(password, 3):
            adjusted_entropy -= 10
            suggestions.append("Avoid sequential characters (abc, 123)")

        # Penalize keyboard patterns
        keyboard_patterns = ["qwerty", "asdf", "zxcv", "qazwsx", "1qaz2wsx"]
        if any(p in password.lower() for p in keyboard_patterns):
            adjusted_entropy -= 15
            suggestions.append("Avoid keyboard patterns")

        # Penalize common words
        if any(word in password.lower() for word in COMMON_WORDS):
            adjusted_entropy -= 10
            suggestions.append("Avoid common dictionary words")

        # Penalize short passwords
        if len(password) < 8:
            adjusted_entropy -= 20
            suggestions.append("Use at least 8 characters")
        elif len(password) < 12:
            suggestions.append("Consider using 12+ characters for better security")

        # Penalize lack of diversity
        if not has_upper:
            suggestions.append("Add uppercase letters")
        if not has_lower:
            suggestions.append("Add lowercase letters")
        if not has_digit:
            suggestions.append("Add digits")
        if not has_special:
            suggestions.append("Add special characters")

        adjusted_entropy = max(0, adjusted_entropy)

        # Estimate crack time (10 billion guesses/second for GPU)
        guesses_per_second = 10_000_000_000
        total_guesses = 2 ** adjusted_entropy if adjusted_entropy > 0 else 1
        crack_time_seconds = total_guesses / guesses_per_second
        crack_time_display = self._format_time(crack_time_seconds)

        # Score (0-100)
        score = min(100, max(0, int(adjusted_entropy * 1.5)))

        # Strength level
        if is_common:
            strength_level = "very_weak"
            score = 0
        elif score < 20:
            strength_level = "very_weak"
        elif score < 40:
            strength_level = "weak"
        elif score < 60:
            strength_level = "fair"
        elif score < 80:
            strength_level = "strong"
        else:
            strength_level = "very_strong"

        if is_common:
            suggestions.insert(0, "This is a commonly used password")

        return {
            "score": score,
            "entropy": round(adjusted_entropy, 2),
            "crack_time_seconds": crack_time_seconds,
            "crack_time_display": crack_time_display,
            "strength_level": strength_level,
            "suggestions": suggestions,
            "is_common": is_common,
            "length": len(password),
            "charset_size": charset_size,
        }

    @staticmethod
    def _has_sequential(password: str, min_length: int) -> bool:
        """Check for sequential characters."""
        for i in range(len(password) - min_length + 1):
            segment = password[i:i + min_length]
            ords = [ord(c) for c in segment]
            if all(ords[j + 1] - ords[j] == 1 for j in range(len(ords) - 1)):
                return True
            if all(ords[j] - ords[j + 1] == 1 for j in range(len(ords) - 1)):
                return True
        return False

    @staticmethod
    def _format_time(seconds: float) -> str:
        """Format seconds into human-readable time string."""
        if seconds < 1:
            return "instant"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds / 3600:.1f} hours"
        elif seconds < 86400 * 365:
            return f"{seconds / 86400:.1f} days"
        elif seconds < 86400 * 365 * 1000:
            return f"{seconds / (86400 * 365):.1f} years"
        elif seconds < 86400 * 365 * 1e6:
            return f"{seconds / (86400 * 365 * 1000):.1f} thousand years"
        elif seconds < 86400 * 365 * 1e9:
            return f"{seconds / (86400 * 365 * 1e6):.1f} million years"
        else:
            return "centuries+"

    # ------------------------------------------------------------------
    # Common Password Check
    # ------------------------------------------------------------------

    def is_common_password(self, password: str) -> bool:
        """Check if a password is in the common passwords list.

        Args:
            password: Password to check.

        Returns:
            True if the password is commonly used.
        """
        return password.lower() in self._common_passwords

    def check_password_breach(
        self,
        password: str,
        k_anon_prefix_length: int = 5,
    ) -> Dict:
        """Check if a password has appeared in known data breaches.

        Uses the Have I Been Pwned API with k-anonymity.

        Args:
            password: Password to check.
            k_anon_prefix_length: SHA-1 prefix length for k-anonymity.

        Returns:
            Dict with: found, occurrence_count, hash_prefix.
        """
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:k_anon_prefix_length]
        suffix = sha1[k_anon_prefix_length:]

        try:
            import requests
            resp = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"},
                timeout=15,
            )
            resp.raise_for_status()

            for line in resp.text.splitlines():
                parts = line.strip().split(":")
                if len(parts) >= 2 and parts[0] == suffix:
                    count = int(parts[1])
                    return {
                        "found": True,
                        "occurrence_count": count,
                        "hash_prefix": prefix,
                    }

        except Exception as exc:
            logger.warning("Breach check failed: %s", exc)

        return {
            "found": False,
            "occurrence_count": 0,
            "hash_prefix": prefix,
        }

    def load_common_passwords(self, filepath: str) -> int:
        """Load a custom common passwords file.

        Args:
            filepath: Path to wordlist file (one per line).

        Returns:
            Number of passwords loaded.
        """
        count = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    word = line.strip()
                    if word:
                        self._common_passwords.add(word.lower())
                        count += 1
        except OSError as exc:
            logger.error("Failed to load common passwords: %s", exc)
        logger.info("Loaded %d common passwords", count)
        return count

    # ------------------------------------------------------------------
    # Password Mutation
    # ------------------------------------------------------------------

    def mutate_password(
        self,
        base_word: str,
        max_mutations: int = 100,
    ) -> List[str]:
        """Generate password mutations for auditing.

        Applies common transformation rules to a base word to generate
        likely password variations.

        Args:
            base_word: Base word to mutate.
            max_mutations: Maximum number of mutations to generate.

        Returns:
            List of mutated password strings.
        """
        mutations: Set[str] = set()

        # Rule sets
        leet_map = {
            "a": ["4", "@"],
            "e": ["3"],
            "i": ["1", "!"],
            "o": ["0"],
            "s": ["5", "$"],
            "t": ["7"],
            "l": ["1"],
            "g": ["9"],
            "b": ["8"],
        }

        suffixes = [
            "", "1", "12", "123", "1234", "!", "!!", "!@#", "01", "007",
            "2023", "2024", "2025", "69", "99", "00", "000",
        ]

        prefixes = [
            "", "!", "@", "#", "*", "my", "the", "im", "i",
        ]

        capitalizations = [
            base_word,
            base_word.lower(),
            base_word.upper(),
            base_word.capitalize(),
            base_word.swapcase(),
            # CamelCase for multi-word
            base_word.title(),
        ]

        # Apply capitalizations
        for cap_word in capitalizations:
            mutations.add(cap_word)

            # Add suffixes
            for suffix in suffixes:
                mutations.add(cap_word + suffix)
                if len(mutations) >= max_mutations:
                    return sorted(mutations)

            # Add prefixes
            for prefix in prefixes:
                mutations.add(prefix + cap_word)
                if len(mutations) >= max_mutations:
                    return sorted(mutations)

        # Leet speak transformations
        leet_variants = self._generate_leet_variants(base_word, leet_map, max_mutations // 4)
        mutations.update(leet_variants)

        # Reverse
        mutations.add(base_word[::-1])
        mutations.add(base_word[::-1].capitalize())

        # Double the word
        mutations.add(base_word * 2)
        mutations.add((base_word + base_word).capitalize())

        # Remove/replace specific chars
        if len(base_word) > 2:
            mutations.add(base_word[:-1] + "!")
            mutations.add(base_word[:-1] + "1")

        # Trim to max
        result = sorted(mutations)[:max_mutations]
        return result

    def _generate_leet_variants(
        self,
        word: str,
        leet_map: Dict[str, List[str]],
        max_variants: int,
    ) -> Set[str]:
        """Generate leet speak variants of a word."""
        variants: Set[str] = set()
        word_lower = word.lower()

        # Single substitution
        for i, char in enumerate(word_lower):
            if char in leet_map:
                for replacement in leet_map[char]:
                    variant = word_lower[:i] + replacement + word_lower[i + 1:]
                    variants.add(variant)
                    variants.add(variant.capitalize())
                    if len(variants) >= max_variants:
                        return variants

        # All substitutions
        all_leet = word_lower
        for char, replacements in leet_map.items():
            all_leet = all_leet.replace(char, replacements[0])
        variants.add(all_leet)

        return variants

    def generate_mutations_batch(
        self,
        words: List[str],
        max_per_word: int = 50,
    ) -> List[str]:
        """Generate mutations for multiple base words.

        Args:
            words: List of base words.
            max_per_word: Max mutations per word.

        Returns:
            Combined list of all mutations.
        """
        all_mutations: List[str] = []
        for word in words:
            all_mutations.extend(self.mutate_password(word, max_per_word))
        return sorted(set(all_mutations))

    # ------------------------------------------------------------------
    # WPA Passphrase Generation
    # ------------------------------------------------------------------

    @staticmethod
    def generate_wpa_passphrase(
        length: int = 20,
        method: str = "random",
    ) -> str:
        """Generate a WPA/WPA2 passphrase.

        WPA passphrases must be 8-63 ASCII characters (32-95 in decimal).

        Args:
            length: Passphrase length (8-63). Default 20.
            method: Generation method - 'random' or 'passphrase'.

        Returns:
            Valid WPA passphrase string.
        """
        length = max(8, min(63, length))

        if method == "passphrase":
            # Generate a memorable passphrase
            tools = PasswordTools()
            return tools.generate_passphrase(
                num_words=max(3, length // 5),
                separator="-",
                capitalize=True,
            )
        else:
            # Random WPA passphrase
            # Use printable ASCII characters (32-126)
            chars = string.printable[:-6]  # Exclude whitespace chars beyond space
            passphrase = []
            for _ in range(length):
                idx = ord(os.urandom(1)) % len(chars)
                passphrase.append(chars[idx])
            return "".join(passphrase)

    @staticmethod
    def validate_wpa_passphrase(passphrase: str) -> Dict:
        """Validate a WPA/WPA2 passphrase.

        Args:
            passphrase: Passphrase to validate.

        Returns:
            Dict with: valid, errors, length.
        """
        errors: List[str] = []

        if len(passphrase) < 8:
            errors.append("WPA passphrase must be at least 8 characters")
        if len(passphrase) > 63:
            errors.append("WPA passphrase must be at most 63 characters")

        # Check for non-ASCII characters
        try:
            passphrase.encode("ascii")
        except UnicodeEncodeError:
            errors.append("WPA passphrase must contain only ASCII characters (32-126)")

        # Check for control characters
        for i, char in enumerate(passphrase):
            if ord(char) < 32 or ord(char) > 126:
                errors.append(f"Invalid character at position {i}: code {ord(char)}")
                break

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "length": len(passphrase),
        }

    @staticmethod
    def passphrase_to_pmk(passphrase: str, ssid: str) -> bytes:
        """Convert WPA passphrase to Pairwise Master Key (PMK).

        Uses PBKDF2-SHA1 with 4096 iterations.

        Args:
            passphrase: WPA passphrase (8-63 chars).
            ssid: Network SSID.

        Returns:
            32-byte PMK.
        """
        if len(passphrase) < 8 or len(passphrase) > 63:
            raise ValueError("WPA passphrase must be 8-63 characters")

        return hashlib.pbkdf2_hmac(
            "sha1",
            passphrase.encode("ascii"),
            ssid.encode("utf-8"),
            4096,
            dklen=32,
        )

    # ------------------------------------------------------------------
    # Hash utilities
    # ------------------------------------------------------------------

    @staticmethod
    def hash_password(password: str, algorithm: str = "sha256") -> str:
        """Hash a password using the specified algorithm.

        Args:
            password: Password to hash.
            algorithm: Hash algorithm (md5, sha1, sha256, sha512).

        Returns:
            Hex digest of the hash.
        """
        h = hashlib.new(algorithm)
        h.update(password.encode("utf-8"))
        return h.hexdigest()

    def generate_wordlist(
        self,
        base_words: List[str],
        output_path: str,
        max_mutations: int = 100,
    ) -> int:
        """Generate a wordlist file from base word mutations.

        Args:
            base_words: List of base words to mutate.
            output_path: Output file path.
            max_mutations: Maximum total mutations.

        Returns:
            Number of words written.
        """
        mutations = self.generate_mutations_batch(base_words, max_per_word=max_mutations // max(len(base_words), 1))
        mutations = mutations[:max_mutations]

        try:
            with open(output_path, "w", encoding="utf-8") as fh:
                for word in sorted(mutations):
                    fh.write(word + "\n")
        except OSError as exc:
            logger.error("Failed to write wordlist: %s", exc)

        return len(mutations)
