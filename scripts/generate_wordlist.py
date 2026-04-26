#!/usr/bin/env python3
"""WiFiAIO Wordlist Generator.

Generates custom wordlists for WiFi security assessments with
configurable mutation rules, language patterns, and charset options.
"""

import argparse
import itertools
import os
import random
import string
import sys
from typing import List, Optional, Set


# Common WiFi password patterns
SSID_PATTERNS = [
    "{vendor}{year}", "{vendor}{digits4}", "{word}{digits3}",
    "{word}{special}{digits}", "{name}{year}", "{phone_region}{digits}",
    "{phrase}{special}", "{word}{word}{digits2}",
]

# Common password words by category
COMMON_WORDS = {
    "general": [
        "password", "admin", "welcome", "login", "access", "master",
        "secret", "changeme", "default", "gateway", "network", "wifi",
        "internet", "connect", "wireless", "router", "modem", "setup",
        "config", "system", "security", "update", "install", "service",
    ],
    "vendor": [
        "tp-link", "tplink", "netgear", "dlink", "asus", "linksys",
        "huawei", "xiaomi", "tendalink", "cisco", "zyxel", "belkin",
        "arrismotorola", "sagemcom", "technicolor", "ubiquiti",
    ],
    "names": [
        "james", "john", "robert", "michael", "david", "william",
        "mary", "patricia", "jennifer", "linda", "sarah", "elizabeth",
        "admin", "root", "user", "guest", "support", "operator",
    ],
    "places": [
        "home", "office", "school", "hotel", "cafe", "library",
        "airport", "mall", "restaurant", "hospital", "bank", "store",
    ],
}

# Common suffixes
YEAR_RANGE = [str(y) for y in range(2015, 2026)]
DIGIT_SUFFIXES = [str(i).zfill(2) for i in range(100)] + [str(i).zfill(3) for i in range(1000)]
SPECIAL_CHARS = ["!", "@", "#", "$", "*", "_"]


def generate_basic_wordlist(
    min_length: int = 8,
    max_length: int = 16,
    count: int = 10000,
    charset: str = "alphanumeric",
) -> List[str]:
    """Generate random passwords with specified parameters.

    Args:
        min_length: Minimum password length.
        max_length: Maximum password length.
        count: Number of passwords to generate.
        charset: Character set - "alpha", "alphanumeric", "full".

    Returns:
        List of generated passwords.
    """
    if charset == "alpha":
        chars = string.ascii_letters
    elif charset == "alphanumeric":
        chars = string.ascii_letters + string.digits
    else:
        chars = string.ascii_letters + string.digits + string.punctuation

    passwords = set()
    while len(passwords) < count:
        length = random.randint(min_length, max_length)
        passwords.add("".join(random.choice(chars) for _ in range(length)))
    return sorted(passwords)


def generate_pattern_wordlist(ssid: str = "", vendor: str = "") -> List[str]:
    """Generate passwords based on SSID and vendor patterns.

    Args:
        ssid: Target SSID for pattern-based generation.
        vendor: Router vendor name.

    Returns:
        List of generated password candidates.
    """
    passwords = set()
    base_words = [ssid.lower(), vendor.lower()] if ssid or vendor else []
    base_words = [w for w in base_words if w]

    # Add common words
    for category_words in COMMON_WORDS.values():
        base_words.extend(category_words)

    # Pattern: word + year
    for word in base_words[:50]:
        for year in YEAR_RANGE:
            passwords.add(f"{word}{year}")
            passwords.add(f"{word.capitalize()}{year}")
            passwords.add(f"{word}_{year}")

    # Pattern: word + digits
    for word in base_words[:30]:
        for suffix in DIGIT_SUFFIXES[:50]:
            passwords.add(f"{word}{suffix}")
            passwords.add(f"{word.capitalize()}{suffix}")

    # Pattern: word + special + digits
    for word in base_words[:20]:
        for special in SPECIAL_CHARS:
            for digits in ["123", "1234", "0000", "1111", "2024", "2025"]:
                passwords.add(f"{word}{special}{digits}")
                passwords.add(f"{word.capitalize()}{special}{digits}")

    return sorted(passwords)


def generate_phone_patterns(country_code: str = "1") -> List[str]:
    """Generate phone-number-based password patterns.

    Args:
        country_code: Country code for phone patterns.

    Returns:
        List of phone-pattern passwords.
    """
    passwords = set()
    # Common area codes (US)
    area_codes = ["212", "310", "415", "512", "617", "702", "808", "305", "404", "602"]

    for area in area_codes:
        for i in range(100):
            passwords.add(f"{area}{i:04d}")
            passwords.add(f"{area}{i:06d}")

    return sorted(passwords)


def apply_mutations(word: str) -> List[str]:
    """Apply common password mutations to a word.

    Args:
        word: Base word to mutate.

    Returns:
        List of mutated variants.
    """
    mutations = {word}

    # Case variations
    mutations.add(word.lower())
    mutations.add(word.upper())
    mutations.add(word.capitalize())
    mutations.add(word.title())

    # Leet speak
    leet_map = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
    leet = word.lower()
    for char, replacement in leet_map.items():
        leet = leet.replace(char, replacement, 1)
    mutations.add(leet)

    # Reversed
    mutations.add(word[::-1])

    # With common suffixes
    for suffix in ["1", "12", "123", "1234", "!", "@", "#", "!!", "01"]:
        mutations.add(f"{word}{suffix}")
        mutations.add(f"{word.capitalize()}{suffix}")

    return sorted(mutations)


def load_custom_wordlist(filepath: str) -> List[str]:
    """Load words from a file.

    Args:
        filepath: Path to wordlist file.

    Returns:
        List of words from the file.
    """
    words = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith("#"):
                    words.append(word)
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}", file=sys.stderr)
    return words


def main():
    parser = argparse.ArgumentParser(description="WiFiAIO Wordlist Generator")
    parser.add_argument("-o", "--output", default="-", help="Output file (default: stdout)")
    parser.add_argument("-m", "--min-length", type=int, default=8, help="Minimum password length")
    parser.add_argument("-M", "--max-length", type=int, default=16, help="Maximum password length")
    parser.add_argument("-c", "--count", type=int, default=10000, help="Number of random passwords")
    parser.add_argument("--charset", default="alphanumeric", choices=["alpha", "alphanumeric", "full"])
    parser.add_argument("--ssid", default="", help="Target SSID for pattern-based generation")
    parser.add_argument("--vendor", default="", help="Router vendor for pattern-based generation")
    parser.add_argument("--patterns", action="store_true", help="Generate pattern-based passwords")
    parser.add_argument("--phone", action="store_true", help="Generate phone-number patterns")
    parser.add_argument("--mutate", default="", help="Apply mutations to words from file")
    parser.add_argument("--append", default="", help="Append custom wordlist file")
    parser.add_argument("--unique", action="store_true", default=True, help="Remove duplicates")

    args = parser.parse_args()
    passwords = []

    # Generate random passwords
    info_msg = f"Generating {args.count} random passwords ({args.charset}, {args.min_length}-{args.max_length} chars)"
    print(f"# {info_msg}", file=sys.stderr)
    passwords.extend(generate_basic_wordlist(
        min_length=args.min_length,
        max_length=args.max_length,
        count=args.count,
        charset=args.charset,
    ))

    # Pattern-based generation
    if args.patterns or args.ssid or args.vendor:
        print("# Generating pattern-based passwords...", file=sys.stderr)
        passwords.extend(generate_pattern_wordlist(ssid=args.ssid, vendor=args.vendor))

    # Phone patterns
    if args.phone:
        print("# Generating phone-number patterns...", file=sys.stderr)
        passwords.extend(generate_phone_patterns())

    # Mutation mode
    if args.mutate:
        print(f"# Applying mutations to {args.mutate}...", file=sys.stderr)
        words = load_custom_wordlist(args.mutate)
        for word in words:
            passwords.extend(apply_mutations(word))

    # Append custom wordlist
    if args.append:
        print(f"# Appending {args.append}...", file=sys.stderr)
        passwords.extend(load_custom_wordlist(args.append))

    # Deduplicate and filter by length
    if args.unique:
        seen = set()
        unique = []
        for pw in passwords:
            if pw not in seen and args.min_length <= len(pw) <= args.max_length:
                seen.add(pw)
                unique.append(pw)
        passwords = unique

    # Output
    output_file = sys.stdout if args.output == "-" else open(args.output, "w", encoding="utf-8")
    try:
        for pw in passwords:
            print(pw, file=output_file)
    finally:
        if args.output != "-":
            output_file.close()

    print(f"# Generated {len(passwords)} passwords", file=sys.stderr)


if __name__ == "__main__":
    main()
