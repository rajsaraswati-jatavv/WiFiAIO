"""Wordlist mutation rule definitions for Hashcat and John the Ripper.

Provides rule definitions and a pure-Python rule application engine
for generating password mutations during security assessments.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional

# ── Rule Definitions ────────────────────────────────────────────────────

WORDLIST_RULES: Dict[str, Dict] = {
    # ── Case manipulation rules ─────────────────────────────────────────
    "l": {
        "name": "Lowercase",
        "description": "Lowercase all characters",
        "hashcat": "l",
        "john": ":l",
        "category": "case",
    },
    "u": {
        "name": "Uppercase",
        "description": "Uppercase all characters",
        "hashcat": "u",
        "john": ":u",
        "category": "case",
    },
    "c": {
        "name": "Capitalize",
        "description": "Capitalize first letter, lowercase rest",
        "hashcat": "c",
        "john": ":c",
        "category": "case",
    },
    "C": {
        "name": "Invert Capitalize",
        "description": "Lowercase first letter, uppercase rest",
        "hashcat": "C",
        "john": ":C",
        "category": "case",
    },
    "t": {
        "name": "Toggle Case",
        "description": "Toggle case of all characters",
        "hashcat": "t",
        "john": ":t",
        "category": "case",
    },
    "T{n}": {
        "name": "Toggle Case N",
        "description": "Toggle case of character at position N",
        "hashcat": "T{n}",
        "john": ":T{n}",
        "category": "case",
    },
    # ── Appending and prepending rules ──────────────────────────────────
    "a{x}": {
        "name": "Append Character",
        "description": "Append character X to the word",
        "hashcat": "a{x}",
        "john": ":a{x}",
        "category": "append",
    },
    "p{x}": {
        "name": "Prepend Character",
        "description": "Prepend character X to the word",
        "hashcat": "p{x}",
        "john": ":p{x}",
        "category": "prepend",
    },
    # ── Numeric append rules ────────────────────────────────────────────
    "$d": {
        "name": "Append Digit",
        "description": "Append a single digit (0-9) to the word",
        "hashcat": "$[0-9]",
        "john": ":$[0-9]",
        "category": "append",
    },
    "$dd": {
        "name": "Append Two Digits",
        "description": "Append two digits (00-99) to the word",
        "hashcat": "$[0-9]$[0-9]",
        "john": ":$[0-9]$[0-9]",
        "category": "append",
    },
    # ── Deletion and truncation rules ───────────────────────────────────
    "D{n}": {
        "name": "Delete Position N",
        "description": "Delete character at position N",
        "hashcat": "D{n}",
        "john": ":D{n}",
        "category": "delete",
    },
    "@{c}": {
        "name": "Purge Character",
        "description": "Purge all instances of character C",
        "hashcat": "@{c}",
        "john": ":%{c}",
        "category": "delete",
    },
    "'{n}": {
        "name": "Truncate N",
        "description": "Truncate word at position N",
        "hashcat": "'{n}",
        "john": ":'{n}",
        "category": "truncate",
    },
    # ── Substitution rules ──────────────────────────────────────────────
    "s{x}{y}": {
        "name": "Substitute",
        "description": "Replace all instances of X with Y",
        "hashcat": "s{x}{y}",
        "john": ":s{x}{y}",
        "category": "substitute",
    },
    # ── Leet-speak substitution ─────────────────────────────────────────
    "leet": {
        "name": "Leet Speak",
        "description": "Common leet substitutions: a->4, e->3, i->1, o->0, s->5, t->7",
        "hashcat": "custom",
        "john": "custom",
        "category": "substitute",
    },
    # ── Reversal and duplication ────────────────────────────────────────
    "r": {
        "name": "Reverse",
        "description": "Reverse the entire word",
        "hashcat": "r",
        "john": ":r",
        "category": "transform",
    },
    "d": {
        "name": "Duplicate",
        "description": "Duplicate the word (append to itself)",
        "hashcat": "d",
        "john": ":d",
        "category": "transform",
    },
    "f": {
        "name": "Reflect",
        "description": "Append reversed word to itself",
        "hashcat": "f",
        "john": ":f",
        "category": "transform",
    },
    "{": {
        "name": "Rotate Left",
        "description": "Rotate word left by one character",
        "hashcat": "{",
        "john": ":{",
        "category": "transform",
    },
    "}": {
        "name": "Rotate Right",
        "description": "Rotate word right by one character",
        "hashcat": "}",
        "john": ":}",
        "category": "transform",
    },
    # ── Year append rules ───────────────────────────────────────────────
    "year": {
        "name": "Append Year",
        "description": "Append common years (2000-2025)",
        "hashcat": "custom",
        "john": "custom",
        "category": "append",
    },
    # ── Common suffix rules ─────────────────────────────────────────────
    "suffix_special": {
        "name": "Append Special Chars",
        "description": "Append common special characters (!, @, #, $, etc.)",
        "hashcat": "custom",
        "john": "custom",
        "category": "append",
    },
    # ── Combination rules ───────────────────────────────────────────────
    "cap_append_digit": {
        "name": "Capitalize + Append Digit",
        "description": "Capitalize first letter then append digit",
        "hashcat": "c $[0-9]",
        "john": ":c $[0-9]",
        "category": "combo",
    },
    "lower_append_year": {
        "name": "Lowercase + Append Year",
        "description": "Lowercase word then append year",
        "hashcat": "custom",
        "john": "custom",
        "category": "combo",
    },
    "leet_append_digit": {
        "name": "Leet + Append Digit",
        "description": "Apply leet speak then append digit",
        "hashcat": "custom",
        "john": "custom",
        "category": "combo",
    },
}

# Leet-speak mapping table
LEET_MAP: Dict[str, List[str]] = {
    "a": ["4", "@"],
    "b": ["8"],
    "e": ["3"],
    "g": ["9"],
    "i": ["1", "!"],
    "l": ["1"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7"],
    "z": ["2"],
}

# Common years for password mutations
COMMON_YEARS: List[str] = [str(y) for y in range(2000, 2026)]

# Common special character suffixes
COMMON_SUFFIXES: List[str] = ["!", "@", "#", "$", "%", "!!", "!@#", "123", "1234", "1", "12", "12345"]


def apply_rule(word: str, rule: str) -> List[str]:
    """Apply a mutation rule to a word and return all resulting mutations.

    Args:
        word: Input word to mutate.
        rule: Rule name to apply (from WORDLIST_RULES keys).

    Returns:
        List of mutated words.
    """
    if not word:
        return []

    results: List[str] = []

    if rule == "l":
        results.append(word.lower())
    elif rule == "u":
        results.append(word.upper())
    elif rule == "c":
        results.append(word.capitalize())
    elif rule == "C":
        if word:
            results.append(word[0].lower() + word[1:].upper())
    elif rule == "t":
        results.append(word.swapcase())
    elif rule == "r":
        results.append(word[::-1])
    elif rule == "d":
        results.append(word + word)
    elif rule == "f":
        results.append(word + word[::-1])
    elif rule == "{":
        if len(word) > 1:
            results.append(word[1:] + word[0])
        else:
            results.append(word)
    elif rule == "}":
        if len(word) > 1:
            results.append(word[-1] + word[:-1])
        else:
            results.append(word)
    elif rule == "leet":
        results.extend(_apply_leet(word))
    elif rule == "$d":
        for d in "0123456789":
            results.append(word + d)
    elif rule == "$dd":
        for d1 in "0123456789":
            for d2 in "0123456789":
                results.append(word + d1 + d2)
    elif rule == "year":
        for y in COMMON_YEARS:
            results.append(word + y)
    elif rule == "suffix_special":
        for sfx in COMMON_SUFFIXES:
            results.append(word + sfx)
    elif rule == "cap_append_digit":
        cap = word.capitalize()
        for d in "0123456789":
            results.append(cap + d)
    elif rule == "lower_append_year":
        low = word.lower()
        for y in COMMON_YEARS:
            results.append(low + y)
    elif rule == "leet_append_digit":
        leet_variants = _apply_leet(word)
        for variant in leet_variants:
            for d in "0123456789":
                results.append(variant + d)
    elif rule.startswith("T") and len(rule) > 1:
        try:
            pos = int(rule[1:])
            if 0 <= pos < len(word):
                chars = list(word)
                chars[pos] = chars[pos].swapcase()
                results.append("".join(chars))
        except ValueError:
            pass
    elif rule.startswith("D") and len(rule) > 1:
        try:
            pos = int(rule[1:])
            if 0 <= pos < len(word):
                results.append(word[:pos] + word[pos + 1:])
        except ValueError:
            pass
    elif rule.startswith("'") and len(rule) > 1:
        try:
            pos = int(rule[1:])
            results.append(word[:pos])
        except ValueError:
            pass
    elif rule.startswith("s") and len(rule) == 3:
        old_char = rule[1]
        new_char = rule[2]
        results.append(word.replace(old_char, new_char))
    elif rule.startswith("a") and len(rule) == 2:
        results.append(word + rule[1])
    elif rule.startswith("p") and len(rule) == 2:
        results.append(rule[1] + word)
    elif rule.startswith("@") and len(rule) == 2:
        results.append(word.replace(rule[1], ""))
    else:
        results.append(word)

    return results


def apply_rules(word: str, rules: Optional[List[str]] = None) -> List[str]:
    """Apply multiple rules to a word, returning all unique mutations.

    Args:
        word: Input word to mutate.
        rules: List of rule names. If None, applies all rules.

    Returns:
        Deduplicated list of mutated words.
    """
    if rules is None:
        rules = list(WORDLIST_RULES.keys())

    results = set()
    for rule in rules:
        results.update(apply_rule(word, rule))

    return sorted(results)


def _apply_leet(word: str) -> List[str]:
    """Apply leet-speak substitutions to a word.

    Generates all possible single-substitution leet variants.

    Args:
        word: Input word.

    Returns:
        List of leet-speak variants.
    """
    results = []
    word_lower = word.lower()
    for i, char in enumerate(word_lower):
        if char in LEET_MAP:
            for replacement in LEET_MAP[char]:
                results.append(word[:i] + replacement + word[i + 1:])
    return results


def generate_hashcat_rules() -> str:
    """Generate a Hashcat rule file content from defined rules.

    Returns:
        String containing Hashcat-compatible rule definitions.
    """
    lines = []
    for key, info in WORDLIST_RULES.items():
        hc_rule = info.get("hashcat", "")
        if hc_rule and hc_rule != "custom":
            lines.append(hc_rule)
    return "\n".join(lines)
