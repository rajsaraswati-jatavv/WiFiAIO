"""Hashcat/John mutation rule engine.

Parses and applies hashcat-style and John the Ripper mutation rules
to password candidates.  Supports the full hashcat rule language
including multi-rule application.
"""

import re
from typing import Callable, Dict, Generator, List, Optional, Tuple

from wifi_aio.exceptions import CrackingError


class RuleEngine:
    """Parse and apply hashcat/John mutation rules to password candidates.

    Implements the hashcat rule language:

    * ``:`` – no-op (pass through)
    * ``l`` – lowercase all
    * ``u`` – uppercase all
    * ``c`` – capitalize
    * ``C`` – lowercase first, upper rest
    * ``t`` – toggle case of all
    * ``T<N>`` – toggle case at position N
    * ``r`` – reverse
    * ``d`` – duplicate
    * ``p<N>`` – duplicate N times
    * ``f`` – append reversed
    * ``{`` – rotate left
    * ``}`` – rotate right
    * ``$<c>`` – append character c
    * ``^<c>`` – prepend character c
    * ``[`` – delete first character
    * ``]`` – delete last character
    * ``D<N>`` – delete character at position N
    * ``x<NM>`` – extract M characters starting at position N
    * ``O<NM>`` – omit M characters starting at position N
    * ``i<Nc>`` – insert character c at position N
    * ``o<Nc>`` – overwrite character at position N with c
    * ``'N`` – truncate to N characters
    * ``s<xy>`` – replace all instances of x with y
    * ``@<c>`` – purge all instances of c
    * ``z<N>`` – duplicate first character N times
    * ``Z<N>`` – duplicate last character N times
    * ``q`` – duplicate every character
    * ``+<N>`` – increment character at position N
    * ``-<N>`` – decrement character at position N
    * ``.N`` – replace character at current position with character at position N
    * ``k`` – swap first two characters
    * ``K`` – swap last two characters
    * ``L`` – shift left (bitwise) of first char
    * ``R`` – shift right (bitwise) of first char
    """

    def __init__(self) -> None:
        self._rules: Dict[str, Callable] = {
            ":": self._rule_nop,
            "l": self._rule_lowercase,
            "u": self._rule_uppercase,
            "c": self._rule_capitalize,
            "C": self._rule_lower_first_upper_rest,
            "t": self._rule_toggle_all,
            "r": self._rule_reverse,
            "d": self._rule_duplicate,
            "f": self._rule_append_reversed,
            "{": self._rule_rotate_left,
            "}": self._rule_rotate_right,
            "[": self._rule_delete_first,
            "]": self._rule_delete_last,
            "k": self._rule_swap_first,
            "K": self._rule_swap_last,
            "q": self._rule_duplicate_each,
            "L": self._rule_shift_left,
            "R": self._rule_shift_right,
        }

    # ── Public API ─────────────────────────────────────────────────────

    def apply_rule(self, rule: str, word: str) -> Optional[str]:
        """Apply a single hashcat rule to a word.

        Parameters
        ----------
        rule:
            A hashcat rule string (e.g. ``"c$1"``, ``"T0u"``).
        word:
            The input word.

        Returns
        -------
        str or None
            The mutated word, or ``None`` if the rule rejects the word.
        """
        result = word
        operations = self._parse_rule(rule)

        for op_name, op_arg in operations:
            result = self._apply_operation(op_name, op_arg, result)
            if result is None:
                return None

        return result

    def apply_rules(self, rules: List[str], word: str) -> List[str]:
        """Apply multiple rules to a word, returning all non-None results."""
        results = []
        for rule in rules:
            mutated = self.apply_rule(rule, word)
            if mutated is not None:
                results.append(mutated)
        return results

    def apply_rules_to_words(
        self,
        rules: List[str],
        words: List[str],
    ) -> Generator[str, None, None]:
        """Apply rules to all words, yielding unique mutated results."""
        seen = set()
        for word in words:
            for rule in rules:
                mutated = self.apply_rule(rule, word)
                if mutated is not None and mutated not in seen:
                    seen.add(mutated)
                    yield mutated

    def parse_rule_file(self, path: str) -> List[str]:
        """Load rules from a hashcat-style rule file."""
        rules = []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    rules.append(line)
        return rules

    def validate_rule(self, rule: str) -> Tuple[bool, Optional[str]]:
        """Validate a rule string.

        Returns ``(is_valid, error_message)``.
        """
        try:
            operations = self._parse_rule(rule)
            for op_name, op_arg in operations:
                if op_name not in self._rules and op_name not in (
                    "T", "$", "^", "D", "x", "O", "i", "o", "'",
                    "s", "@", "z", "Z", "p", "+", "-",
                ):
                    return False, f"Unknown rule operation: {op_name!r}"
            return True, None
        except Exception as exc:
            return False, str(exc)

    # ── Rule parsing ───────────────────────────────────────────────────

    def _parse_rule(self, rule: str) -> List[Tuple[str, str]]:
        """Parse a hashcat rule string into a list of (operation, argument) tuples.

        A rule like ``"c$1T0"`` becomes ``[("c", ""), ("$", "1"), ("T", "0")]``.
        """
        operations: List[Tuple[str, str]] = []
        i = 0
        rule = rule.strip()

        while i < len(rule):
            ch = rule[i]

            # Simple single-character rules (no argument)
            if ch in self._rules:
                operations.append((ch, ""))
                i += 1
                continue

            # Rules with numeric argument
            if ch == "T":  # Toggle at position
                i += 1
                arg, i = self._read_position(rule, i)
                operations.append(("T", arg))
            elif ch == "D":  # Delete at position
                i += 1
                arg, i = self._read_position(rule, i)
                operations.append(("D", arg))
            elif ch == "'":  # Truncate
                i += 1
                arg, i = self._read_position(rule, i)
                operations.append(("'", arg))
            elif ch == "p":  # Duplicate N times
                i += 1
                arg, i = self._read_position(rule, i)
                operations.append(("p", arg))
            elif ch == "z":  # Duplicate first char N times
                i += 1
                arg, i = self._read_position(rule, i)
                operations.append(("z", arg))
            elif ch == "Z":  # Duplicate last char N times
                i += 1
                arg, i = self._read_position(rule, i)
                operations.append(("Z", arg))
            elif ch == "+":  # Increment at position
                i += 1
                arg, i = self._read_position(rule, i)
                operations.append(("+", arg))
            elif ch == "-":  # Decrement at position
                i += 1
                arg, i = self._read_position(rule, i)
                operations.append(("-", arg))

            # Rules with character argument
            elif ch == "$":  # Append char
                i += 1
                if i < len(rule):
                    operations.append(("$", rule[i]))
                    i += 1
            elif ch == "^":  # Prepend char
                i += 1
                if i < len(rule):
                    operations.append(("^", rule[i]))
                    i += 1

            # Rules with two arguments
            elif ch == "x":  # Extract NM
                i += 1
                arg, i = self._read_two_positions(rule, i)
                operations.append(("x", arg))
            elif ch == "O":  # Omit NM
                i += 1
                arg, i = self._read_two_positions(rule, i)
                operations.append(("O", arg))
            elif ch == "i":  # Insert Nc
                i += 1
                pos, i = self._read_position(rule, i)
                if i < len(rule):
                    arg = pos + "," + rule[i]
                    i += 1
                else:
                    arg = pos + ","
                operations.append(("i", arg))
            elif ch == "o":  # Overwrite Nc
                i += 1
                pos, i = self._read_position(rule, i)
                if i < len(rule):
                    arg = pos + "," + rule[i]
                    i += 1
                else:
                    arg = pos + ","
                operations.append(("o", arg))

            # String replacement
            elif ch == "s":  # Replace x with y
                i += 1
                if i + 1 < len(rule):
                    arg = rule[i] + rule[i + 1]
                    i += 2
                elif i < len(rule):
                    arg = rule[i]
                    i += 1
                else:
                    arg = ""
                operations.append(("s", arg))

            # Purge
            elif ch == "@":  # Purge char
                i += 1
                if i < len(rule):
                    operations.append(("@", rule[i]))
                    i += 1

            else:
                # Unknown operation – skip
                i += 1

        return operations

    @staticmethod
    def _read_position(rule: str, i: int) -> Tuple[str, int]:
        """Read a position number from the rule string."""
        if i >= len(rule):
            return "0", i

        # Try to read a digit or two
        start = i
        while i < len(rule) and rule[i].isdigit():
            i += 1

        if i == start:
            return "0", i + 1  # skip non-digit

        return rule[start:i], i

    @staticmethod
    def _read_two_positions(rule: str, i: int) -> Tuple[str, int]:
        """Read two position numbers (N and M) from the rule string."""
        first, i = RuleEngine._read_position(rule, i)
        second, i = RuleEngine._read_position(rule, i)
        return f"{first},{second}", i

    # ── Operation application ──────────────────────────────────────────

    def _apply_operation(self, op_name: str, op_arg: str, word: str) -> Optional[str]:
        """Apply a single parsed operation to a word."""
        # Simple rules (in the lookup table)
        if op_name in self._rules:
            return self._rules[op_name](word)

        # Rules with arguments
        if op_name == "T":
            return self._rule_toggle_at(word, int(op_arg) if op_arg else 0)
        elif op_name == "$":
            return self._rule_append_char(word, op_arg)
        elif op_name == "^":
            return self._rule_prepend_char(word, op_arg)
        elif op_name == "D":
            return self._rule_delete_at(word, int(op_arg) if op_arg else 0)
        elif op_name == "'":
            return self._rule_truncate(word, int(op_arg) if op_arg else 0)
        elif op_name == "p":
            return self._rule_duplicate_n(word, int(op_arg) if op_arg else 1)
        elif op_name == "z":
            return self._rule_duplicate_first_n(word, int(op_arg) if op_arg else 1)
        elif op_name == "Z":
            return self._rule_duplicate_last_n(word, int(op_arg) if op_arg else 1)
        elif op_name == "+":
            return self._rule_increment_at(word, int(op_arg) if op_arg else 0)
        elif op_name == "-":
            return self._rule_decrement_at(word, int(op_arg) if op_arg else 0)
        elif op_name == "x":
            parts = op_arg.split(",", 1)
            pos = int(parts[0]) if parts[0] else 0
            length = int(parts[1]) if len(parts) > 1 and parts[1] else 1
            return self._rule_extract(word, pos, length)
        elif op_name == "O":
            parts = op_arg.split(",", 1)
            pos = int(parts[0]) if parts[0] else 0
            length = int(parts[1]) if len(parts) > 1 and parts[1] else 1
            return self._rule_omit(word, pos, length)
        elif op_name == "i":
            parts = op_arg.split(",", 1)
            pos = int(parts[0]) if parts[0] else 0
            char = parts[1] if len(parts) > 1 else ""
            return self._rule_insert(word, pos, char)
        elif op_name == "o":
            parts = op_arg.split(",", 1)
            pos = int(parts[0]) if parts[0] else 0
            char = parts[1] if len(parts) > 1 else ""
            return self._rule_overwrite(word, pos, char)
        elif op_name == "s":
            if len(op_arg) >= 2:
                return self._rule_replace(word, op_arg[0], op_arg[1])
            return word
        elif op_name == "@":
            return self._rule_purge(word, op_arg)

        return word

    # ── Simple rule implementations ────────────────────────────────────

    @staticmethod
    def _rule_nop(word: str) -> str:
        return word

    @staticmethod
    def _rule_lowercase(word: str) -> str:
        return word.lower()

    @staticmethod
    def _rule_uppercase(word: str) -> str:
        return word.upper()

    @staticmethod
    def _rule_capitalize(word: str) -> str:
        if not word:
            return word
        return word[0].upper() + word[1:].lower()

    @staticmethod
    def _rule_lower_first_upper_rest(word: str) -> str:
        if not word:
            return word
        return word[0].lower() + word[1:].upper()

    @staticmethod
    def _rule_toggle_all(word: str) -> str:
        return word.swapcase()

    @staticmethod
    def _rule_toggle_at(word: str, pos: int) -> str:
        if pos < 0 or pos >= len(word):
            return word
        return word[:pos] + word[pos].swapcase() + word[pos + 1:]

    @staticmethod
    def _rule_reverse(word: str) -> str:
        return word[::-1]

    @staticmethod
    def _rule_duplicate(word: str) -> str:
        return word + word

    @staticmethod
    def _rule_duplicate_n(word: str, n: int) -> str:
        return word * max(1, n)

    @staticmethod
    def _rule_append_reversed(word: str) -> str:
        return word + word[::-1]

    @staticmethod
    def _rule_rotate_left(word: str) -> str:
        if len(word) <= 1:
            return word
        return word[1:] + word[0]

    @staticmethod
    def _rule_rotate_right(word: str) -> str:
        if len(word) <= 1:
            return word
        return word[-1] + word[:-1]

    @staticmethod
    def _rule_append_char(word: str, char: str) -> str:
        return word + char

    @staticmethod
    def _rule_prepend_char(word: str, char: str) -> str:
        return char + word

    @staticmethod
    def _rule_delete_first(word: str) -> str:
        return word[1:] if word else word

    @staticmethod
    def _rule_delete_last(word: str) -> str:
        return word[:-1] if word else word

    @staticmethod
    def _rule_delete_at(word: str, pos: int) -> str:
        if pos < 0 or pos >= len(word):
            return word
        return word[:pos] + word[pos + 1:]

    @staticmethod
    def _rule_truncate(word: str, length: int) -> str:
        if length <= 0:
            return ""
        return word[:length]

    @staticmethod
    def _rule_extract(word: str, pos: int, length: int) -> str:
        if pos < 0 or pos >= len(word):
            return ""
        return word[pos: pos + length]

    @staticmethod
    def _rule_omit(word: str, pos: int, length: int) -> str:
        if pos < 0 or pos >= len(word):
            return word
        return word[:pos] + word[pos + length:]

    @staticmethod
    def _rule_insert(word: str, pos: int, char: str) -> str:
        pos = min(pos, len(word))
        return word[:pos] + char + word[pos:]

    @staticmethod
    def _rule_overwrite(word: str, pos: int, char: str) -> str:
        if pos < 0 or pos >= len(word):
            return word
        return word[:pos] + char + word[pos + 1:]

    @staticmethod
    def _rule_replace(word: str, old: str, new: str) -> str:
        return word.replace(old, new)

    @staticmethod
    def _rule_purge(word: str, char: str) -> str:
        return word.replace(char, "")

    @staticmethod
    def _rule_duplicate_first_n(word: str, n: int) -> str:
        if not word:
            return word
        return word[0] * n + word

    @staticmethod
    def _rule_duplicate_last_n(word: str, n: int) -> str:
        if not word:
            return word
        return word + word[-1] * n

    @staticmethod
    def _rule_duplicate_each(word: str) -> str:
        return "".join(c * 2 for c in word)

    @staticmethod
    def _rule_swap_first(word: str) -> str:
        if len(word) < 2:
            return word
        return word[1] + word[0] + word[2:]

    @staticmethod
    def _rule_swap_last(word: str) -> str:
        if len(word) < 2:
            return word
        return word[:-2] + word[-1] + word[-2]

    @staticmethod
    def _rule_shift_left(word: str) -> str:
        if not word:
            return word
        shifted = chr(((ord(word[0]) - 32) << 1) % 95 + 32) if 32 <= ord(word[0]) <= 126 else word[0]
        return shifted + word[1:]

    @staticmethod
    def _rule_shift_right(word: str) -> str:
        if not word:
            return word
        shifted = chr(((ord(word[0]) - 32) >> 1) + 32) if 32 <= ord(word[0]) <= 126 else word[0]
        return shifted + word[1:]

    @staticmethod
    def _rule_increment_at(word: str, pos: int) -> str:
        if pos < 0 or pos >= len(word):
            return word
        c = word[pos]
        if 32 <= ord(c) <= 126:
            return word[:pos] + chr(ord(c) + 1) + word[pos + 1:]
        return word

    @staticmethod
    def _rule_decrement_at(word: str, pos: int) -> str:
        if pos < 0 or pos >= len(word):
            return word
        c = word[pos]
        if 33 <= ord(c) <= 127:
            return word[:pos] + chr(ord(c) - 1) + word[pos + 1:]
        return word
