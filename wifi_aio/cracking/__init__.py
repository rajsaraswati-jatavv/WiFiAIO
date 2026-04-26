"""WiFiAIO cracking sub-package.

Provides WPA/WPA2 password cracking tools including dictionary attacks,
brute-force, mask-based attacks, hybrid attacks, hash extraction and
conversion, wordlist generation, mutation rules, PMK pre-computation,
benchmarking, and session management.
"""

from wifi_aio.cracking.dictionary import DictionaryAttack
from wifi_aio.cracking.brute_force import BruteForceAttack
from wifi_aio.cracking.mask_attack import MaskAttack
from wifi_aio.cracking.hybrid import HybridAttack
from wifi_aio.cracking.hash_extractor import HashExtractor
from wifi_aio.cracking.hash_converter import HashConverter
from wifi_aio.cracking.wordlist_gen import WordlistGenerator
from wifi_aio.cracking.rule_engine import RuleEngine
from wifi_aio.cracking.pmk_calculator import PMKCalculator
from wifi_aio.cracking.benchmark import Benchmark
from wifi_aio.cracking.session_manager import CrackingSessionManager

__all__ = [
    "DictionaryAttack",
    "BruteForceAttack",
    "MaskAttack",
    "HybridAttack",
    "HashExtractor",
    "HashConverter",
    "WordlistGenerator",
    "RuleEngine",
    "PMKCalculator",
    "Benchmark",
    "CrackingSessionManager",
]
