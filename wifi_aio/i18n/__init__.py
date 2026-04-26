"""Internationalization (i18n) sub-package for WiFiAIO.

Provides language loading, translation lookup, and locale management
using built-in Python translation dictionaries.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from wifi_aio.i18n.en import EN_TRANSLATIONS
from wifi_aio.i18n.hi import HI_TRANSLATIONS

logger = logging.getLogger(__name__)

# Built-in language modules
_BUILTIN_LANGUAGES: Dict[str, Dict[str, str]] = {
    "en": EN_TRANSLATIONS,
    "hi": HI_TRANSLATIONS,
}


class I18n:
    """Internationalization manager for WiFiAIO.

    Loads translations from built-in language modules and optional
    external JSON files. Provides a simple key-based lookup with
    fallback to English.
    """

    def __init__(self, locale_dir: Optional[str] = None, language: str = "en"):
        """Initialize the i18n manager.

        Args:
            locale_dir: Directory containing translation JSON files.
                If None, uses the package's built-in translations.
            language: Default language code (e.g. 'en', 'hi').
        """
        self.locale_dir = Path(
            os.path.expanduser(locale_dir or "~/.config/wifi_aio/locales")
        )
        self._language = language
        self._translations: Dict[str, str] = dict(EN_TRANSLATIONS)
        self._loaded_languages: Dict[str, Dict[str, str]] = dict(_BUILTIN_LANGUAGES)

        # Load the requested language
        if language != "en":
            self.set_language(language)

    @property
    def language(self) -> str:
        """Current language code."""
        return self._language

    def set_language(self, language: str) -> None:
        """Switch to a different language.

        Args:
            language: Language code (e.g. 'en', 'hi').
        """
        if language == self._language and language in self._loaded_languages:
            return

        # Load the language if not already cached
        if language not in self._loaded_languages:
            translations = self._load_language(language)
            if translations:
                self._loaded_languages[language] = translations
            else:
                logger.warning("No translations found for language '%s'; falling back to English", language)
                self._language = "en"
                self._translations = dict(EN_TRANSLATIONS)
                return

        self._language = language
        self._translations = dict(EN_TRANSLATIONS)
        self._translations.update(self._loaded_languages[language])

    def t(self, key: str, **kwargs) -> str:
        """Translate a key to the current language.

        Args:
            key: Translation key (e.g. 'cmd.scan').
            **kwargs: Format parameters for string interpolation.

        Returns:
            Translated string, or the key itself if not found.
        """
        text = self._translations.get(key, key)
        if kwargs:
            try:
                return text.format(**kwargs)
            except (KeyError, IndexError):
                return text
        return text

    def __call__(self, key: str, **kwargs) -> str:
        """Shorthand for t()."""
        return self.t(key, **kwargs)

    def get_available_languages(self) -> List[str]:
        """Return a list of available language codes."""
        languages = set(_BUILTIN_LANGUAGES.keys())
        # Check locale dir for JSON files
        if self.locale_dir.exists():
            for f in self.locale_dir.iterdir():
                if f.is_file() and f.suffix == ".json":
                    languages.add(f.stem)
        languages.update(self._loaded_languages.keys())
        return sorted(languages)

    def _load_language(self, language: str) -> Optional[Dict[str, str]]:
        """Load a language from built-in modules or JSON files.

        Args:
            language: Language code.

        Returns:
            Dict of translations or None if not found.
        """
        # Check built-in first
        if language in _BUILTIN_LANGUAGES:
            return dict(_BUILTIN_LANGUAGES[language])

        # Check external JSON files
        lang_file = self.locale_dir / f"{language}.json"
        if not lang_file.exists():
            return None

        try:
            with open(lang_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                logger.warning("Language file %s is not a JSON object", lang_file)
                return None
            return {str(k): str(v) for k, v in data.items()}
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load language file %s: %s", lang_file, exc)
            return None

    def add_translations(self, language: str, translations: Dict[str, str]) -> None:
        """Programmatically add translations for a language.

        Args:
            language: Language code.
            translations: Dict of key -> translation string.
        """
        if language not in self._loaded_languages:
            self._loaded_languages[language] = {}
        self._loaded_languages[language].update(translations)

        if language == self._language:
            self._translations.update(translations)

    def export_language(self, language: str = "en", filepath: Optional[str] = None) -> str:
        """Export translations for a language to a JSON file.

        Args:
            language: Language code to export.
            filepath: Output file path. If None, writes to locale_dir/<language>.json.

        Returns:
            The path the file was written to.
        """
        translations = self._loaded_languages.get(language, {})
        if filepath is None:
            self.locale_dir.mkdir(parents=True, exist_ok=True)
            filepath = str(self.locale_dir / f"{language}.json")

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(translations, fh, indent=2, ensure_ascii=False, sort_keys=True)

        return filepath


# Global instance
_i18n_instance: Optional[I18n] = None


def get_i18n() -> I18n:
    """Get the global I18n instance.

    Returns:
        The global I18n instance, creating it if necessary.
    """
    global _i18n_instance
    if _i18n_instance is None:
        _i18n_instance = I18n()
    return _i18n_instance


def t(key: str, **kwargs) -> str:
    """Translate a key using the global I18n instance.

    Args:
        key: Translation key.
        **kwargs: Format parameters.

    Returns:
        Translated string.
    """
    return get_i18n().t(key, **kwargs)


__all__ = ["I18n", "get_i18n", "t"]
