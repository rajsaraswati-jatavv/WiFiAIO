"""Update checker for WiFiAIO."""

import json
import logging
import os
from typing import Dict, Optional, Tuple

from wifi_aio.constants import GITHUB_RELEASES_URL

logger = logging.getLogger(__name__)


def check_for_updates(current_version: Optional[str] = None) -> Optional[Dict]:
    """Check GitHub for the latest release of WiFiAIO.

    Args:
        current_version: Version string to compare against. If None, uses package version.

    Returns:
        Dict with keys: 'has_update' (bool), 'latest_version' (str),
        'current_version' (str), 'download_url' (str), 'release_notes' (str).
        Returns None if the check cannot be performed (no network, etc.).
    """
    if current_version is None:
        from wifi_aio import __version__
        current_version = __version__

    try:
        import requests
    except ImportError:
        logger.warning("requests library not installed; cannot check for updates")
        return None

    try:
        response = requests.get(
            GITHUB_RELEASES_URL,
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=10,
        )
        if response.status_code != 200:
            logger.debug("GitHub API returned status %d", response.status_code)
            return None

        data = response.json()
    except (requests.RequestException, json.JSONDecodeError) as exc:
        logger.debug("Update check failed: %s", exc)
        return None

    latest_version = data.get("tag_name", "").lstrip("v")
    if not latest_version:
        latest_version = data.get("name", "").lstrip("v")

    download_url = ""
    assets = data.get("assets", [])
    if assets:
        # Prefer .whl or .tar.gz
        for asset in assets:
            name = asset.get("name", "").lower()
            if name.endswith(".whl") or name.endswith(".tar.gz"):
                download_url = asset.get("browser_download_url", "")
                break
        if not download_url and assets:
            download_url = assets[0].get("browser_download_url", "")
    else:
        download_url = data.get("html_url", "")

    release_notes = data.get("body", "")

    has_update = _compare_versions(latest_version, current_version) > 0

    result = {
        "has_update": has_update,
        "latest_version": latest_version,
        "current_version": current_version,
        "download_url": download_url,
        "release_notes": release_notes,
        "release_url": data.get("html_url", ""),
    }

    if has_update:
        logger.info(
            "Update available: %s → %s",
            current_version,
            latest_version,
        )
    else:
        logger.debug("WiFiAIO is up to date (%s)", current_version)

    return result


def _compare_versions(v1: str, v2: str) -> int:
    """Compare two PEP 440 version strings.

    Returns:
        > 0 if v1 > v2, 0 if equal, < 0 if v1 < v2.
    """
    def normalize(ver: str) -> list:
        parts = []
        for segment in ver.split("."):
            # Extract leading numeric portion
            num = ""
            for ch in segment:
                if ch.isdigit():
                    num += ch
                else:
                    break
            parts.append(int(num) if num else 0)
        return parts

    parts1 = normalize(v1)
    parts2 = normalize(v2)

    # Pad with zeros
    max_len = max(len(parts1), len(parts2))
    parts1.extend([0] * (max_len - len(parts1)))
    parts2.extend([0] * (max_len - len(parts2)))

    for a, b in zip(parts1, parts2):
        if a != b:
            return a - b
    return 0
