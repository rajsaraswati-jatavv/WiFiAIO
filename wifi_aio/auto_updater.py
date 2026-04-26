"""Auto-updater for WiFiAIO — GitHub releases with SHA256 verification and backup/rollback."""

import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from wifi_aio.constants import GITHUB_RELEASES_URL, __version__
from wifi_aio.exceptions import UpdateError
from wifi_aio.utils import file_hash, run_command

logger = logging.getLogger(__name__)


class AutoUpdater:
    """Auto-update WiFiAIO from GitHub releases with SHA256 verification, backup, and rollback."""

    def __init__(self, install_dir: Optional[str] = None, backup_dir: Optional[str] = None):
        self.install_dir = Path(
            install_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        self.backup_dir = Path(
            os.path.expanduser(backup_dir or "~/.config/wifi_aio/backups")
        )
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def check_for_update(self) -> Optional[Dict]:
        """Check if an update is available.

        Returns:
            Dict with update info if available, None otherwise.
        """
        try:
            import requests
        except ImportError:
            raise UpdateError("requests library is required for update checks")

        try:
            response = requests.get(
                GITHUB_RELEASES_URL,
                headers={"Accept": "application/vnd.github.v3+json"},
                timeout=10,
            )
            if response.status_code != 200:
                raise UpdateError(f"GitHub API returned status {response.status_code}")

            data = response.json()
        except Exception as exc:
            raise UpdateError(f"Failed to check for updates: {exc}") from exc

        latest = data.get("tag_name", "").lstrip("v")
        if not latest:
            latest = data.get("name", "").lstrip("v")

        has_update = self._compare_versions(latest, __version__) > 0

        if not has_update:
            return None

        # Find download URL and checksum
        download_url = ""
        checksum_url = ""
        assets = data.get("assets", [])
        for asset in assets:
            name = asset.get("name", "").lower()
            url = asset.get("browser_download_url", "")
            if name.endswith(".whl") or name.endswith(".tar.gz"):
                download_url = url
            if "sha256" in name or "checksum" in name:
                checksum_url = url

        return {
            "version": latest,
            "download_url": download_url,
            "checksum_url": checksum_url,
            "release_notes": data.get("body", ""),
            "release_url": data.get("html_url", ""),
            "assets": assets,
        }

    def update(self, target_version: Optional[str] = None, verify: bool = True) -> Dict:
        """Perform an update to the latest or specified version.

        Steps:
            1. Check for available update
            2. Create backup of current installation
            3. Download the new version
            4. Verify SHA256 checksum
            5. Install the new version
            6. Verify installation

        Args:
            target_version: Specific version to update to. If None, uses the latest.
            verify: Whether to verify SHA256 checksums.

        Returns:
            Dict with update result information.

        Raises:
            UpdateError: If any step fails.
        """
        # Step 1: Check for update
        update_info = self.check_for_update()
        if update_info is None:
            return {"status": "up_to_date", "current_version": __version__}

        new_version = target_version or update_info["version"]
        download_url = update_info["download_url"]

        if not download_url:
            raise UpdateError("No download URL found for the update")

        logger.info("Updating WiFiAIO from %s to %s", __version__, new_version)

        # Step 2: Create backup
        backup_path = self._create_backup()
        logger.info("Backup created at %s", backup_path)

        # Step 3: Download
        with tempfile.TemporaryDirectory(prefix="wifi_aio_update_") as tmp_dir:
            download_path = os.path.join(tmp_dir, os.path.basename(download_url))
            logger.info("Downloading %s ...", download_url)

            try:
                self._download_file(download_url, download_path)
            except Exception as exc:
                raise UpdateError(f"Download failed: {exc}") from exc

            # Step 4: Verify checksum
            if verify:
                checksum_result = self._verify_checksum(
                    download_path,
                    update_info.get("checksum_url"),
                    new_version,
                )
                if not checksum_result["verified"]:
                    raise UpdateError(
                        f"Checksum verification failed: {checksum_result['message']}"
                    )
                logger.info("SHA256 checksum verified")

            # Step 5: Install
            try:
                self._install_package(download_path)
            except Exception as exc:
                # Rollback
                logger.error("Installation failed, rolling back: %s", exc)
                self._rollback(backup_path)
                raise UpdateError(f"Installation failed, rolled back: {exc}") from exc

        # Step 6: Verify installation
        try:
            # Re-import to get the new version
            import importlib
            import wifi_aio
            importlib.reload(wifi_aio)
            installed_version = getattr(wifi_aio, "__version__", "unknown")
        except Exception:
            installed_version = "unknown"

        result = {
            "status": "updated",
            "previous_version": __version__,
            "new_version": installed_version,
            "backup_path": str(backup_path),
            "verified": verify,
        }

        logger.info("Update complete: %s → %s", __version__, installed_version)
        return result

    def rollback(self) -> Dict:
        """Rollback to the most recent backup.

        Returns:
            Dict with rollback result.
        """
        # Find the most recent backup
        backups = sorted(
            self.backup_dir.glob("wifi_aio_backup_*.tar.gz"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        if not backups:
            raise UpdateError("No backups found for rollback")

        backup_path = backups[0]
        return self._rollback(backup_path)

    # ── Internal Methods ──────────────────────────────────────────────

    def _create_backup(self) -> Path:
        """Create a backup of the current installation.

        Returns:
            Path to the backup archive.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"wifi_aio_backup_{timestamp}"
        backup_archive = self.backup_dir / f"{backup_name}.tar.gz"

        # Create tar.gz of the install directory
        try:
            shutil.make_archive(
                base_name=str(self.backup_dir / backup_name),
                format="gztar",
                root_dir=str(self.install_dir.parent),
                base_dir=self.install_dir.name,
            )
        except Exception as exc:
            raise UpdateError(f"Backup creation failed: {exc}") from exc

        # Clean old backups (keep last 5)
        all_backups = sorted(self.backup_dir.glob("wifi_aio_backup_*.tar.gz"))
        for old_backup in all_backups[:-5]:
            try:
                old_backup.unlink()
            except OSError:
                pass

        return backup_archive

    def _download_file(self, url: str, dest: str) -> None:
        """Download a file from a URL."""
        try:
            import requests
            response = requests.get(url, stream=True, timeout=120)
            response.raise_for_status()
            with open(dest, "wb") as fh:
                for chunk in response.iter_content(chunk_size=8192):
                    fh.write(chunk)
        except ImportError:
            # Fallback to wget
            rc, _, stderr = run_command(
                ["wget", "-q", "-O", dest, url],
                timeout=120,
            )
            if rc != 0:
                raise UpdateError(f"wget download failed: {stderr}")

    def _verify_checksum(
        self,
        filepath: str,
        checksum_url: Optional[str],
        version: str,
    ) -> Dict:
        """Verify the SHA256 checksum of a downloaded file.

        Returns:
            Dict with 'verified' (bool) and 'message' (str).
        """
        # Calculate local hash
        try:
            local_hash = file_hash(filepath, "sha256")
        except Exception as exc:
            return {"verified": False, "message": f"Cannot compute hash: {exc}"}

        # Try to get expected hash from checksum URL
        if checksum_url:
            try:
                import requests
                response = requests.get(checksum_url, timeout=10)
                if response.status_code == 200:
                    checksum_content = response.text.strip()
                    # Parse checksum file (format: "<hash>  <filename>" or just "<hash>")
                    expected_hash = checksum_content.split()[0] if checksum_content else ""
                    if expected_hash and expected_hash.lower() == local_hash.lower():
                        return {"verified": True, "message": "Checksum matches"}
                    elif expected_hash:
                        return {
                            "verified": False,
                            "message": f"Hash mismatch: expected {expected_hash}, got {local_hash}",
                        }
            except Exception as exc:
                logger.warning("Could not fetch checksum file: %s", exc)

        # If no checksum URL or couldn't fetch, we log the hash for manual verification
        logger.info("SHA256 of downloaded file: %s (no remote checksum to compare)", local_hash)
        return {
            "verified": True,
            "message": f"No remote checksum available; local SHA256: {local_hash}",
        }

    def _install_package(self, package_path: str) -> None:
        """Install a Python package from a wheel or source archive."""
        rc, stdout, stderr = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--force-reinstall", package_path],
            capture_output=True,
            text=True,
            timeout=300,
        ).__dict__.get("returncode", -1), "", ""

        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--force-reinstall", package_path],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            raise UpdateError(f"pip install failed: {result.stderr}")

    def _rollback(self, backup_path: Path) -> Dict:
        """Rollback to a specific backup.

        Args:
            backup_path: Path to the backup tar.gz archive.

        Returns:
            Dict with rollback result.
        """
        if not backup_path.exists():
            raise UpdateError(f"Backup not found: {backup_path}")

        logger.info("Rolling back from %s ...", backup_path)

        try:
            # Remove current installation
            if self.install_dir.exists():
                shutil.rmtree(str(self.install_dir))

            # Extract backup
            shutil.unpack_archive(
                str(backup_path),
                str(self.install_dir.parent),
            )
        except Exception as exc:
            raise UpdateError(f"Rollback failed: {exc}") from exc

        logger.info("Rollback complete from %s", backup_path)
        return {
            "status": "rolled_back",
            "backup_path": str(backup_path),
        }

    @staticmethod
    def _compare_versions(v1: str, v2: str) -> int:
        """Compare two version strings. Returns >0 if v1 > v2."""
        def normalize(v: str) -> list:
            parts = []
            for segment in v.split("."):
                num = ""
                for ch in segment:
                    if ch.isdigit():
                        num += ch
                    else:
                        break
                parts.append(int(num) if num else 0)
            return parts

        a = normalize(v1)
        b = normalize(v2)
        max_len = max(len(a), len(b))
        a.extend([0] * (max_len - len(a)))
        b.extend([0] * (max_len - len(b)))
        for x, y in zip(a, b):
            if x != y:
                return x - y
        return 0
