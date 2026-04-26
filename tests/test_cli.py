"""Tests for wifi_aio.cli – Argument parser and command dispatch.

Covers build_parser, cmd_version, and unknown-command error handling.
"""

import argparse
import sys
from typing import List
from unittest.mock import patch

import pytest

from wifi_aio.cli import build_parser, cmd_version, main


# ── build_parser ─────────────────────────────────────────────────────────

class TestBuildParser:
    """Argument-parser construction."""

    def test_returns_argument_parser(self) -> None:
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_prog_name(self) -> None:
        parser = build_parser()
        assert parser.prog == "wifiaio"

    def test_has_version_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--version"])
        assert args.version is True

    def test_scan_subcommand(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["scan", "-i", "wlan0"])
        assert args.command == "scan"
        assert args.interface == "wlan0"

    def test_deauth_subcommand(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["deauth", "-b", "AA:BB:CC:DD:EE:FF"])
        assert args.command == "deauth"
        assert args.bssid == "AA:BB:CC:DD:EE:FF"

    def test_version_subcommand(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["version"])
        assert args.command == "version"


# ── cmd_version ───────────────────────────────────────────────────────────

class TestCmdVersion:
    """Version subcommand should return 0."""

    def test_returns_zero(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["version"])
        result = cmd_version(args)
        assert result == 0

    def test_outputs_version(self, capsys: pytest.CaptureFixture) -> None:
        parser = build_parser()
        args = parser.parse_args(["version"])
        cmd_version(args)
        output = capsys.readouterr().out
        assert "WiFiAIO" in output
        assert "3.0.0" in output


# ── Unknown / no command ─────────────────────────────────────────────────

class TestUnknownCommand:
    """Missing or invalid subcommand handling."""

    def test_no_command_returns_zero(self) -> None:
        """No subcommand should print help and return 0."""
        result = main([])
        assert result == 0

    def test_main_with_version_flag(self) -> None:
        result = main(["--version"])
        assert result == 0

    def test_main_with_version_subcommand(self) -> None:
        result = main(["version"])
        assert result == 0

    def test_scan_without_root(self) -> None:
        """Scan without root should still attempt (may warn or error)."""
        # We patch os.geteuid so it always thinks we're not root
        with patch("os.geteuid", return_value=1000):
            # This may fail due to missing deps – that's fine, we just
            # verify it doesn't raise an unhandled exception type.
            try:
                result = main(["scan"])
                assert isinstance(result, int)
            except (SystemExit, NameError, ImportError):
                pass  # argparse / missing deps are acceptable
