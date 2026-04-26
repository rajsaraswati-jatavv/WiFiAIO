"""WiFiAIO Command-Line Interface.

Provides a comprehensive CLI with subcommands for every WiFiAIO operation:
scan, capture, crack, deauth, evil-twin, wps, sniff, signal, vuln,
osint, forensics, bluetooth, geo, speed, password, compliance,
topology, report, export, workflow, config, session, plugin, deps,
tui, web, and more.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from wifi_aio.constants import VERSION, AUTHOR, DEFAULT_CONFIG
from wifi_aio.exceptions import WiFiAIOError, WiFiPermissionError


def _check_root() -> None:
    """Check if running as root, warn if not."""
    import os
    if os.geteuid() != 0:
        print("[!] Warning: Most WiFi operations require root privileges.")
        print("    Consider running with sudo.")


def _get_config(args: argparse.Namespace) -> Any:
    """Get ConfigManager from args or create default."""
    from wifi_aio.config import ConfigManager
    config_path = getattr(args, "config", None)
    if config_path:
        return ConfigManager(config_path=config_path)
    return ConfigManager()


def _print_json(data: Any) -> None:
    """Pretty-print JSON data."""
    if isinstance(data, (dict, list)):
        print(json.dumps(data, indent=2, default=str))
    else:
        print(data)


def _print_table(headers: List[str], rows: List[List[str]], title: str = "") -> None:
    """Print a formatted table using Rich if available, else plain text."""
    try:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        table = Table(title=title, show_header=True, header_style="bold magenta")
        for h in headers:
            table.add_column(h)
        for row in rows:
            table.add_row(*[str(c) for c in row])
        console.print(table)
    except ImportError:
        # Fallback plain text
        if title:
            print(f"\n{title}")
            print("=" * len(title))
        fmt = "  ".join(f"{{:<{max(len(h), 12)}}}" for h in headers)
        print(fmt.format(*headers))
        print("-" * len(fmt.format(*headers)))
        for row in rows:
            print(fmt.format(*[str(c)[:12] for c in row]))


# ── Subcommand Handlers ────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> int:
    """Scan for wireless networks."""
    _check_root()
    config = _get_config(args)
    interface = args.interface or config.get("general.interface", "wlan0")
    timeout = args.timeout or config.get("scan.timeout", 30)

    from wifi_aio.core.network_scanner import NetworkScanner
    scanner = NetworkScanner(interface=interface, config=config)

    print(f"[*] Scanning on {interface} for {timeout}s...")
    try:
        if args.passive:
            networks = scanner.scan_passive(timeout=timeout)
        else:
            networks = scanner.scan_active(timeout=timeout)

        if not networks:
            print("[!] No networks found.")
            return 0

        headers = ["SSID", "BSSID", "Channel", "Signal", "Security", "Vendor"]
        rows = []
        for n in networks:
            rows.append([
                n.get("ssid", "<hidden>"),
                n.get("bssid", "Unknown"),
                str(n.get("channel", "?")),
                str(n.get("signal_dbm", -100)),
                n.get("security", "Unknown"),
                n.get("vendor", "Unknown"),
            ])
        _print_table(headers, rows, title=f"Found {len(networks)} Network(s)")

        if args.save:
            from wifi_aio.database import Database
            db = Database(config.get("database.path"))
            for n in networks:
                db.insert_ap(
                    bssid=n.get("bssid", ""),
                    ssid=n.get("ssid", ""),
                    channel=n.get("channel", 0),
                    signal=n.get("signal_dbm", -100),
                    security=n.get("security", ""),
                    vendor=n.get("vendor", ""),
                )
            print(f"[*] Results saved to database.")
        return 0
    except WiFiAIOError as e:
        print(f"[!] Error: {e}")
        return 1


def cmd_capture(args: argparse.Namespace) -> int:
    """Capture packets / handshakes."""
    _check_root()
    config = _get_config(args)
    interface = args.interface or config.get("general.interface", "wlan0")

    if args.type == "handshake":
        from wifi_aio.core.handshake_capture import HandshakeCapturer
        capturer = HandshakeCapturer(interface=interface, config=config)
        print(f"[*] Capturing handshake for {args.bssid} on channel {args.channel}...")
        result = capturer.capture_handshake(
            bssid=args.bssid,
            channel=int(args.channel),
            timeout=args.timeout or 300,
            deauth=getattr(args, "deauth", True),
        )
        if result:
            print(f"[+] Handshake captured! Saved to {result.get('output_file', 'N/A')}")
        else:
            print("[-] Handshake capture failed or timed out.")
    elif args.type == "pmkid":
        from wifi_aio.core.handshake_capture import HandshakeCapturer
        capturer = HandshakeCapturer(interface=interface, config=config)
        print(f"[*] Capturing PMKID for {args.bssid}...")
        result = capturer.capture_pmkid(bssid=args.bssid)
        if result:
            print(f"[+] PMKID captured! Saved to {result.get('output_file', 'N/A')}")
        else:
            print("[-] PMKID capture failed.")
    else:
        from wifi_aio.capture.scapy_capture import ScapyCapture
        capture = ScapyCapture(interface=interface, config=config)
        output = args.output or f"/tmp/wifiaio_capture_{int(time.time())}.pcap"
        print(f"[*] Capturing packets on {interface}...")
        capture.start(output_file=output, timeout=args.timeout or 60)
        print(f"[+] Capture saved to {output}")
    return 0


def cmd_crack(args: argparse.Namespace) -> int:
    """Crack WiFi passwords."""
    config = _get_config(args)

    if not args.capture_file:
        print("[!] Error: --capture-file is required")
        return 1

    method = args.method or "dictionary"
    if method == "dictionary":
        from wifi_aio.cracking.dictionary import DictionaryCracker
        wordlist = args.wordlist or config.get("cracking.wordlist", "/usr/share/wordlists/rockyou.txt")
        cracker = DictionaryCracker(config=config)
        print(f"[*] Running dictionary attack with {wordlist}...")
        result = cracker.crack(
            capture_file=args.capture_file,
            wordlist=wordlist,
        )
    elif method == "brute":
        from wifi_aio.cracking.brute_force import BruteForceCracker
        cracker = BruteForceCracker(config=config)
        print("[*] Running brute-force attack...")
        result = cracker.crack(capture_file=args.capture_file)
    elif method == "mask":
        from wifi_aio.cracking.mask_attack import MaskAttack
        cracker = MaskAttack(config=config)
        print(f"[*] Running mask attack with pattern {args.mask or '?d?d?d?d?d?d?d?d'}...")
        result = cracker.crack(
            capture_file=args.capture_file,
            mask=args.mask or "?d?d?d?d?d?d?d?d",
        )
    elif method == "hybrid":
        from wifi_aio.cracking.hybrid import HybridCracker
        wordlist = args.wordlist or config.get("cracking.wordlist", "/usr/share/wordlists/rockyou.txt")
        cracker = HybridCracker(config=config)
        print("[*] Running hybrid attack...")
        result = cracker.crack(
            capture_file=args.capture_file,
            wordlist=wordlist,
        )
    else:
        print(f"[!] Unknown cracking method: {method}")
        return 1

    if result and result.get("password"):
        print(f"[+] Password found: {result['password']}")
        return 0
    else:
        print("[-] Password not found.")
        return 1


def cmd_deauth(args: argparse.Namespace) -> int:
    """Send deauthentication frames."""
    _check_root()
    config = _get_config(args)
    interface = args.interface or config.get("general.interface", "wlan0")
    count = args.count or 5

    from wifi_aio.core.deauth_engine import DeauthEngine
    engine = DeauthEngine(interface=interface, config=config)
    print(f"[*] Sending {count} deauth frames to {args.bssid}...")
    try:
        result = engine.deauth(
            bssid=args.bssid,
            client=args.client or "FF:FF:FF:FF:FF:FF",
            count=count,
            channel=int(args.channel or 1),
        )
        print(f"[+] Sent {result.get('frames_sent', count)} deauth frames.")
        return 0
    except WiFiAIOError as e:
        print(f"[!] Error: {e}")
        return 1


def cmd_evil_twin(args: argparse.Namespace) -> int:
    """Launch an Evil Twin / Rogue AP."""
    _check_root()
    config = _get_config(args)

    from wifi_aio.core.evil_twin import EvilTwin
    twin = EvilTwin(config=config)

    if args.action == "start":
        interface = args.interface or config.get("general.interface", "wlan0")
        print(f"[*] Starting Evil Twin '{args.ssid}' on channel {args.channel or 6}...")
        twin.start(
            interface=interface,
            ssid=args.ssid,
            channel=int(args.channel or 6),
        )
        print("[+] Evil Twin AP running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            twin.stop()
            print("[*] Evil Twin stopped.")
    elif args.action == "stop":
        twin.stop()
        print("[*] Evil Twin stopped.")
    return 0


def cmd_wps(args: argparse.Namespace) -> int:
    """WPS attacks (PixieDust / PIN brute-force)."""
    _check_root()
    config = _get_config(args)
    interface = args.interface or config.get("general.interface", "wlan0")

    from wifi_aio.core.wps_engine import WPSEngine
    engine = WPSEngine(interface=interface, config=config)

    if args.method == "pixiedust":
        print(f"[*] Running PixieDust attack on {args.bssid}...")
        result = engine.pixiedust(bssid=args.bssid)
    else:
        print(f"[*] Running PIN brute-force on {args.bssid}...")
        result = engine.pin_bruteforce(bssid=args.bssid)

    if result and result.get("pin"):
        print(f"[+] WPS PIN: {result['pin']}")
        if result.get("password"):
            print(f"[+] Password: {result['password']}")
    else:
        print("[-] WPS attack failed.")
    return 0


def cmd_vuln(args: argparse.Namespace) -> int:
    """Check for vulnerabilities."""
    config = _get_config(args)

    from wifi_aio.vuln.vuln_report import VulnReport
    reporter = VulnReport(config=config)
    print(f"[*] Checking vulnerabilities for {args.bssid}...")
    findings = reporter.check_all(
        bssid=args.bssid,
        ssid=args.ssid or "",
        security=args.security or "",
    )

    if findings:
        headers = ["Vulnerability", "Severity", "Description"]
        rows = [[f.get("name", ""), f.get("severity", ""), f.get("description", "")] for f in findings]
        _print_table(headers, rows, title=f"Vulnerability Report: {args.bssid}")
    else:
        print("[+] No vulnerabilities found.")
    return 0


def cmd_osint(args: argparse.Namespace) -> int:
    """OSINT intelligence gathering."""
    config = _get_config(args)

    from wifi_aio.core.osint import OSINTEngine
    engine = OSINTEngine(config=config)
    print(f"[*] Running OSINT on {args.bssid}...")
    results = engine.lookup(bssid=args.bssid, ssid=args.ssid or "")
    _print_json(results)
    return 0


def cmd_signal(args: argparse.Namespace) -> int:
    """Analyze WiFi signal strength."""
    _check_root()
    config = _get_config(args)
    interface = args.interface or config.get("general.interface", "wlan0")

    from wifi_aio.core.signal_analyzer import SignalAnalyzer
    analyzer = SignalAnalyzer(interface=interface, config=config)
    print(f"[*] Analyzing signal for {args.bssid}...")
    results = analyzer.analyze(bssid=args.bssid, duration=args.duration or 30)
    _print_json(results)
    return 0


def cmd_sniff(args: argparse.Namespace) -> int:
    """Live packet sniffing."""
    _check_root()
    config = _get_config(args)
    interface = args.interface or config.get("general.interface", "wlan0")

    from wifi_aio.core.packet_sniffer import PacketSniffer
    sniffer = PacketSniffer(interface=interface, config=config)
    print(f"[*] Sniffing on {interface}... Press Ctrl+C to stop.")
    try:
        sniffer.start(timeout=args.timeout or 0)
    except KeyboardInterrupt:
        sniffer.stop()
        print("[*] Sniffing stopped.")
    return 0


def cmd_forensics(args: argparse.Namespace) -> int:
    """PCAP forensics analysis."""
    config = _get_config(args)

    from wifi_aio.core.forensics import ForensicsEngine
    engine = ForensicsEngine(config=config)
    print(f"[*] Analyzing {args.capture_file}...")
    results = engine.analyze(capture_file=args.capture_file)
    _print_json(results)
    return 0


def cmd_geo(args: argparse.Namespace) -> int:
    """Geolocate a BSSID."""
    config = _get_config(args)

    from wifi_aio.core.geolocation import GeoLocator
    locator = GeoLocator(config=config)
    print(f"[*] Geolocating {args.bssid} via {args.method or 'wigle'}...")
    result = locator.locate(bssid=args.bssid, method=args.method or "wigle")
    _print_json(result)
    return 0


def cmd_compliance(args: argparse.Namespace) -> int:
    """Check compliance against security standards."""
    config = _get_config(args)

    from wifi_aio.core.compliance_checker import ComplianceChecker
    checker = ComplianceChecker(config=config)
    print(f"[*] Checking {args.standard or 'all'} compliance for {args.bssid}...")
    result = checker.check(
        bssid=args.bssid,
        ssid=args.ssid or "",
        standard=args.standard or "all",
    )
    _print_json(result)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate audit report."""
    config = _get_config(args)

    from wifi_aio.report_engine import ReportEngine
    engine = ReportEngine(config=config)
    print(f"[*] Generating {args.format or 'html'} report...")
    output = engine.generate(
        session_id=args.session_id or "latest",
        format=args.format or "html",
        output_path=args.output,
    )
    print(f"[+] Report saved to {output}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Export scan data."""
    config = _get_config(args)

    from wifi_aio.export_engine import ExportEngine
    engine = ExportEngine(config=config)
    print(f"[*] Exporting data as {args.format or 'json'}...")
    output = engine.export(
        data_type=args.type or "networks",
        format=args.format or "json",
        output_path=args.output,
    )
    print(f"[+] Data exported to {output}")
    return 0


def cmd_workflow(args: argparse.Namespace) -> int:
    """Execute automation workflows."""
    config = _get_config(args)

    from wifi_aio.automation.workflow_engine import WorkflowEngine
    engine = WorkflowEngine(config=config)

    if args.list:
        workflows = engine.list_workflows()
        headers = ["Name", "Description", "Steps"]
        rows = [[w["name"], w["description"], str(w["steps"])] for w in workflows]
        _print_table(headers, rows, title="Available Workflows")
        return 0

    if args.name:
        print(f"[*] Running workflow: {args.name}...")
        result = engine.run(workflow_name=args.name, params=json.loads(args.params or "{}"))
        if result.get("success"):
            print(f"[+] Workflow completed successfully.")
        else:
            print(f"[-] Workflow failed: {result.get('error', 'Unknown')}")
        return 0 if result.get("success") else 1

    print("[!] Specify --name to run a workflow or --list to see available workflows.")
    return 1


def cmd_config(args: argparse.Namespace) -> int:
    """View or modify configuration."""
    config = _get_config(args)

    if args.action == "show":
        _print_json(config.to_dict())
    elif args.action == "get":
        value = config.get(args.key)
        print(f"{args.key} = {value}")
    elif args.action == "set":
        config.set(args.key, args.value)
        config.save()
        print(f"[+] Set {args.key} = {args.value}")
    elif args.action == "reset":
        config.reset()
        print("[+] Configuration reset to defaults.")
    return 0


def cmd_session(args: argparse.Namespace) -> int:
    """Manage audit sessions."""
    config = _get_config(args)

    from wifi_aio.session import SessionManager
    from wifi_aio.database import Database
    db = Database(config.get("database.path"))
    manager = SessionManager(database=db, config=config)

    if args.action == "list":
        sessions = manager.list_sessions()
        headers = ["ID", "Name", "Created", "Status"]
        rows = [[s["id"], s["name"], s["created"], s["status"]] for s in sessions]
        _print_table(headers, rows, title="Audit Sessions")
    elif args.action == "create":
        session = manager.create(name=args.name or f"session_{int(time.time())}")
        print(f"[+] Session created: {session.get('id', 'N/A')}")
    elif args.action == "export":
        output = manager.export(session_id=args.session_id, format=args.format or "json")
        print(f"[+] Session exported to {output}")
    return 0


def cmd_deps(args: argparse.Namespace) -> int:
    """Check dependency status."""
    from wifi_aio.dependency_checker import check_dependencies
    deps = check_dependencies()

    headers = ["Tool", "Installed", "Version", "Required"]
    rows = [[d["name"], "Yes" if d["installed"] else "No", d.get("version", "N/A"), d.get("required", "")] for d in deps]
    _print_table(headers, rows, title="Dependency Status")

    missing = [d["name"] for d in deps if not d["installed"]]
    if missing:
        print(f"\n[!] Missing: {', '.join(missing)}")
        if args.install:
            from wifi_aio.auto_installer import auto_install
            auto_install(missing)
    return 0


def cmd_tui(args: argparse.Namespace) -> int:
    """Launch the Textual TUI interface."""
    config = _get_config(args)
    from wifi_aio.tui import run_tui
    run_tui(config=config)
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    """Launch the REST API server."""
    import uvicorn
    from wifi_aio.api.server import create_app
    app = create_app()
    host = args.host or "0.0.0.0"
    port = args.port or 8000
    print(f"[*] Starting WiFiAIO API on {host}:{port}")
    print(f"[*] Swagger docs: http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port)
    return 0


def cmd_plugins(args: argparse.Namespace) -> int:
    """Manage plugins."""
    config = _get_config(args)
    from wifi_aio.plugin_manager import PluginManager
    manager = PluginManager(config=config)

    if args.action == "list":
        plugins = manager.list_plugins()
        headers = ["Name", "Version", "Description", "Enabled"]
        rows = [[p["name"], p["version"], p["description"], "Yes" if p["enabled"] else "No"] for p in plugins]
        _print_table(headers, rows, title="Installed Plugins")
    elif args.action == "enable":
        manager.enable(args.plugin_name)
        print(f"[+] Plugin '{args.plugin_name}' enabled.")
    elif args.action == "disable":
        manager.disable(args.plugin_name)
        print(f"[+] Plugin '{args.plugin_name}' disabled.")
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    """Check for / apply updates."""
    from wifi_aio.auto_updater import AutoUpdater
    updater = AutoUpdater()

    if args.check:
        result = updater.check()
        if result.get("update_available"):
            print(f"[+] Update available: {result['latest_version']}")
        else:
            print(f"[*] You're on the latest version ({VERSION}).")
    elif args.apply:
        print("[*] Applying update...")
        result = updater.update()
        if result.get("success"):
            print(f"[+] Updated to {result['version']}!")
        else:
            print(f"[-] Update failed: {result.get('error')}")
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    """Show version information."""
    print(f"WiFiAIO v{VERSION}")
    print(f"Author: {AUTHOR}")
    print(f"Python: {sys.version.split()[0]}")
    return 0


# ── Argument Parser ────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Build the main CLI argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="wifiaio",
        description="WiFiAIO - All-in-One WiFi Security Toolkit",
        epilog="Use 'wifiaio <command> --help' for more info on a command.",
    )
    parser.add_argument("--config", "-c", help="Path to config file")
    parser.add_argument("--version", "-v", action="store_true", help="Show version")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── scan ────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Scan for wireless networks")
    p_scan.add_argument("-i", "--interface", help="Wireless interface")
    p_scan.add_argument("-t", "--timeout", type=int, help="Scan timeout (seconds)")
    p_scan.add_argument("--passive", action="store_true", help="Passive scan mode")
    p_scan.add_argument("--save", action="store_true", help="Save results to database")
    p_scan.set_defaults(func=cmd_scan)

    # ── capture ─────────────────────────────────────────────────────
    p_capture = sub.add_parser("capture", help="Capture packets / handshakes")
    p_capture.add_argument("-i", "--interface", help="Wireless interface")
    p_capture.add_argument("-b", "--bssid", help="Target BSSID")
    p_capture.add_argument("-ch", "--channel", help="Channel number")
    p_capture.add_argument("--type", choices=["handshake", "pmkid", "packets"], default="packets", help="Capture type")
    p_capture.add_argument("-t", "--timeout", type=int, help="Capture timeout")
    p_capture.add_argument("-o", "--output", help="Output file path")
    p_capture.add_argument("--no-deauth", dest="deauth", action="store_false", help="Skip deauth during handshake capture")
    p_capture.set_defaults(func=cmd_capture)

    # ── crack ───────────────────────────────────────────────────────
    p_crack = sub.add_parser("crack", help="Crack WiFi passwords")
    p_crack.add_argument("-f", "--capture-file", required=True, help="Capture file path")
    p_crack.add_argument("-m", "--method", choices=["dictionary", "brute", "mask", "hybrid"], default="dictionary", help="Cracking method")
    p_crack.add_argument("-w", "--wordlist", help="Wordlist path")
    p_crack.add_argument("--mask", help="Mask pattern for mask attack")
    p_crack.set_defaults(func=cmd_crack)

    # ── deauth ──────────────────────────────────────────────────────
    p_deauth = sub.add_parser("deauth", help="Send deauthentication frames")
    p_deauth.add_argument("-i", "--interface", help="Wireless interface")
    p_deauth.add_argument("-b", "--bssid", required=True, help="Target BSSID")
    p_deauth.add_argument("-c", "--client", help="Client MAC (default: broadcast)")
    p_deauth.add_argument("-ch", "--channel", help="Channel")
    p_deauth.add_argument("-n", "--count", type=int, default=5, help="Number of deauth frames")
    p_deauth.set_defaults(func=cmd_deauth)

    # ── evil-twin ───────────────────────────────────────────────────
    p_et = sub.add_parser("evil-twin", help="Evil Twin / Rogue AP")
    p_et.add_argument("action", choices=["start", "stop"], help="Start or stop")
    p_et.add_argument("-i", "--interface", help="Wireless interface")
    p_et.add_argument("-s", "--ssid", help="SSID to clone")
    p_et.add_argument("-ch", "--channel", help="Channel")
    p_et.set_defaults(func=cmd_evil_twin)

    # ── wps ─────────────────────────────────────────────────────────
    p_wps = sub.add_parser("wps", help="WPS attacks")
    p_wps.add_argument("-i", "--interface", help="Wireless interface")
    p_wps.add_argument("-b", "--bssid", required=True, help="Target BSSID")
    p_wps.add_argument("-m", "--method", choices=["pixiedust", "pin"], default="pixiedust", help="WPS attack method")
    p_wps.set_defaults(func=cmd_wps)

    # ── vuln ────────────────────────────────────────────────────────
    p_vuln = sub.add_parser("vuln", help="Vulnerability scanning")
    p_vuln.add_argument("-b", "--bssid", required=True, help="Target BSSID")
    p_vuln.add_argument("-s", "--ssid", help="SSID")
    p_vuln.add_argument("--security", help="Security type")
    p_vuln.set_defaults(func=cmd_vuln)

    # ── osint ───────────────────────────────────────────────────────
    p_osint = sub.add_parser("osint", help="OSINT intelligence")
    p_osint.add_argument("-b", "--bssid", required=True, help="Target BSSID")
    p_osint.add_argument("-s", "--ssid", help="SSID")
    p_osint.set_defaults(func=cmd_osint)

    # ── signal ──────────────────────────────────────────────────────
    p_signal = sub.add_parser("signal", help="Signal analysis")
    p_signal.add_argument("-i", "--interface", help="Wireless interface")
    p_signal.add_argument("-b", "--bssid", required=True, help="Target BSSID")
    p_signal.add_argument("-d", "--duration", type=int, default=30, help="Duration (seconds)")
    p_signal.set_defaults(func=cmd_signal)

    # ── sniff ───────────────────────────────────────────────────────
    p_sniff = sub.add_parser("sniff", help="Live packet sniffing")
    p_sniff.add_argument("-i", "--interface", help="Wireless interface")
    p_sniff.add_argument("-t", "--timeout", type=int, help="Sniff timeout (0 = infinite)")
    p_sniff.set_defaults(func=cmd_sniff)

    # ── forensics ───────────────────────────────────────────────────
    p_f = sub.add_parser("forensics", help="PCAP forensics")
    p_f.add_argument("-f", "--capture-file", required=True, help="PCAP file path")
    p_f.set_defaults(func=cmd_forensics)

    # ── geo ─────────────────────────────────────────────────────────
    p_geo = sub.add_parser("geo", help="Geolocate BSSID")
    p_geo.add_argument("-b", "--bssid", required=True, help="Target BSSID")
    p_geo.add_argument("-m", "--method", choices=["wigle", "google"], default="wigle", help="Geolocation method")
    p_geo.set_defaults(func=cmd_geo)

    # ── compliance ──────────────────────────────────────────────────
    p_comp = sub.add_parser("compliance", help="Compliance checks")
    p_comp.add_argument("-b", "--bssid", required=True, help="Target BSSID")
    p_comp.add_argument("-s", "--ssid", help="SSID")
    p_comp.add_argument("--standard", choices=["pci-dss", "nist", "cis", "iso27001", "all"], default="all", help="Compliance standard")
    p_comp.set_defaults(func=cmd_compliance)

    # ── report ──────────────────────────────────────────────────────
    p_report = sub.add_parser("report", help="Generate reports")
    p_report.add_argument("--session-id", help="Session ID")
    p_report.add_argument("-f", "--format", choices=["html", "json", "csv", "pdf"], default="html", help="Report format")
    p_report.add_argument("-o", "--output", help="Output path")
    p_report.set_defaults(func=cmd_report)

    # ── export ──────────────────────────────────────────────────────
    p_export = sub.add_parser("export", help="Export data")
    p_export.add_argument("--type", choices=["networks", "sessions", "credentials", "vulns"], default="networks", help="Data type")
    p_export.add_argument("-f", "--format", choices=["json", "csv", "xml"], default="json", help="Export format")
    p_export.add_argument("-o", "--output", help="Output path")
    p_export.set_defaults(func=cmd_export)

    # ── workflow ────────────────────────────────────────────────────
    p_wf = sub.add_parser("workflow", help="Automation workflows")
    p_wf.add_argument("--name", help="Workflow name to run")
    p_wf.add_argument("--params", help="JSON params for workflow")
    p_wf.add_argument("--list", action="store_true", help="List available workflows")
    p_wf.set_defaults(func=cmd_workflow)

    # ── config ──────────────────────────────────────────────────────
    p_config = sub.add_parser("config", help="Configuration")
    p_config.add_argument("action", choices=["show", "get", "set", "reset"], help="Config action")
    p_config.add_argument("--key", help="Config key")
    p_config.add_argument("--value", help="Config value")
    p_config.set_defaults(func=cmd_config)

    # ── session ─────────────────────────────────────────────────────
    p_session = sub.add_parser("session", help="Manage sessions")
    p_session.add_argument("action", choices=["list", "create", "export"], help="Session action")
    p_session.add_argument("--name", help="Session name")
    p_session.add_argument("--session-id", help="Session ID")
    p_session.add_argument("--format", choices=["json", "csv"], default="json", help="Export format")
    p_session.set_defaults(func=cmd_session)

    # ── deps ────────────────────────────────────────────────────────
    p_deps = sub.add_parser("deps", help="Check dependencies")
    p_deps.add_argument("--install", action="store_true", help="Auto-install missing")
    p_deps.set_defaults(func=cmd_deps)

    # ── tui ─────────────────────────────────────────────────────────
    p_tui = sub.add_parser("tui", help="Launch TUI interface")
    p_tui.set_defaults(func=cmd_tui)

    # ── web ─────────────────────────────────────────────────────────
    p_web = sub.add_parser("web", help="Launch REST API server")
    p_web.add_argument("--host", default="0.0.0.0", help="Bind host")
    p_web.add_argument("--port", type=int, default=8000, help="Bind port")
    p_web.set_defaults(func=cmd_web)

    # ── plugins ─────────────────────────────────────────────────────
    p_plugins = sub.add_parser("plugins", help="Manage plugins")
    p_plugins.add_argument("action", choices=["list", "enable", "disable"], help="Plugin action")
    p_plugins.add_argument("--plugin-name", help="Plugin name")
    p_plugins.set_defaults(func=cmd_plugins)

    # ── update ──────────────────────────────────────────────────────
    p_update = sub.add_parser("update", help="Check / apply updates")
    p_update.add_argument("--check", action="store_true", help="Check for updates")
    p_update.add_argument("--apply", action="store_true", help="Apply update")
    p_update.set_defaults(func=cmd_update)

    # ── version ─────────────────────────────────────────────────────
    p_ver = sub.add_parser("version", help="Show version")
    p_ver.set_defaults(func=cmd_version)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for the WiFiAIO CLI.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 = success, 1 = error).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    # Handle --version flag
    if args.version:
        return cmd_version(args)

    # No subcommand → show help
    if not args.command:
        parser.print_help()
        return 0

    # Dispatch to subcommand handler
    try:
        return args.func(args)
    except WiFiPermissionError:
        print("[!] Permission denied. Run with sudo/root.")
        return 2
    except WiFiAIOError as e:
        print(f"[!] Error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
        return 130
    except Exception as e:
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        if os.environ.get("WIFAIO_DEBUG"):
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
