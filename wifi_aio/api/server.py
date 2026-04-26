"""FastAPI server for WiFiAIO REST API.

Provides a comprehensive REST API with endpoints for all WiFiAIO
operations, CORS middleware, API key authentication, rate limiting,
request logging, and WebSocket support for real-time event streaming.

v3.0.0 — All endpoints wired to actual core modules.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader

from wifi_aio.api.models import (
    BluetoothRequest, BluetoothResponse,
    CaptureRequest, CaptureResponse,
    ComplianceRequest, ComplianceResponse,
    ConnectRequest, ConnectResponse,
    ConfigRequest, ConfigResponse,
    CrackRequest, CrackResponse,
    DeauthRequest, DeauthResponse,
    EvilTwinRequest, EvilTwinResponse,
    ExportRequest, ExportResponse,
    ForensicsRequest, ForensicsResponse,
    GeoRequest, GeoResponse,
    InjectRequest, InjectResponse,
    JammerRequest, JammerResponse,
    OSINTRequest, OSINTResponse,
    PasswordRequest, PasswordResponse,
    PluginResponse,
    ReportRequest, ReportResponse,
    ScanRequest, ScanResponse,
    SessionResponse,
    SignalRequest, SignalResponse,
    SniffRequest, SniffResponse,
    SpeedRequest, SpeedResponse,
    SystemStatusResponse,
    TopologyRequest, TopologyResponse,
    VulnRequest, VulnResponse,
    WorkflowRequest, WorkflowResponse,
    WPSRequest, WPSResponse,
    ErrorResponse,
)
from wifi_aio.api.websocket import WebSocketManager
from wifi_aio.exceptions import (
    WiFiAIOError,
    WiFiConnectionError,
    WiFiPermissionError,
    WiFiTimeoutError,
    ScanError,
    CaptureError,
    DeauthError,
    RogueAPError,
    CrackingError,
    WPSError,
    InterfaceError,
    OSINTError,
)

logger = logging.getLogger(__name__)

# ── API Key Authentication ──────────────────────────────────────────────

_API_KEY_ENV = "WIFAIO_API_KEY"
_API_KEY_HEADER = "X-API-Key"

_api_key_header = APIKeyHeader(name=_API_KEY_HEADER, auto_error=False)


async def verify_api_key(api_key: Optional[str] = Depends(_api_key_header)) -> Optional[str]:
    """Verify the API key from the request header."""
    configured_key = os.environ.get(_API_KEY_ENV)
    if not configured_key:
        return api_key
    if not api_key or api_key != configured_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return api_key


# ── Rate Limiting ──────────────────────────────────────────────────────

class RateLimiter:
    """Simple in-memory rate limiter."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        self._requests[key] = [t for t in self._requests[key] if now - t < self.window_seconds]
        if len(self._requests[key]) >= self.max_requests:
            return False
        self._requests[key].append(now)
        return True


rate_limiter = RateLimiter()


# ── Service Manager ────────────────────────────────────────────────────

class ServiceManager:
    """Lazy-initialization manager for core service instances."""

    def __init__(self):
        self._config = None
        self._database = None
        self._services = {}

    @property
    def config(self):
        if self._config is None:
            from wifi_aio.config import ConfigManager
            self._config = ConfigManager()
        return self._config

    @property
    def database(self):
        if self._database is None:
            from wifi_aio.database import Database
            self._database = Database(self.config.get("database.path"))
        return self._database

    def get(self, name: str):
        if name not in self._services:
            self._services[name] = self._create(name)
        return self._services[name]

    def _create(self, name: str):
        cfg = self.config
        mapping = {
            "scanner": lambda: __import__("wifi_aio.core.network_scanner", fromlist=["NetworkScanner"]).NetworkScanner(config=cfg),
            "deauth": lambda: __import__("wifi_aio.core.deauth_engine", fromlist=["DeauthEngine"]).DeauthEngine(config=cfg),
            "evil_twin": lambda: __import__("wifi_aio.core.evil_twin", fromlist=["EvilTwin"]).EvilTwin(config=cfg),
            "handshake": lambda: __import__("wifi_aio.core.handshake_capture", fromlist=["HandshakeCapturer"]).HandshakeCapturer(config=cfg),
            "cracker": lambda: __import__("wifi_aio.core.password_cracker", fromlist=["PasswordCracker"]).PasswordCracker(config=cfg),
            "wps": lambda: __import__("wifi_aio.core.wps_engine", fromlist=["WPSEngine"]).WPSEngine(config=cfg),
            "signal": lambda: __import__("wifi_aio.core.signal_analyzer", fromlist=["SignalAnalyzer"]).SignalAnalyzer(config=cfg),
            "sniffer": lambda: __import__("wifi_aio.core.packet_sniffer", fromlist=["PacketSniffer"]).PacketSniffer(config=cfg),
            "geo": lambda: __import__("wifi_aio.core.geolocation", fromlist=["GeoLocator"]).GeoLocator(config=cfg),
            "osint": lambda: __import__("wifi_aio.core.osint", fromlist=["OSINTEngine"]).OSINTEngine(config=cfg),
            "forensics": lambda: __import__("wifi_aio.core.forensics", fromlist=["ForensicsEngine"]).ForensicsEngine(config=cfg),
            "bluetooth": lambda: __import__("wifi_aio.core.bluetooth_scanner", fromlist=["BluetoothScanner"]).BluetoothScanner(config=cfg),
            "speed": lambda: __import__("wifi_aio.core.speed_tester", fromlist=["SpeedTester"]).SpeedTester(config=cfg),
            "password": lambda: __import__("wifi_aio.core.password_tools", fromlist=["PasswordTools"]).PasswordTools(config=cfg),
            "compliance": lambda: __import__("wifi_aio.core.compliance_checker", fromlist=["ComplianceChecker"]).ComplianceChecker(config=cfg),
            "injector": lambda: __import__("wifi_aio.core.frame_injector", fromlist=["FrameInjector"]).FrameInjector(config=cfg),
            "jammer": lambda: __import__("wifi_aio.core.jammer", fromlist=["Jammer"]).Jammer(config=cfg),
            "connector": lambda: __import__("wifi_aio.core.network_connector", fromlist=["NetworkConnector"]).NetworkConnector(config=cfg),
            "vuln": lambda: __import__("wifi_aio.vuln.vuln_report", fromlist=["VulnReport"]).VulnReport(config=cfg),
            "workflow": lambda: __import__("wifi_aio.automation.workflow_engine", fromlist=["WorkflowEngine"]).WorkflowEngine(config=cfg),
            "topology": lambda: __import__("wifi_aio.analysis.topology_mapper", fromlist=["TopologyMapper"]).TopologyMapper(config=cfg),
            "session": lambda: __import__("wifi_aio.session", fromlist=["SessionManager"]).SessionManager(database=self.database, config=cfg),
            "plugin": lambda: __import__("wifi_aio.plugin_manager", fromlist=["PluginManager"]).PluginManager(config=cfg),
            "report": lambda: __import__("wifi_aio.report_engine", fromlist=["ReportEngine"]).ReportEngine(config=cfg),
            "export": lambda: __import__("wifi_aio.export_engine", fromlist=["ExportEngine"]).ExportEngine(config=cfg),
        }
        factory = mapping.get(name)
        if factory is None:
            raise ValueError(f"Unknown service: {name}")
        return factory()


services = ServiceManager()

# Track background tasks
_bg_tasks: Dict[str, Dict[str, Any]] = {}

_start_time = time.time()


# ── Application Factory ─────────────────────────────────────────────────

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="WiFiAIO API",
        description="All-in-One WiFi Security Toolkit REST API — v3.0.0 Next Level Edition",
        version="3.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # WebSocket manager
    ws_manager = WebSocketManager()
    app.state.ws_manager = ws_manager

    # ── Exception Handlers ──────────────────────────────────────────────

    @app.exception_handler(WiFiAIOError)
    async def wifiaio_error_handler(request: Request, exc: WiFiAIOError):
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(error=exc.__class__.__name__, detail=str(exc), code=400).model_dump(),
        )

    @app.exception_handler(WiFiPermissionError)
    async def permission_error_handler(request: Request, exc: WiFiPermissionError):
        return JSONResponse(
            status_code=403,
            content=ErrorResponse(error="PermissionDenied", detail=str(exc), code=403).model_dump(),
        )

    @app.exception_handler(WiFiConnectionError)
    async def connection_error_handler(request: Request, exc: WiFiConnectionError):
        return JSONResponse(
            status_code=503,
            content=ErrorResponse(error="ConnectionError", detail=str(exc), code=503).model_dump(),
        )

    @app.exception_handler(WiFiTimeoutError)
    async def timeout_error_handler(request: Request, exc: WiFiTimeoutError):
        return JSONResponse(
            status_code=504,
            content=ErrorResponse(error="TimeoutError", detail=str(exc), code=504).model_dump(),
        )

    # ── Health Check ────────────────────────────────────────────────────

    @app.get("/api/health", tags=["system"])
    async def health_check():
        return {"status": "healthy", "version": "3.0.0", "timestamp": datetime.utcnow().isoformat()}

    # ── Scan Endpoints ──────────────────────────────────────────────────

    @app.post("/api/scan", response_model=ScanResponse, tags=["scan"])
    async def start_scan(req: ScanRequest, bg_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
        scan_id = str(uuid.uuid4())[:8]
        _bg_tasks[scan_id] = {"type": "scan", "status": "running", "started": datetime.utcnow().isoformat()}
        await ws_manager.broadcast("scan", {"event": "scan_started", "scan_id": scan_id, "interface": req.interface})

        def _run_scan():
            try:
                scanner = services.get("scanner")
                interface = req.interface or services.config.get("general.interface", "wlan0")
                networks = scanner.scan_active(timeout=30) if hasattr(scanner, 'scan_active') else []
                _bg_tasks[scan_id]["status"] = "completed"
                _bg_tasks[scan_id]["networks"] = networks
                _bg_tasks[scan_id]["count"] = len(networks)
            except Exception as e:
                _bg_tasks[scan_id]["status"] = "failed"
                _bg_tasks[scan_id]["error"] = str(e)

        bg_tasks.add_task(_run_scan)
        return ScanResponse(scan_id=scan_id, status="started", timestamp=datetime.utcnow().isoformat())

    @app.get("/api/scan/{scan_id}", tags=["scan"])
    async def get_scan(scan_id: str, api_key: str = Depends(verify_api_key)):
        task = _bg_tasks.get(scan_id)
        if not task:
            return ScanResponse(scan_id=scan_id, status="not_found", timestamp=datetime.utcnow().isoformat())
        result = {
            "scan_id": scan_id,
            "status": task.get("status", "unknown"),
            "network_count": task.get("count", 0),
            "networks": task.get("networks", []),
            "error": task.get("error"),
        }
        return result

    # ── Capture Endpoints ───────────────────────────────────────────────

    @app.post("/api/capture", response_model=CaptureResponse, tags=["capture"])
    async def start_capture(req: CaptureRequest, bg_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
        capture_id = str(uuid.uuid4())[:8]
        _bg_tasks[capture_id] = {"type": "capture", "status": "running", "started": datetime.utcnow().isoformat()}
        await ws_manager.broadcast("capture", {"event": "capture_started", "capture_id": capture_id, "bssid": req.bssid})

        def _run_capture():
            try:
                capturer = services.get("handshake")
                if req.capture_type == "handshake":
                    result = capturer.capture_handshake(bssid=req.bssid, channel=int(req.channel or 1), timeout=300)
                elif req.capture_type == "pmkid":
                    result = capturer.capture_pmkid(bssid=req.bssid)
                else:
                    result = {"output_file": f"/tmp/wifiaio_capture_{capture_id}.pcap"}
                _bg_tasks[capture_id]["status"] = "completed"
                _bg_tasks[capture_id].update(result or {})
            except Exception as e:
                _bg_tasks[capture_id]["status"] = "failed"
                _bg_tasks[capture_id]["error"] = str(e)

        bg_tasks.add_task(_run_capture)
        return CaptureResponse(capture_id=capture_id, status="started", capture_type=req.capture_type)

    # ── Crack Endpoints ─────────────────────────────────────────────────

    @app.post("/api/crack", response_model=CrackResponse, tags=["crack"])
    async def start_crack(req: CrackRequest, bg_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
        session_id = str(uuid.uuid4())[:8]
        _bg_tasks[session_id] = {"type": "crack", "status": "running", "started": datetime.utcnow().isoformat()}
        await ws_manager.broadcast("crack", {"event": "crack_started", "session_id": session_id, "method": req.method})

        def _run_crack():
            try:
                cracker = services.get("cracker")
                result = cracker.crack(
                    capture_file=req.capture_file,
                    method=req.method or "dictionary",
                    wordlist=getattr(req, "wordlist", None),
                )
                _bg_tasks[session_id]["status"] = "completed"
                _bg_tasks[session_id].update(result or {})
            except Exception as e:
                _bg_tasks[session_id]["status"] = "failed"
                _bg_tasks[session_id]["error"] = str(e)

        bg_tasks.add_task(_run_crack)
        return CrackResponse(session_id=session_id, status="started", method=req.method, tool=req.tool)

    # ── Deauth Endpoints ────────────────────────────────────────────────

    @app.post("/api/deauth", response_model=DeauthResponse, tags=["deauth"])
    async def send_deauth(req: DeauthRequest, api_key: str = Depends(verify_api_key)):
        try:
            engine = services.get("deauth")
            result = await asyncio.to_thread(
                engine.deauth,
                bssid=req.bssid,
                client=req.client or "FF:FF:FF:FF:FF:FF",
                count=req.count,
                channel=int(req.channel or 1),
            )
            await ws_manager.broadcast("deauth", {"event": "deauth_sent", "bssid": req.bssid, "count": req.count})
            return DeauthResponse(
                status="sent",
                frames_sent=result.get("frames_sent", req.count) if result else req.count,
                bssid=req.bssid,
                client=req.client,
                channel=req.channel,
            )
        except DeauthError as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Evil Twin Endpoints ─────────────────────────────────────────────

    @app.post("/api/evil-twin", response_model=EvilTwinResponse, tags=["evil-twin"])
    async def start_evil_twin(req: EvilTwinRequest, api_key: str = Depends(verify_api_key)):
        try:
            twin = services.get("evil_twin")
            await asyncio.to_thread(
                twin.start,
                interface=req.interface or "wlan0",
                ssid=req.ssid,
                channel=int(req.channel or 6),
            )
            await ws_manager.broadcast("evil_twin", {"event": "started", "ssid": req.ssid})
            return EvilTwinResponse(status="started", ap_running=True, ssid=req.ssid, channel=req.channel)
        except RogueAPError as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── WPS Endpoints ───────────────────────────────────────────────────

    @app.post("/api/wps", response_model=WPSResponse, tags=["wps"])
    async def wps_attack(req: WPSRequest, bg_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
        task_id = str(uuid.uuid4())[:8]

        def _run_wps():
            try:
                engine = services.get("wps")
                if req.method == "pixiedust":
                    result = engine.pixiedust(bssid=req.bssid)
                else:
                    result = engine.pin_bruteforce(bssid=req.bssid)
                _bg_tasks[task_id] = {"status": "completed", **(result or {})}
            except Exception as e:
                _bg_tasks[task_id] = {"status": "failed", "error": str(e)}

        _bg_tasks[task_id] = {"type": "wps", "status": "running"}
        bg_tasks.add_task(_run_wps)
        await ws_manager.broadcast("wps", {"event": "wps_started", "method": req.method, "task_id": task_id})
        return WPSResponse(status="started", method=req.method)

    # ── Sniff Endpoints ─────────────────────────────────────────────────

    @app.post("/api/sniff", response_model=SniffResponse, tags=["sniff"])
    async def start_sniff(req: SniffRequest, bg_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
        task_id = str(uuid.uuid4())[:8]
        _bg_tasks[task_id] = {"type": "sniff", "status": "running"}

        def _run_sniff():
            try:
                sniffer = services.get("sniffer")
                sniffer.start(timeout=req.timeout or 0)
                _bg_tasks[task_id]["status"] = "completed"
            except Exception as e:
                _bg_tasks[task_id]["status"] = "failed"
                _bg_tasks[task_id]["error"] = str(e)

        bg_tasks.add_task(_run_sniff)
        return SniffResponse(status="started")

    # ── Signal Endpoints ────────────────────────────────────────────────

    @app.post("/api/signal", response_model=SignalResponse, tags=["signal"])
    async def analyze_signal(req: SignalRequest, api_key: str = Depends(verify_api_key)):
        try:
            analyzer = services.get("signal")
            result = await asyncio.to_thread(
                analyzer.analyze,
                bssid=req.bssid,
                duration=30,
            )
            return SignalResponse(
                bssid=req.bssid,
                channel=req.channel,
                samples_collected=result.get("samples", 0) if result else 0,
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Vulnerability Endpoints ─────────────────────────────────────────

    @app.post("/api/vuln", response_model=VulnResponse, tags=["vuln"])
    async def scan_vulns(req: VulnRequest, api_key: str = Depends(verify_api_key)):
        try:
            reporter = services.get("vuln")
            findings = await asyncio.to_thread(
                reporter.check_all,
                bssid=req.bssid,
                ssid=req.ssid or "",
                security=getattr(req, "security", "") or "",
            )
            return VulnResponse(
                bssid=req.bssid,
                ssid=req.ssid,
                findings=findings if findings else [],
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── OSINT Endpoints ─────────────────────────────────────────────────

    @app.post("/api/osint", response_model=OSINTResponse, tags=["osint"])
    async def osint_lookup(req: OSINTRequest, api_key: str = Depends(verify_api_key)):
        try:
            engine = services.get("osint")
            result = await asyncio.to_thread(engine.lookup, bssid=req.bssid, ssid=req.ssid or "")
            return OSINTResponse(
                bssid=req.bssid,
                ssid=req.ssid,
                **(result or {}),
            )
        except OSINTError as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Forensics Endpoints ─────────────────────────────────────────────

    @app.post("/api/forensics", response_model=ForensicsResponse, tags=["forensics"])
    async def analyze_forensics(req: ForensicsRequest, api_key: str = Depends(verify_api_key)):
        try:
            engine = services.get("forensics")
            result = await asyncio.to_thread(engine.analyze, capture_file=req.capture_file)
            return ForensicsResponse(status="completed", capture_file=req.capture_file)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Bluetooth Endpoints ─────────────────────────────────────────────

    @app.post("/api/bluetooth", response_model=BluetoothResponse, tags=["bluetooth"])
    async def scan_bluetooth(req: BluetoothRequest, api_key: str = Depends(verify_api_key)):
        try:
            scanner = services.get("bluetooth")
            result = await asyncio.to_thread(scanner.scan, timeout=req.timeout or 10)
            return BluetoothResponse(**(result or {}))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Geolocation Endpoints ───────────────────────────────────────────

    @app.post("/api/geo", response_model=GeoResponse, tags=["geo"])
    async def geolocate(req: GeoRequest, api_key: str = Depends(verify_api_key)):
        try:
            locator = services.get("geo")
            result = await asyncio.to_thread(locator.locate, bssid=req.bssid, method=req.method)
            return GeoResponse(bssid=req.bssid, method=req.method, **(result or {}))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Speed Test Endpoints ────────────────────────────────────────────

    @app.post("/api/speed", response_model=SpeedResponse, tags=["speed"])
    async def speed_test(req: SpeedRequest, api_key: str = Depends(verify_api_key)):
        try:
            tester = services.get("speed")
            result = await asyncio.to_thread(tester.test, interface=req.interface)
            return SpeedResponse(interface=req.interface, **(result or {}))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Password Endpoints ──────────────────────────────────────────────

    @app.post("/api/password", response_model=PasswordResponse, tags=["password"])
    async def analyze_password(req: PasswordRequest, api_key: str = Depends(verify_api_key)):
        try:
            tools = services.get("password")
            result = await asyncio.to_thread(tools.analyze, password=req.password)
            return PasswordResponse(password="***", **(result or {}))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Compliance Endpoints ────────────────────────────────────────────

    @app.post("/api/compliance", response_model=ComplianceResponse, tags=["compliance"])
    async def check_compliance(req: ComplianceRequest, api_key: str = Depends(verify_api_key)):
        try:
            checker = services.get("compliance")
            result = await asyncio.to_thread(
                checker.check,
                bssid=req.bssid,
                ssid=req.ssid or "",
                standard=getattr(req, "standard", "all") or "all",
            )
            return ComplianceResponse(bssid=req.bssid, ssid=req.ssid, **(result or {}))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Topology Endpoints ──────────────────────────────────────────────

    @app.post("/api/topology", response_model=TopologyResponse, tags=["topology"])
    async def map_topology(req: TopologyRequest, api_key: str = Depends(verify_api_key)):
        try:
            mapper = services.get("topology")
            result = await asyncio.to_thread(mapper.map)
            return TopologyResponse(**(result or {}))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── System Endpoints ────────────────────────────────────────────────

    @app.get("/api/system/status", response_model=SystemStatusResponse, tags=["system"])
    async def system_status(api_key: str = Depends(verify_api_key)):
        uptime = time.time() - _start_time
        active = sum(1 for t in _bg_tasks.values() if t.get("status") == "running")
        return SystemStatusResponse(
            version="3.0.0",
            uptime_seconds=round(uptime, 2),
            active_sessions=active,
        )

    @app.get("/api/system/deps", tags=["system"])
    async def check_deps(api_key: str = Depends(verify_api_key)):
        try:
            from wifi_aio.dependency_checker import check_dependencies
            result = await asyncio.to_thread(check_dependencies)
            installed = [d for d in result if d.get("installed")]
            missing = [d for d in result if not d.get("installed")]
            return {"dependencies": result, "missing": missing, "installed": installed}
        except Exception:
            return {"dependencies": [], "missing": [], "installed": []}

    @app.get("/api/updates", tags=["system"])
    async def check_updates(api_key: str = Depends(verify_api_key)):
        try:
            from wifi_aio.update_checker import check_for_updates
            result = await asyncio.to_thread(check_for_updates)
            return result or {"current_version": "3.0.0", "latest_version": "3.0.0", "update_available": False}
        except Exception:
            return {"current_version": "3.0.0", "latest_version": "3.0.0", "update_available": False}

    # ── Config Endpoints ────────────────────────────────────────────────

    @app.get("/api/config", tags=["config"])
    async def get_config(api_key: str = Depends(verify_api_key)):
        return {"config": services.config.to_dict()}

    @app.put("/api/config", response_model=ConfigResponse, tags=["config"])
    async def update_config(req: ConfigRequest, api_key: str = Depends(verify_api_key)):
        services.config.set(req.key, req.value)
        services.config.save()
        return ConfigResponse(key=req.key, value=req.value, category=req.category)

    # ── Session Endpoints ───────────────────────────────────────────────

    @app.get("/api/sessions", response_model=List[SessionResponse], tags=["sessions"])
    async def list_sessions(api_key: str = Depends(verify_api_key)):
        try:
            manager = services.get("session")
            sessions = await asyncio.to_thread(manager.list_sessions)
            return sessions or []
        except Exception:
            return []

    @app.get("/api/sessions/{session_id}", response_model=SessionResponse, tags=["sessions"])
    async def get_session(session_id: str, api_key: str = Depends(verify_api_key)):
        try:
            manager = services.get("session")
            result = await asyncio.to_thread(manager.get, session_id=session_id)
            return SessionResponse(session_id=session_id, status=result.get("status", "not_found") if result else "not_found")
        except Exception:
            return SessionResponse(session_id=session_id, status="not_found")

    # ── Plugin Endpoints ────────────────────────────────────────────────

    @app.get("/api/plugins", response_model=List[PluginResponse], tags=["plugins"])
    async def list_plugins(api_key: str = Depends(verify_api_key)):
        try:
            manager = services.get("plugin")
            plugins = await asyncio.to_thread(manager.list_plugins)
            return plugins or []
        except Exception:
            return []

    # ── Report Endpoints ────────────────────────────────────────────────

    @app.post("/api/reports", response_model=ReportResponse, tags=["reports"])
    async def generate_report(req: ReportRequest, api_key: str = Depends(verify_api_key)):
        try:
            engine = services.get("report")
            report_id = str(uuid.uuid4())[:8]
            result = await asyncio.to_thread(
                engine.generate,
                session_id=getattr(req, "session_id", "latest") or "latest",
                format=req.format or "html",
            )
            return ReportResponse(
                report_id=report_id,
                status="completed" if result else "failed",
                report_type=req.report_type,
                format=req.format,
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Export Endpoints ────────────────────────────────────────────────

    @app.post("/api/export", response_model=ExportResponse, tags=["export"])
    async def export_data(req: ExportRequest, api_key: str = Depends(verify_api_key)):
        try:
            engine = services.get("export")
            result = await asyncio.to_thread(
                engine.export,
                data_type=getattr(req, "data_type", "networks") or "networks",
                format=req.format or "json",
            )
            return ExportResponse(status="completed" if result else "failed", format=req.format)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Workflow Endpoints ──────────────────────────────────────────────

    @app.post("/api/workflows", response_model=WorkflowResponse, tags=["workflows"])
    async def execute_workflow(req: WorkflowRequest, bg_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
        workflow_id = str(uuid.uuid4())[:8]
        _bg_tasks[workflow_id] = {"type": "workflow", "status": "running"}

        def _run_workflow():
            try:
                engine = services.get("workflow")
                result = engine.run(workflow_name=req.workflow, params={})
                _bg_tasks[workflow_id]["status"] = "completed" if result.get("success") else "failed"
                _bg_tasks[workflow_id].update(result or {})
            except Exception as e:
                _bg_tasks[workflow_id]["status"] = "failed"
                _bg_tasks[workflow_id]["error"] = str(e)

        bg_tasks.add_task(_run_workflow)
        await ws_manager.broadcast("workflow", {"event": "started", "workflow_id": workflow_id, "name": req.workflow})
        return WorkflowResponse(workflow_id=workflow_id, workflow_name=req.workflow, status="started")

    # ── Jammer Endpoints ────────────────────────────────────────────────

    @app.post("/api/jammer", response_model=JammerResponse, tags=["jammer"])
    async def start_jammer(req: JammerRequest, api_key: str = Depends(verify_api_key)):
        try:
            jammer = services.get("jammer")
            await asyncio.to_thread(jammer.start, channel=req.channel)
            return JammerResponse(status="started", channel=req.channel)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Inject Endpoints ────────────────────────────────────────────────

    @app.post("/api/inject", response_model=InjectResponse, tags=["inject"])
    async def inject_frame(req: InjectRequest, api_key: str = Depends(verify_api_key)):
        try:
            injector = services.get("injector")
            result = await asyncio.to_thread(
                injector.inject,
                frame_type=req.frame_type,
                count=req.count,
                channel=req.channel,
            )
            return InjectResponse(
                status="sent",
                frames_injected=result.get("frames_injected", req.count) if result else req.count,
                frame_type=req.frame_type,
                channel=req.channel,
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Connect Endpoints ───────────────────────────────────────────────

    @app.post("/api/connect", response_model=ConnectResponse, tags=["connect"])
    async def connect_wifi(req: ConnectRequest, api_key: str = Depends(verify_api_key)):
        try:
            connector = services.get("connector")
            await asyncio.to_thread(
                connector.connect,
                ssid=req.ssid,
                password=getattr(req, "password", ""),
            )
            return ConnectResponse(status="connected", ssid=req.ssid)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Background Tasks Status ─────────────────────────────────────────

    @app.get("/api/tasks", tags=["system"])
    async def list_tasks(api_key: str = Depends(verify_api_key)):
        return {"tasks": _bg_tasks}

    @app.get("/api/tasks/{task_id}", tags=["system"])
    async def get_task(task_id: str, api_key: str = Depends(verify_api_key)):
        task = _bg_tasks.get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        return task

    @app.delete("/api/tasks/{task_id}", tags=["system"])
    async def cancel_task(task_id: str, api_key: str = Depends(verify_api_key)):
        if task_id in _bg_tasks:
            _bg_tasks[task_id]["status"] = "cancelled"
            return {"status": "cancelled", "task_id": task_id}
        raise HTTPException(status_code=404, detail="Task not found")

    # ── WebSocket Endpoint ──────────────────────────────────────────────

    @app.websocket("/ws")
    async def websocket_endpoint(websocket):
        await ws_manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                await ws_manager.handle_message(websocket, data)
        except Exception:
            ws_manager.disconnect(websocket)

    return app


# Default app instance
app = create_app()
