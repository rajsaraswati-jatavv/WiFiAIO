"""WebSocket handler for real-time WiFiAIO events.

Manages WebSocket connections and broadcasts real-time events
including scan results, capture status, cracking progress,
deauth alerts, and system notifications.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


# ── Event Types ─────────────────────────────────────────────────────────

EVENT_SCAN_RESULT = "scan_result"
EVENT_SCAN_PROGRESS = "scan_progress"
EVENT_CAPTURE_STATUS = "capture_status"
EVENT_CAPTURE_HANDSHAKE = "capture_handshake"
EVENT_CRACK_PROGRESS = "crack_progress"
EVENT_CRACK_RESULT = "crack_result"
EVENT_DEAUTH_ALERT = "deauth_alert"
EVENT_EVIL_TWIN_CLIENT = "evil_twin_client"
EVENT_EVIL_TWIN_CRED = "evil_twin_credential"
EVENT_WPS_STATUS = "wps_status"
EVENT_SIGNAL_UPDATE = "signal_update"
EVENT_VULN_FOUND = "vulnerability_found"
EVENT_SYSTEM_NOTIFICATION = "system_notification"
EVENT_WORKFLOW_STEP = "workflow_step"
EVENT_ERROR = "error"


@dataclass
class WebSocketEvent:
    """Represents a WebSocket event to be broadcast."""
    event_type: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    source: str = ""

    def to_json(self) -> str:
        """Serialize the event to JSON."""
        return json.dumps({
            "type": self.event_type,
            "data": self.data,
            "timestamp": self.timestamp,
            "source": self.source,
        }, default=str)


class ConnectionManager:
    """Manages individual WebSocket connections with subscription filtering."""

    def __init__(self, websocket: WebSocket, subscriptions: Optional[Set[str]] = None):
        self.websocket = websocket
        self.subscriptions = subscriptions  # None means all events
        self.connected_at = datetime.utcnow().isoformat()
        self.last_ping = time.time()
        self.messages_sent = 0

    def is_subscribed(self, event_type: str) -> bool:
        """Check if this connection is subscribed to an event type.

        Args:
            event_type: Event type to check.

        Returns:
            True if subscribed (or subscribed to all).
        """
        if self.subscriptions is None:
            return True
        return event_type in self.subscriptions


class WebSocketManager:
    """Manages WebSocket connections and event broadcasting.

    Supports topic-based subscriptions, automatic heartbeat/ping,
    connection lifecycle management, and event history buffering.
    """

    def __init__(self, max_history: int = 1000, ping_interval: float = 30.0):
        """Initialize the WebSocket manager.

        Args:
            max_history: Maximum number of historical events to buffer.
            ping_interval: Interval in seconds between ping checks.
        """
        self._connections: Dict[WebSocket, ConnectionManager] = {}
        self._event_history: List[WebSocketEvent] = []
        self._max_history = max_history
        self._ping_interval = ping_interval
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, subscriptions: Optional[Set[str]] = None) -> None:
        """Accept and register a new WebSocket connection.

        Args:
            websocket: The WebSocket connection to register.
            subscriptions: Optional set of event types to subscribe to.
        """
        await websocket.accept()
        async with self._lock:
            self._connections[websocket] = ConnectionManager(websocket, subscriptions)
        logger.info("WebSocket client connected. Total connections: %d", len(self._connections))

        # Send connection acknowledgment
        ack_event = WebSocketEvent(
            event_type="connection_established",
            data={"message": "Connected to WiFiAIO WebSocket", "subscriptions": list(subscriptions) if subscriptions else ["all"]},
            source="server",
        )
        await self._send_to_connection(websocket, ack_event)

        # Send recent event history
        if self._event_history:
            history_event = WebSocketEvent(
                event_type="event_history",
                data={"count": len(self._event_history), "events": [e.data for e in self._event_history[-50:]]},
                source="server",
            )
            await self._send_to_connection(websocket, history_event)

    def disconnect(self, websocket: WebSocket) -> None:
        """Unregister a WebSocket connection.

        Args:
            websocket: The WebSocket connection to remove.
        """
        if websocket in self._connections:
            del self._connections[websocket]
            logger.info("WebSocket client disconnected. Total connections: %d", len(self._connections))

    async def broadcast(self, event_type: str, data: Dict[str, Any], source: str = "") -> int:
        """Broadcast an event to all subscribed connections.

        Args:
            event_type: Type of event (e.g., "scan_result", "crack_progress").
            data: Event payload data.
            source: Source identifier for the event.

        Returns:
            Number of connections the event was sent to.
        """
        event = WebSocketEvent(
            event_type=event_type,
            data=data,
            source=source,
        )

        # Store in history
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]

        # Send to subscribed connections
        sent_count = 0
        async with self._lock:
            dead_connections = []
            for ws, manager in self._connections.items():
                if manager.is_subscribed(event_type):
                    try:
                        await self._send_to_connection(ws, event)
                        sent_count += 1
                    except Exception:
                        dead_connections.append(ws)

            # Clean up dead connections
            for ws in dead_connections:
                self._connections.pop(ws, None)

        return sent_count

    async def send_to(self, websocket: WebSocket, event_type: str, data: Dict[str, Any], source: str = "") -> bool:
        """Send an event to a specific connection.

        Args:
            websocket: Target WebSocket connection.
            event_type: Event type.
            data: Event payload.
            source: Source identifier.

        Returns:
            True if the message was sent successfully.
        """
        event = WebSocketEvent(event_type=event_type, data=data, source=source)
        try:
            await self._send_to_connection(websocket, event)
            return True
        except Exception:
            self.disconnect(websocket)
            return False

    async def handle_message(self, websocket: WebSocket, message: str) -> None:
        """Handle an incoming message from a WebSocket client.

        Supports subscription management commands and ping/pong.

        Args:
            websocket: The WebSocket connection that sent the message.
            message: The raw message string (expected JSON).
        """
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            await self.send_to(websocket, EVENT_ERROR, {"message": "Invalid JSON"})
            return

        command = data.get("command", "")
        manager = self._connections.get(websocket)

        if not manager:
            return

        if command == "subscribe":
            topics = data.get("topics", [])
            if manager.subscriptions is None:
                manager.subscriptions = set()
            manager.subscriptions.update(topics)
            await self.send_to(websocket, "subscription_updated", {
                "subscriptions": list(manager.subscriptions),
            })

        elif command == "unsubscribe":
            topics = data.get("topics", [])
            if manager.subscriptions:
                manager.subscriptions -= set(topics)
            await self.send_to(websocket, "subscription_updated", {
                "subscriptions": list(manager.subscriptions or []),
            })

        elif command == "ping":
            manager.last_ping = time.time()
            await self.send_to(websocket, "pong", {"timestamp": datetime.utcnow().isoformat()})

        elif command == "get_history":
            limit = data.get("limit", 50)
            events = [e.data for e in self._event_history[-limit:]]
            await self.send_to(websocket, "event_history", {"events": events, "count": len(events)})

        elif command == "get_status":
            status = {
                "connected_clients": len(self._connections),
                "events_buffered": len(self._event_history),
                "uptime": "active",
            }
            await self.send_to(websocket, "server_status", status)

        else:
            await self.send_to(websocket, EVENT_ERROR, {"message": f"Unknown command: {command}"})

    async def _send_to_connection(self, websocket: WebSocket, event: WebSocketEvent) -> None:
        """Send an event to a specific WebSocket connection.

        Args:
            websocket: Target WebSocket connection.
            event: Event to send.

        Raises:
            Exception: If the send fails.
        """
        await websocket.send_text(event.to_json())
        manager = self._connections.get(websocket)
        if manager:
            manager.messages_sent += 1

    @property
    def connection_count(self) -> int:
        """Return the number of active connections."""
        return len(self._connections)

    @property
    def event_history_count(self) -> int:
        """Return the number of buffered events."""
        return len(self._event_history)

    def get_connection_info(self) -> List[Dict[str, Any]]:
        """Get information about all active connections.

        Returns:
            List of connection info dicts.
        """
        info = []
        for ws, manager in self._connections.items():
            info.append({
                "connected_at": manager.connected_at,
                "subscriptions": list(manager.subscriptions) if manager.subscriptions else ["all"],
                "messages_sent": manager.messages_sent,
                "last_ping": manager.last_ping,
            })
        return info
