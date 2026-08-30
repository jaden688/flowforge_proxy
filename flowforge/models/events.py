"""
Pydantic data models for real-time WebSocket and SSE event payloads.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Standard event types emitted by FlowForge Pub/Sub Hub."""
    FLOW_CREATED = "flow_created"
    FLOW_COMPLETED = "flow_completed"
    TRIAGE_ANNOTATED = "triage_annotated"
    WS_FRAME = "ws_frame"
    PROXY_STATS = "proxy_stats"
    MATRIX_PROGRESS = "matrix_progress"

    # Dynamic Schema & Dossier Events
    SCHEMA_UPDATED = "schema_updated"
    DOSSIER_UPDATED = "dossier_updated"

    # Automated Proposal Events
    PROPOSAL_CREATED = "proposal_created"
    PROPOSAL_UPDATED = "proposal_updated"
    PROPOSAL_EXECUTED = "proposal_executed"
    PROPOSAL_DISMISSED = "proposal_dismissed"
    PROPOSAL_STATS = "proposal_stats"

    # Active Intruder Events
    INTRUDER_RESULT = "intruder_result"
    INTRUDER_STATUS = "intruder_status"


class FlowEvent(BaseModel):
    """Standardized event packet broadcast to WebSocket and SSE clients."""
    event: str
    type: Optional[str] = None
    event_type: Optional[str] = None
    flow_id: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)
    data: Dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        # Keep event, type, and event_type aligned for dual compatibility
        if not self.type:
            self.type = self.event
        if not self.event_type:
            self.event_type = self.event
        if not self.event:
            self.event = self.type or self.event_type or ""
        if not self.flow_id and isinstance(self.data, dict):
            self.flow_id = self.data.get("flow_id")


class ProxyStatsEvent(BaseModel):
    """Live telemetry packet emitted by proxy engine."""
    uptime_seconds: float
    total_flows: int
    active_connections: int
    db_queue_size: int
    total_ws_messages: int
    is_running: bool
    listen_host: str
    listen_port: int


class MatrixProgressEvent(BaseModel):
    """Event emitted during test matrix execution."""
    matrix_id: str
    case_index: int
    total_cases: int
    completed: bool
    status: str
    result: Optional[Dict[str, Any]] = None
