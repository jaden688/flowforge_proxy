"""
Pydantic data models for HTTP/HTTPS/WebSocket flows, requests, and responses.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from flowforge.models.telemetry import FlowTelemetry


class RequestModel(BaseModel):
    """Represents an intercepted HTTP request."""
    method: str
    url: str
    path: str
    query_string: str = ""
    query_params: Dict[str, Any] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    content_type: Optional[str] = None
    content_length: int = 0
    body: Optional[str] = None
    body_is_binary: bool = False
    cookies: Dict[str, str] = Field(default_factory=dict)


class ResponseModel(BaseModel):
    """Represents an intercepted HTTP response."""
    status_code: Optional[int] = None
    reason: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    content_type: Optional[str] = None
    content_length: int = 0
    body: Optional[str] = None
    body_is_binary: bool = False
    cookies: Dict[str, str] = Field(default_factory=dict)


class FlowRecord(BaseModel):
    """Complete representation of an intercepted network flow."""
    id: str
    timestamp_start: float = Field(default_factory=time.time)
    timestamp_end: Optional[float] = None
    duration_ms: Optional[float] = None

    # Network & Protocol
    client_ip: Optional[str] = "127.0.0.1"
    client_port: Optional[int] = None
    server_host: str
    server_port: int = 80
    scheme: str = "http"  # 'http', 'https', 'ws', 'wss'
    http_version: str = "HTTP/1.1"

    # Request & Response
    request: RequestModel
    response: Optional[ResponseModel] = None

    # Error & Status
    error_message: Optional[str] = None
    is_websocket: bool = False
    websocket_message_count: int = 0

    # Security & Triage Metadata
    tags: List[str] = Field(default_factory=list)
    triage_data: Dict[str, Any] = Field(default_factory=dict)

    # Operator Flags
    is_intercepted: bool = False
    is_favorite: bool = False
    notes: Optional[str] = None

    # Telemetry
    telemetry: Optional[FlowTelemetry] = None

    def to_summary(self) -> "FlowSummary":
        """Convert full flow to lightweight summary model."""
        ttfb_ms = self.telemetry.timings.ttfb_ms if self.telemetry else None
        total_bytes = (
            self.telemetry.bandwidth.total_bytes
            if self.telemetry
            else (self.request.content_length + (self.response.content_length if self.response else 0))
        )
        tls_version = self.telemetry.tls.version if (self.telemetry and self.telemetry.tls) else None
        cipher_suite = self.telemetry.tls.cipher_suite if (self.telemetry and self.telemetry.tls) else None

        return FlowSummary(
            id=self.id,
            timestamp_start=self.timestamp_start,
            timestamp_end=self.timestamp_end,
            duration_ms=self.duration_ms,
            method=self.request.method,
            url=self.request.url,
            host=self.server_host,
            path=self.request.path,
            scheme=self.scheme,
            status_code=self.response.status_code if self.response else None,
            request_content_length=self.request.content_length,
            response_content_length=self.response.content_length if self.response else 0,
            response_content_type=self.response.content_type if self.response else None,
            is_websocket=self.is_websocket,
            tags=self.tags,
            is_favorite=self.is_favorite,
            has_error=bool(self.error_message),
            error_message=self.error_message,
            ttfb_ms=ttfb_ms,
            total_bytes=total_bytes,
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            telemetry=self.telemetry,
        )


class FlowSummary(BaseModel):
    """Lightweight summary model for tables, lists, and streaming feeds."""
    id: str
    timestamp_start: float
    timestamp_end: Optional[float] = None
    duration_ms: Optional[float] = None
    method: str
    url: str
    host: str
    path: str
    scheme: str
    status_code: Optional[int] = None
    request_content_length: int = 0
    response_content_length: int = 0
    response_content_type: Optional[str] = None
    is_websocket: bool = False
    tags: List[str] = Field(default_factory=list)
    is_favorite: bool = False
    has_error: bool = False
    error_message: Optional[str] = None

    # Summary Telemetry Metrics
    ttfb_ms: Optional[float] = None
    total_bytes: Optional[int] = None
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    telemetry: Optional[FlowTelemetry] = None


class FlowFilterParams(BaseModel):
    """Query parameters for filtering flows in repository / API."""
    page: int = 1
    page_size: int = 50
    host: Optional[str] = None
    method: Optional[str] = None
    status_code: Optional[int] = None
    status_min: Optional[int] = None
    status_max: Optional[int] = None
    scheme: Optional[str] = None
    tag: Optional[str] = None
    is_websocket: Optional[bool] = None
    is_favorite: Optional[bool] = None
    search: Optional[str] = None
    since: Optional[float] = None
    order_by: str = "timestamp_start"
    desc: bool = True


class FlowReplayRequest(BaseModel):
    """Payload for replaying an existing flow with optional overrides."""
    override_method: Optional[str] = None
    override_url: Optional[str] = None
    override_headers: Optional[Dict[str, str]] = None
    override_body: Optional[str] = None


class CustomSendRequest(BaseModel):
    """Payload for sending arbitrary custom requests from operator canvas."""
    method: str = "GET"
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
