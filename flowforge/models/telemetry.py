"""
Pydantic data models for rich network, TLS, lifecycle timing, and bandwidth telemetry.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


class TLSTelemetry(BaseModel):
    """TLS connection parameters and cipher negotiation details."""
    version: Optional[str] = None          # e.g. "TLSv1.3", "TLSv1.2"
    cipher_suite: Optional[str] = None     # e.g. "TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES128-GCM-SHA256"
    sni: Optional[str] = None              # Server Name Indication
    alpn: Optional[str] = None             # Negotiated Application-Layer Protocol, e.g. "h2", "http/1.1"
    resumed: bool = False                  # TLS session resumption indicator


class TimingTelemetry(BaseModel):
    """Detailed request/response lifecycle timing metrics in milliseconds."""
    dns_ms: Optional[float] = None
    tcp_connect_ms: Optional[float] = None
    tls_handshake_ms: Optional[float] = None
    request_send_ms: Optional[float] = None
    ttfb_ms: Optional[float] = None        # Time To First Byte in milliseconds
    response_transfer_ms: Optional[float] = None
    total_duration_ms: float = 0.0


class BandwidthTelemetry(BaseModel):
    """Byte transfer metrics across request and response streams."""
    request_headers_bytes: int = 0
    request_body_bytes: int = 0
    response_headers_bytes: int = 0
    response_body_bytes: int = 0
    total_bytes: int = 0


class FlowTelemetry(BaseModel):
    """Aggregate telemetry container serialized with an intercepted flow."""
    tls: Optional[TLSTelemetry] = None
    timings: TimingTelemetry = Field(default_factory=TimingTelemetry)
    bandwidth: BandwidthTelemetry = Field(default_factory=BandwidthTelemetry)


# Backward-compatible and cross-spec aliases
TLSSecurityTelemetry = TLSTelemetry
TimingMetrics = TimingTelemetry
BandwidthMetrics = BandwidthTelemetry
TelemetryData = FlowTelemetry
