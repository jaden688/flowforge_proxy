"""
Tier 1 Feature Tests: TLS Telemetry, Request Lifecycle Timing Telemetry,
and Telemetry Domain / SQLite DB Serialization (Features F08–F10).
"""

from __future__ import annotations

import asyncio
import time
import uuid
import pytest

from flowforge.db.connection import get_connection, init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.models.flow import FlowRecord, FlowSummary, RequestModel, ResponseModel
from flowforge.models.telemetry import (
    BandwidthTelemetry,
    FlowTelemetry,
    TimingTelemetry,
    TLSTelemetry,
)


# ===========================================================================
# F08: TLS Handshake Telemetry Extraction Tests
# ===========================================================================

def test_f08_tls_telemetry_model_construction():
    """Verify TLSTelemetry domain model attributes for TLS 1.2 and 1.3."""
    tls13 = TLSTelemetry(
        version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        sni="secure.target.internal",
        alpn="h2",
        resumed=False,
    )
    assert tls13.version == "TLSv1.3"
    assert tls13.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert tls13.sni == "secure.target.internal"
    assert tls13.alpn == "h2"
    assert tls13.resumed is False

    tls12 = TLSTelemetry(
        version="TLSv1.2",
        cipher_suite="ECDHE-RSA-AES128-GCM-SHA256",
        sni="legacy.target.internal",
        alpn="http/1.1",
        resumed=True,
    )
    assert tls12.version == "TLSv1.2"
    assert tls12.resumed is True


def test_f08_tls_telemetry_summary_mapping():
    """Verify FlowRecord with TLS telemetry serializes TLS version and cipher into FlowSummary."""
    tls = TLSTelemetry(
        version="TLSv1.3",
        cipher_suite="TLS_CHACHA20_POLY1305_SHA256",
        sni="api.flowforge.dev",
        alpn="h2",
    )
    flow = FlowRecord(
        id=str(uuid.uuid4()),
        server_host="api.flowforge.dev",
        server_port=443,
        scheme="https",
        request=RequestModel(method="GET", url="https://api.flowforge.dev/status", path="/status"),
        telemetry=FlowTelemetry(tls=tls),
    )

    summary: FlowSummary = flow.to_summary()
    assert summary.tls_version == "TLSv1.3"
    assert summary.cipher_suite == "TLS_CHACHA20_POLY1305_SHA256"
    assert summary.telemetry is not None
    assert summary.telemetry.tls.sni == "api.flowforge.dev"


# ===========================================================================
# F09: Request Lifecycle Timing & Bandwidth Telemetry Tests
# ===========================================================================

def test_f09_timing_telemetry_lifecycle_metrics():
    """Verify precise request timing breakdown (TTFB, DNS, TCP, TLS, transfer latency)."""
    timings = TimingTelemetry(
        dns_ms=2.45,
        tcp_connect_ms=11.20,
        tls_handshake_ms=18.60,
        request_send_ms=1.10,
        ttfb_ms=45.80,
        response_transfer_ms=12.30,
        total_duration_ms=91.45,
    )
    assert timings.ttfb_ms == 45.80
    assert timings.dns_ms == 2.45
    assert timings.total_duration_ms == 91.45


def test_f09_bandwidth_telemetry_calculation():
    """Verify bandwidth telemetry tracking for request/response headers and bodies."""
    bandwidth = BandwidthTelemetry(
        request_headers_bytes=340,
        request_body_bytes=1024,
        response_headers_bytes=280,
        response_body_bytes=4096,
        total_bytes=340 + 1024 + 280 + 4096,
    )
    assert bandwidth.total_bytes == 5740
    assert bandwidth.request_body_bytes == 1024
    assert bandwidth.response_body_bytes == 4096


def test_f09_flow_summary_ttfb_and_bandwidth_aggregation():
    """Verify FlowRecord.to_summary() calculates TTFB and total bandwidth correctly."""
    timings = TimingTelemetry(ttfb_ms=32.1, total_duration_ms=65.0)
    bandwidth = BandwidthTelemetry(
        request_headers_bytes=150,
        request_body_bytes=50,
        response_headers_bytes=200,
        response_body_bytes=800,
        total_bytes=1200,
    )
    flow = FlowRecord(
        id=str(uuid.uuid4()),
        server_host="api.target.com",
        request=RequestModel(method="POST", url="http://api.target.com/data", path="/data", content_length=50),
        response=ResponseModel(status_code=200, content_length=800),
        telemetry=FlowTelemetry(timings=timings, bandwidth=bandwidth),
    )

    summary = flow.to_summary()
    assert summary.ttfb_ms == 32.1
    assert summary.total_bytes == 1200


# ===========================================================================
# F10: Telemetry DB Serialization & Persistence Roundtrip Tests
# ===========================================================================

async def test_f10_telemetry_sqlite_db_persistence_roundtrip(tmp_db_path: str):
    """Verify storing and retrieving FlowRecord with rich telemetry in SQLite database."""
    await init_db(tmp_db_path)

    writer = AsyncDBWriter(db_path=tmp_db_path, flush_interval_ms=10)
    await writer.start()

    repo = FlowRepository(db_path=tmp_db_path)

    flow_id = str(uuid.uuid4())
    tls = TLSTelemetry(
        version="TLSv1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256",
        sni="api.telemetry-test.com",
        alpn="h2",
    )
    timings = TimingTelemetry(
        dns_ms=1.5,
        tcp_connect_ms=8.0,
        tls_handshake_ms=15.0,
        ttfb_ms=28.5,
        response_transfer_ms=5.0,
        total_duration_ms=58.0,
    )
    bandwidth = BandwidthTelemetry(
        request_headers_bytes=220,
        request_body_bytes=100,
        response_headers_bytes=180,
        response_body_bytes=2048,
        total_bytes=2548,
    )
    telemetry = FlowTelemetry(tls=tls, timings=timings, bandwidth=bandwidth)

    flow = FlowRecord(
        id=flow_id,
        timestamp_start=time.time(),
        timestamp_end=time.time() + 0.058,
        duration_ms=58.0,
        server_host="api.telemetry-test.com",
        server_port=443,
        scheme="https",
        request=RequestModel(
            method="GET",
            url="https://api.telemetry-test.com/v1/metrics",
            path="/v1/metrics",
            headers={"host": "api.telemetry-test.com"},
            content_length=100,
        ),
        response=ResponseModel(
            status_code=200,
            headers={"content-type": "application/json"},
            content_length=2048,
            body='{"metrics": "ok"}',
        ),
        tags=["telemetry", "test"],
        triage_data={"telemetry": telemetry.dict()},
        telemetry=telemetry,
    )

    await writer.enqueue_flow(flow)
    await writer.flush()
    await writer.stop()

    # Query back from repository
    retrieved = await repo.get_flow_by_id(flow_id)
    assert retrieved is not None
    assert retrieved.id == flow_id
    assert retrieved.server_host == "api.telemetry-test.com"
    assert retrieved.duration_ms == 58.0

    # Verify telemetry in triage_data
    t_data = retrieved.triage_data
    assert "telemetry" in t_data
    assert t_data["telemetry"]["tls"]["version"] == "TLSv1.3"
    assert t_data["telemetry"]["timings"]["ttfb_ms"] == 28.5
    assert t_data["telemetry"]["bandwidth"]["total_bytes"] == 2548


async def test_f10_flow_summary_fallback_without_telemetry():
    """Verify FlowRecord without telemetry falls back to content_length addition and None timings."""
    flow = FlowRecord(
        id=str(uuid.uuid4()),
        server_host="plain.http.test",
        scheme="http",
        request=RequestModel(method="GET", url="http://plain.http.test/ping", path="/ping", content_length=120),
        response=ResponseModel(status_code=200, content_length=350),
        telemetry=None,
    )

    summary = flow.to_summary()
    assert summary.ttfb_ms is None
    assert summary.total_bytes == 120 + 350
    assert summary.tls_version is None
    assert summary.cipher_suite is None
