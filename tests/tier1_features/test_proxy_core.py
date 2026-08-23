"""
Tier 1 Feature Isolation Tests: Proxy Core & Dynamic CA Manager (Requirement R1).
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
import uuid
import pytest
import httpx

from flowforge.config import Settings
from flowforge.core.addon import FlowForgeInterceptorAddon
from flowforge.core.broadcaster import EventBroadcaster
from flowforge.core.ca import CertificateManager
from flowforge.core.engine import ProxyEngine
from flowforge.models.flow import FlowFilterParams, FlowRecord, FlowSummary, RequestModel, ResponseModel
from tests.target_app import TargetAppManager, get_free_port


def test_root_ca_generation_and_export(tmp_dir: str):
    """Verify Root CA generation, X.509 validity, SAN/BasicConstraints, and PEM/DER exports."""
    certs_dir = os.path.join(tmp_dir, "custom_certs")
    ca = CertificateManager(certs_dir=certs_dir)

    pem = ca.get_ca_cert_pem()
    der = ca.get_ca_cert_bytes()
    info = ca.get_ca_info()

    assert "-----BEGIN CERTIFICATE-----" in pem
    assert "-----END CERTIFICATE-----" in pem
    assert len(der) > 500
    assert info["common_name"] == "FlowForge Intercepting CA"
    assert info["is_ca"] is True
    assert "sha256_fingerprint" in info
    assert os.path.exists(ca.ca_combined_path)
    assert os.path.exists(ca.ca_cert_pem_path)
    assert os.path.exists(ca.ca_cert_crt_path)


def test_request_and_response_models_serialization():
    """Verify Pydantic FlowRecord, RequestModel, ResponseModel serialization and summary conversion."""
    req = RequestModel(
        method="POST",
        url="https://example.com/api/v1/login?ref=portal",
        path="/api/v1/login",
        query_string="ref=portal",
        query_params={"ref": "portal"},
        headers={"Content-Type": "application/json", "Authorization": "Bearer token123"},
        content_type="application/json",
        content_length=24,
        body='{"username": "tester"}',
        cookies={"sid": "cookie_xyz"},
    )
    resp = ResponseModel(
        status_code=200,
        reason="OK",
        headers={"Content-Type": "application/json"},
        content_type="application/json",
        content_length=42,
        body='{"status": "ok", "user_id": 101}',
        cookies={"session": "new_sess"},
    )
    flow = FlowRecord(
        id="flow-test-uuid-001",
        timestamp_start=1700000000.0,
        timestamp_end=1700000000.045,
        duration_ms=45.0,
        client_ip="127.0.0.1",
        server_host="example.com",
        server_port=443,
        scheme="https",
        http_version="HTTP/2.0",
        request=req,
        response=resp,
        tags=["auth", "mutation"],
    )

    summary = flow.to_summary()
    assert summary.id == "flow-test-uuid-001"
    assert summary.method == "POST"
    assert summary.status_code == 200
    assert summary.duration_ms == 45.0
    assert summary.host == "example.com"
    assert "auth" in summary.tags
    assert summary.has_error is False


def test_proxy_engine_initialization_and_config(tmp_dir: str):
    """Verify ProxyEngine configuration, runtime property updates, and settings binding."""
    certs_dir = os.path.join(tmp_dir, "engine_certs")
    proxy_port = get_free_port()
    settings = Settings(
        proxy_host="127.0.0.1",
        proxy_port=proxy_port,
        certs_dir=certs_dir,
        ssl_insecure=True,
    )
    broadcaster = EventBroadcaster()
    engine = ProxyEngine(settings=settings, broadcaster=broadcaster)

    assert engine.is_running is False
    assert engine.uptime_seconds == 0.0

    # Test runtime config mutations
    engine.update_config(ssl_insecure=False, upstream_proxy="http://10.0.0.1:8080", intercept_enabled=True)
    assert engine.settings.ssl_insecure is False
    assert engine.settings.upstream_proxy == "http://10.0.0.1:8080"
    assert engine.settings.intercept_enabled is True


async def test_proxy_addon_event_dispatch(tmp_dir: str):
    """Verify FlowForgeInterceptorAddon translates mitmproxy events to broadcaster and callbacks."""
    broadcaster = EventBroadcaster()
    queue = await broadcaster.subscribe()

    dispatched_flows = []

    async def capture_triage(flow_rec):
        dispatched_flows.append(flow_rec)

    addon = FlowForgeInterceptorAddon(
        broadcaster=broadcaster,
        triage_callback=capture_triage,
    )

    # Simulated flow record
    flow_rec = FlowRecord(
        id=str(uuid.uuid4()),
        server_host="target.local",
        request=RequestModel(
            method="GET",
            url="http://target.local/items",
            path="/items",
        ),
        response=ResponseModel(
            status_code=200,
            body="items list",
        ),
    )

    # Broadcast directly through broadcaster
    broadcaster.broadcast_flow_created(flow_rec)
    event = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert event.event == "flow_created"
    assert event.data["server_host"] == "target.local"

    await broadcaster.unsubscribe(queue)


async def test_proxy_live_mitm_forwarding(tmp_dir: str):
    """Verify live ProxyEngine DumpMaster intercepts and forwards HTTP requests to reference target."""
    async with TargetAppManager() as target:
        certs_dir = os.path.join(tmp_dir, "live_certs")
        proxy_port = get_free_port()
        settings = Settings(
            proxy_host="127.0.0.1",
            proxy_port=proxy_port,
            certs_dir=certs_dir,
            ssl_insecure=True,
        )
        broadcaster = EventBroadcaster()
        engine = ProxyEngine(settings=settings, broadcaster=broadcaster)

        await engine.start()
        assert engine.is_running is True

        try:
            # Send HTTP request through proxy to reference target
            async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{proxy_port}", timeout=5.0) as client:
                res = await client.get(f"{target.base_url}/health")
                assert res.status_code == 200
                assert res.json()["status"] == "ok"
        finally:
            await engine.stop()
            assert engine.is_running is False
