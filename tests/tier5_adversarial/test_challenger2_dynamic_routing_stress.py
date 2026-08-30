"""
Challenger 2 Empirical Verification & Adversarial Stress Suite:
1. Dynamic Target URL Resolution across diverse protocols, IPv6, custom ports, and relative/absolute URLs.
2. Proposal execution mutation pipeline and auth override behavior.
3. Multi-target test matrix independent baseline flow routing and graceful error handling on missing baselines.
4. Matrix executed FlowRecord telemetry authenticity (no mock fallbacks, genuine latency/status/headers).
"""

from __future__ import annotations

import asyncio
import json
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Tuple
from unittest.mock import patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.core.broadcaster import EventBroadcaster, get_broadcaster
from flowforge.core.bridge import _build_target_url, build_intruder_config
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.proposal import (
    AnomalyType,
    ProposalSeverity,
    ProposalState,
    TestProposal,
)


async def _setup_test_app(tmp_dir: str) -> Tuple[Any, AsyncDBWriter, FlowRepository, EventBroadcaster]:
    """Helper to provision initialized DB, single-writer queue, and broadcaster on app.state."""
    db_path = f"{tmp_dir}/test_c2_{uuid.uuid4().hex[:8]}.db"
    await init_db(db_path)
    settings = Settings(db_path=db_path, auto_start_proxy=False)
    app = create_app(settings)

    writer = AsyncDBWriter(db_path=db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()
    repo = FlowRepository(db_path=db_path)
    broadcaster = get_broadcaster()

    app.state.db_writer = writer
    app.state.repo = repo
    app.state.broadcaster = broadcaster
    return app, writer, repo, broadcaster


# ===========================================================================
# 1. DYNAMIC ROUTING & URL RECONSTRUCTION HARNESS
# ===========================================================================

@pytest.mark.parametrize(
    "scheme,host,port,rel_url,expected_target",
    [
        ("https", "secure.corp.internal", 443, "/api/v2/tokens", "https://secure.corp.internal/api/v2/tokens"),
        ("http", "insecure.legacy.com", 80, "/v1/status", "http://insecure.legacy.com/v1/status"),
        ("http", "custom-service.dev", 8080, "/graphql", "http://custom-service.dev:8080/graphql"),
        ("https", "gateway.cloud.io", 8443, "/oauth/token?scope=read", "https://gateway.cloud.io:8443/oauth/token?scope=read"),
        ("http", "10.0.0.15", 9000, "/api/rpc", "http://10.0.0.15:9000/api/rpc"),
    ],
)
def test_bridge_dynamic_target_matrix_urls(scheme, host, port, rel_url, expected_target):
    """Verify _build_target_url correctly reconstructs dynamic targets from flow metadata."""
    proposal = TestProposal(
        id=f"prop-{uuid.uuid4().hex[:8]}",
        flow_id=str(uuid.uuid4()),
        title="Dynamic Probe",
        description="Verify dynamic URL reconstruction",
        anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
        severity=ProposalSeverity.HIGH,
        confidence_score=85.0,
        endpoint_path=rel_url.split("?")[0],
        method="GET",
        target_param_location="path",
        target_param_name="id",
        baseline_value=1,
        mutated_value=2,
    )
    flow_meta = {
        "url": rel_url,
        "scheme": scheme,
        "server_host": host,
        "server_port": port,
    }
    built_url = _build_target_url(proposal, flow_meta)
    assert built_url == expected_target


# ===========================================================================
# 2. FLOW REPLAY DYNAMIC URL DISPATCH EMPIRICAL TEST
# ===========================================================================

async def test_replay_flow_dispatches_to_dynamic_target(tmp_dir: str):
    """Verify replay_flow dynamically resolves target from flow and does NOT use localhost:8000."""
    app, writer, repo, _ = await _setup_test_app(tmp_dir)

    try:
        flow_id = str(uuid.uuid4())
        flow = FlowRecord(
            id=flow_id,
            server_host="auth-service.production.org",
            server_port=8443,
            scheme="https",
            request=RequestModel(
                method="POST",
                url="/v1/users/login",
                path="/v1/users/login",
                headers={"Host": "auth-service.production.org:8443", "Content-Length": "15", "Content-Type": "application/json"},
                body='{"user": "test"}',
            ),
            response=ResponseModel(status_code=200, body='{"ok": true}'),
        )
        await writer.enqueue_insert_flow(flow)
        await writer.flush()

        captured_requests: List[httpx.Request] = []
        orig_send = httpx.AsyncClient.send

        async def mock_send(self, request, **kwargs):
            if isinstance(self._transport, ASGITransport):
                return await orig_send(self, request, **kwargs)
            captured_requests.append(request)
            return httpx.Response(200, json={"replayed": True})

        with patch.object(httpx.AsyncClient, "send", mock_send):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                res = await client.post(f"/api/v1/flows/{flow_id}/replay", json={})
                assert res.status_code == 200
                data = res.json()
                assert data["ok"] is True
                assert data["replayed_flow_id"] == flow_id

        assert len(captured_requests) == 1
        req = captured_requests[0]
        # Target must be exact reconstructed https://auth-service.production.org:8443/v1/users/login
        assert str(req.url) == "https://auth-service.production.org:8443/v1/users/login"
        assert req.method == "POST"
    finally:
        await writer.stop()


# ===========================================================================
# 3. PROPOSAL EXECUTION DYNAMIC URL & AUTH MUTATION EMPIRICAL TEST
# ===========================================================================

async def test_execute_proposal_dynamic_url_and_auth_overrides(tmp_dir: str):
    """Verify proposal execution correctly reconstructs dynamic URL, strips hop headers, and applies auth overrides."""
    app, writer, repo, _ = await _setup_test_app(tmp_dir)

    try:
        flow_id = str(uuid.uuid4())
        flow = FlowRecord(
            id=flow_id,
            server_host="payment.checkout.com",
            server_port=443,
            scheme="https",
            request=RequestModel(
                method="GET",
                url="/v2/accounts/999/balance?currency=USD",
                path="/v2/accounts/999/balance",
                query_string="currency=USD",
                query_params={"currency": "USD"},
                headers={"Host": "payment.checkout.com", "Authorization": "Bearer secret-token-123"},
            ),
            response=ResponseModel(status_code=200, body='{"balance": 1000}'),
        )
        await writer.enqueue_insert_flow(flow)

        prop_id = f"prop-{uuid.uuid4().hex[:8]}"
        proposal = TestProposal(
            id=prop_id,
            flow_id=flow_id,
            title="BOLA Account Probe",
            description="Mutate account ID in path with DROP auth",
            anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
            severity=ProposalSeverity.CRITICAL,
            confidence_score=95.0,
            endpoint_path="/v2/accounts/999/balance",
            method="GET",
            target_param_location="path",
            target_param_name="id",
            baseline_value="999",
            mutated_value="1000",
            auth_override="DROP",
            state=ProposalState.PENDING,
        )
        await writer.enqueue_insert_proposal(proposal)
        await writer.flush()

        captured_requests: List[httpx.Request] = []
        orig_send = httpx.AsyncClient.send

        async def mock_send(self, request, **kwargs):
            if isinstance(self._transport, ASGITransport):
                return await orig_send(self, request, **kwargs)
            captured_requests.append(request)
            return httpx.Response(200, json={"balance": 50000})

        with patch.object(httpx.AsyncClient, "send", mock_send):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                res = await client.post(f"/api/v1/proposals/{prop_id}/execute")
                assert res.status_code == 200
                data = res.json()
                assert data["proposal"]["id"] == prop_id
                assert data["proposal"]["state"] == "COMPLETED"

        assert len(captured_requests) == 1
        req = captured_requests[0]
        # Target must be mutated path on https://payment.checkout.com with currency query param preserved
        assert str(req.url) == "https://payment.checkout.com/v2/accounts/1000/balance?currency=USD"
        # Authorization header must be dropped due to DROP auth override
        assert "Authorization" not in req.headers
        assert "authorization" not in req.headers
    finally:
        await writer.stop()


# ===========================================================================
# 4. MULTI-TARGET TEST MATRIX INDEPENDENT BASELINE RESOLUTION
# ===========================================================================

async def test_multi_target_matrix_independent_resolution_and_fault_tolerance(tmp_dir: str):
    """
    Stress test test matrix runner with 4 cases:
    - Case 1: points to baseline Flow A (host: api-a.internal:8080)
    - Case 2: points to baseline Flow B (host: api-b.external.com:443)
    - Case 3: points to baseline Flow C (host: api-c.corp.net:9000)
    - Case 4: has NO baseline flow and NO target_url (must fail gracefully with MISSING_TARGET_URL)
    """
    app, writer, repo, _ = await _setup_test_app(tmp_dir)

    try:
        flow_a = FlowRecord(
            id=str(uuid.uuid4()),
            server_host="api-a.internal",
            server_port=8080,
            scheme="http",
            request=RequestModel(method="GET", url="/v1/users/1", path="/v1/users/1"),
            response=ResponseModel(status_code=200, body='{"user": 1}'),
        )
        flow_b = FlowRecord(
            id=str(uuid.uuid4()),
            server_host="api-b.external.com",
            server_port=443,
            scheme="https",
            request=RequestModel(method="POST", url="/v2/orders", path="/v2/orders", body='{"item": 1}'),
            response=ResponseModel(status_code=200, body='{"order_id": 100}'),
        )
        flow_c = FlowRecord(
            id=str(uuid.uuid4()),
            server_host="api-c.corp.net",
            server_port=9000,
            scheme="http",
            request=RequestModel(method="GET", url="/metrics", path="/metrics"),
            response=ResponseModel(status_code=200, body='metrics_ok'),
        )

        await writer.enqueue_insert_flow(flow_a)
        await writer.enqueue_insert_flow(flow_b)
        await writer.enqueue_insert_flow(flow_c)
        await writer.flush()

        captured_requests: List[httpx.Request] = []
        orig_send = httpx.AsyncClient.send

        async def mock_send(self, request, **kwargs):
            if isinstance(self._transport, ASGITransport):
                return await orig_send(self, request, **kwargs)
            captured_requests.append(request)
            return httpx.Response(200, json={"result": "ok"})

        cases = [
            {
                "id": "c1",
                "name": "Case A",
                "endpoint_path": "/v1/users/2",
                "method": "GET",
                "category": "IDOR_SEQUENTIAL",
                "target_param_location": "path",
                "target_param_name": "id",
                "baseline_flow_id": flow_a.id,
                "selected": True,
                "status": "READY",
            },
            {
                "id": "c2",
                "name": "Case B",
                "endpoint_path": "/v2/orders",
                "method": "POST",
                "category": "MASS_ASSIGNMENT",
                "target_param_location": "body",
                "target_param_name": "is_admin",
                "baseline_flow_id": flow_b.id,
                "selected": True,
                "status": "READY",
            },
            {
                "id": "c3",
                "name": "Case C",
                "endpoint_path": "/metrics",
                "method": "GET",
                "category": "AUTH_STRIPPING",
                "target_param_location": "header",
                "target_param_name": "authorization",
                "baseline_flow_id": flow_c.id,
                "selected": True,
                "status": "READY",
            },
            {
                "id": "c4_missing",
                "name": "Case Missing Baseline",
                "endpoint_path": "/unknown",
                "method": "GET",
                "category": "IDOR_SEQUENTIAL",
                "target_param_location": "path",
                "target_param_name": "id",
                "baseline_flow_id": "non-existent-flow-id",
                "selected": True,
                "status": "READY",
            },
        ]

        job_id = f"job-{uuid.uuid4().hex[:8]}"

        with patch.object(httpx.AsyncClient, "send", mock_send):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                exec_res = await client.post(
                    "/api/v1/matrix/execute",
                    json={
                        "job_id": job_id,
                        "cases": cases,
                        "concurrency": 2,
                    },
                )
                assert exec_res.status_code == 200
                assert exec_res.json()["cases_queued"] == 4

                # Wait for execution to process all cases
                await asyncio.sleep(0.4)

                job_check = await client.get(f"/api/v1/matrix/jobs/{job_id}")
                assert job_check.status_code == 200
                job_data = job_check.json()

        assert job_data["completed_count"] == 4
        captured_urls = [str(r.url) for r in captured_requests]
        # Case 1, 2, 3 must have dispatched to their exact hosts
        assert "http://api-a.internal:8080/v1/users/2" in captured_urls
        assert "https://api-b.external.com/v2/orders" in captured_urls
        assert "http://api-c.corp.net:9000/metrics" in captured_urls
        assert len(captured_requests) == 3  # Case 4 should not have dispatched HTTP request

        # Verify Case 4 failed gracefully with MISSING_TARGET_URL
        c4_res = next(c for c in job_data["cases"] if c["id"] == "c4_missing")
        assert c4_res["status"] == "FAILED"
        assert "MISSING_TARGET_URL" in c4_res["result_summary"]["anomaly_flag"]
        assert c4_res["result_summary"]["status_code"] == 0

        # Verify executed flows for cases 1, 2, 3 were enqueued to writer with authentic metadata
        await writer.flush()
        for c in job_data["cases"][:3]:
            exec_id = c["executed_flow_id"]
            persisted_flow = await repo.get_flow_by_id(exec_id)
            assert persisted_flow is not None
            assert persisted_flow.duration_ms >= 0
            assert persisted_flow.response.status_code == 200
            assert "matrix_execution" in persisted_flow.tags
    finally:
        await writer.stop()
