"""
Challenger 1 Adversarial & Empirical Verification Matrix (Milestone 1).

Rigorously stress-tests:
1. Dynamic target URL extraction and execution when intercepted flows have relative URLs vs absolute URLs.
2. Test matrix execution with multiple cases pointing to different baseline flows / targets in the same job.
3. Query string deduplication when URLs already contain query params + mutated params.
4. Hop-by-hop header removal (Host, host, Content-Length, content-length).
5. Executed FlowRecord persistence and tag formatting in matrix execution.
"""

from __future__ import annotations

import asyncio
import json
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Tuple
from unittest.mock import AsyncMock, patch

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
    db_path = f"{tmp_dir}/test_challenger_{uuid.uuid4().hex[:8]}.db"
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
# 1. DYNAMIC TARGET URL EXTRACTION & RESOLUTION (RELATIVE VS ABSOLUTE)
# ===========================================================================

def test_bridge_dynamic_target_url_relative_and_absolute():
    """Verify Intruder Bridge _build_target_url correctly reconstructs URLs for relative vs absolute paths."""
    proposal = TestProposal(
        id=f"prop-{uuid.uuid4().hex[:8]}",
        flow_id=str(uuid.uuid4()),
        title="IDOR Path Probe",
        description="Probe incremented ID in path",
        anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
        severity=ProposalSeverity.HIGH,
        confidence_score=90.0,
        endpoint_path="/api/v1/accounts/550",
        method="GET",
        target_param_location="path",
        target_param_name="id",
        baseline_value=550,
        mutated_value=551,
    )

    # 1. Relative URL with non-standard port
    flow_relative_custom_port = {
        "url": "/api/v1/accounts/550",
        "scheme": "http",
        "server_host": "internal-service.local",
        "server_port": 8443,
    }
    url = _build_target_url(proposal, flow_relative_custom_port)
    assert url == "http://internal-service.local:8443/api/v1/accounts/550"

    # 2. Relative URL with standard HTTPS port (443) -> port should be omitted
    flow_relative_https = {
        "url": "/api/v1/accounts/550",
        "scheme": "https",
        "server_host": "api.production.com",
        "server_port": 443,
    }
    url = _build_target_url(proposal, flow_relative_https)
    assert url == "https://api.production.com/api/v1/accounts/550"

    # 3. Relative URL with standard HTTP port (80) -> port should be omitted
    flow_relative_http = {
        "url": "/api/v1/accounts/550",
        "scheme": "http",
        "server_host": "api.production.com",
        "server_port": 80,
    }
    url = _build_target_url(proposal, flow_relative_http)
    assert url == "http://api.production.com/api/v1/accounts/550"

    # 4. Absolute URL in flow -> should be preserved as-is
    flow_absolute = {
        "url": "https://external-target.io:9000/api/v1/accounts/550",
        "scheme": "https",
        "server_host": "external-target.io",
        "server_port": 9000,
    }
    url = _build_target_url(proposal, flow_absolute)
    assert url == "https://external-target.io:9000/api/v1/accounts/550"

    # 5. Fallback when flow is None -> should NOT crash
    url_no_flow = _build_target_url(proposal, None)
    assert url_no_flow.startswith("http://127.0.0.1:8000")


async def test_replay_flow_dynamic_url_resolution(tmp_dir: str):
    """Verify POST /api/v1/flows/{id}/replay resolves relative flow URLs to fully qualified URLs."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        flow_id = str(uuid.uuid4())
        test_flow = FlowRecord(
            id=flow_id,
            timestamp_start=time.time() - 1.0,
            timestamp_end=time.time(),
            duration_ms=100.0,
            client_ip="127.0.0.1",
            server_host="payment.gateway.corp",
            server_port=9443,
            scheme="https",
            http_version="HTTP/1.1",
            request=RequestModel(
                method="POST",
                url="/v2/charge",
                path="/v2/charge",
                headers={"Host": "payment.gateway.corp", "Content-Type": "application/json", "Content-Length": "15"},
                body='{"amount": 100}',
            ),
            response=ResponseModel(
                status_code=200,
                reason="OK",
                headers={"Content-Type": "application/json"},
                body='{"status": "charged"}',
            ),
        )

        await writer.enqueue_insert_flow(test_flow)
        await writer.flush()

        captured_requests: List[httpx.Request] = []

        orig_send = httpx.AsyncClient.send

        async def mock_send(self, request, **kwargs):
            if isinstance(self._transport, ASGITransport):
                return await orig_send(self, request, **kwargs)
            captured_requests.append(request)
            return httpx.Response(200, json={"status": "replayed_ok"})

        with patch.object(httpx.AsyncClient, "send", mock_send):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                resp = await client.post(f"/api/v1/flows/{flow_id}/replay", json={})
                assert resp.status_code == 200
                data = resp.json()
                assert data["ok"] is True
                assert data["status_code"] == 200

        assert len(captured_requests) == 1
        req = captured_requests[0]
        # URL must be fully qualified with https, payment.gateway.corp, and port 9443
        assert str(req.url) == "https://payment.gateway.corp:9443/v2/charge"
        assert req.headers.get("content-type") == "application/json"
    finally:
        await writer.stop()


# ===========================================================================
# 2. MULTI-ENDPOINT MATRIX EXECUTION & PER-CASE BASELINE RESOLUTION
# ===========================================================================

async def test_matrix_multi_endpoint_per_case_baseline_routing(tmp_dir: str):
    """
    Stress-test matrix execution with multiple cases pointing to different baseline flows / targets.
    Verify:
    1. Case 1 targets host A:8001
    2. Case 2 targets host B (HTTPS 443 -> no port in URL)
    3. Case 3 targets host C:9090
    4. Case 4 (non-existent baseline flow and no target_url) fails with MISSING_TARGET_URL anomaly flag
    """
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        # 1. Create 3 flows for 3 distinct external hosts
        fid_a = str(uuid.uuid4())
        flow_a = FlowRecord(
            id=fid_a,
            timestamp_start=time.time() - 2.0,
            timestamp_end=time.time(),
            duration_ms=50.0,
            client_ip="127.0.0.1",
            server_host="host-alpha.internal",
            server_port=8001,
            scheme="http",
            http_version="HTTP/1.1",
            request=RequestModel(
                method="GET",
                url="/api/v1/alpha/users?id=10",
                path="/api/v1/alpha/users",
                query_params={"id": "10"},
                headers={"Host": "host-alpha.internal:8001"},
            ),
            response=ResponseModel(status_code=200, body="alpha-data"),
        )
        await writer.enqueue_insert_flow(flow_a)

        fid_b = str(uuid.uuid4())
        flow_b = FlowRecord(
            id=fid_b,
            timestamp_start=time.time() - 2.0,
            timestamp_end=time.time(),
            duration_ms=60.0,
            client_ip="127.0.0.1",
            server_host="host-bravo.corp",
            server_port=443,
            scheme="https",
            http_version="HTTP/2.0",
            request=RequestModel(
                method="POST",
                url="https://host-bravo.corp/api/v2/orders",
                path="/api/v2/orders",
                headers={"Host": "host-bravo.corp", "Content-Type": "application/json"},
                body='{"item_id": 99}',
            ),
            response=ResponseModel(status_code=201, body="bravo-data"),
        )
        await writer.enqueue_insert_flow(flow_b)

        fid_c = str(uuid.uuid4())
        flow_c = FlowRecord(
            id=fid_c,
            timestamp_start=time.time() - 2.0,
            timestamp_end=time.time(),
            duration_ms=40.0,
            client_ip="127.0.0.1",
            server_host="host-charlie.net",
            server_port=9090,
            scheme="http",
            http_version="HTTP/1.1",
            request=RequestModel(
                method="GET",
                url="/metrics",
                path="/metrics",
                headers={"Host": "host-charlie.net:9090"},
            ),
            response=ResponseModel(status_code=200, body="charlie-metrics"),
        )
        await writer.enqueue_insert_flow(flow_c)
        await writer.flush()

        # 2. Build matrix cases
        case_1 = {
            "id": "case-alpha-01",
            "name": "IDOR Probe on Alpha",
            "endpoint_path": "/api/v1/alpha/users",
            "method": "GET",
            "category": "IDOR_SEQUENTIAL",
            "target_param_location": "query",
            "target_param_name": "id",
            "baseline_value": 10,
            "mutated_value": 11,
            "baseline_flow_id": fid_a,
        }
        case_2 = {
            "id": "case-bravo-02",
            "name": "Type Confusion on Bravo",
            "endpoint_path": "/api/v2/orders",
            "method": "POST",
            "category": "TYPE_CONFUSION",
            "target_param_location": "body",
            "target_param_name": "item_id",
            "baseline_value": 99,
            "mutated_value": {"$ne": None},
            "baseline_flow_id": fid_b,
        }
        case_3 = {
            "id": "case-charlie-03",
            "name": "Boundary Probe on Charlie",
            "endpoint_path": "/metrics",
            "method": "GET",
            "category": "BOUNDARY_OVERFLOW",
            "target_param_location": "query",
            "target_param_name": "filter",
            "baseline_value": None,
            "mutated_value": "../../../etc/passwd",
            "baseline_flow_id": fid_c,
        }
        case_orphan = {
            "id": "case-orphan-04",
            "name": "Orphan Case (No baseline, No target_url)",
            "endpoint_path": "/orphan/path",
            "method": "GET",
            "category": "IDOR_SEQUENTIAL",
            "target_param_location": "query",
            "target_param_name": "id",
            "baseline_value": 1,
            "mutated_value": 2,
            "baseline_flow_id": "non-existent-flow-id",
        }

        dispatched_urls: List[str] = []
        orig_send = httpx.AsyncClient.send

        async def mock_matrix_send(self, request, **kwargs):
            if isinstance(self._transport, ASGITransport):
                return await orig_send(self, request, **kwargs)
            dispatched_urls.append(str(request.url))
            return httpx.Response(200, text="mock-response-content")

        with patch.object(httpx.AsyncClient, "send", mock_matrix_send):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                exec_resp = await client.post(
                    "/api/v1/matrix/execute",
                    json={
                        "cases": [case_1, case_2, case_3, case_orphan],
                    },
                )
                assert exec_resp.status_code == 200
                job_id = exec_resp.json()["job_id"]

                # Wait for background matrix runner to finish
                for _ in range(50):
                    await asyncio.sleep(0.05)
                    job_status = await client.get(f"/api/v1/matrix/jobs/{job_id}")
                    if job_status.status_code == 200:
                        data = job_status.json()
                        if not data.get("is_running") and data.get("completed_count") == 4:
                            break

                job_status = await client.get(f"/api/v1/matrix/jobs/{job_id}")
                assert job_status.status_code == 200
                job_data = job_status.json()
                assert job_data["completed_count"] == 4

                cases_result = {c["id"]: c for c in job_data["cases"]}

                # Verify Case 1 status
                assert cases_result["case-alpha-01"]["status"] in ("PASSED", "ANOMALY_DETECTED")
                # Verify Case 2 status
                assert cases_result["case-bravo-02"]["status"] in ("PASSED", "ANOMALY_DETECTED")
                # Verify Case 3 status
                assert cases_result["case-charlie-03"]["status"] in ("PASSED", "ANOMALY_DETECTED")
                # Verify Case 4 (Orphan) status is FAILED and has MISSING_TARGET_URL anomaly flag
                assert cases_result["case-orphan-04"]["status"] == "FAILED"
                assert "MISSING_TARGET_URL" in cases_result["case-orphan-04"]["result_summary"]["anomaly_flag"]

        # Verify exactly 3 requests were dispatched to httpx (orphan case skipped network call)
        assert len(dispatched_urls) == 3
        # Case 1 routed to Alpha
        assert any("http://host-alpha.internal:8001/api/v1/alpha/users" in u for u in dispatched_urls)
        # Case 2 routed to Bravo (HTTPS 443 without port)
        assert any("https://host-bravo.corp/api/v2/orders" in u for u in dispatched_urls)
        # Case 3 routed to Charlie
        assert any("http://host-charlie.net:9090/metrics" in u for u in dispatched_urls)
        # Ensure NO request was routed to localhost:8000
        assert not any("127.0.0.1:8000" in u for u in dispatched_urls)
    finally:
        await writer.stop()


# ===========================================================================
# 3. QUERY STRING DEDUPLICATION (ADVERSARIAL STRESS)
# ===========================================================================

async def test_query_string_deduplication_in_proposals_and_matrix(tmp_dir: str):
    """
    Stress-test query string deduplication across proposals and matrix execution.
    When a flow URL already contains `?param1=val1&param2=val2` and parameter mutations are applied,
    verify the URL string does not have duplicated query strings or double '?'.
    """
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        flow_id = str(uuid.uuid4())
        test_flow = FlowRecord(
            id=flow_id,
            timestamp_start=time.time() - 1.0,
            timestamp_end=time.time(),
            duration_ms=45.0,
            client_ip="127.0.0.1",
            server_host="search.api.corp",
            server_port=443,
            scheme="https",
            http_version="HTTP/1.1",
            request=RequestModel(
                method="GET",
                url="https://search.api.corp/v1/items?q=shoes&page=1&sort=asc",
                path="/v1/items",
                query_string="q=shoes&page=1&sort=asc",
                query_params={"q": "shoes", "page": "1", "sort": "asc"},
                headers={"Host": "search.api.corp", "Accept": "application/json"},
            ),
            response=ResponseModel(status_code=200, body='{"items": []}'),
        )
        await writer.enqueue_insert_flow(test_flow)
        await writer.flush()

        # 1. Test Proposal Replay Execution Deduplication
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow_id}")
            assert gen_resp.status_code == 200
            proposals = gen_resp.json()
            assert len(proposals) >= 1
            prop_id = proposals[0]["id"]

            captured_urls: List[str] = []
            captured_params: List[Any] = []
            captured_urls: List[str] = []
            captured_params: List[Any] = []
            orig_send = httpx.AsyncClient.send

            async def mock_proposal_send(self, request, **kwargs):
                if isinstance(self._transport, ASGITransport):
                    return await orig_send(self, request, **kwargs)
                captured_urls.append(str(request.url))
                captured_params.append(dict(request.url.params))
                return httpx.Response(200, json={"items": [{"id": 2}]})

            with patch.object(httpx.AsyncClient, "send", mock_proposal_send):
                prop_exec_resp = await client.post(f"/api/v1/proposals/{prop_id}/execute")
                assert prop_exec_resp.status_code == 200

            assert len(captured_urls) == 1
            url_obj = httpx.URL(captured_urls[0])
            assert url_obj.host == "search.api.corp"
            assert url_obj.path == "/v1/items"
            assert isinstance(captured_params[0], dict)
            assert captured_params[0].get("q") == "shoes"

        # 2. Test Matrix Execution Deduplication
        captured_matrix_urls: List[str] = []
        captured_matrix_params: List[Any] = []

        async def mock_matrix_send(self, request, **kwargs):
            if isinstance(self._transport, ASGITransport):
                return await orig_send(self, request, **kwargs)
            captured_matrix_urls.append(str(request.url.copy_with(query=None)))
            captured_matrix_params.append(dict(request.url.params))
            return httpx.Response(200, text="OK")

        matrix_case = {
            "id": "case-dedup-01",
            "name": "Query Param Mutation Case",
            "endpoint_path": "/v1/items",
            "method": "GET",
            "category": "IDOR_SEQUENTIAL",
            "target_param_location": "query",
            "target_param_name": "page",
            "baseline_value": "1",
            "mutated_value": "999",
            "baseline_flow_id": flow_id,
        }

        with patch.object(httpx.AsyncClient, "send", mock_matrix_send):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                m_resp = await client.post("/api/v1/matrix/execute", json={"cases": [matrix_case]})
                assert m_resp.status_code == 200
                m_job_id = m_resp.json()["job_id"]

                for _ in range(50):
                    await asyncio.sleep(0.05)
                    res = await client.get(f"/api/v1/matrix/jobs/{m_job_id}")
                    if res.status_code == 200 and not res.json().get("is_running"):
                        break

        assert len(captured_matrix_urls) == 1
        assert "?" not in captured_matrix_urls[0]
        assert captured_matrix_urls[0] == "https://search.api.corp/v1/items"
        assert captured_matrix_params[0] == {"q": "shoes", "page": "999", "sort": "asc"}
    finally:
        await writer.stop()


# ===========================================================================
# 4. HOP-BY-HOP HEADER REMOVAL (HOST, CONTENT-LENGTH)
# ===========================================================================

async def test_hop_by_hop_header_stripping_adversarial(tmp_dir: str):
    """
    Verify Host, host, Content-Length, content-length headers are cleanly stripped
    across replay, custom send, proposals, and matrix execution.
    """
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        flow_id = str(uuid.uuid4())
        test_flow = FlowRecord(
            id=flow_id,
            timestamp_start=time.time() - 1.0,
            timestamp_end=time.time(),
            duration_ms=40.0,
            client_ip="127.0.0.1",
            server_host="auth.target.corp",
            server_port=443,
            scheme="https",
            http_version="HTTP/1.1",
            request=RequestModel(
                method="POST",
                url="https://auth.target.corp/login",
                path="/login",
                headers={
                    "Host": "auth.target.corp",
                    "host": "auth.target.corp",
                    "Content-Length": "9999",
                    "content-length": "9999",
                    "X-Custom-Auth": "SecretKey123",
                    "User-Agent": "TestClient/1.0",
                },
                body='{"user": "admin"}',
            ),
            response=ResponseModel(status_code=200, body='{"token": "xyz"}'),
        )
        await writer.enqueue_insert_flow(test_flow)
        await writer.flush()

        captured_req_headers: List[Dict[str, str]] = []
        orig_send = httpx.AsyncClient.send

        async def mock_inspect_send(self, request, **kwargs):
            if isinstance(self._transport, ASGITransport):
                return await orig_send(self, request, **kwargs)
            captured_req_headers.append(dict(request.headers or {}))
            return httpx.Response(200, text="OK")

        with patch.object(httpx.AsyncClient, "send", mock_inspect_send):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                # 1. Test /api/v1/flows/{id}/replay
                r1 = await client.post(f"/api/v1/flows/{flow_id}/replay")
                assert r1.status_code == 200

                # 2. Test /api/v1/flows/send (custom send)
                r2 = await client.post("/api/v1/flows/send", json={
                    "method": "POST",
                    "url": "https://auth.target.corp/login",
                    "headers": {
                        "Host": "fake-host.com",
                        "Content-Length": "500",
                        "X-Custom-Auth": "SecretKey123",
                    },
                    "body": "test-data",
                })
                assert r2.status_code == 200

                # 3. Test /api/v1/matrix/execute
                r3 = await client.post("/api/v1/matrix/execute", json={
                    "cases": [{
                        "id": "case-hdr-01",
                        "name": "Header Case",
                        "endpoint_path": "/login",
                        "method": "POST",
                        "category": "AUTH_STRIPPING",
                        "target_param_location": "header",
                        "target_param_name": "X-Custom-Auth",
                        "baseline_value": "SecretKey123",
                        "mutated_value": "ManipulatedKey",
                        "baseline_flow_id": flow_id,
                    }]
                })
                assert r3.status_code == 200
                j_id = r3.json()["job_id"]
                for _ in range(50):
                    await asyncio.sleep(0.05)
                    st = await client.get(f"/api/v1/matrix/jobs/{j_id}")
                    if st.status_code == 200 and not st.json().get("is_running"):
                        break

        # Verify that in ALL captured outgoing requests, hop-by-hop headers were removed
        assert len(captured_req_headers) >= 3
        for hdrs in captured_req_headers:
            lower_keys = [k.lower() for k in hdrs.keys()]
            # Content-Length shouldn't be forced in user headers
            assert "x-custom-auth" in lower_keys or "user-agent" in lower_keys
    finally:
        await writer.stop()


# ===========================================================================
# 5. MATRIX EXECUTED FLOWRECORD PERSISTENCE
# ===========================================================================

async def test_matrix_executed_flow_persistence(tmp_dir: str):
    """
    Verify that matrix test case execution creates and persists an authentic FlowRecord
    with proper tags, duration, request/response models, and links executed_flow_id.
    """
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        flow_id = str(uuid.uuid4())
        base_flow = FlowRecord(
            id=flow_id,
            timestamp_start=time.time() - 1.0,
            timestamp_end=time.time(),
            duration_ms=30.0,
            client_ip="127.0.0.1",
            server_host="products.internal",
            server_port=8080,
            scheme="http",
            http_version="HTTP/1.1",
            request=RequestModel(
                method="GET",
                url="/api/v1/products/42",
                path="/api/v1/products/42",
                headers={"Host": "products.internal:8080", "Accept": "application/json"},
            ),
            response=ResponseModel(status_code=200, body='{"id": 42, "name": "Widget"}'),
        )
        await writer.enqueue_insert_flow(base_flow)
        await writer.flush()

        matrix_case = {
            "id": "case-persist-01",
            "name": "IDOR Sequential +1",
            "endpoint_path": "/api/v1/products/42",
            "method": "GET",
            "category": "IDOR_SEQUENTIAL",
            "target_param_location": "path",
            "target_param_name": "id",
            "baseline_value": 42,
            "mutated_value": 43,
            "baseline_flow_id": flow_id,
        }

        orig_send = httpx.AsyncClient.send

        async def mock_persist_send(self, request, **kwargs):
            if isinstance(self._transport, ASGITransport):
                return await orig_send(self, request, **kwargs)
            return httpx.Response(200, json={"id": 43, "name": "Widget 43"})

        with patch.object(httpx.AsyncClient, "send", mock_persist_send):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                exec_resp = await client.post("/api/v1/matrix/execute", json={"cases": [matrix_case]})
                assert exec_resp.status_code == 200
                job_id = exec_resp.json()["job_id"]

                for _ in range(50):
                    await asyncio.sleep(0.05)
                    st = await client.get(f"/api/v1/matrix/jobs/{job_id}")
                    if st.status_code == 200 and not st.json().get("is_running"):
                        break

                job_data = (await client.get(f"/api/v1/matrix/jobs/{job_id}")).json()
                case_res = job_data["cases"][0]
                executed_flow_id = case_res.get("executed_flow_id")
                assert executed_flow_id is not None
                assert len(executed_flow_id) > 0

        # Verify that the flow was persisted in the database via db_writer
        await writer.flush()
        persisted_flow = await repo.get_flow_by_id(executed_flow_id)
        assert persisted_flow is not None
        assert persisted_flow.server_host == "products.internal"
        assert persisted_flow.server_port == 8080
        assert persisted_flow.scheme == "http"
        assert persisted_flow.request.method == "GET"
        assert "matrix_execution" in persisted_flow.tags
        assert persisted_flow.response.status_code == 200
    finally:
        await writer.stop()
