"""
Tier 1 Feature Tests: Automated Proposal Synthesis, Management REST APIs, 1-Click Replay Execution,
Curated/Matrix Integrations, and WebSocket Event Hub Broadcasting (Features F1–F5).
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Optional, Tuple
import pytest
from httpx import ASGITransport, AsyncClient

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.core.broadcaster import EventBroadcaster, get_broadcaster
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.models import (
    EncodingStatus,
    EndpointCategory,
    ExtractedParameter,
    FindingSeverity,
    IdentifierFinding,
    IdentifierType,
    ParameterLocation,
    ReflectionContext,
    ReflectionFinding,
    SecretFinding,
    TriageSummary,
)
from flowforge.heuristics.proposal_synthesizer import ProposalSynthesizer
from flowforge.models.curation import CuratedPayload, PayloadGroup, PruneFilterRequest
from flowforge.models.events import EventType, FlowEvent
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.proposal import (
    AnomalyType,
    BatchProposalActionRequest,
    ProposalExecutionResult,
    ProposalSeverity,
    ProposalState,
    TestProposal,
)


# ===========================================================================
# Helpers & App Fixture Setup
# ===========================================================================

def _create_test_flow(
    flow_id: Optional[str] = None,
    method: str = "GET",
    path: str = "/api/v1/orders/1001",
    query_params: Optional[dict] = None,
    headers: Optional[dict] = None,
    req_body: Optional[str] = None,
    resp_status: int = 200,
    resp_body: Optional[str] = '{"status": "ok"}',
    tags: Optional[list] = None,
    triage_data: Optional[dict] = None,
) -> FlowRecord:
    f_id = flow_id or f"flow-{uuid.uuid4().hex[:8]}"
    q_params = query_params or {}
    hdrs = headers or {"Host": "127.0.0.1:8000", "User-Agent": "FlowForgeTest/1.0"}
    req_b = req_body or ""
    resp_b = resp_body or ""

    return FlowRecord(
        id=f_id,
        timestamp_start=time.time() - 0.05,
        timestamp_end=time.time(),
        duration_ms=50.0,
        client_ip="127.0.0.1",
        server_host="127.0.0.1",
        server_port=8000,
        scheme="http",
        http_version="HTTP/1.1",
        request=RequestModel(
            method=method,
            url=f"http://127.0.0.1:8000{path}",
            path=path,
            query_string="&".join(f"{k}={v}" for k, v in q_params.items()),
            query_params=q_params,
            headers=hdrs,
            content_type="application/json" if req_b.startswith("{") else "text/plain",
            content_length=len(req_b.encode("utf-8")),
            body=req_b,
        ),
        response=ResponseModel(
            status_code=resp_status,
            reason="OK" if resp_status == 200 else "Created",
            headers={"Content-Type": "application/json"},
            content_type="application/json",
            content_length=len(resp_b.encode("utf-8")),
            body=resp_b,
        ),
        tags=tags or [],
        triage_data=triage_data or {},
    )


async def _setup_test_app(tmp_dir: str) -> Tuple[Any, AsyncDBWriter, FlowRepository, EventBroadcaster]:
    """Helper to provision initialized DB, single-writer queue, and broadcaster on app.state."""
    db_path = f"{tmp_dir}/test_proposals_{uuid.uuid4().hex[:8]}.db"
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
# Feature 1: Automated Proposal Synthesizer across Anomaly Classes
# ===========================================================================

def test_proposal_synthesis_html_reflection_xss():
    """T1.F1.1: Intercepted flow with HTML reflection synthesizes DOM breakout XSS proposals."""
    synthesizer = ProposalSynthesizer()
    flow = _create_test_flow(
        method="GET",
        path="/reflect/html",
        query_params={"q": "<test>", "attr": "value"},
        resp_body="<html><body><h1>Search: <test></h1><input value='value'></body></html>",
    )
    triage = TriageSummary(
        flow_id=flow.id,
        canonical_endpoint="GET /reflect/html",
        endpoint_category=EndpointCategory.DATA_READ,
        parameters=[
            ExtractedParameter(name="q", location=ParameterLocation.QUERY, value="<test>", raw_value="<test>"),
            ExtractedParameter(name="attr", location=ParameterLocation.QUERY, value="value", raw_value="value"),
        ],
        reflections=[
            ReflectionFinding(
                parameter_name="q",
                source_location=ParameterLocation.QUERY,
                reflected_value="<test>",
                context=ReflectionContext.HTML_BODY_TEXT,
                encoding_status=EncodingStatus.UNENCODED_RAW,
                start_offset=27,
                end_offset=33,
                matched_in="body",
                severity=FindingSeverity.HIGH,
                snippet="Search: <test>",
            ),
            ReflectionFinding(
                parameter_name="attr",
                source_location=ParameterLocation.QUERY,
                reflected_value="value",
                context=ReflectionContext.HTML_ATTR_QUOTED,
                encoding_status=EncodingStatus.UNENCODED_RAW,
                start_offset=53,
                end_offset=58,
                matched_in="body",
                severity=FindingSeverity.HIGH,
                snippet="<input value='value'>",
            ),
        ],
        tags=["reflection"],
        has_high_priority_anomalies=True,
    )

    proposals = synthesizer.synthesize(flow, triage)
    assert len(proposals) >= 2

    # Check XSS proposals
    reflection_props = [p for p in proposals if p.anomaly_type == AnomalyType.REFLECTION]
    assert len(reflection_props) >= 2

    q_prop = next(p for p in reflection_props if p.target_param_name == "q")
    assert q_prop.severity in (ProposalSeverity.HIGH, ProposalSeverity.CRITICAL)
    assert q_prop.confidence_score >= 80.0
    assert q_prop.state == ProposalState.PENDING
    # Curated SecLists vectors must carry an executable XSS marker (alert()) so the
    # verdict engine can confirm reflections downstream.
    assert "alert(" in str(q_prop.mutated_value)
    assert any(t in q_prop.tags for t in ("curated", "dom_breakout"))


def test_proposal_synthesis_sequential_integer_idor():
    """T1.F1.2: Intercepted flow with sequential integer parameters synthesizes IDOR boundary proposals."""
    synthesizer = ProposalSynthesizer()
    flow = _create_test_flow(
        method="GET",
        path="/api/v1/orders/1001",
        resp_body='{"order_id": 1001, "customer": "Alice", "total": 99.95}',
    )
    triage = TriageSummary(
        flow_id=flow.id,
        canonical_endpoint="GET /api/v1/orders/{id}",
        endpoint_category=EndpointCategory.DATA_READ,
        parameters=[
            ExtractedParameter(name="id", location=ParameterLocation.PATH, value=1001, raw_value="1001", idor_score=0.85),
        ],
        identifier_findings=[
            IdentifierFinding(
                parameter_name="id",
                location=ParameterLocation.PATH,
                raw_value="1001",
                id_type=IdentifierType.SEQUENTIAL_INTEGER,
                idor_risk_score=0.85,
                is_mutation=False,
                canonical_pattern="/api/v1/orders/{id}",
            )
        ],
        tags=["idor_candidate"],
        has_high_priority_anomalies=True,
    )

    proposals = synthesizer.synthesize(flow, triage)
    idor_props = [p for p in proposals if p.anomaly_type == AnomalyType.IDOR_SEQUENTIAL]
    assert len(idor_props) >= 4

    mutated_vals = [p.mutated_value for p in idor_props]
    assert 1002 in mutated_vals  # N + 1
    assert 1000 in mutated_vals  # N - 1
    assert 0 in mutated_vals     # Zero boundary
    assert 999999999 in mutated_vals or -1 in mutated_vals


def test_proposal_synthesis_unauth_sensitive_access():
    """T1.F1.3: Intercepted sensitive endpoint without auth or with auth header synthesizes auth enforcement probes."""
    synthesizer = ProposalSynthesizer()
    flow = _create_test_flow(
        method="GET",
        path="/api/v1/admin/users",
        headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"},
        resp_body='[{"id": 1, "username": "admin"}]',
    )
    triage = TriageSummary(
        flow_id=flow.id,
        canonical_endpoint="GET /api/v1/admin/users",
        endpoint_category=EndpointCategory.ADMIN_MANAGEMENT,
        parameters=[],
        tags=["admin", "auth", "jwt"],
        has_high_priority_anomalies=True,
    )

    proposals = synthesizer.synthesize(flow, triage)
    auth_props = [p for p in proposals if p.anomaly_type in (AnomalyType.AUTH_DEVIATION, AnomalyType.JWT_ANOMALY)]
    assert len(auth_props) >= 3

    auth_overrides = [p.auth_override for p in auth_props]
    assert "DROP" in auth_overrides
    assert "USER_B" in auth_overrides
    assert "ALG_NONE" in auth_overrides or "EXPIRED" in auth_overrides


def test_proposal_synthesis_nested_json_state_mutation():
    """T1.F1.4: Intercepted POST/PUT flows with JSON body synthesize mass assignment & type confusion proposals."""
    synthesizer = ProposalSynthesizer()
    flow = _create_test_flow(
        method="POST",
        path="/api/v1/users/update",
        req_body='{"user_id": 42, "profile": {"email": "user@example.com", "display_name": "User42"}}',
        resp_body='{"status": "updated"}',
    )
    triage = TriageSummary(
        flow_id=flow.id,
        canonical_endpoint="POST /api/v1/users/update",
        endpoint_category=EndpointCategory.MUTATION_ACTION,
        parameters=[
            ExtractedParameter(name="user_id", location=ParameterLocation.BODY_JSON, value=42, raw_value="42"),
        ],
        tags=["state_mutation"],
        has_high_priority_anomalies=False,
    )

    proposals = synthesizer.synthesize(flow, triage)
    schema_props = [p for p in proposals if p.anomaly_type == AnomalyType.JSON_SCHEMA]
    assert len(schema_props) >= 1

    mass_assign = next((p for p in schema_props if "Mass Assignment" in p.title), None)
    assert mass_assign is not None
    assert isinstance(mass_assign.mutated_value, dict)
    assert mass_assign.mutated_value.get("role") == "admin" or mass_assign.mutated_value.get("is_admin") is True


def test_proposal_synthesis_flow_lineage_and_metadata():
    """T1.F1.5: Generated proposals retain full flow lineage, endpoint hash, timestamps, and default PENDING state."""
    synthesizer = ProposalSynthesizer()
    flow = _create_test_flow(
        flow_id="flow-meta-test-12345",
        method="GET",
        path="/api/v1/documents/555",
        resp_body='{"doc_id": 555, "title": "Confidential Report"}',
    )
    triage = TriageSummary(
        flow_id=flow.id,
        canonical_endpoint="GET /api/v1/documents/{id}",
        endpoint_category=EndpointCategory.DATA_READ,
        parameters=[
            ExtractedParameter(name="doc_id", location=ParameterLocation.PATH, value=555, raw_value="555", idor_score=0.9),
        ],
        identifier_findings=[
            IdentifierFinding(
                parameter_name="doc_id",
                location=ParameterLocation.PATH,
                raw_value="555",
                id_type=IdentifierType.SEQUENTIAL_INTEGER,
                idor_risk_score=0.9,
                is_mutation=False,
                canonical_pattern="/api/v1/documents/{id}",
            )
        ],
        tags=["idor_candidate"],
    )

    proposals = synthesizer.synthesize(flow, triage)
    assert len(proposals) > 0

    for p in proposals:
        assert p.flow_id == "flow-meta-test-12345"
        assert p.endpoint_path == "/api/v1/documents/555"
        assert p.method == "GET"
        assert p.state == ProposalState.PENDING
        assert p.created_at > 0
        assert p.updated_at > 0
        assert p.endpoint_hash is not None
        assert len(p.endpoint_hash) > 0


def test_proposal_synthesis_high_entropy_secret_probe():
    """T1.F1.6: Intercepted secrets synthesize token validation and reachability probes."""
    synthesizer = ProposalSynthesizer()
    flow = _create_test_flow(
        method="GET",
        path="/api/v1/config",
        resp_body='{"aws_secret": "AKIAIOSFODNN7EXAMPLE", "stripe_key": "sk_test_51Mz..."}',
    )
    triage = TriageSummary(
        flow_id=flow.id,
        canonical_endpoint="GET /api/v1/config",
        endpoint_category=EndpointCategory.DATA_READ,
        parameters=[],
        secret_findings=[
            SecretFinding(
                secret_type="AWS_ACCESS_KEY",
                severity=FindingSeverity.CRITICAL,
                matched_pattern="AKIA[0-9A-Z]{16}",
                masked_value="AKIAIOSFODNN7EXAMPLE",
                location=ParameterLocation.BODY_JSON,
                entropy=4.5,
            )
        ],
        tags=["secrets"],
        has_high_priority_anomalies=True,
    )

    proposals = synthesizer.synthesize(flow, triage)
    secret_props = [p for p in proposals if p.anomaly_type == AnomalyType.SECRET_EXPOSURE]
    assert len(secret_props) >= 1
    assert secret_props[0].severity == ProposalSeverity.CRITICAL
    assert "AWS_ACCESS_KEY" in secret_props[0].title


# ===========================================================================
# Feature 2: Proposal Management REST API
# ===========================================================================

async def test_api_proposals_list_and_filtering(tmp_dir: str):
    """T1.F2.1: GET /api/v1/proposals lists proposals with flow_id, state, severity, and search filtering."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Create flow first
            flow = _create_test_flow(flow_id="flow-list-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            # Generate proposals
            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            assert gen_resp.status_code == 200
            proposals = gen_resp.json()
            assert len(proposals) >= 1
            await writer.flush()

            # 1. List all
            resp = await client.get("/api/v1/proposals")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total"] >= len(proposals)
            assert len(data["items"]) >= 1

            # 2. Filter by flow_id
            resp_flow = await client.get(f"/api/v1/proposals?flow_id={flow.id}")
            assert resp_flow.status_code == 200
            assert resp_flow.json()["total"] == len(proposals)

            # 3. Filter by state
            resp_state = await client.get("/api/v1/proposals?state=PENDING")
            assert resp_state.status_code == 200
            assert all(p["state"] == "PENDING" for p in resp_state.json()["items"])
    finally:
        await writer.stop()


async def test_api_proposal_get_by_id_details(tmp_dir: str):
    """T1.F2.2: GET /api/v1/proposals/{proposal_id} returns single proposal details and 404 for invalid ID."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(flow_id="flow-get-1", method="GET", path="/users/42")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            assert gen_resp.status_code == 200
            proposals = gen_resp.json()
            assert len(proposals) > 0
            target_id = proposals[0]["id"]
            await writer.flush()

            # Valid get
            get_resp = await client.get(f"/api/v1/proposals/{target_id}")
            assert get_resp.status_code == 200
            prop_data = get_resp.json()
            assert prop_data["id"] == target_id
            assert prop_data["flow_id"] == flow.id

            # 404 for missing proposal
            missing_resp = await client.get("/api/v1/proposals/non-existent-prop-id-999")
            assert missing_resp.status_code == 404
    finally:
        await writer.stop()


async def test_api_proposal_dismiss_lifecycle(tmp_dir: str):
    """T1.F2.3: POST /api/v1/proposals/{id}/dismiss transitions state to DISMISSED cleanly."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(flow_id="flow-dismiss-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            proposals = gen_resp.json()
            assert len(proposals) > 0
            target_id = proposals[0]["id"]
            await writer.flush()

            # Dismiss
            dismiss_resp = await client.post(f"/api/v1/proposals/{target_id}/dismiss", json={"reason": "False positive"})
            assert dismiss_resp.status_code == 200
            dismissed_data = dismiss_resp.json()
            assert dismissed_data["state"] == "DISMISSED"

            # Verify DB state
            get_resp = await client.get(f"/api/v1/proposals/{target_id}")
            assert get_resp.status_code == 200
            assert get_resp.json()["state"] == "DISMISSED"
    finally:
        await writer.stop()


async def test_api_proposals_batch_actions(tmp_dir: str):
    """T1.F2.4: POST /api/v1/proposals/batch atomically approves or dismisses multiple proposals."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(flow_id="flow-batch-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            proposals = gen_resp.json()
            assert len(proposals) >= 2
            p_ids = [p["id"] for p in proposals[:2]]
            await writer.flush()

            # Batch Approve
            batch_resp = await client.post(
                "/api/v1/proposals/batch",
                json={"proposal_ids": p_ids, "action": "approve"},
            )
            assert batch_resp.status_code == 200
            res = batch_resp.json()
            assert res["success_count"] == 2
            assert set(res["updated_ids"]) == set(p_ids)

            # Batch Dismiss
            batch_d_resp = await client.post(
                "/api/v1/proposals/batch",
                json={"proposal_ids": p_ids, "action": "dismiss"},
            )
            assert batch_d_resp.status_code == 200
            assert batch_d_resp.json()["success_count"] == 2
    finally:
        await writer.stop()


async def test_api_proposals_stats_summary(tmp_dir: str):
    """T1.F2.5: GET /api/v1/proposals/stats returns aggregated counts of staged, approved, executed, dismissed items."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(flow_id="flow-stats-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            proposals = gen_resp.json()
            assert len(proposals) >= 2
            await writer.flush()

            # Approve one
            await client.post(f"/api/v1/proposals/{proposals[0]['id']}/approve")
            # Dismiss one
            if len(proposals) > 1:
                await client.post(f"/api/v1/proposals/{proposals[1]['id']}/dismiss")

            stats_resp = await client.get("/api/v1/proposals/stats")
            assert stats_resp.status_code == 200
            stats = stats_resp.json()
            assert stats["total"] >= len(proposals)
            assert stats["approved"] >= 1
            assert stats["dismissed"] >= 1
    finally:
        await writer.stop()


# ===========================================================================
# Feature 3: 1-Click Execution, Replay Engine & Diff Streaming
# ===========================================================================

async def test_proposal_1click_approve_and_run(tmp_dir: str):
    """T1.F3.1: POST /api/v1/proposals/{id}/execute runs replay and transitions proposal to COMPLETED."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(
                flow_id="flow-exec-1",
                method="GET",
                path="/api/v1/orders/1001",
                resp_body='{"order_id": 1001, "total": 20.00}',
            )
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            proposals = gen_resp.json()
            assert len(proposals) > 0
            target_prop = proposals[0]
            await writer.flush()

            exec_resp = await client.post(f"/api/v1/proposals/{target_prop['id']}/execute")
            assert exec_resp.status_code == 200
            data = exec_resp.json()

            assert data["proposal"]["state"] == "COMPLETED"
            assert data["proposal"]["execution_result"] is not None
            assert "diff" in data
            assert data["diff"]["status_match"] is not None
    finally:
        await writer.stop()


async def test_proposal_execution_diff_calculation(tmp_dir: str):
    """T1.F3.2: Execution calculates delta metrics (status delta, length delta, reflection flag)."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(
                flow_id="flow-diff-1",
                method="GET",
                path="/api/v1/orders/1001",
                resp_body='{"order_id": 1001, "user": "Alice"}',
            )
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            proposals = gen_resp.json()
            target_prop = next(p for p in proposals if p["anomaly_type"] == "IDOR_SEQUENTIAL")
            await writer.flush()

            exec_resp = await client.post(f"/api/v1/proposals/{target_prop['id']}/execute")
            assert exec_resp.status_code == 200
            data = exec_resp.json()
            diff = data["diff"]

            assert "length_delta_bytes" in diff
            assert "status_delta" in diff
            assert "anomaly_verdict" in diff
            assert diff["anomaly_verdict"]["level"] in ("CRITICAL_IDOR", "INFO_DIFF", "IDENTICAL", "AUTH_BYPASS")
    finally:
        await writer.stop()


async def test_proposal_execution_error_handling(tmp_dir: str):
    """T1.F3.3: Replay against missing flow returns clean 404 rather than 500 internal server error."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/api/v1/proposals/non-existent-prop-999/execute")
            assert resp.status_code == 404
            assert "not found" in resp.json()["detail"].lower()
    finally:
        await writer.stop()


async def test_proposal_execution_diff_streaming_broadcast(tmp_dir: str):
    """T1.F3.4: Proposal execution emits proposal_executed event through broadcaster."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(
                flow_id="flow-stream-bc-1",
                method="GET",
                path="/orders/1001",
            )
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            proposals = gen_resp.json()
            target_id = proposals[0]["id"]
            await writer.flush()

            sub_queue = await broadcaster.subscribe("test_exec_subscriber")

            await client.post(f"/api/v1/proposals/{target_id}/execute")

            received_events = []
            while not sub_queue.empty():
                received_events.append(sub_queue.get_nowait())

            await broadcaster.unsubscribe("test_exec_subscriber")
            executed_events = [e for e in received_events if e.event == "proposal_executed"]
            assert len(executed_events) >= 1
            assert executed_events[0].flow_id == flow.id
    finally:
        await writer.stop()


async def test_proposal_reexecution_idempotency(tmp_dir: str):
    """T1.F3.5: Re-executing a completed proposal safely updates the execution summary without errors."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(flow_id="flow-idempotent-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            proposals = gen_resp.json()
            target_id = proposals[0]["id"]
            await writer.flush()

            # First run
            resp1 = await client.post(f"/api/v1/proposals/{target_id}/execute")
            assert resp1.status_code == 200

            # Second run
            resp2 = await client.post(f"/api/v1/proposals/{target_id}/execute")
            assert resp2.status_code == 200
            assert resp2.json()["proposal"]["state"] == "COMPLETED"
    finally:
        await writer.stop()


# ===========================================================================
# Feature 4: Curated Collections & Matrix Builder Integration
# ===========================================================================

async def test_proposal_save_to_curated_collection(tmp_dir: str):
    """T1.F4.1: POST /api/v1/proposals/{id}/to-curated transfers proposal to Curated Collections store."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(flow_id="flow-cur-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            proposals = gen_resp.json()
            assert len(proposals) > 0
            target_id = proposals[0]["id"]
            await writer.flush()

            # Transfer to curated
            cur_resp = await client.post(
                f"/api/v1/proposals/{target_id}/to-curated",
                json={"group_id": "default", "custom_name": "Starred Security Probe"},
            )
            assert cur_resp.status_code == 200
            data = cur_resp.json()
            assert data["ok"] is True
            assert "curated_payload_id" in data
    finally:
        await writer.stop()


async def test_proposal_transfer_to_matrix_builder(tmp_dir: str):
    """T1.F4.2: POST /api/v1/proposals/{id}/to-matrix transfers proposal to Matrix Builder staging grid."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(flow_id="flow-matrix-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            proposals = gen_resp.json()
            assert len(proposals) > 0
            target_id = proposals[0]["id"]
            await writer.flush()

            # Transfer to matrix
            mat_resp = await client.post(
                f"/api/v1/proposals/{target_id}/to-matrix",
                json={"custom_name": "Transferred IDOR Matrix Case"},
            )
            assert mat_resp.status_code == 200
            data = mat_resp.json()
            assert data["ok"] is True
            assert "job_id" in data
            assert "case_id" in data
    finally:
        await writer.stop()


async def test_proposal_curated_export_roundtrip(tmp_dir: str):
    """T1.F4.3: Proposals saved to curated collections survive export & import JSON roundtrip."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(flow_id="flow-exp-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            target_id = gen_resp.json()[0]["id"]
            await writer.flush()

            # Save to curated
            await client.post(f"/api/v1/proposals/{target_id}/to-curated", json={"custom_name": "Export Test Case"})

            # Export
            exp_resp = await client.get("/api/v1/curation/export")
            assert exp_resp.status_code == 200
            exp_data = exp_resp.json()

            # Re-import
            imp_resp = await client.post("/api/v1/curation/import", json=exp_data)
            assert imp_resp.status_code == 200
            assert imp_resp.json()["status"] == "success"
    finally:
        await writer.stop()


async def test_proposal_matrix_tuning_and_execution(tmp_dir: str):
    """T1.F4.4: Proposals transferred to Matrix Builder allow parameter editing and execute cleanly."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(flow_id="flow-mat-tun-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            target_id = gen_resp.json()[0]["id"]
            await writer.flush()

            mat_resp = await client.post(f"/api/v1/proposals/{target_id}/to-matrix")
            job_id = mat_resp.json()["job_id"]

            # Run matrix execution
            exec_resp = await client.post("/api/v1/matrix/execute", json={"job_id": job_id})
            assert exec_resp.status_code == 200
            assert "Matrix execution started" in exec_resp.json()["message"]
    finally:
        await writer.stop()


async def test_proposal_curation_preserves_starred_on_prune(tmp_dir: str):
    """T1.F4.5: Curated items originating from auto-proposals are marked starred and protected from pruning."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(flow_id="flow-prune-star-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            target_id = gen_resp.json()[0]["id"]
            await writer.flush()

            # Save to curated (sets starred=True)
            cur_res = await client.post(f"/api/v1/proposals/{target_id}/to-curated")
            cur_id = cur_res.json().get("curated_payload_id")
            if cur_id:
                await client.post(f"/api/v1/curation/payloads/{cur_id}/star", params={"starred": True})

            # Selective prune with preserve_starred=True
            prune_resp = await client.post(
                "/api/v1/curation/prune",
                json={"preserve_starred": True, "status_filter": ["READY", "FAILED", "PASSED"]},
            )
            assert prune_resp.status_code == 200
            assert prune_resp.json()["preserved_count"] >= 1
    finally:
        await writer.stop()


# ===========================================================================
# Feature 5: WebSocket Real-Time Event Hub
# ===========================================================================

async def test_ws_broadcast_proposal_staged_event(tmp_dir: str):
    """T1.F5.1: Proposal generation emits proposal_created event with proposal list."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            sub_queue = await broadcaster.subscribe("test_ws_sub_1")

            flow = _create_test_flow(flow_id="flow-ws-staged-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            await client.post(f"/api/v1/proposals/generate/{flow.id}")

            events = []
            while not sub_queue.empty():
                events.append(sub_queue.get_nowait())

            await broadcaster.unsubscribe("test_ws_sub_1")
            created_events = [e for e in events if e.event == "proposal_created"]
            assert len(created_events) >= 1
            assert created_events[0].flow_id == flow.id
            assert "proposals" in created_events[0].data
    finally:
        await writer.stop()


async def test_ws_broadcast_proposal_status_update(tmp_dir: str):
    """T1.F5.2: Approving or dismissing a proposal emits proposal_updated / proposal_dismissed events."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(flow_id="flow-ws-upd-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            proposals = gen_resp.json()
            target_id = proposals[0]["id"]
            await writer.flush()

            sub_queue = await broadcaster.subscribe("test_ws_sub_2")

            # Approve
            await client.post(f"/api/v1/proposals/{target_id}/approve")
            # Dismiss
            if len(proposals) > 1:
                await client.post(f"/api/v1/proposals/{proposals[1]['id']}/dismiss")

            events = []
            while not sub_queue.empty():
                events.append(sub_queue.get_nowait())

            await broadcaster.unsubscribe("test_ws_sub_2")
            upd_events = [e for e in events if e.event in ("proposal_updated", "proposal_dismissed")]
            assert len(upd_events) >= 1
    finally:
        await writer.stop()


async def test_ws_broadcast_batch_proposal_summary(tmp_dir: str):
    """T1.F5.3: Batch operations broadcast events for each updated proposal in batch."""
    app, writer, repo, broadcaster = await _setup_test_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_test_flow(flow_id="flow-ws-batch-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            proposals = gen_resp.json()
            assert len(proposals) >= 2
            p_ids = [p["id"] for p in proposals[:2]]
            await writer.flush()

            sub_queue = await broadcaster.subscribe("test_ws_sub_3")

            await client.post(
                "/api/v1/proposals/batch",
                json={"proposal_ids": p_ids, "action": "approve"},
            )

            events = []
            while not sub_queue.empty():
                events.append(sub_queue.get_nowait())

            await broadcaster.unsubscribe("test_ws_sub_3")
            assert len(events) >= 2
    finally:
        await writer.stop()


async def test_ws_broadcast_live_badge_counter(tmp_dir: str):
    """T1.F5.4: Live pending count can be broadcast via broadcast_proposal_stats."""
    broadcaster = EventBroadcaster()
    sub_queue = await broadcaster.subscribe("test_ws_sub_4")

    broadcaster.broadcast_proposal_stats({"total": 10, "pending": 5, "approved": 3, "completed": 2})

    event = sub_queue.get_nowait()
    assert event.event == "proposal_stats"
    assert event.data["pending"] == 5
    await broadcaster.unsubscribe("test_ws_sub_4")


async def test_ws_broadcast_subscriber_isolation(tmp_dir: str):
    """T1.F5.5: Slow or disconnected subscriber does not block event distribution to active subscribers."""
    broadcaster = EventBroadcaster(max_queue_size=5)

    q1 = await broadcaster.subscribe("sub_1")
    q2 = await broadcaster.subscribe("sub_2")

    for i in range(10):
        broadcaster.broadcast_stats({"iteration": i})

    assert q1.qsize() == 5
    assert q2.qsize() == 5

    await broadcaster.unsubscribe("sub_1")
    await broadcaster.unsubscribe("sub_2")
