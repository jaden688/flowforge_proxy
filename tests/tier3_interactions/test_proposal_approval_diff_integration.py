"""
Tier 3 Multi-Module Interaction Integration Tests: End-to-End Pipeline Interception,
Proposal Synthesis, WebSocket Events, Operator Approval, Replay Diffing, Matrix Workbench,
and Curated Collections Bridging.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any, Optional, Tuple
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
    TriageSummary,
)
from flowforge.heuristics.pipeline import default_pipeline
from flowforge.heuristics.proposal_synthesizer import ProposalSynthesizer
from flowforge.models.curation import CuratedPayload, PayloadGroup, PruneFilterRequest
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.proposal import (
    AnomalyType,
    BatchProposalActionRequest,
    ProposalExecutionResult,
    ProposalSeverity,
    ProposalState,
    TestProposal,
)
from flowforge.models.rules import MatchRule, RuleCondition, RuleOperator, RuleSeverity


def _create_interaction_flow(
    flow_id: Optional[str] = None,
    method: str = "GET",
    url: str = "http://127.0.0.1:8000/api/v1/orders/1001",
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
            url=url,
            path=path,
            query_string="&".join(f"{k}={v}" for k, v in (query_params or {}).items()),
            query_params=query_params or {},
            headers=headers or {"Host": "127.0.0.1:8000", "Authorization": "Bearer valid-token"},
            content_type="application/json" if (req_body and req_body.startswith("{")) else "text/plain",
            content_length=len(req_body.encode("utf-8")) if req_body else 0,
            body=req_body or "",
        ),
        response=ResponseModel(
            status_code=resp_status,
            reason="OK" if resp_status == 200 else "Created",
            headers={"Content-Type": "application/json"},
            content_type="application/json",
            content_length=len(resp_body.encode("utf-8")) if resp_body else 0,
            body=resp_body or "",
        ),
        tags=tags or [],
        triage_data=triage_data or {},
    )


async def _setup_interaction_app(tmp_dir: str) -> Tuple[Any, AsyncDBWriter, FlowRepository, EventBroadcaster]:
    db_path = f"{tmp_dir}/test_interaction_{uuid.uuid4().hex[:8]}.db"
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
# Tier 3 Multi-Module Interaction Tests (T3.1 - T3.5)
# ===========================================================================

async def test_interaction_full_intercept_triage_proposal_approval_diff_pipeline(tmp_dir: str):
    """T3.1: Full Pipeline: Flow Ingestion -> Triage -> Proposal Synthesis -> WS Broadcast -> Approve -> Replay -> Diff Delta."""
    app, writer, repo, broadcaster = await _setup_interaction_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # 1. Subscribe to WebSocket Event Broadcaster
            sub_queue = await broadcaster.subscribe("test_full_pipeline_sub")

            # 2. Intercept and ingest baseline flow
            flow = _create_interaction_flow(
                flow_id="flow-pipe-1",
                method="GET",
                path="/api/v1/orders/1001",
                resp_body='{"order_id": 1001, "customer": "Alice", "total": 49.99}',
            )
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            # 3. Triage & Synthesize proposals
            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            assert gen_resp.status_code == 200
            proposals = gen_resp.json()
            assert len(proposals) >= 1
            await writer.flush()

            # Verify WebSocket received proposal_created event
            events = []
            while not sub_queue.empty():
                events.append(sub_queue.get_nowait())
            created_events = [e for e in events if e.event == "proposal_created"]
            assert len(created_events) >= 1

            # 4. Operator reviews and approves a specific IDOR proposal
            target_proposal = next(p for p in proposals if p["anomaly_type"] == "IDOR_SEQUENTIAL")
            prop_id = target_proposal["id"]

            appr_resp = await client.post(f"/api/v1/proposals/{prop_id}/approve")
            assert appr_resp.status_code == 200
            assert appr_resp.json()["state"] == "APPROVED"

            # 5. Operator 1-Click executes the approved proposal
            exec_resp = await client.post(f"/api/v1/proposals/{prop_id}/execute")
            assert exec_resp.status_code == 200
            exec_data = exec_resp.json()

            # 6. Verify executed proposal state, diff calculation, and broadcast event
            assert exec_data["proposal"]["state"] == "COMPLETED"
            assert exec_data["proposal"]["execution_result"] is not None
            assert "diff" in exec_data
            assert "status_delta" in exec_data["diff"]
            assert "length_delta_bytes" in exec_data["diff"]

            # Drain broadcaster events to confirm proposal_executed was emitted
            exec_events = []
            while not sub_queue.empty():
                exec_events.append(sub_queue.get_nowait())
            await broadcaster.unsubscribe("test_full_pipeline_sub")

            executed_evts = [e for e in exec_events if e.event == "proposal_executed"]
            assert len(executed_evts) >= 1
            assert executed_evts[0].flow_id == flow.id
    finally:
        await writer.stop()


async def test_interaction_proposal_to_matrix_builder_custom_run(tmp_dir: str):
    """T3.2: Transfer proposal to Matrix Builder, customize test parameters, and execute matrix job."""
    app, writer, repo, broadcaster = await _setup_interaction_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_interaction_flow(flow_id="flow-matrix-pipe-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            target_prop = gen_resp.json()[0]
            await writer.flush()

            # 1. Transfer proposal to matrix workbench
            mat_transfer_resp = await client.post(
                f"/api/v1/proposals/{target_prop['id']}/to-matrix",
                json={"custom_name": "Custom Matrix Workflow Case"},
            )
            assert mat_transfer_resp.status_code == 200
            transfer_data = mat_transfer_resp.json()
            job_id = transfer_data["job_id"]

            # 2. Execute Matrix Job
            mat_exec_resp = await client.post("/api/v1/matrix/execute", json={"job_id": job_id})
            assert mat_exec_resp.status_code == 200
            assert "started" in mat_exec_resp.json()["message"].lower()
    finally:
        await writer.stop()


async def test_interaction_proposal_to_curation_starring_and_selective_prune(tmp_dir: str):
    """T3.3: Transfer proposal to Curated Collections, star, execute selective prune, and verify retention."""
    app, writer, repo, broadcaster = await _setup_interaction_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_interaction_flow(flow_id="flow-cur-pipe-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            target_prop = gen_resp.json()[0]
            await writer.flush()

            # 1. Transfer proposal to curated collection
            cur_resp = await client.post(
                f"/api/v1/proposals/{target_prop['id']}/to-curated",
                json={"group_id": "critical_idor", "custom_name": "Golden IDOR Regression Probe"},
            )
            assert cur_resp.status_code == 200
            cur_id = cur_resp.json().get("curated_payload_id")
            if cur_id:
                await client.post(f"/api/v1/curation/payloads/{cur_id}/star", params={"starred": True})

            # 2. Add an unstarred test payload to curation store directly
            unstarred_resp = await client.post(
                "/api/v1/curation/payloads",
                json={
                    "group_id": "critical_idor",
                    "name": "Temporary Noise Payload",
                    "endpoint_path": "/test/noise",
                    "method": "GET",
                    "target_param_location": "query",
                    "target_param_name": "temp",
                    "starred": False,
                    "status": "PASSED",
                },
            )
            assert unstarred_resp.status_code == 200

            # 3. Perform selective pruning with preserve_starred=True
            prune_resp = await client.post(
                "/api/v1/curation/prune",
                json={"preserve_starred": True, "status_filter": ["PASSED", "READY"]},
            )
            assert prune_resp.status_code == 200
            prune_data = prune_resp.json()
            assert prune_data["deleted_count"] >= 1
            assert prune_data["preserved_count"] >= 1

            # 4. Export JSON collection catalog
            export_resp = await client.get("/api/v1/curation/export")
            assert export_resp.status_code == 200
            assert "payloads" in export_resp.json()
    finally:
        await writer.stop()


async def test_interaction_custom_rule_engine_to_proposal_pipeline(tmp_dir: str):
    """T3.4: Custom rule match in triage triggers synthesizer and generates scoped proposals."""
    synthesizer = ProposalSynthesizer()

    # Flow matching a custom rule pattern (e.g. sensitive header or path)
    flow = _create_interaction_flow(
        flow_id="flow-custom-rule-1",
        method="POST",
        path="/api/v1/debug/execute",
        headers={"X-Debug-Mode": "true", "Authorization": "Bearer admin-debug"},
        resp_body='{"debug_status": "enabled", "output": "root"}',
    )
    triage = TriageSummary(
        flow_id=flow.id,
        canonical_endpoint="POST /api/v1/debug/execute",
        endpoint_category=EndpointCategory.ADMIN_MANAGEMENT,
        parameters=[
            ExtractedParameter(name="X-Debug-Mode", location=ParameterLocation.HEADER, value="true", raw_value="true"),
        ],
        tags=["custom_rule:debug_mode_active", "admin", "state_mutation"],
        rule_matches=[{"rule_id": "rule-debug-01", "name": "Debug Mode Endpoint Flagged"}],
    )

    proposals = synthesizer.synthesize(flow, triage)
    assert len(proposals) >= 1
    assert any(p.anomaly_type in (AnomalyType.CUSTOM_RULE, AnomalyType.AUTH_DEVIATION, AnomalyType.JSON_SCHEMA) for p in proposals)


async def test_interaction_batch_approval_concurrent_execution_and_diff_stream(tmp_dir: str):
    """T3.5: Batch approval of 5 proposals across multiple endpoints executes concurrently with diff streams."""
    app, writer, repo, broadcaster = await _setup_interaction_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow1 = _create_interaction_flow(flow_id="flow-batch-pipe-1", method="GET", path="/orders/1001")
            flow2 = _create_interaction_flow(flow_id="flow-batch-pipe-2", method="GET", path="/users/42")
            await writer.enqueue_insert_flow(flow1)
            await writer.enqueue_insert_flow(flow2)
            await writer.flush()

            gen1 = await client.post(f"/api/v1/proposals/generate/{flow1.id}")
            gen2 = await client.post(f"/api/v1/proposals/generate/{flow2.id}")
            all_proposals = gen1.json() + gen2.json()
            assert len(all_proposals) >= 5
            prop_ids = [p["id"] for p in all_proposals[:5]]
            await writer.flush()

            # 1. Batch Approve all 5
            batch_resp = await client.post(
                "/api/v1/proposals/batch",
                json={"proposal_ids": prop_ids, "action": "approve"},
            )
            assert batch_resp.status_code == 200
            assert batch_resp.json()["success_count"] == 5

            # 2. Execute all 5 proposals concurrently
            exec_tasks = [client.post(f"/api/v1/proposals/{pid}/execute") for pid in prop_ids]
            exec_results = await asyncio.gather(*exec_tasks)

            # 3. Assert all executed successfully with diff calculations
            for res in exec_results:
                assert res.status_code == 200
                res_data = res.json()
                assert res_data["proposal"]["state"] == "COMPLETED"
                assert "diff" in res_data
                assert "length_delta_bytes" in res_data["diff"]
    finally:
        await writer.stop()
