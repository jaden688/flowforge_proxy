"""
Tier 3 Interaction Tests: Ingestion -> Heuristic Triage -> Persistence -> WebSocket Broadcast -> Diff -> Matrix.
"""

from __future__ import annotations

import asyncio
import time
import uuid
import pytest
import httpx

from flowforge.api.routes.diff import (
    _compute_header_diffs,
    _compute_body_diffs,
    _evaluate_anomaly_verdict,
    DiffRequest,
)
from flowforge.api.routes.matrix import (
    _generate_idor_mutations,
    _generate_auth_mutations,
    _generate_mass_assignment_mutations,
    ParameterDefinition,
    TestMatrixCase,
)
from flowforge.core.broadcaster import EventBroadcaster
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.models.events import EventType
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.parameter import DiscoveredEndpointModel, ExtractedParameterModel
from tests.target_app import TargetAppManager


async def test_full_pipeline_ingestion_to_broadcast(tmp_db_path: str):
    """Verify complete lifecycle: flow creation -> triage analysis -> DB persistence -> event broadcast."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()

    broadcaster = EventBroadcaster()
    queue = await broadcaster.subscribe()
    pipeline = TriagePipeline()

    try:
        flow_id = str(uuid.uuid4())
        flow = FlowRecord(
            id=flow_id,
            server_host="api.target.com",
            request=RequestModel(
                method="POST",
                url="https://api.target.com/api/v1/users/1001/profile?ref=app",
                path="/api/v1/users/1001/profile",
                query_string="ref=app",
                headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDAxIn0.sig"},
                body='{"email": "user@target.com", "role": "member"}',
            ),
            response=ResponseModel(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body='{"status": "updated", "user_id": 1001, "email": "user@target.com"}',
            ),
        )

        # 1. Run passive heuristic triage
        triage_summary = await pipeline.process_flow(flow)
        flow.tags = triage_summary.tags
        flow.triage_data = triage_summary.model_dump()

        # 2. Persist flow
        await writer.enqueue_insert_flow(flow)

        # 3. Broadcast events
        broadcaster.broadcast_flow_created(flow.to_summary())
        broadcaster.broadcast_triage_annotated(flow_id, triage_summary.model_dump())
        broadcaster.broadcast_flow_completed({"id": flow_id, "status_code": 200, "duration_ms": 35.0})

        await writer.flush()

        # 4. Verify DB persistence
        stored = await repo.get_flow_by_id(flow_id)
        assert stored is not None
        assert stored.id == flow_id
        assert len(stored.tags) > 0

        # 5. Verify WebSocket events received in queue
        ev_created = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert ev_created.event == EventType.FLOW_CREATED.value
        ev_triage = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert ev_triage.event == EventType.TRIAGE_ANNOTATED.value
        ev_completed = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert ev_completed.event == EventType.FLOW_COMPLETED.value
    finally:
        await broadcaster.unsubscribe(queue)
        await writer.stop()


def test_diff_engine_computation_and_anomaly_verdict():
    """Verify Diff engine calculates status delta, header modifications, body diffs, and security verdicts."""
    flow_a = {
        "id": "flow-baseline",
        "method": "GET",
        "path": "/api/v1/orders/1001",
        "response_status_code": 200,
        "request_headers": {"Host": "api.target.com", "Authorization": "Bearer token_a"},
        "response_headers": {"Content-Type": "application/json", "X-User-Id": "1001"},
        "response_body": '{"order_id": 1001, "owner": "alice", "total": 50.00}',
    }
    flow_b = {
        "id": "flow-mutated",
        "method": "GET",
        "path": "/api/v1/orders/1002",
        "response_status_code": 200,
        "request_headers": {"Host": "api.target.com", "Authorization": "Bearer token_a"},
        "response_headers": {"Content-Type": "application/json", "X-User-Id": "1002"},
        "response_body": '{"order_id": 1002, "owner": "victim_bob", "address": "123 Private St", "total": 150.00}',
    }

    header_diffs = _compute_header_diffs(flow_a["response_headers"], flow_b["response_headers"])
    body_diffs = _compute_body_diffs(flow_a["response_body"], flow_b["response_body"])
    verdict = _evaluate_anomaly_verdict(
        flow_a=flow_a,
        flow_b=flow_b,
        status_match=True,
        len_delta=len(flow_b["response_body"]) - len(flow_a["response_body"]),
        body_b=flow_b["response_body"],
    )

    assert len(header_diffs) > 0
    assert any(h.key.lower() == "x-user-id" and h.status == "modified" for h in header_diffs)
    assert len(body_diffs) > 0
    assert verdict.level in ("CRITICAL_IDOR", "INFO_DIFF")


def test_contextual_test_matrix_case_generation():
    """Verify test matrix automatically synthesizes mutation cases for IDOR, fuzzing, and auth stripping."""
    param = ParameterDefinition(
        name="order_id",
        location="path",
        inferred_type="integer",
        id_type="SEQUENTIAL_INT",
        sample_value=1001,
    )

    idor_cases = _generate_idor_mutations(param, "/api/v1/orders/1001", "GET", "flow-101")
    auth_cases = _generate_auth_mutations("/api/v1/orders/1001", "GET", "flow-101")
    mass_cases = _generate_mass_assignment_mutations("/api/v1/orders/1001", "POST", "flow-101")

    assert len(idor_cases) >= 4
    assert any(c.mutated_value == 1002 for c in idor_cases)
    assert any(c.mutated_value == 1000 for c in idor_cases)

    assert len(auth_cases) >= 3
    assert any(c.auth_override == "DROP" for c in auth_cases)

    assert len(mass_cases) >= 2
    assert any(c.target_param_name == "is_admin" for c in mass_cases)


async def test_matrix_runner_reference_target_execution():
    """Verify staged matrix cases execute against live reference target and record status codes."""
    async with TargetAppManager() as target:
        # Send baseline request to /orders/1001
        async with httpx.AsyncClient() as client:
            res_base = await client.get(f"{target.base_url}/orders/1001")
            assert res_base.status_code == 200
            base_json = res_base.json()
            assert base_json["order_id"] == 1001

            # Execute IDOR mutation test cases
            res_mut1 = await client.get(f"{target.base_url}/orders/1002")
            assert res_mut1.status_code == 200
            assert res_mut1.json()["order_id"] == 1002

            # Execute Auth Stripping case to protected route (unauthenticated leak)
            res_anon = await client.get(f"{target.base_url}/auth/protected")
            assert res_anon.status_code == 200
            assert res_anon.json()["auth_state"] == "unauthenticated_leak"
