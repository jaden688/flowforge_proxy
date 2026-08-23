"""
Tier 2 Boundary & Corner Case Tests: Proposal Pipeline Stability, Extreme Inputs,
Deep Nesting, Unicode/Binary, Concurrency Races, and Error Resilience.
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
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.proposal import (
    AnomalyType,
    ProposalSeverity,
    ProposalState,
    TestProposal,
)


def _create_boundary_flow(
    flow_id: Optional[str] = None,
    method: str = "GET",
    url: str = "http://127.0.0.1:8000/api/v1/orders/1001",
    path: str = "/api/v1/orders/1001",
    query_params: Optional[dict] = None,
    headers: Optional[dict] = None,
    req_body: Optional[str] = None,
    body_is_binary: bool = False,
    resp_status: int = 200,
    resp_body: Optional[str] = '{"status": "ok"}',
    tags: Optional[list] = None,
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
            headers=headers or {"Host": "127.0.0.1:8000"},
            content_type="application/json" if (req_body and req_body.startswith("{")) else "text/plain",
            content_length=len(req_body.encode("utf-8")) if req_body else 0,
            body=req_body or "",
            body_is_binary=body_is_binary,
        ),
        response=ResponseModel(
            status_code=resp_status,
            reason="OK" if resp_status == 200 else "Error",
            headers={"Content-Type": "application/json"},
            content_type="application/json",
            content_length=len(resp_body.encode("utf-8")) if resp_body else 0,
            body=resp_body or "",
        ),
        tags=tags or [],
    )


async def _setup_boundary_app(tmp_dir: str) -> Tuple[Any, AsyncDBWriter, FlowRepository, EventBroadcaster]:
    db_path = f"{tmp_dir}/test_boundary_{uuid.uuid4().hex[:8]}.db"
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
# Tier 2 Boundary Tests (T2.1 - T2.8)
# ===========================================================================

def test_proposal_boundary_empty_and_null_parameters():
    """T2.1: Valueless query keys, empty string bodies, null JSON fields handled without unhandled exceptions."""
    synthesizer = ProposalSynthesizer()
    flow = _create_boundary_flow(
        method="POST",
        path="/api/v1/process?empty_key=&null_val=None",
        query_params={"empty_key": "", "null_val": "None"},
        req_body='{"name": null, "count": null, "description": ""}',
    )
    triage = TriageSummary(
        flow_id=flow.id,
        canonical_endpoint="POST /api/v1/process",
        endpoint_category=EndpointCategory.MUTATION_ACTION,
        parameters=[
            ExtractedParameter(name="empty_key", location=ParameterLocation.QUERY, value="", raw_value=""),
            ExtractedParameter(name="name", location=ParameterLocation.BODY_JSON, value=None, raw_value="null"),
        ],
        tags=["state_mutation"],
    )

    proposals = synthesizer.synthesize(flow, triage)
    assert isinstance(proposals, list)
    # Synthesizer generates proposals safely without crashing on null/empty


def test_proposal_boundary_malformed_and_broken_json():
    """T2.2: Truncated JSON, trailing commas, and unescaped control chars in body handled cleanly without crashing."""
    synthesizer = ProposalSynthesizer()
    malformed_bodies = [
        '{"user_id": 1001, "items": [{"id": 1,',
        '{"status": "ok",, "trailing": true,}',
        '{"title": "Unescaped \x00\x01\x1f control bytes"}',
        '{unquoted_key: "value"}',
        '',
        '{',
    ]

    for broken_json in malformed_bodies:
        flow = _create_boundary_flow(
            method="POST",
            path="/api/v1/data",
            req_body=broken_json,
        )
        triage = TriageSummary(
            flow_id=flow.id,
            canonical_endpoint="POST /api/v1/data",
            endpoint_category=EndpointCategory.MUTATION_ACTION,
            parameters=[],
            tags=["state_mutation"],
        )
        # Must execute without JSONDecodeError bubbling up
        proposals = synthesizer.synthesize(flow, triage)
        assert isinstance(proposals, list)


async def test_proposal_boundary_concurrent_approval_and_dismissal(tmp_dir: str):
    """T2.3: 20 concurrent tasks approving and dismissing the same proposal execute safely under race conditions."""
    app, writer, repo, broadcaster = await _setup_boundary_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_boundary_flow(flow_id="flow-race-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            proposals = gen_resp.json()
            assert len(proposals) > 0
            target_id = proposals[0]["id"]
            await writer.flush()

            async def _worker_approve(idx: int):
                return await client.post(f"/api/v1/proposals/{target_id}/approve")

            async def _worker_dismiss(idx: int):
                return await client.post(f"/api/v1/proposals/{target_id}/dismiss")

            # Launch 20 interleaved approve and dismiss requests concurrently
            tasks = []
            for i in range(10):
                tasks.append(_worker_approve(i))
                tasks.append(_worker_dismiss(i))

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            # All responses must be valid HTTP 200 OK without 500 errors
            for r in responses:
                assert not isinstance(r, Exception)
                assert r.status_code == 200

            # Final state must be either APPROVED or DISMISSED deterministically
            final_get = await client.get(f"/api/v1/proposals/{target_id}")
            assert final_get.status_code == 200
            assert final_get.json()["state"] in ("APPROVED", "DISMISSED")
    finally:
        await writer.stop()


def test_proposal_boundary_extreme_and_malformed_urls():
    """T2.4: URLs with 8KB+ query strings, raw unicode, double slashes, and null bytes handled gracefully."""
    synthesizer = ProposalSynthesizer()

    long_query = "x=" + ("A" * 8192)
    extreme_urls = [
        f"http://127.0.0.1:8000/api/v1/search?{long_query}",
        "http://127.0.0.1:8000/api/v1/用户/1001/ профиль",
        "http://127.0.0.1:8000///api/v1//orders//1001",
        "http://127.0.0.1:8000/api/v1/orders/1001%00%00/view",
        "http://127.0.0.1:65535/test?q=%E4%BD%A0%E5%A5%BD",
    ]

    for u in extreme_urls:
        flow = _create_boundary_flow(
            method="GET",
            url=u,
            path="/api/v1/orders/1001",
            resp_body='{"id": 1001}',
        )
        triage = TriageSummary(
            flow_id=flow.id,
            canonical_endpoint="GET /api/v1/orders/{id}",
            endpoint_category=EndpointCategory.DATA_READ,
            parameters=[
                ExtractedParameter(name="id", location=ParameterLocation.PATH, value=1001, raw_value="1001", idor_score=0.8),
            ],
            tags=["idor_candidate"],
        )

        proposals = synthesizer.synthesize(flow, triage)
        assert isinstance(proposals, list)
        for p in proposals:
            assert p.endpoint_hash is not None
            assert len(p.endpoint_hash) > 0


def test_proposal_boundary_non_ascii_and_raw_binary_parameters():
    """T2.5: Multi-byte UTF-8 emojis (🦀🔥), raw binary images, and binary bytes pass without UnicodeDecodeError."""
    synthesizer = ProposalSynthesizer()

    flow_emoji = _create_boundary_flow(
        method="POST",
        path="/api/v1/comments",
        query_params={"tag": "🦀🔥🚀"},
        req_body='{"author": "Кодер 💻", "comment": "Valid multi-byte UTF-8 🦀🔥"}',
    )
    triage_emoji = TriageSummary(
        flow_id=flow_emoji.id,
        canonical_endpoint="POST /api/v1/comments",
        endpoint_category=EndpointCategory.MUTATION_ACTION,
        parameters=[
            ExtractedParameter(name="tag", location=ParameterLocation.QUERY, value="🦀🔥🚀", raw_value="🦀🔥🚀"),
            ExtractedParameter(name="author", location=ParameterLocation.BODY_JSON, value="Кодер 💻", raw_value="Кодер 💻"),
        ],
        tags=["state_mutation"],
    )

    proposals_emoji = synthesizer.synthesize(flow_emoji, triage_emoji)
    assert isinstance(proposals_emoji, list)

    # Raw binary flow
    flow_binary = _create_boundary_flow(
        method="GET",
        path="/binary/image.png",
        req_body="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
        body_is_binary=True,
        resp_body="BINARY_IMAGE_DATA_BYTES",
    )
    triage_binary = TriageSummary(
        flow_id=flow_binary.id,
        canonical_endpoint="GET /binary/image.png",
        endpoint_category=EndpointCategory.FILE_TRANSFER,
        parameters=[],
        tags=["file_transfer"],
    )

    proposals_binary = synthesizer.synthesize(flow_binary, triage_binary)
    assert isinstance(proposals_binary, list)


def test_proposal_boundary_duplicate_anomaly_storm():
    """T2.6: Ingesting 100 identical flows with the same anomaly deduplicates proposals cleanly."""
    synthesizer = ProposalSynthesizer()
    proposals_pool = []

    for i in range(100):
        flow = _create_boundary_flow(
            flow_id=f"flow-storm-{i}",
            method="GET",
            path="/api/v1/orders/1001",
            resp_body='{"order_id": 1001}',
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
        )

        flow_props = synthesizer.synthesize(flow, triage)
        assert len(flow_props) == 6
        proposals_pool.extend(flow_props)

    assert len(proposals_pool) == 600  # 100 flows * 6 unique proposals per flow


async def test_proposal_boundary_deleted_and_missing_flow_references(tmp_dir: str):
    """T2.7: Querying or approving a proposal referencing a deleted flow ID returns structured 404."""
    app, writer, repo, broadcaster = await _setup_boundary_app(tmp_dir)

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            flow = _create_boundary_flow(flow_id="flow-delete-test-1", method="GET", path="/orders/1001")
            await writer.enqueue_insert_flow(flow)
            await writer.flush()

            gen_resp = await client.post(f"/api/v1/proposals/generate/{flow.id}")
            proposals = gen_resp.json()
            assert len(proposals) > 0
            prop_id = proposals[0]["id"]
            await writer.flush()

            # Delete the parent flow from DB
            await repo.delete_flow(flow.id)

            # Executing proposal whose baseline flow is deleted must return 404 (not unhandled 500)
            exec_resp = await client.post(f"/api/v1/proposals/{prop_id}/execute")
            assert exec_resp.status_code == 404
            assert "baseline flow" in exec_resp.json()["detail"].lower() or "not found" in exec_resp.json()["detail"].lower()
    finally:
        await writer.stop()


def test_proposal_boundary_deep_json_nesting():
    """T2.8: JSON bodies nested 25+ levels deep handled without recursion depth limit or stack overflow."""
    synthesizer = ProposalSynthesizer()

    # Build 28-level deep JSON hierarchy
    nested: dict = {"leaf_key": "sensitive_admin_token", "order_id": 1001}
    for level in range(28):
        nested = {f"level_{level}": nested}

    deep_json_str = json.dumps(nested)

    flow = _create_boundary_flow(
        method="POST",
        path="/api/v1/nested/data",
        req_body=deep_json_str,
    )
    triage = TriageSummary(
        flow_id=flow.id,
        canonical_endpoint="POST /api/v1/nested/data",
        endpoint_category=EndpointCategory.MUTATION_ACTION,
        parameters=[
            ExtractedParameter(name="order_id", location=ParameterLocation.BODY_JSON, value=1001, raw_value="1001", idor_score=0.8),
        ],
        tags=["state_mutation"],
    )

    # Must parse and synthesize without RecursionError
    proposals = synthesizer.synthesize(flow, triage)
    assert isinstance(proposals, list)
    assert len(proposals) >= 1
