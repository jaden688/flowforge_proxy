"""
Tier 4 End-to-End Application Workflow Tests: Real-World Pen-Testing Scenarios
Executing Auto-Find, Live Anomaly Highlighting, Operator Approval, and Replay Diffing
against the live Reference Target App.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any, Optional, Tuple
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.core.broadcaster import EventBroadcaster, get_broadcaster
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.pipeline import default_pipeline
from flowforge.heuristics.proposal_synthesizer import ProposalSynthesizer
from flowforge.models.curation import CuratedPayload
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.proposal import (
    AnomalyType,
    ProposalExecutionResult,
    ProposalSeverity,
    ProposalState,
    TestProposal,
)
from tests.target_app import TargetAppManager


async def _setup_e2e_app(tmp_dir: str) -> Tuple[Any, AsyncDBWriter, FlowRepository, EventBroadcaster]:
    db_path = f"{tmp_dir}/test_e2e_{uuid.uuid4().hex[:8]}.db"
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
# Tier 4 E2E Application Tests (T4.1 - T4.4)
# ===========================================================================

async def test_e2e_reflected_xss_autofind_and_approval_workflow(tmp_dir: str):
    """T4.1: Pen-Test Scenario 1 - Reflected XSS Auto-Find & Operator Approval Workflow."""
    app, writer, repo, broadcaster = await _setup_e2e_app(tmp_dir)

    async with TargetAppManager() as target:
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as api_client:
                # 1. Live Client issues search request against Reference Target
                search_url = f"{target.base_url}/reflect/html?q=test_query&attr=test_attr"
                async with httpx.AsyncClient() as live_http:
                    live_resp = await live_http.get(search_url)
                    assert live_resp.status_code == 200

                # 2. Ingest intercepted live flow record into FlowForge DB
                flow_id = f"flow-xss-{uuid.uuid4().hex[:8]}"
                flow_record = FlowRecord(
                    id=flow_id,
                    server_host=target.host,
                    server_port=target.port,
                    request=RequestModel(
                        method="GET",
                        url=search_url,
                        path="/reflect/html",
                        query_string="q=test_query&attr=test_attr",
                        query_params={"q": "test_query", "attr": "test_attr"},
                        headers={"Host": f"{target.host}:{target.port}", "User-Agent": "Mozilla/5.0"},
                    ),
                    response=ResponseModel(
                        status_code=live_resp.status_code,
                        headers=dict(live_resp.headers),
                        content_type="text/html; charset=utf-8",
                        content_length=len(live_resp.content),
                        body=live_resp.text,
                    ),
                )
                await writer.enqueue_insert_flow(flow_record)
                await writer.flush()

                # 3. Trigger Auto-Find Proposal Generation
                gen_resp = await api_client.post(f"/api/v1/proposals/generate/{flow_id}")
                assert gen_resp.status_code == 200
                proposals = gen_resp.json()
                assert len(proposals) >= 1

                # Locate XSS reflection proposal
                xss_prop = next((p for p in proposals if p["anomaly_type"] == "REFLECTION"), proposals[0])
                prop_id = xss_prop["id"]
                await writer.flush()

                # 4. Operator approves the high-confidence XSS proposal
                approve_resp = await api_client.post(f"/api/v1/proposals/{prop_id}/approve")
                assert approve_resp.status_code == 200
                assert approve_resp.json()["state"] == "APPROVED"

                # 5. Operator 1-Click executes the approved proposal against live reference target
                exec_resp = await api_client.post(f"/api/v1/proposals/{prop_id}/execute")
                assert exec_resp.status_code == 200
                exec_data = exec_resp.json()

                # 6. Verify executed proposal and diff delta
                assert exec_data["proposal"]["state"] == "COMPLETED"
                exec_result = exec_data["proposal"]["execution_result"]
                assert exec_result["reflected"] is True
                assert "diff" in exec_data

                # 7. Promote verified finding to Curated Collections
                cur_resp = await api_client.post(
                    f"/api/v1/proposals/{prop_id}/to-curated",
                    json={"group_id": "verified_xss", "custom_name": "Confirmed Reflected XSS Probe"},
                )
                assert cur_resp.status_code == 200
                assert cur_resp.json()["ok"] is True
        finally:
            await writer.stop()


async def test_e2e_sequential_bola_idor_matrix_escalation_workflow(tmp_dir: str):
    """T4.2: Pen-Test Scenario 2 - Sequential BOLA/IDOR Matrix Escalation Workflow."""
    app, writer, repo, broadcaster = await _setup_e2e_app(tmp_dir)

    async with TargetAppManager() as target:
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as api_client:
                # 1. Live Client queries own order 1001 (Alice)
                order_url = f"{target.base_url}/orders/1001"
                async with httpx.AsyncClient() as live_http:
                    live_resp = await live_http.get(order_url)
                    assert live_resp.status_code == 200
                    order_json = live_resp.json()
                    assert order_json["owner"] == "alice@example.com"

                # 2. Ingest intercepted flow
                flow_id = f"flow-idor-{uuid.uuid4().hex[:8]}"
                flow_record = FlowRecord(
                    id=flow_id,
                    server_host=target.host,
                    server_port=target.port,
                    request=RequestModel(
                        method="GET",
                        url=order_url,
                        path="/orders/1001",
                        headers={"Host": f"{target.host}:{target.port}"},
                    ),
                    response=ResponseModel(
                        status_code=200,
                        headers={"Content-Type": "application/json"},
                        body=live_resp.text,
                    ),
                )
                await writer.enqueue_insert_flow(flow_record)
                await writer.flush()

                # 3. Generate proposals -> detects sequential ID 1001
                gen_resp = await api_client.post(f"/api/v1/proposals/generate/{flow_id}")
                assert gen_resp.status_code == 200
                proposals = gen_resp.json()
                idor_proposals = [p for p in proposals if p["anomaly_type"] == "IDOR_SEQUENTIAL"]
                assert len(idor_proposals) >= 4
                await writer.flush()

                # 4. Find proposal incrementing ID to 1002 (Bob's order)
                bob_prop = next(p for p in idor_proposals if p["mutated_value"] == 1002)
                bob_prop_id = bob_prop["id"]

                # 5. Operator approves and executes ID 1002 probe against live reference target
                await api_client.post(f"/api/v1/proposals/{bob_prop_id}/approve")
                exec_resp = await api_client.post(f"/api/v1/proposals/{bob_prop_id}/execute")
                assert exec_resp.status_code == 200
                exec_data = exec_resp.json()

                # 6. Verify cross-tenant data was accessed
                assert exec_data["proposal"]["state"] == "COMPLETED"
                resp_preview = exec_data["proposal"]["execution_result"]["response_body_preview"]
                assert "bob@example.com" in resp_preview or "1002" in resp_preview

                # 7. Transfer to Matrix Builder for automated boundary sweep
                mat_resp = await api_client.post(
                    f"/api/v1/proposals/{bob_prop_id}/to-matrix",
                    json={"custom_name": "Orders BOLA Multi-Tenant Matrix"},
                )
                assert mat_resp.status_code == 200
                assert mat_resp.json()["ok"] is True
        finally:
            await writer.stop()


async def test_e2e_auth_anomaly_and_jwt_forgery_operator_workflow(tmp_dir: str):
    """T4.3: Pen-Test Scenario 3 - Auth Anomaly & JWT Forgery Operator Workflow."""
    app, writer, repo, broadcaster = await _setup_e2e_app(tmp_dir)

    async with TargetAppManager() as target:
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as api_client:
                # 1. Login to obtain valid JWT token
                login_url = f"{target.base_url}/auth/login"
                async with httpx.AsyncClient() as live_http:
                    login_resp = await live_http.post(login_url)
                    assert login_resp.status_code == 200
                    jwt_token = login_resp.json()["token"]

                    # 2. Access protected endpoint with Bearer token
                    prot_url = f"{target.base_url}/auth/protected"
                    prot_resp = await live_http.get(prot_url, headers={"Authorization": f"Bearer {jwt_token}"})
                    assert prot_resp.status_code == 200

                # 3. Ingest protected flow
                flow_id = f"flow-auth-{uuid.uuid4().hex[:8]}"
                flow_record = FlowRecord(
                    id=flow_id,
                    server_host=target.host,
                    server_port=target.port,
                    request=RequestModel(
                        method="GET",
                        url=prot_url,
                        path="/auth/protected",
                        headers={"Host": f"{target.host}:{target.port}", "Authorization": f"Bearer {jwt_token}"},
                    ),
                    response=ResponseModel(
                        status_code=200,
                        headers={"Content-Type": "application/json"},
                        body=prot_resp.text,
                    ),
                )
                await writer.enqueue_insert_flow(flow_record)
                await writer.flush()

                # 4. Generate Auth / JWT Proposals
                gen_resp = await api_client.post(f"/api/v1/proposals/generate/{flow_id}")
                assert gen_resp.status_code == 200
                proposals = gen_resp.json()
                auth_proposals = [p for p in proposals if p["anomaly_type"] in ("AUTH_DEVIATION", "JWT_ANOMALY")]
                assert len(auth_proposals) >= 1
                await writer.flush()

                # 5. Execute Auth Stripping (DROP) probe
                drop_prop = next(p for p in auth_proposals if p["auth_override"] == "DROP")
                drop_id = drop_prop["id"]

                await api_client.post(f"/api/v1/proposals/{drop_id}/approve")
                exec_drop = await api_client.post(f"/api/v1/proposals/{drop_id}/execute")
                assert exec_drop.status_code == 200
                exec_drop_data = exec_drop.json()

                assert exec_drop_data["proposal"]["state"] == "COMPLETED"
                assert "diff" in exec_drop_data
        finally:
            await writer.stop()


async def test_e2e_json_state_mutation_mass_assignment_workflow(tmp_dir: str):
    """T4.4: Pen-Test Scenario 4 - JSON State Mutation Mass Assignment Workflow."""
    app, writer, repo, broadcaster = await _setup_e2e_app(tmp_dir)

    async with TargetAppManager() as target:
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as api_client:
                # 1. Intercept checkout state mutation
                checkout_url = f"{target.base_url}/orders/checkout"
                req_json = {"customer_id": 42, "items": [{"item_id": 10, "qty": 2}]}
                async with httpx.AsyncClient() as live_http:
                    live_resp = await live_http.post(checkout_url, json=req_json)
                    assert live_resp.status_code == 201

                # 2. Ingest flow
                flow_id = f"flow-checkout-{uuid.uuid4().hex[:8]}"
                flow_record = FlowRecord(
                    id=flow_id,
                    server_host=target.host,
                    server_port=target.port,
                    request=RequestModel(
                        method="POST",
                        url=checkout_url,
                        path="/orders/checkout",
                        headers={"Host": f"{target.host}:{target.port}", "Content-Type": "application/json"},
                        body=json.dumps(req_json),
                    ),
                    response=ResponseModel(
                        status_code=201,
                        headers={"Content-Type": "application/json"},
                        body=live_resp.text,
                    ),
                )
                await writer.enqueue_insert_flow(flow_record)
                await writer.flush()

                # 3. Generate proposals -> detects JSON schema mass assignment opportunities
                gen_resp = await api_client.post(f"/api/v1/proposals/generate/{flow_id}")
                assert gen_resp.status_code == 200
                proposals = gen_resp.json()
                schema_props = [p for p in proposals if p["anomaly_type"] == "JSON_SCHEMA"]
                assert len(schema_props) >= 1
                await writer.flush()

                # 4. Operator approves Mass Assignment probe
                target_prop_id = schema_props[0]["id"]
                await api_client.post(f"/api/v1/proposals/{target_prop_id}/approve")

                # 5. Execute mutated request against live reference target
                exec_resp = await api_client.post(f"/api/v1/proposals/{target_prop_id}/execute")
                assert exec_resp.status_code == 200
                exec_data = exec_resp.json()

                assert exec_data["proposal"]["state"] == "COMPLETED"
                assert exec_data["proposal"]["execution_result"] is not None
                assert "diff" in exec_data
        finally:
            await writer.stop()
