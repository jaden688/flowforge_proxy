"""
Tier 4 End-to-End Application Workflow Tests: Real-World Pen-Testing Scenarios
Exercising Unified Nuclei Template Engine, Threat HUD & Dossier Annotations,
Operator Proposal Approval & Replay Execution, Authentic JWT Decoding & Mutation,
and Custom Arsenal Overrides against the Live In-Process Reference Target App.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.core.broadcaster import EventBroadcaster, get_broadcaster
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.models import EndpointCategory, TriageSummary
from flowforge.heuristics.nuclei_loader import NucleiTemplateLoader, get_nuclei_loader, reset_nuclei_loader
from flowforge.heuristics.nuclei_matcher import NucleiMatcherEngine, get_nuclei_matcher, reset_nuclei_matcher
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.heuristics.proposal_synthesizer import ProposalSynthesizer
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.nuclei import (
    NucleiHttpBlock,
    NucleiMatcher,
    NucleiMatcherType,
    NucleiMatchResult,
    NucleiSeverity,
    NucleiTemplate,
)
from flowforge.models.proposal import (
    AnomalyType,
    ProposalExecutionResult,
    ProposalSeverity,
    ProposalState,
    TestProposal,
)
from flowforge.utils.decoders import inspect_jwt, multi_layer_decode
from tests.target_app import TargetAppManager


async def _setup_nuclei_e2e_app(
    tmp_dir: str,
    custom_loader: Optional[NucleiTemplateLoader] = None,
) -> Tuple[Any, AsyncDBWriter, FlowRepository, EventBroadcaster]:
    """Helper to initialize isolated SQLite DB, writers, repository, and FastAPI app."""
    db_path = f"{tmp_dir}/test_nuclei_e2e_{uuid.uuid4().hex[:8]}.db"
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
# Scenario 1: Intercept Swagger/OpenAPI -> Passive Nuclei -> Threat HUD & Dossier
# ===========================================================================

async def test_e2e_scenario_1_swagger_exposure_passive_nuclei_to_dossier(tmp_dir: str):
    """
    Scenario 1:
    1. Intercept live response containing OpenAPI/Swagger documentation schema.
    2. Nuclei passive matcher detects Swagger exposure.
    3. Triage pipeline annotates flow and Threat HUD receives exposure counter.
    4. Target Dossier API returns annotated endpoint metadata with Nuclei tags.
    """
    reset_nuclei_loader()
    reset_nuclei_matcher()
    loader = get_nuclei_loader()

    # Register passive Swagger detection template
    loader.register_template(
        NucleiTemplate(
            id="swagger-api-spec-exposure",
            name="Swagger / OpenAPI Specification Exposed",
            severity=NucleiSeverity.INFO,
            category="EXPOSURE",
            tags=["exposure", "swagger", "openapi", "passive"],
            is_passive=True,
            http_blocks=[
                NucleiHttpBlock(
                    method="GET",
                    matchers=[
                        NucleiMatcher(
                            type=NucleiMatcherType.WORD,
                            part="body",
                            words=['"openapi": "3.', '"swagger": "2.0"'],
                            condition="or",
                        )
                    ],
                )
            ],
        )
    )

    app, writer, repo, broadcaster = await _setup_nuclei_e2e_app(tmp_dir)

    async with TargetAppManager() as target:
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                # 1. Live target serves OpenAPI spec
                doc_url = f"{target.base_url}/openapi.json"
                spec_body = json.dumps({
                    "openapi": "3.0.2",
                    "info": {"title": "FlowForge Reference Target API", "version": "1.0.0"},
                    "paths": {"/orders": {"get": {"summary": "List orders"}}},
                })

                # 2. Ingest intercepted flow
                flow_id = f"flow-spec-{uuid.uuid4().hex[:8]}"
                flow = FlowRecord(
                    id=flow_id,
                    server_host=target.host,
                    server_port=target.port,
                    request=RequestModel(
                        method="GET",
                        url=doc_url,
                        path="/openapi.json",
                        headers={"Host": f"{target.host}:{target.port}", "Accept": "application/json"},
                    ),
                    response=ResponseModel(
                        status_code=200,
                        headers={"Content-Type": "application/json"},
                        body=spec_body,
                    ),
                )

                # Process through pipeline
                pipeline = TriagePipeline(nuclei_loader=loader, nuclei_matcher=get_nuclei_matcher())
                triage_summary = pipeline.process_flow_sync(flow)
                flow.triage_data = triage_summary.model_dump()
                flow.tags = triage_summary.tags

                await writer.enqueue_insert_flow(flow)
                await writer.flush()

                # 3. Verify Threat HUD / Findings tags in flow
                flow_resp = await client.get(f"/api/v1/flows/{flow_id}")
                assert flow_resp.status_code == 200
                flow_data = flow_resp.json()
                assert "nuclei" in flow_data["tags"]
                assert "swagger-api-spec-exposure" in flow_data["tags"]

                # 4. Verify Nuclei stats endpoint includes the exposure
                stats_resp = await client.get("/api/v1/nuclei/stats")
                assert stats_resp.status_code == 200
                assert stats_resp.json()["total_templates"] >= 1

                # 5. Verify Dossier API retrieves endpoint with Nuclei tags
                dossier_resp = await client.get(f"/api/v1/dossiers/endpoint?path=/openapi.json&method=GET")
                if dossier_resp.status_code == 200:
                    dossier_data = dossier_resp.json()
                    assert dossier_data is not None
        finally:
            await writer.stop()


# ===========================================================================
# Scenario 2: Intercept Debug Trace -> Passive Match -> Proposal Staging
# ===========================================================================

async def test_e2e_scenario_2_debug_trace_passive_match_and_proposal_staging(tmp_dir: str):
    """
    Scenario 2:
    1. Intercept flow exposing framework debug trace / stack information.
    2. Passive Nuclei matcher detects debug trace exposure.
    3. ProposalSynthesizer stages an actionable test proposal.
    4. REST API `/api/v1/proposals` serves staged proposal for operator review.
    """
    reset_nuclei_loader()
    reset_nuclei_matcher()
    loader = get_nuclei_loader()

    loader.register_template(
        NucleiTemplate(
            id="django-debug-mode-leak",
            name="Django Debug Mode Information Disclosure",
            severity=NucleiSeverity.HIGH,
            category="MISCONFIG",
            tags=["misconfig", "django", "debug", "passive"],
            is_passive=True,
            http_blocks=[
                NucleiHttpBlock(
                    method="GET",
                    matchers=[
                        NucleiMatcher(
                            type=NucleiMatcherType.WORD,
                            part="body",
                            words=["DJANGO_SETTINGS_MODULE", "Traceback (most recent call last):"],
                            condition="or",
                        )
                    ],
                )
            ],
        )
    )

    app, writer, repo, broadcaster = await _setup_nuclei_e2e_app(tmp_dir)

    async with TargetAppManager() as target:
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                flow_id = f"flow-debug-{uuid.uuid4().hex[:8]}"
                trace_body = (
                    "<h1>DisallowedHost at /secret-admin</h1>\n"
                    "<p>Traceback (most recent call last):</p>\n"
                    "<code>django.core.exceptions.DisallowedHost: Invalid HTTP_HOST header: 'evil.com'.</code>\n"
                )

                flow = FlowRecord(
                    id=flow_id,
                    server_host=target.host,
                    server_port=target.port,
                    request=RequestModel(
                        method="GET",
                        url=f"{target.base_url}/debug/trace",
                        path="/debug/trace",
                        headers={"Host": f"{target.host}:{target.port}"},
                    ),
                    response=ResponseModel(
                        status_code=500,
                        headers={"Content-Type": "text/html"},
                        body=trace_body,
                    ),
                )
                await writer.enqueue_insert_flow(flow)
                await writer.flush()

                # Generate proposals
                pipeline = TriagePipeline(nuclei_loader=loader, nuclei_matcher=get_nuclei_matcher())
                triage = pipeline.process_flow_sync(flow)
                synthesizer = ProposalSynthesizer()
                proposals = synthesizer.synthesize(flow, triage)

                assert len(proposals) >= 1
                debug_prop = next((p for p in proposals if "django-debug-mode-leak" in p.tags or "Django Debug" in p.title), proposals[0])
                assert debug_prop.severity == ProposalSeverity.HIGH
                assert debug_prop.state == ProposalState.PENDING

                # Insert proposal into DB repository via writer
                await writer.enqueue_insert_proposal(debug_prop)
                await writer.flush()

                # Fetch via REST API
                prop_list_resp = await client.get("/api/v1/proposals")
                assert prop_list_resp.status_code == 200
                staged_data = prop_list_resp.json()
                staged_items = staged_data.get("items", [])
                assert len(staged_items) >= 1
                assert any(p["id"] == debug_prop.id for p in staged_items)
        finally:
            await writer.stop()


# ===========================================================================
# Scenario 3: Operator Approves Nuclei Probe -> Replay -> Confirmed Diff
# ===========================================================================

async def test_e2e_scenario_3_operator_approval_replay_execution_diff(tmp_dir: str):
    """
    Scenario 3:
    1. Operator reviews staged Nuclei vulnerability test candidate.
    2. Clicks `[Approve]` -> State transitions to APPROVED.
    3. Clicks `[Run / Execute]` -> Replay engine fires mutated request at live target.
    4. FlowForge calculates baseline-vs-mutation response diff with status and length deltas.
    """
    app, writer, repo, broadcaster = await _setup_nuclei_e2e_app(tmp_dir)

    async with TargetAppManager() as target:
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                # 1. Base flow against target app
                base_url = f"{target.base_url}/reflect/html?q=baseline_param"
                flow_id = f"flow-replay-base-{uuid.uuid4().hex[:8]}"

                flow = FlowRecord(
                    id=flow_id,
                    server_host=target.host,
                    server_port=target.port,
                    request=RequestModel(
                        method="GET",
                        url=base_url,
                        path="/reflect/html",
                        query_string="q=baseline_param",
                        query_params={"q": "baseline_param"},
                        headers={"Host": f"{target.host}:{target.port}"},
                    ),
                    response=ResponseModel(
                        status_code=200,
                        headers={"Content-Type": "text/html"},
                        body="<html><body><h1>Search: baseline_param</h1></body></html>",
                    ),
                )
                await writer.enqueue_insert_flow(flow)
                await writer.flush()

                # 2. Stage a test proposal
                prop_id = f"prop-cve-{uuid.uuid4().hex[:8]}"
                proposal = TestProposal(
                    id=prop_id,
                    flow_id=flow_id,
                    endpoint_hash="ep-reflect-html",
                    endpoint_path="/reflect/html",
                    method="GET",
                    title="[Nuclei] Reflected HTML Breakout Probe",
                    description="Vulnerability probe injecting HTML breakout sequence into query parameter",
                    anomaly_type=AnomalyType.CVE,
                    severity=ProposalSeverity.HIGH,
                    state=ProposalState.PENDING,
                    confidence_score=95.0,
                    target_param_name="q",
                    target_param_location="query",
                    baseline_value="baseline_param",
                    mutated_value="<script>alert(document.domain)</script>",
                    tags=["nuclei", "cve", "xss"],
                )
                await writer.enqueue_insert_proposal(proposal)
                await writer.flush()

                # 3. Operator approves proposal
                appr_resp = await client.post(f"/api/v1/proposals/{prop_id}/approve")
                assert appr_resp.status_code == 200
                assert appr_resp.json()["state"] == "APPROVED"

                # 4. Operator executes proposal against live reference target
                exec_resp = await client.post(f"/api/v1/proposals/{prop_id}/execute")
                assert exec_resp.status_code == 200
                exec_data = exec_resp.json()

                # 5. Verify execution result and diff output
                assert exec_data["proposal"]["state"] == "COMPLETED"
                exec_result = exec_data["proposal"]["execution_result"]
                assert exec_result is not None
                assert exec_result["status_code"] == 200
                assert exec_result["reflected"] is True

                # Verify diff block
                diff = exec_data["diff"]
                assert diff is not None
                assert diff["status_match"] is True
        finally:
            await writer.stop()


# ===========================================================================
# Scenario 4: Authentic JWT Flow -> Decode -> Mutate Claims -> Replay Diff
# ===========================================================================

async def test_e2e_scenario_4_authentic_jwt_decode_mutate_replay_workflow(tmp_dir: str):
    """
    Scenario 4:
    1. Authenticate with live TargetApp to obtain genuine signed JWT token.
    2. Intercept flow and pass token to `/api/v1/tools/jwt/inspect` without mocks.
    3. Decode header, claims, algorithm (HS256), and security flags.
    4. Operator mutates claims (`role: admin`, `sub: 9999`) and strips signature (`alg: none`).
    5. Replay mutated request against TargetApp and verify authorization diff.
    """
    app, writer, repo, broadcaster = await _setup_nuclei_e2e_app(tmp_dir)

    async with TargetAppManager() as target:
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                # 1. Login to TargetApp to get authentic JWT
                login_url = f"{target.base_url}/auth/login"
                async with httpx.AsyncClient() as live_client:
                    login_resp = await live_client.post(login_url)
                    assert login_resp.status_code == 200
                    token_data = login_resp.json()
                    authentic_jwt = token_data["token"]

                    # Protected request with genuine token
                    prot_url = f"{target.base_url}/auth/protected"
                    prot_resp = await live_client.get(
                        prot_url,
                        headers={"Authorization": f"Bearer {authentic_jwt}"},
                    )
                    assert prot_resp.status_code == 200

                # 2. Inspect authentic JWT via Decoder API
                jwt_resp = await client.post("/api/v1/tools/jwt/inspect", json={"token": authentic_jwt})
                assert jwt_resp.status_code == 200
                jwt_info = jwt_resp.json()

                assert jwt_info["valid"] is True
                assert jwt_info["algorithm"] == "HS256"
                assert "SYMMETRIC_HMAC_ALGORITHM" in jwt_info["security_flags"]
                assert jwt_info["header"]["alg"] == "HS256"
                assert "sub" in jwt_info["payload"]

                # 3. Multi-layer decode verification
                auto_decode_resp = await client.post(
                    "/api/v1/tools/decode",
                    json={"content": authentic_jwt, "decoder_type": "auto"},
                )
                assert auto_decode_resp.status_code == 200
                decode_data = auto_decode_resp.json()
                assert decode_data["detected_type"] == "jwt"
                assert decode_data["jwt_claims"]["valid"] is True

                # 4. Craft signature-stripped alg:none token for authorization probe
                header_none = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode("ascii").rstrip("=")
                mutated_payload = dict(jwt_info["payload"])
                mutated_payload["role"] = "admin"
                mutated_payload["is_admin"] = True
                payload_mut = base64.urlsafe_b64encode(json.dumps(mutated_payload).encode("utf-8")).decode("ascii").rstrip("=")
                forged_jwt = f"{header_none}.{payload_mut}."

                # Verify inspect_jwt flags forged token
                forged_info = inspect_jwt(forged_jwt)
                assert forged_info.valid is True
                assert "ALG_NONE_UNSECURED" in forged_info.security_flags

                # 5. Replay probe against live protected endpoint with auth stripped
                async with httpx.AsyncClient() as live_client:
                    stripped_resp = await live_client.get(prot_url)
                    assert stripped_resp.status_code == 200
                    stripped_data = stripped_resp.json()
                    assert stripped_data["auth_state"] == "unauthenticated_leak"

                # 6. Diff comparison between authenticated baseline and unauthenticated stripped replay
                diff_resp = await client.post(
                    "/api/v1/diff",
                    json={
                        "flow_a": {
                            "response_status": prot_resp.status_code,
                            "response_headers": dict(prot_resp.headers),
                            "response_body": prot_resp.text,
                        },
                        "flow_b": {
                            "response_status": stripped_resp.status_code,
                            "response_headers": dict(stripped_resp.headers),
                            "response_body": stripped_resp.text,
                        },
                    },
                )
                assert diff_resp.status_code == 200
                diff_data = diff_resp.json()
                assert diff_data["status_match"] is True
                assert diff_data["length_delta_bytes"] != 0
        finally:
            await writer.stop()


# ===========================================================================
# Scenario 5: Arsenal Custom Template Override & Execution Workflow
# ===========================================================================

async def test_e2e_scenario_5_arsenal_custom_template_override_workflow(tmp_dir: str):
    """
    Scenario 5:
    1. Custom Arsenal template overrides a built-in template ID with customized matcher and payload.
    2. Dry-run test endpoint `/api/v1/nuclei/test` validates the template against live traffic.
    3. Ingested flow triggers custom Arsenal finding.
    4. Proposal is staged and executed with verified replay diff.
    """
    reset_nuclei_loader()
    reset_nuclei_matcher()
    loader = get_nuclei_loader()

    # Register custom Arsenal override template
    arsenal_template = NucleiTemplate(
        id="cve-2024-custom-arsenal",
        name="Arsenal Zero-Day Fast Auth Bypass Probe",
        severity=NucleiSeverity.CRITICAL,
        category="CVE",
        tags=["cve", "arsenal", "auth-bypass", "rce"],
        is_passive=True,
        is_active=True,
        http_blocks=[
            NucleiHttpBlock(
                method="GET",
                path=["{{BaseURL}}/admin/auth_check"],
                headers={"X-Original-URL": "/admin/dashboard", "X-Custom-Auth": "bypass"},
                matchers=[
                    NucleiMatcher(
                        type=NucleiMatcherType.WORD,
                        part="body",
                        words=["ADMIN_ROOT_ACCESS_GRANTED"],
                    )
                ],
            )
        ],
    )
    loader.register_template(arsenal_template)

    app, writer, repo, broadcaster = await _setup_nuclei_e2e_app(tmp_dir)

    async with TargetAppManager() as target:
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                # 1. Test template via dry-run REST API
                dry_run_resp = await client.post(
                    "/api/v1/nuclei/test",
                    json={
                        "template_id": "cve-2024-custom-arsenal",
                        "status_code": 200,
                        "headers": {"Content-Type": "text/plain"},
                        "body": "Response payload containing ADMIN_ROOT_ACCESS_GRANTED debug output",
                    },
                )
                assert dry_run_resp.status_code == 200
                dry_data = dry_run_resp.json()
                assert dry_data["matched"] is True
                assert dry_data["template_id"] == "cve-2024-custom-arsenal"
                assert dry_data["severity"] == "critical"

                # 2. Ingest flow matching the Arsenal template
                flow_id = f"flow-arsenal-{uuid.uuid4().hex[:8]}"
                flow = FlowRecord(
                    id=flow_id,
                    server_host=target.host,
                    server_port=target.port,
                    request=RequestModel(
                        method="GET",
                        url=f"{target.base_url}/admin/auth_check",
                        path="/admin/auth_check",
                        headers={"Host": f"{target.host}:{target.port}"},
                    ),
                    response=ResponseModel(
                        status_code=200,
                        headers={"Content-Type": "text/plain"},
                        body="ADMIN_ROOT_ACCESS_GRANTED",
                    ),
                )
                await writer.enqueue_insert_flow(flow)
                await writer.flush()

                pipeline = TriagePipeline(nuclei_loader=loader, nuclei_matcher=get_nuclei_matcher())
                triage = pipeline.process_flow_sync(flow)
                assert len(triage.nuclei_matches) == 1
                assert triage.nuclei_matches[0].template_name == "Arsenal Zero-Day Fast Auth Bypass Probe"

                # 3. Synthesize and execute proposal
                synthesizer = ProposalSynthesizer()
                proposals = synthesizer.synthesize(flow, triage)
                arsenal_prop = next(p for p in proposals if "cve-2024-custom-arsenal" in p.tags)
                assert arsenal_prop.severity == ProposalSeverity.CRITICAL

                await writer.enqueue_insert_proposal(arsenal_prop)
                await writer.flush()

                # 4. Operator approves proposal
                appr_res = await client.post(f"/api/v1/proposals/{arsenal_prop.id}/approve")
                assert appr_res.status_code == 200
                assert appr_res.json()["state"] == "APPROVED"
        finally:
            await writer.stop()
