"""
Tier 3 Cross-Module Interaction Tests: Nuclei Engine Pipeline, Multi-Root Overrides,
Triage Pipeline Stage 8b, Threat HUD Statistics, Proposal Staging, and Event Broadcasting.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List
import pytest

from flowforge.core.broadcaster import EventBroadcaster, get_broadcaster
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.models import EndpointCategory, TriageSummary
from flowforge.heuristics.nuclei_loader import NucleiTemplateLoader
from flowforge.heuristics.nuclei_matcher import NucleiMatcherEngine
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.heuristics.proposal_synthesizer import ProposalSynthesizer
from flowforge.models.events import FlowEvent
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.nuclei import (
    NucleiHttpBlock,
    NucleiMatcher,
    NucleiMatcherType,
    NucleiMatchResult,
    NucleiSeverity,
    NucleiTemplate,
)
from flowforge.models.proposal import AnomalyType, ProposalSeverity, ProposalState, TestProposal


# ===========================================================================
# 1. Full Pipeline: Flow -> Stage 8b Match -> Triage -> Proposal -> Broadcast
# ===========================================================================

async def test_t3_nuclei_full_pipeline_ingest_triage_proposal_broadcast():
    """
    Verify complete cross-module integration:
    Flow Ingestion -> TriagePipeline Nuclei matching -> TriageSummary ->
    Threat HUD tags -> ProposalSynthesizer staging -> EventBroadcaster dispatch.
    """
    broadcaster = EventBroadcaster(max_queue_size=100)
    client_queue = await broadcaster.subscribe("client-hud-subscriber")

    # 1. Set up loader with passive exposure template
    loader = NucleiTemplateLoader(roots=[], auto_load=False)
    matcher = NucleiMatcherEngine()

    swagger_template = NucleiTemplate(
        id="swagger-api-doc-exposure",
        name="Swagger API Documentation Exposure",
        severity=NucleiSeverity.LOW,
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
                        words=['"swagger":', '"openapi":', "Swagger UI"],
                        condition="or",
                    )
                ],
            )
        ],
    )
    loader.register_template(swagger_template)

    pipeline = TriagePipeline(nuclei_loader=loader, nuclei_matcher=matcher)
    synthesizer = ProposalSynthesizer()

    # 2. Ingest intercepted FlowRecord
    flow = FlowRecord(
        id=f"flow-swagger-{uuid.uuid4().hex[:8]}",
        server_host="api.target.com",
        server_port=443,
        request=RequestModel(
            method="GET",
            url="https://api.target.com/v2/api-docs",
            path="/v2/api-docs",
            headers={"Host": "api.target.com"},
        ),
        response=ResponseModel(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"swagger": "2.0", "info": {"title": "Internal Banking API", "version": "1.0.0"}}',
        ),
    )

    # 3. Process flow through triage pipeline (Stage 8b Nuclei passive match)
    triage: TriageSummary = pipeline.process_flow_sync(flow)

    assert len(triage.nuclei_matches) == 1
    match: NucleiMatchResult = triage.nuclei_matches[0]
    assert match.template_id == "swagger-api-doc-exposure"
    assert match.matched is True
    assert match.severity == NucleiSeverity.LOW

    # Verify tags added to TriageSummary for Threat HUD
    assert "nuclei" in triage.tags
    assert "swagger-api-doc-exposure" in triage.tags
    assert "exposure" in triage.tags

    # 4. Synthesize test proposals from triage summary
    proposals: List[TestProposal] = synthesizer.synthesize(flow, triage)
    nuclei_props = [p for p in proposals if p.title.startswith("[Nuclei]")]

    assert len(nuclei_props) >= 1
    staged_prop = nuclei_props[0]
    assert "Swagger API Documentation Exposure" in staged_prop.title
    assert staged_prop.anomaly_type == AnomalyType.EXPOSURE
    assert staged_prop.state == ProposalState.PENDING
    assert staged_prop.flow_id == flow.id

    # 5. Broadcast triage and proposal events
    broadcaster.broadcast_triage_annotated(flow.id, triage)
    broadcaster.broadcast_flow_created(flow)

    # Verify event received on WebSocket client queue
    event: FlowEvent = await asyncio.wait_for(client_queue.get(), timeout=1.0)
    assert event.event_type == "triage_annotated"
    assert event.flow_id == flow.id
    assert "nuclei" in event.data["tags"]

    await broadcaster.unsubscribe("client-hud-subscriber")


# ===========================================================================
# 2. Multi-Root Custom Arsenal Override Interaction
# ===========================================================================

def test_t3_nuclei_arsenal_custom_template_override_in_triage():
    """
    Verify Arsenal template overrides built-in template ID, changing its severity,
    match criteria, and resulting in custom Arsenal proposal generation during triage.
    """
    with tempfile.TemporaryDirectory(prefix="ff_t3_roots_") as temp_dir:
        builtin_dir = Path(temp_dir) / "builtin"
        arsenal_dir = Path(temp_dir) / "arsenal"

        (builtin_dir / "cves").mkdir(parents=True, exist_ok=True)
        (arsenal_dir / "cves").mkdir(parents=True, exist_ok=True)

        # Built-in version: CVE-2024-9999 with INFO severity and passive=False
        (builtin_dir / "cves" / "cve-2024-9999.yaml").write_text("""
id: CVE-2024-9999
info:
  name: Built-in Base CVE
  severity: info
  author: base_researcher
  tags: cve,base
http:
  - method: GET
    matchers:
      - type: status
        status:
          - 500
""", encoding="utf-8")

        # Arsenal version: CVE-2024-9999 with CRITICAL severity, passive=True, and custom body match
        (arsenal_dir / "cves" / "cve-2024-9999.yaml").write_text("""
id: CVE-2024-9999
info:
  name: Arsenal Overridden Exploit CVE-2024-9999
  severity: critical
  author: arsenal_elite
  tags: cve,arsenal,rce,passive
http:
  - method: GET
    matchers:
      - type: word
        part: body
        words:
          - "EXPLOIT_PAYLOAD_EXECUTED_ROOT"
""", encoding="utf-8")

        loader = NucleiTemplateLoader(roots=[builtin_dir, arsenal_dir], auto_load=True)
        matcher = NucleiMatcherEngine()
        pipeline = TriagePipeline(nuclei_loader=loader, nuclei_matcher=matcher)
        synthesizer = ProposalSynthesizer()

        assert loader.total_count == 1
        overridden_tmpl = loader.get_template("CVE-2024-9999")
        assert overridden_tmpl.author == "arsenal_elite"
        assert overridden_tmpl.severity == NucleiSeverity.CRITICAL

        # Flow that triggers Arsenal template
        flow = FlowRecord(
            id="flow-arsenal-test",
            server_host="vulnerable.corp",
            request=RequestModel(method="GET", url="http://vulnerable.corp/app", path="/app"),
            response=ResponseModel(
                status_code=200,
                headers={"Content-Type": "text/plain"},
                body="Output: EXPLOIT_PAYLOAD_EXECUTED_ROOT [uid=0]",
            ),
        )

        triage = pipeline.process_flow_sync(flow)
        assert len(triage.nuclei_matches) == 1
        assert triage.nuclei_matches[0].severity == NucleiSeverity.CRITICAL
        assert triage.nuclei_matches[0].template_name == "Arsenal Overridden Exploit CVE-2024-9999"

        # Proposals generated reflect CRITICAL Arsenal metadata
        proposals = synthesizer.synthesize(flow, triage)
        cve_props = [p for p in proposals if "CVE-2024-9999" in p.title]
        assert len(cve_props) >= 1
        assert cve_props[0].severity == ProposalSeverity.CRITICAL
        assert cve_props[0].anomaly_type == AnomalyType.CVE


# ===========================================================================
# 3. Concurrent Multi-Flow Ingestion & Triage Thread Safety
# ===========================================================================

def test_t3_nuclei_concurrent_flow_triage_thread_safety():
    """Verify concurrent flow triage across multiple threads does not cause race conditions or state corruption."""
    loader = NucleiTemplateLoader(roots=[], auto_load=False)
    matcher = NucleiMatcherEngine()

    for i in range(10):
        tmpl = NucleiTemplate(
            id=f"concurrent-tmpl-{i}",
            name=f"Concurrent Check {i}",
            severity=NucleiSeverity.MEDIUM,
            tags=["passive"],
            is_passive=True,
            http_blocks=[
                NucleiHttpBlock(
                    matchers=[
                        NucleiMatcher(
                            type=NucleiMatcherType.WORD,
                            part="body",
                            words=[f"MARKER_{i}"],
                        )
                    ]
                )
            ],
        )
        loader.register_template(tmpl)

    pipeline = TriagePipeline(nuclei_loader=loader, nuclei_matcher=matcher)

    import concurrent.futures

    def _process(flow_idx: int) -> TriageSummary:
        f = FlowRecord(
            id=f"flow-concurrency-{flow_idx}",
            server_host="test.local",
            request=RequestModel(method="GET", url=f"http://test.local/{flow_idx}", path=f"/{flow_idx}"),
            response=ResponseModel(status_code=200, body=f"Data with MARKER_{flow_idx % 10}"),
        )
        return pipeline.process_flow_sync(f)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(_process, range(40)))

    assert len(results) == 40
    for idx, res in enumerate(results):
        expected_tmpl = f"concurrent-tmpl-{idx % 10}"
        assert len(res.nuclei_matches) == 1
        assert res.nuclei_matches[0].template_id == expected_tmpl


# ===========================================================================
# 4. Composite Findings: Nuclei + Reflection + Auth Deviations
# ===========================================================================

def test_t3_nuclei_composite_triage_findings():
    """Verify flow containing Nuclei exposure, parameter reflection, and missing auth produces composite findings."""
    loader = NucleiTemplateLoader(roots=[], auto_load=False)
    matcher = NucleiMatcherEngine()

    loader.register_template(
        NucleiTemplate(
            id="debug-mode-active",
            name="Debug Mode Active",
            severity=NucleiSeverity.HIGH,
            category="MISCONFIG",
            tags=["misconfig", "debug", "passive"],
            is_passive=True,
            http_blocks=[
                NucleiHttpBlock(
                    matchers=[
                        NucleiMatcher(
                            type=NucleiMatcherType.WORD,
                            part="body",
                            words=["DEBUG_TOOLBAR_VERSION", "Django Debug Toolbar"],
                            condition="or",
                        )
                    ]
                )
            ],
        )
    )

    pipeline = TriagePipeline(nuclei_loader=loader, nuclei_matcher=matcher)
    synthesizer = ProposalSynthesizer()

    # Flow with reflection (?user=alice reflected in body) + Django debug toolbar + unauthenticated sensitive path
    flow = FlowRecord(
        id="flow-composite-01",
        server_host="portal.target.com",
        request=RequestModel(
            method="GET",
            url="https://portal.target.com/admin/settings?user=alice_admin",
            path="/admin/settings",
            query_string="user=alice_admin",
            query_params={"user": "alice_admin"},
        ),
        response=ResponseModel(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body='<html><body><h1>Settings</h1><input name="user" value="alice_admin"><div id="djDebug">Django Debug Toolbar</div></body></html>',
        ),
    )

    triage = pipeline.process_flow_sync(flow)

    # 1. Nuclei match present
    assert len(triage.nuclei_matches) == 1
    assert triage.nuclei_matches[0].template_id == "debug-mode-active"

    # 2. Reflection findings present
    assert len(triage.reflections) >= 1
    assert any(r.parameter_name == "user" for r in triage.reflections)

    # 3. Composite tags present
    assert "nuclei" in triage.tags
    assert "reflection" in triage.tags
    assert "debug-mode-active" in triage.tags

    # 4. Synthesizer produces both Reflection and Nuclei test proposals
    proposals = synthesizer.synthesize(flow, triage)
    prop_types = [p.anomaly_type for p in proposals]
    assert AnomalyType.REFLECTION in prop_types
    assert AnomalyType.MISCONFIG in prop_types
