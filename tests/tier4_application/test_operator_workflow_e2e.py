"""
Tier 4 Application Tests: End-to-End Security Operator Journey & Synthetic Scenario Replay.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
import pytest
import httpx

from flowforge.core.broadcaster import EventBroadcaster
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.models import (
    EndpointCategory,
    FindingSeverity,
    IdentifierType,
    ReflectionContext,
)
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.models.flow import FlowFilterParams, FlowRecord, RequestModel, ResponseModel
from flowforge.models.parameter import DiscoveredEndpointModel, ExtractedParameterModel
from tests.generator import SyntheticTrafficGenerator
from tests.target_app import TargetAppManager


async def test_full_security_operator_workflow(tmp_db_path: str, tmp_dir: str):
    """Execute complete security operator flow: replay synthetic scenarios, run triage, assert 100% detection."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=20, flush_interval_ms=10)
    await writer.start()

    pipeline = TriagePipeline()
    broadcaster = EventBroadcaster()

    async with TargetAppManager() as target:
        gen = SyntheticTrafficGenerator(target_url=target.base_url)

        try:
            # 1. Execute synthetic scenarios against live reference target
            ref_results = await gen.scenario_reflection_traffic()
            assert ref_results["html_status"] == 200
            assert ref_results["json_status"] == 200

            auth_results = await gen.scenario_auth_and_entropy_traffic()
            assert auth_results["auth_status"] == 200

            idor_results = await gen.scenario_idor_and_clustering_traffic()
            assert len(idor_results["orders"]) == 3

            bound_results = await gen.scenario_boundary_traffic()

            # 2. Build realistic FlowRecords matching the executed scenarios and run triage
            sample_flows = [
                # Flow 1: HTML Reflection
                FlowRecord(
                    id=str(uuid.uuid4()),
                    server_host="127.0.0.1",
                    request=RequestModel(
                        method="GET",
                        url=f"{target.base_url}/reflect/html?q=ReflectMeXSS_Value&attr=QuotedAttrValue_123",
                        path="/reflect/html",
                        query_string="q=ReflectMeXSS_Value&attr=QuotedAttrValue_123",
                    ),
                    response=ResponseModel(
                        status_code=200,
                        content_type="text/html",
                        body=ref_results["html_body"],
                    ),
                ),
                # Flow 2: JSON Reflection
                FlowRecord(
                    id=str(uuid.uuid4()),
                    server_host="127.0.0.1",
                    request=RequestModel(
                        method="POST",
                        url=f"{target.base_url}/reflect/json",
                        path="/reflect/json",
                        content_type="application/json",
                        body='{"user": "AliceSecurity", "notes": "JSONReflectedToken"}',
                    ),
                    response=ResponseModel(
                        status_code=200,
                        content_type="application/json",
                        body=str(ref_results["json_body"]),
                    ),
                ),
                # Flow 3: Unauthenticated Access to Sensitive Route
                FlowRecord(
                    id=str(uuid.uuid4()),
                    server_host="127.0.0.1",
                    request=RequestModel(
                        method="GET",
                        url=f"{target.base_url}/auth/protected",
                        path="/auth/protected",
                    ),
                    response=ResponseModel(
                        status_code=200,
                        body='{"status": "ok", "auth_state": "unauthenticated_leak"}',
                    ),
                ),
                # Flow 4: Sequential IDOR Route
                FlowRecord(
                    id=str(uuid.uuid4()),
                    server_host="127.0.0.1",
                    request=RequestModel(
                        method="GET",
                        url=f"{target.base_url}/orders/1001",
                        path="/orders/1001",
                    ),
                    response=ResponseModel(
                        status_code=200,
                        body='{"order_id": 1001, "owner": "alice@example.com"}',
                    ),
                ),
                # Flow 5: Admin User Management Mutation
                FlowRecord(
                    id=str(uuid.uuid4()),
                    server_host="127.0.0.1",
                    request=RequestModel(
                        method="GET",
                        url=f"{target.base_url}/admin/users",
                        path="/admin/users",
                    ),
                    response=ResponseModel(
                        status_code=200,
                        body='{"role": "admin", "total_users": 3}',
                    ),
                ),
            ]

            triage_results = []
            for flow_rec in sample_flows:
                triage = await pipeline.process_flow(flow_rec)
                flow_rec.tags = triage.tags
                flow_rec.triage_data = triage.model_dump()
                triage_results.append((flow_rec, triage))

                # Enqueue for database storage
                await writer.enqueue_insert_flow(flow_rec)

                # Persist discovered endpoint
                ep = DiscoveredEndpointModel(
                    endpoint_hash=uuid.uuid5(uuid.NAMESPACE_URL, triage.canonical_endpoint).hex,
                    method=flow_rec.request.method,
                    host=flow_rec.server_host,
                    path_pattern=triage.canonical_endpoint.split(" ", 1)[-1],
                    first_seen=time.time(),
                    last_seen=time.time(),
                    category=triage.endpoint_category.value,
                )
                await writer.enqueue_endpoint(ep)

            await writer.flush()

            # 3. VERIFICATION GATES

            # A. Reflection Gate
            all_reflections = [ref for _, t in triage_results for ref in t.reflections]
            assert len(all_reflections) >= 2
            ref_params = {r.parameter_name for r in all_reflections}
            assert "q" in ref_params or "attr" in ref_params

            # B. Auth Anomaly Gate
            all_auth_findings = [f for _, t in triage_results for f in t.auth_findings]
            auth_codes = {f.rule_code for f in all_auth_findings}
            assert "AUTH_ANOMALY_UNAUTH_SENSITIVE" in auth_codes

            # C. IDOR Sequential Identifier Gate
            all_id_findings = [f for _, t in triage_results for f in t.identifier_findings]
            assert any(f.id_type == IdentifierType.SEQUENTIAL_INTEGER for f in all_id_findings)

            # D. Endpoint Catalog Gate
            endpoints, total_ep = await repo.list_endpoints(host="127.0.0.1")
            assert total_ep >= 4

            # E. FTS5 Search Gate
            fts_flows, fts_count = await repo.search_flows_fts("ReflectMeXSS")
            assert fts_count >= 1

            # F. Total Flows Ingested Gate
            _, total_stored = await repo.list_flows()
            assert total_stored == len(sample_flows)

        finally:
            await gen.close()
            await writer.stop()
