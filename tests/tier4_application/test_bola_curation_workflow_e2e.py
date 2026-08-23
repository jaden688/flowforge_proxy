"""
Tier 4 Real-World Application Scenario 2: End-to-End BOLA / IDOR Hunting & Curation Pipeline.
Exercises: Traffic Ingestion, Identifier Classification, Context Recommendations,
Matrix Synthesis, Curation Grouping, Starring, Selective Pruning, and Execution.
"""

from __future__ import annotations

import asyncio
import time
import uuid
import pytest
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel


async def test_e2e_bola_curation_and_pruning_workflow(tmp_dir: str):
    """
    Execute full end-to-end BOLA / IDOR penetration testing workflow:
    1. Ingest traffic on sensitive resource with sequential identifier.
    2. Heuristic triage flags sequential integer with high IDOR susceptibility.
    3. Strategy recommendation ranks IDOR_SEQUENTIAL as #1 (Recommended).
    4. Synthesize test matrix cases pre-populated with endpoint identifier.
    5. Curate cases into 'Active BOLA Probes' collection and star high-value items.
    6. Selectively prune uninteresting non-starred rows.
    7. Execute staged BOLA campaign and verify anomaly detection verdicts.
    """
    db_path = f"{tmp_dir}/bola_workflow.db"
    settings = Settings(db_path=db_path, auto_start_proxy=False)
    app = create_app(settings)
    pipeline = TriagePipeline()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # -------------------------------------------------------------------
        # Step 1: Intercept flow on an authenticated endpoint with numeric ID
        # -------------------------------------------------------------------
        flow = FlowRecord(
            id=str(uuid.uuid4()),
            timestamp_start=time.time(),
            server_host="api.bank.internal",
            scheme="https",
            request=RequestModel(
                method="GET",
                url="https://api.bank.internal/api/v1/accounts/1042/statement?period=monthly",
                path="/api/v1/accounts/1042/statement",
                query_string="period=monthly",
                query_params={"period": "monthly"},
                headers={
                    "Host": "api.bank.internal",
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDQyIn0.sig",
                },
            ),
            response=ResponseModel(
                status_code=200,
                headers={"Content-Type": "application/json"},
                content_length=480,
                body='{"account_id": 1042, "balance": 9500.50, "owner": "Alice"}',
            ),
        )

        # -------------------------------------------------------------------
        # Step 2: Run Heuristic Triage Pipeline
        # -------------------------------------------------------------------
        triage = pipeline.process_flow_sync(flow)
        assert "idor_candidate" in triage.tags
        assert "auth" in triage.tags
        assert len(triage.identifier_findings) >= 1
        id_finding = triage.identifier_findings[0]
        assert id_finding.idor_risk_score >= 0.45

        # -------------------------------------------------------------------
        # Step 3: Query Strategy Recommendations for Target Endpoint
        # -------------------------------------------------------------------
        rec_resp = await client.post(
            "/api/v1/matrix/strategies/recommend",
            json={
                "method": "GET",
                "path": "/api/v1/accounts/1042/statement",
                "parameters": [
                    {"name": "id", "value": 1042, "location": "path", "id_type": "sequential_integer", "idor_score": id_finding.idor_risk_score},
                    {"name": "period", "value": "monthly", "location": "query", "data_type": "string"},
                ],
                "triage_tags": triage.tags,
                "has_auth": True,
            },
        )
        assert rec_resp.status_code == 200
        rec_data = rec_resp.json()
        assert rec_data["top_recommended"]["badge"] == "#1 (Recommended)"
        assert rec_data["top_recommended"]["strategy_id"] in ("IDOR_SEQUENTIAL", "IDOR_ROLE_SWAP")

        # -------------------------------------------------------------------
        # Step 4: Synthesize Test Matrix for the Target Endpoint
        # -------------------------------------------------------------------
        matrix_resp = await client.post(
            "/api/v1/matrix/generate",
            json={
                "endpoint_path": "/api/v1/accounts/1042/statement",
                "method": "GET",
                "parameters": [
                    {"name": "id", "location": "path", "sample_value": 1042, "id_type": "SEQUENTIAL_INT"},
                ],
                "categories": ["IDOR_SEQUENTIAL", "IDOR_ROLE_SWAP"],
            },
        )
        assert matrix_resp.status_code == 200
        matrix_job = matrix_resp.json()
        cases = matrix_job["cases"]
        assert len(cases) >= 4

        # -------------------------------------------------------------------
        # Step 5: Curate Cases into 'Active BOLA Probes' Collection
        # -------------------------------------------------------------------
        grp_resp = await client.post(
            "/api/v1/curation/groups",
            json={"name": "Active BOLA Probes", "description": "BOLA probes on /api/v1/accounts/{id}/statement"},
        )
        assert grp_resp.status_code == 200
        group_id = grp_resp.json()["id"]

        saved_ids = []
        for c in cases:
            p_res = await client.post("/api/v1/curation/payloads", json={
                "group_id": group_id,
                "name": c["name"],
                "category": c["category"],
                "endpoint_path": c["endpoint_path"],
                "method": c["method"],
                "target_param_name": c["target_param_name"],
                "baseline_value": c["baseline_value"],
                "mutated_value": c["mutated_value"],
                "status": "READY",
            })
            saved_ids.append(p_res.json()["id"])

        # Star the +1 probe and the Role Swap probe
        await client.post(f"/api/v1/curation/payloads/{saved_ids[0]}/star", params={"starred": True})
        await client.post(f"/api/v1/curation/payloads/{saved_ids[1]}/star", params={"starred": True})

        # -------------------------------------------------------------------
        # Step 6: Mark one probe as FAILED and Prune with Star Protection
        # -------------------------------------------------------------------
        # Update 3rd item to FAILED (unstarred)
        await client.patch(f"/api/v1/curation/payloads/{saved_ids[2]}", json={"status": "FAILED"})
        # Update 1st item (starred) to FAILED as well
        await client.patch(f"/api/v1/curation/payloads/{saved_ids[0]}", json={"status": "FAILED"})

        prune_resp = await client.post(
            "/api/v1/curation/prune",
            json={
                "group_id": group_id,
                "preserve_starred": True,
                "status_filter": ["FAILED"],
            },
        )
        assert prune_resp.status_code == 200
        prune_data = prune_resp.json()
        assert prune_data["deleted_count"] == 1  # only unstarred deleted
        assert prune_data["preserved_count"] >= 1  # starred preserved

        # -------------------------------------------------------------------
        # Step 7: Execute Staged Matrix and Verify Anomaly Verdicts
        # -------------------------------------------------------------------
        exec_resp = await client.post(
            "/api/v1/matrix/execute",
            json={
                "job_id": matrix_job["job_id"],
                "cases": [c for c in cases if c["category"] == "IDOR_SEQUENTIAL"],
                "concurrency": 2,
            },
        )
        assert exec_resp.status_code == 200

        # Allow execution runner task to complete
        await asyncio.sleep(0.3)

        job_result = await client.get(f"/api/v1/matrix/jobs/{matrix_job['job_id']}")
        assert job_result.status_code == 200
        j_data = job_result.json()
        assert j_data["completed_count"] >= 2
        assert j_data["anomalies_count"] >= 1
