"""
Tier 3 Cross-Feature Interaction Tests: Strategy Recommendations ->
Matrix Case Synthesis -> Curation Grouping -> Selective Pruning -> Matrix Execution Runner.
"""

from __future__ import annotations

import asyncio
import time
import pytest
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.config import Settings


async def test_t3_recommendations_to_matrix_staging_pipeline(tmp_dir: str):
    """Verify endpoint recommendations inform matrix generation categories and cases."""
    settings = Settings(db_path=f"{tmp_dir}/test_rec_matrix.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Query recommendations for an endpoint with sequential ID and auth carrier
        rec_resp = await client.post(
            "/api/v1/matrix/strategies/recommend",
            json={
                "method": "GET",
                "path": "/api/v1/invoices/9001",
                "parameters": [{"name": "id", "value": 9001, "id_type": "sequential_integer", "idor_score": 0.85}],
                "triage_tags": ["idor_candidate", "auth"],
                "has_auth": True,
            },
        )
        assert rec_resp.status_code == 200
        rec_data = rec_resp.json()
        top_strat = rec_data["top_recommended"]["strategy_id"]
        assert top_strat in ("IDOR_SEQUENTIAL", "IDOR_ROLE_SWAP")

        # 2. Synthesize test matrix specifically for top recommended category
        gen_resp = await client.post(
            "/api/v1/matrix/generate",
            json={
                "endpoint_path": "/api/v1/invoices/9001",
                "method": "GET",
                "parameters": [{"name": "id", "location": "path", "sample_value": 9001, "id_type": "SEQUENTIAL_INT"}],
                "categories": ["IDOR_SEQUENTIAL", "IDOR_ROLE_SWAP"],
            },
        )
        assert gen_resp.status_code == 200
        matrix_job = gen_resp.json()
        assert matrix_job["total_count"] >= 4
        assert all(c["category"] in ("IDOR_SEQUENTIAL", "IDOR_ROLE_SWAP") for c in matrix_job["cases"])


async def test_t3_matrix_cases_to_curation_group_and_starring(tmp_dir: str):
    """Verify staging matrix cases, saving to a named curation group, and starring high-value probes."""
    settings = Settings(db_path=f"{tmp_dir}/test_matrix_curation.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Create a Curation Group
        grp_resp = await client.post("/api/v1/curation/groups", json={"name": "Staged IDOR Suite"})
        grp_id = grp_resp.json()["id"]

        # 2. Generate Matrix
        gen_resp = await client.post("/api/v1/matrix/generate", json={
            "endpoint_path": "/api/v1/users/55",
            "method": "GET",
            "parameters": [{"name": "id", "location": "path", "sample_value": 55, "id_type": "SEQUENTIAL_INT"}],
        })
        cases = gen_resp.json()["cases"]

        # 3. Save cases into curation group
        saved_payload_ids = []
        for c in cases[:3]:
            save_resp = await client.post("/api/v1/curation/payloads", json={
                "group_id": grp_id,
                "name": c["name"],
                "category": c["category"],
                "endpoint_path": c["endpoint_path"],
                "method": c["method"],
                "target_param_name": c["target_param_name"],
                "mutated_value": c["mutated_value"],
                "status": "READY",
            })
            saved_payload_ids.append(save_resp.json()["id"])

        # 4. Star the first probe (+1 probe)
        await client.post(f"/api/v1/curation/payloads/{saved_payload_ids[0]}/star", params={"starred": True})

        # 5. Verify group item count and star status
        grp_check = await client.get(f"/api/v1/curation/groups/{grp_id}")
        assert grp_check.status_code == 200
        assert grp_check.json()["item_count"] == 3
        items = grp_check.json()["items"]
        assert any(i["id"] == saved_payload_ids[0] and i["starred"] is True for i in items)


async def test_t3_selective_pruning_and_matrix_execution_pipeline(tmp_dir: str):
    """Verify pruning unwanted cases prior to running matrix execution."""
    settings = Settings(db_path=f"{tmp_dir}/test_prune_exec.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Generate full test matrix
        gen_resp = await client.post("/api/v1/matrix/generate", json={
            "endpoint_path": "/api/v1/account",
            "method": "POST",
            "parameters": [
                {"name": "id", "location": "query", "sample_value": 100, "id_type": "SEQUENTIAL_INT"},
                {"name": "is_admin", "location": "body", "sample_value": False},
            ],
        })
        cases = gen_resp.json()["cases"]
        job_id = gen_resp.json()["job_id"]

        # 2. Select only IDOR and Mass Assignment cases to run
        selected_cases = [c for c in cases if c["category"] in ("IDOR_SEQUENTIAL", "MASS_ASSIGNMENT")]
        assert len(selected_cases) > 0

        # 3. Execute matrix with selected cases
        exec_resp = await client.post(
            "/api/v1/matrix/execute",
            json={
                "job_id": job_id,
                "cases": selected_cases,
                "concurrency": 2,
            },
        )
        assert exec_resp.status_code == 200
        assert exec_resp.json()["cases_queued"] == len(selected_cases)

        # Allow background runner to complete
        await asyncio.sleep(0.3)

        # 4. Check job status and results
        job_status = await client.get(f"/api/v1/matrix/jobs/{job_id}")
        assert job_status.status_code == 200
        j_data = job_status.json()
        assert j_data["completed_count"] == len(selected_cases)
        assert j_data["anomalies_count"] >= 1  # Simulated IDOR/Mass Assignment anomalies detected


async def test_t3_full_curation_export_and_matrix_replay_roundtrip(tmp_dir: str):
    """Verify curated payloads can be exported, re-imported, and dispatched to execution."""
    settings = Settings(db_path=f"{tmp_dir}/test_curation_roundtrip.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create group and payload
        grp = await client.post("/api/v1/curation/groups", json={"name": "Export Test Group"})
        grp_id = grp.json()["id"]

        await client.post("/api/v1/curation/payloads", json={
            "group_id": grp_id,
            "name": "BOLA Probe 99",
            "category": "IDOR_SEQUENTIAL",
            "endpoint_path": "/api/v1/items/99",
            "method": "GET",
            "target_param_name": "id",
            "mutated_value": 100,
            "starred": True,
        })

        # Export curation data
        export_resp = await client.get("/api/v1/curation/export")
        assert export_resp.status_code == 200
        exported_json = export_resp.json()

        # Import into fresh session with overwrite
        import_resp = await client.post("/api/v1/curation/import", json={"groups": exported_json["groups"], "payloads": exported_json["payloads"], "overwrite": True})
        assert import_resp.status_code == 200
        assert import_resp.json()["imported_payloads_count"] >= 1
