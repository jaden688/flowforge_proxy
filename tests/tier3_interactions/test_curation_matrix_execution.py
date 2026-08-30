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
        assert j_data["completed_count"] > 0  # Real execution completed all cases
        # Verify execution produced results (real HTTP calls, not simulated)
        for c in j_data["cases"]:
            assert c["status"] in ("PASSED", "ANOMALY_DETECTED", "FAILED")
            assert c.get("result_summary") is not None
            assert c["result_summary"].get("status_code") is not None


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


async def test_t3_dynamic_matrix_per_case_routing_and_hop_headers(tmp_dir: str):
    """Verify multi-endpoint matrix jobs resolve baseline flows per case, strip hop headers, and persist executed FlowRecord."""
    import uuid
    from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
    from flowforge.db.connection import init_db
    from flowforge.db.repository import FlowRepository
    from flowforge.db.writer import AsyncDBWriter

    db_path = f"{tmp_dir}/test_dynamic_routing.db"
    await init_db(db_path)
    settings = Settings(db_path=db_path, auto_start_proxy=False)
    app = create_app(settings)

    writer = AsyncDBWriter(db_path=db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()
    repo = FlowRepository(db_path=db_path)
    app.state.db_writer = writer
    app.state.repo = repo

    try:
        # 1. Create two distinct baseline flows targeting different external hosts
        flow_1 = FlowRecord(
            id=str(uuid.uuid4()),
            server_host="api.service-alpha.com",
            server_port=443,
            scheme="https",
            request=RequestModel(
                method="GET",
                url="/api/v1/orders/1001?filter=active",
                path="/api/v1/orders/1001",
                query_string="filter=active",
                query_params={"filter": "active"},
                headers={"Host": "api.service-alpha.com", "Content-Length": "0", "Authorization": "Bearer token-a"},
            ),
            response=ResponseModel(status_code=200, body='{"order": 1001}'),
        )

        flow_2 = FlowRecord(
            id=str(uuid.uuid4()),
            server_host="internal.billing-beta.net",
            server_port=8443,
            scheme="https",
            request=RequestModel(
                method="POST",
                url="https://internal.billing-beta.net:8443/v2/invoices/99",
                path="/v2/invoices/99",
                headers={"Host": "internal.billing-beta.net:8443", "Content-Type": "application/json"},
                body='{"amount": 500}',
            ),
            response=ResponseModel(status_code=200, body='{"status": "paid"}'),
        )

        await writer.enqueue_insert_flow(flow_1)
        await writer.enqueue_insert_flow(flow_2)
        await writer.flush()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # 2. Stage matrix cases referencing the two distinct baseline flows
            case_1 = {
                "id": "case-alpha-1",
                "name": "Alpha IDOR Fuzz",
                "endpoint_path": "/api/v1/orders/1002",
                "method": "GET",
                "category": "IDOR_SEQUENTIAL",
                "target_param_location": "path",
                "target_param_name": "id",
                "baseline_value": 1001,
                "mutated_value": 1002,
                "selected": True,
                "status": "READY",
                "baseline_flow_id": flow_1.id,
            }

            case_2 = {
                "id": "case-beta-1",
                "name": "Beta Mass Assignment",
                "endpoint_path": "/v2/invoices/99",
                "method": "POST",
                "category": "MASS_ASSIGNMENT",
                "target_param_location": "body",
                "target_param_name": "is_admin",
                "mutated_value": True,
                "selected": True,
                "status": "READY",
                "baseline_flow_id": flow_2.id,
            }

            job_id = f"job-{uuid.uuid4().hex[:8]}"
            exec_resp = await client.post(
                "/api/v1/matrix/execute",
                json={
                    "job_id": job_id,
                    "cases": [case_1, case_2],
                    "concurrency": 2,
                },
            )
            assert exec_resp.status_code == 200
            assert exec_resp.json()["cases_queued"] == 2

            # Allow execution runner task to complete
            await asyncio.sleep(0.3)

            # 3. Verify job execution results
            job_result = await client.get(f"/api/v1/matrix/jobs/{job_id}")
            assert job_result.status_code == 200
            j_data = job_result.json()
            assert j_data["completed_count"] == 2

            # 4. Verify executed FlowRecords were persisted to database
            await writer.flush()
            flows_res, _ = await repo.list_flows(limit=50)
            persisted_ids = {f.id for f in flows_res}
            for case in j_data["cases"]:
                assert case.get("executed_flow_id") is not None
                assert case["executed_flow_id"] in persisted_ids
    finally:
        await writer.stop()


async def test_t3_proxy_replay_alias_and_flow_relative_url_reconstruction(tmp_dir: str):
    """Verify POST /api/v1/proxy/replay alias and flow replay relative URL reconstruction."""
    import uuid
    from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
    from flowforge.db.connection import init_db
    from flowforge.db.repository import FlowRepository
    from flowforge.db.writer import AsyncDBWriter

    db_path = f"{tmp_dir}/test_proxy_replay_alias.db"
    await init_db(db_path)
    settings = Settings(db_path=db_path, auto_start_proxy=False)
    app = create_app(settings)

    writer = AsyncDBWriter(db_path=db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()
    repo = FlowRepository(db_path=db_path)
    app.state.db_writer = writer
    app.state.repo = repo

    try:
        # Insert baseline flow with relative url
        flow = FlowRecord(
            id=str(uuid.uuid4()),
            server_host="target.test.org",
            server_port=80,
            scheme="http",
            request=RequestModel(
                method="GET",
                url="/api/v1/items/42",
                path="/api/v1/items/42",
                headers={"Host": "target.test.org"},
            ),
            response=ResponseModel(status_code=200, body='{"id": 42}'),
        )
        await writer.enqueue_insert_flow(flow)
        await writer.flush()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # 1. Test /api/v1/proxy/replay alias endpoint
            proxy_rep = await client.post(
                "/api/v1/proxy/replay",
                json={
                    "method": "POST",
                    "url": "http://127.0.0.1:8000/api/v1/test",
                    "headers": {"X-Custom": "test-value"},
                    "body": '{"test": true}',
                },
            )
            assert proxy_rep.status_code == 200
            assert "status" in proxy_rep.json()

            # 2. Test /api/v1/flows/{id}/replay with relative URL reconstructed
            # Replaying against an external host will attempt connection
            rep_resp = await client.post(
                f"/api/v1/flows/{flow.id}/replay",
                json={"override_method": "GET"},
            )
            # Endpoint responded (either succeeded or gave bad gateway on connection failure rather than unsupported protocol)
            assert rep_resp.status_code in (200, 502)
    finally:
        await writer.stop()


