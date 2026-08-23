"""
Tier 5 Adversarial Tests: Endpoint Ingestion, SQLite Persistence, and Dossier REST/WS Endpoints.
Adversarial Verification Suite for Milestone 1 Challenger (teamwork_preview_challenger_m1_2).

Covers:
1. Concurrency and race condition testing for multiple concurrent flows with distinct endpoint templates.
2. Verification of /api/v1/dossiers, /api/v1/dossier, /api/v1/dossiers/{endpoint_hash} genuine aggregation and authentic 404s.
3. Verification of EventType.SCHEMA_UPDATED broadcast accuracy with evolving cumulative schemas.
4. Stress-testing SQLite persistence under concurrent read/write pressure with zero lock contention.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import time
import urllib.parse
import uuid
from typing import Any, Dict, List
import pytest
from fastapi.testclient import TestClient

from flowforge.api.app import create_app
from flowforge.api.routes.dossier import compute_endpoint_hash, record_endpoint_observation
from flowforge.config import Settings
from flowforge.core.addon import FlowForgeInterceptorAddon
from flowforge.core.broadcaster import EventBroadcaster, get_broadcaster
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.models import (
    EndpointCategory,
    ExtractedParameter,
    IdentifierType,
    ParameterLocation,
)
from flowforge.heuristics.pipeline import default_pipeline
from flowforge.heuristics.schema_inferrer import SchemaInferrer
from flowforge.models.events import EventType, FlowEvent
from flowforge.models.flow import FlowFilterParams, FlowRecord, RequestModel, ResponseModel
from flowforge.models.parameter import DiscoveredEndpointModel, ExtractedParameterModel


# ============================================================================
# Test 1: Concurrency & Race Conditions on Endpoint & Parameter Ingestion
# ============================================================================

async def test_adversarial_concurrent_endpoint_ingestion_sqlite_integrity(tmp_db_path: str):
    """
    Empirically verify that multiple concurrent flows with distinct endpoint templates
    correctly populate SQLite endpoints and parameters tables without race conditions,
    locking failures, or corrupted schemas.
    """
    await init_db(tmp_db_path)
    db_writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=25, flush_interval_ms=10)
    await db_writer.start()
    broadcaster = EventBroadcaster(max_queue_size=1000)
    repo = FlowRepository(db_path=tmp_db_path)

    addon = FlowForgeInterceptorAddon(
        db_writer=db_writer,
        broadcaster=broadcaster,
        triage_callback=default_pipeline.process_flow_sync,
    )

    # Define 20 distinct canonical endpoint templates
    endpoint_templates = [
        ("GET", "api.target.local", "/api/v1/users/{integer_id}", {"id": "1001", "role": "admin"}),
        ("POST", "api.target.local", "/api/v1/users", {"username": "alice", "email": "alice@test.com", "tier": "gold"}),
        ("PUT", "api.target.local", "/api/v1/users/{integer_id}/settings", {"theme": "dark", "notifications": True}),
        ("DELETE", "api.target.local", "/api/v1/users/{integer_id}", {}),
        ("GET", "api.target.local", "/api/v1/orders", {"status": "pending", "limit": "20"}),
        ("POST", "api.target.local", "/api/v1/orders", {"item_id": 55, "quantity": 2, "coupon": "DISCOUNT10"}),
        ("GET", "api.target.local", "/api/v1/orders/{id}", {"order_id": "ord-99"}),
        ("POST", "api.target.local", "/api/v1/auth/login", {"username": "admin", "password": "secretpassword"}),
        ("POST", "api.target.local", "/api/v1/auth/refresh", {"refresh_token": "rt_12345"}),
        ("GET", "api.target.local", "/api/v1/products", {"category": "electronics", "sort": "asc"}),
        ("GET", "api.target.local", "/api/v1/products/{id}", {"sku": "SKU-9901"}),
        ("POST", "api.target.local", "/api/v1/products", {"sku": "SKU-NEW", "price": 99.95, "in_stock": True}),
        ("GET", "admin.target.local", "/admin/metrics", {"period": "24h"}),
        ("GET", "admin.target.local", "/admin/audit-logs", {"level": "error", "page": "1"}),
        ("POST", "admin.target.local", "/admin/roles/grant", {"user_id": "1001", "role": "SUPERADMIN"}),
        ("GET", "billing.target.local", "/v2/invoices", {"year": "2026", "paid": "true"}),
        ("POST", "billing.target.local", "/v2/checkout", {"currency": "USD", "amount": 1500}),
        ("GET", "search.target.local", "/search/v1/query", {"q": "adversarial test", "fuzzy": "1"}),
        ("POST", "search.target.local", "/search/v1/index", {"doc_id": "d-1", "content": "indexed payload"}),
        ("GET", "telemetry.target.local", "/v1/health", {}),
    ]

    total_flows = 100  # 5 iterations of each of the 20 templates with concurrent polymorphic variations

    async def ingest_flow_worker(flow_idx: int):
        tmpl_idx = flow_idx % len(endpoint_templates)
        method, host, path_tmpl, base_data = endpoint_templates[tmpl_idx]

        # Vary path and payload per iteration to stress schema evolution & parameter extraction
        flow_id = f"flow-concur-{flow_idx:04d}-{uuid.uuid4().hex[:6]}"
        actual_path = (
            path_tmpl
            .replace("{integer_id}", str(1000 + flow_idx))
            .replace("{id}", f"ord-{flow_idx}" if "orders" in path_tmpl else f"SKU-{flow_idx}")
        )

        # Polymorphic payload variation
        body_dict = dict(base_data)
        if flow_idx % 2 == 0:
            body_dict["iteration"] = flow_idx
            body_dict["extra_meta"] = {"source": f"concur_thread_{flow_idx}", "tags": ["stress", "concurrency"]}
        else:
            body_dict["iteration"] = str(flow_idx)  # Type union test: int vs str
            body_dict["score"] = flow_idx * 1.5

        req_body = json.dumps(body_dict) if method in ("POST", "PUT") else ""
        resp_body = json.dumps({"status": "ok", "flow_id": flow_id, "result_count": flow_idx})

        flow = FlowRecord(
            id=flow_id,
            timestamp_start=time.time(),
            timestamp_end=time.time() + 0.01,
            duration_ms=10.0,
            server_host=host,
            server_port=443,
            scheme="https",
            request=RequestModel(
                method=method,
                url=f"https://{host}{actual_path}",
                path=actual_path,
                query_params={"q_var": f"v_{flow_idx}", "step": str(flow_idx)},
                headers={"Content-Type": "application/json", "Authorization": f"Bearer token_{flow_idx}"},
                body=req_body,
            ),
            response=ResponseModel(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=resp_body,
            ),
        )

        # 1. Enqueue flow write
        await db_writer.enqueue_insert_flow(flow)

        # 2. Run triage & process endpoint/schema
        triage_summary = default_pipeline.process_flow_sync(flow)
        await addon._process_endpoint_and_schema(flow, triage_summary)
        return flow_id

    # Execute all 100 flow ingestions concurrently
    flow_ids = await asyncio.gather(*(ingest_flow_worker(i) for i in range(total_flows)))
    assert len(flow_ids) == total_flows

    # Force flush and stop writer
    await db_writer.flush()
    await db_writer.stop()

    # Verify SQLite Persisted State
    endpoints, total_eps = await repo.list_endpoints()
    assert total_eps == len(endpoint_templates), f"Expected {len(endpoint_templates)} distinct endpoints, got {total_eps}"

    # Verify flow count in DB
    flows, total_f = await repo.list_flows()
    assert total_f == total_flows, f"Expected {total_flows} flows in DB, got {total_f}"

    # Verify parameters count in DB
    params, total_p = await repo.list_parameters(limit=5000)
    assert total_p > total_flows, f"Expected at least {total_flows} extracted parameters, got {total_p}"

    # Verify cumulative schema on an endpoint that received both integer and string 'iteration'
    # POST api.target.local /api/v1/users
    post_users_ep = next((e for e in endpoints if e.path_pattern == "/api/v1/users" and e.method == "POST"), None)
    assert post_users_ep is not None
    assert post_users_ep.request_count >= 5

    req_schema = post_users_ep.schema_summary.get("request", {})
    props = req_schema.get("properties", {})
    assert "username" in props
    assert "email" in props
    assert "iteration" in props

    # The 'iteration' field was sent as int in even iterations and str in odd iterations -> type union ['integer', 'string']
    iter_type = props["iteration"]["type"]
    assert isinstance(iter_type, list)
    assert sorted(iter_type) == ["integer", "string"]


# ============================================================================
# Test 2: Target Dossier REST Endpoints Authenticity & 404 Validation
# ============================================================================

def test_adversarial_dossier_rest_aggregation_and_authentic_404s(tmp_db_path: str):
    """
    Verify that:
    1. /api/v1/dossiers and /api/v1/dossier return genuine aggregated data.
    2. /api/v1/dossiers/{endpoint_hash} returns authentic details for existing hashes.
    3. /api/v1/dossiers/{endpoint_hash} returns authentic 404s for nonexistent hashes
       and adversarial malicious inputs (SQLi, null bytes, long strings).
    4. Zero fake stubs or fabricated fallback data are returned.
    """
    app = create_app()
    client = TestClient(app)

    # Populate genuine observation in dossier
    ep_hash = record_endpoint_observation(
        method="POST",
        host="secure.vault.internal",
        path_pattern="/v1/vault/secrets",
        category="MUTATION_ACTION",
        parameters=[
            ExtractedParameter(
                name="secret_key",
                location=ParameterLocation.BODY_JSON,
                value="sk_live_999888777",
                raw_value="sk_live_999888777",
                inferred_type="string",
                entropy=4.8,
            ),
            ExtractedParameter(
                name="account_id",
                location=ParameterLocation.QUERY,
                value="10099",
                raw_value="10099",
                inferred_type="integer",
                identifier_type=IdentifierType.SEQUENTIAL_INTEGER,
                idor_score=0.92,
            ),
        ],
        schema={
            "type": "object",
            "properties": {
                "secret_key": {"type": "string", "x-flowforge-observed-count": 1},
                "payload": {"type": "string", "x-flowforge-observed-count": 1},
            },
            "required": ["secret_key"],
        },
    )

    # 1. Verify GET /api/v1/dossiers (plural)
    res_dossiers = client.get("/api/v1/dossiers")
    assert res_dossiers.status_code == 200
    data_dossiers = res_dossiers.json()
    assert "hosts" in data_dossiers
    assert data_dossiers["total_endpoints"] >= 1
    assert data_dossiers["total_parameters"] >= 2

    # Check host grouping
    vault_host = next((h for h in data_dossiers["hosts"] if h["host"] == "secure.vault.internal"), None)
    assert vault_host is not None
    assert vault_host["endpoint_count"] >= 1

    # 2. Verify GET /api/v1/dossier (singular alias)
    res_dossier = client.get("/api/v1/dossier")
    assert res_dossier.status_code == 200
    data_dossier = res_dossier.json()
    assert data_dossier == data_dossiers  # Singular and plural must be identical

    # 3. Verify GET /api/v1/dossiers/{endpoint_hash} with valid hash
    res_detail = client.get(f"/api/v1/dossiers/{ep_hash}")
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert detail["endpoint_hash"] == ep_hash
    assert detail["method"] == "POST"
    assert detail["host"] == "secure.vault.internal"
    assert detail["path_pattern"] == "/v1/vault/secrets"
    assert detail["has_critical_idor"] is True
    assert len(detail["parameters"]) >= 2

    # 4. Verify authentic 404 responses for nonexistent & adversarial hashes
    adversarial_nonexistent_hashes = [
        "nonexistent_hash_1234",
        "0000000000000000",
        "deadbeefdeadbeef",
        "' OR 1=1 --",
        "admin' UNION SELECT 1,2,3,4,5 --",
        "<script>alert(1)</script>",
        "hash_with_\x00_null_byte",
        "   ",
        "a" * 500,  # Long string hash
    ]

    for bad_hash in adversarial_nonexistent_hashes:
        enc_hash = urllib.parse.quote(bad_hash, safe="")
        # Check /api/v1/dossiers/{hash}
        r_plur = client.get(f"/api/v1/dossiers/{enc_hash}")
        assert r_plur.status_code == 404, f"Expected 404 for bad hash '{bad_hash}', got {r_plur.status_code}"
        assert "not found" in r_plur.json().get("detail", "").lower()

        # Check /api/v1/dossier/{hash}
        r_sing = client.get(f"/api/v1/dossier/{enc_hash}")
        assert r_sing.status_code == 404, f"Expected 404 for bad hash '{bad_hash}', got {r_sing.status_code}"
        assert "not found" in r_sing.json().get("detail", "").lower()

        # Check /api/v1/endpoints/{hash}
        r_ep = client.get(f"/api/v1/endpoints/{enc_hash}")
        assert r_ep.status_code == 404, f"Expected 404 for bad hash '{bad_hash}', got {r_ep.status_code}"
        assert "not found" in r_ep.json().get("detail", "").lower()


# ============================================================================
# Test 3: EventType.SCHEMA_UPDATED WebSocket Broadcasting & Schema Evolution
# ============================================================================

async def test_adversarial_schema_updated_broadcast_cumulative_accuracy():
    """
    Verify that EventType.SCHEMA_UPDATED broadcasts accurate cumulative schema structures
    across progressive payload mutations and polymorphic field types.
    """
    broadcaster = EventBroadcaster(max_queue_size=100)
    sub1_q = await broadcaster.subscribe("subscriber-alpha")
    sub2_q = await broadcaster.subscribe("subscriber-beta")

    inferrer = SchemaInferrer()
    ep_hash = compute_endpoint_hash("POST", "ecommerce.target.local", "/api/v2/cart/items")

    # Step 1: Initial payload
    payload1 = {
        "item_id": 101,
        "quantity": 1,
        "sku": "SKU-A",
    }
    s1 = inferrer.infer_payload_schema(payload1)
    cum_schema = inferrer.merge_schemas(None, s1, sample_count=1)

    broadcaster.broadcast_schema_updated(
        endpoint_hash=ep_hash,
        host="ecommerce.target.local",
        path_pattern="/api/v2/cart/items",
        method="POST",
        schema_summary={"request": cum_schema},
        parameters=[
            {"name": "item_id", "location": "body_json", "data_type": "integer"},
            {"name": "quantity", "location": "body_json", "data_type": "integer"},
            {"name": "sku", "location": "body_json", "data_type": "string"},
        ],
        category="MUTATION_ACTION",
        request_count=1,
    )

    ev1_a: FlowEvent = await asyncio.wait_for(sub1_q.get(), timeout=2.0)
    ev1_b: FlowEvent = await asyncio.wait_for(sub2_q.get(), timeout=2.0)

    assert ev1_a.event == EventType.SCHEMA_UPDATED.value
    assert ev1_a.event_type == EventType.SCHEMA_UPDATED.value
    assert ev1_a.data["endpoint_hash"] == ep_hash
    assert ev1_a.data["request_count"] == 1
    props1 = ev1_a.data["schema_summary"]["request"]["properties"]
    assert "item_id" in props1
    assert "quantity" in props1
    assert "sku" in props1
    assert ev1_a.data["schema_summary"]["request"]["required"] == ["item_id", "quantity", "sku"]

    # Step 2: Second payload with new fields & type polymorphism
    # 'quantity' sent as string "2", 'discount_code' added, 'metadata' nested object added
    payload2 = {
        "item_id": 102,
        "quantity": "2",  # Polymorphic: int -> ['integer', 'string']
        "sku": "SKU-B",
        "discount_code": "FALL2026",  # Optional
        "metadata": {
            "gift_wrap": True,
            "notes": "Fragile shipment",
        },
    }
    s2 = inferrer.infer_payload_schema(payload2)
    cum_schema = inferrer.merge_schemas(cum_schema, s2, sample_count=2)

    broadcaster.broadcast_schema_updated(
        endpoint_hash=ep_hash,
        host="ecommerce.target.local",
        path_pattern="/api/v2/cart/items",
        method="POST",
        schema_summary={"request": cum_schema},
        parameters=[
            {"name": "item_id", "location": "body_json", "data_type": "integer"},
            {"name": "quantity", "location": "body_json", "data_type": "string"},
            {"name": "sku", "location": "body_json", "data_type": "string"},
            {"name": "discount_code", "location": "body_json", "data_type": "string"},
        ],
        category="MUTATION_ACTION",
        request_count=2,
    )

    ev2: FlowEvent = await asyncio.wait_for(sub1_q.get(), timeout=2.0)
    assert ev2.event == EventType.SCHEMA_UPDATED.value
    assert ev2.data["request_count"] == 2

    req_s2 = ev2.data["schema_summary"]["request"]
    props2 = req_s2["properties"]

    # Required fields: item_id and sku (quantity was present in both, but type changed; check required list)
    assert "item_id" in req_s2["required"]
    assert "sku" in req_s2["required"]
    assert "discount_code" not in req_s2["required"]

    # Type union check on quantity
    qty_type = props2["quantity"]["type"]
    assert isinstance(qty_type, list)
    assert sorted(qty_type) == ["integer", "string"]

    # Nested object check on metadata
    assert "metadata" in props2
    assert props2["metadata"]["type"] == "object"
    meta_props = props2["metadata"]["properties"]
    assert "gift_wrap" in meta_props
    assert "notes" in meta_props

    # Step 3: Frequency metrics check
    assert props2["item_id"]["x-flowforge-observed-count"] == 2
    assert props2["item_id"]["x-flowforge-frequency"] == 1.0
    assert props2["discount_code"]["x-flowforge-observed-count"] == 1
    assert props2["discount_code"]["x-flowforge-frequency"] == 0.5

    await broadcaster.unsubscribe(sub1_q)
    await broadcaster.unsubscribe(sub2_q)


# ============================================================================
# Test 4: Concurrent Read/Write Stress against SQLite FlowRepository
# ============================================================================

async def test_adversarial_sqlite_concurrent_read_write_stress(tmp_db_path: str):
    """
    Stress-test SQLite database under high-concurrency simultaneous reads and writes.
    Asserts zero 'database is locked' errors and 100% data consistency.
    """
    await init_db(tmp_db_path)
    db_writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=20, flush_interval_ms=10)
    await db_writer.start()
    repo = FlowRepository(db_path=tmp_db_path)

    write_count = 60
    read_count = 40

    async def writer_task(i: int):
        flow_id = f"stress-rw-{i:03d}"
        ep_hash = compute_endpoint_hash("GET", "rw-stress.local", f"/api/items/{i % 5}")
        flow = FlowRecord(
            id=flow_id,
            timestamp_start=time.time(),
            timestamp_end=time.time() + 0.005,
            server_host="rw-stress.local",
            request=RequestModel(
                method="GET",
                url=f"https://rw-stress.local/api/items/{i % 5}?idx={i}",
                path=f"/api/items/{i % 5}",
                query_params={"idx": str(i)},
            ),
            response=ResponseModel(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=json.dumps({"id": i, "data": f"content_{i}"}),
            ),
        )
        await db_writer.enqueue_insert_flow(flow)

        param = ExtractedParameterModel(
            flow_id=flow_id,
            endpoint_hash=ep_hash,
            location="query",
            name="idx",
            value=str(i),
            data_type="integer",
            timestamp=time.time(),
        )
        await db_writer.enqueue_parameter(param)

        ep = DiscoveredEndpointModel(
            endpoint_hash=ep_hash,
            method="GET",
            host="rw-stress.local",
            path_pattern=f"/api/items/{i % 5}",
            first_seen=time.time(),
            last_seen=time.time(),
            request_count=1,
            category="DATA_READ",
        )
        await db_writer.enqueue_endpoint(ep)

    async def reader_task(i: int):
        await asyncio.sleep(0.01)  # Stagger slightly to interleave with writes
        # Run diverse repository queries
        stats = await repo.get_stats()
        assert isinstance(stats, dict)
        flows, _ = await repo.list_flows(FlowFilterParams(page_size=10))
        eps, _ = await repo.list_endpoints(limit=5)
        params, _ = await repo.list_parameters(limit=10)
        return len(flows) + len(eps) + len(params)

    # Interleave writers and readers concurrently
    writers = [writer_task(i) for i in range(write_count)]
    readers = [reader_task(i) for i in range(read_count)]

    # Gather all tasks simultaneously
    results = await asyncio.gather(*writers, *readers, return_exceptions=True)

    # Check for any exceptions
    for res in results:
        if isinstance(res, Exception):
            pytest.fail(f"Concurrent SQLite read/write threw exception: {res}")

    await db_writer.flush()
    await db_writer.stop()

    # Final consistency check
    final_stats = await repo.get_stats()
    assert final_stats["total_flows"] == write_count
    assert final_stats["total_parameters"] == write_count
    assert final_stats["total_endpoints"] == 5  # 5 distinct item paths (i % 5)
