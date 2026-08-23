"""
Tests for Dynamic JSON Schema Evolution, Cumulative Field Merging, and Target Dossier Persistence (Milestone 1).
"""

import asyncio
import hashlib
import json
import time
from typing import Any, Dict, List
import pytest
from fastapi.testclient import TestClient

from flowforge.api.app import create_app
from flowforge.api.routes.dossier import compute_endpoint_hash
from flowforge.config import Settings
from flowforge.core.addon import FlowForgeInterceptorAddon
from flowforge.core.broadcaster import EventBroadcaster
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.models import EndpointCategory, ExtractedParameter, ParameterLocation
from flowforge.heuristics.pipeline import default_pipeline
from flowforge.heuristics.schema_inferrer import SchemaInferrer
from flowforge.models.events import EventType
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.parameter import DiscoveredEndpointModel, ExtractedParameterModel


# ============================================================================
# 1. SchemaInferrer: Primitives, Formats & Boundary Tracking
# ============================================================================

def test_schema_inferrer_primitives_boundaries_and_formats():
    """Verify SchemaInferrer correctly identifies formats and tracks numeric/string boundaries."""
    inferrer = SchemaInferrer()

    payload = {
        "user_uuid": "c3d5a420-53bc-42b7-8911-379ef54bc2e8",
        "email_addr": "security@flowforge.internal",
        "registered_at": "2026-08-22T12:00:00Z",
        "birth_date": "1995-06-15",
        "server_ip": "192.168.1.100",
        "api_docs_url": "https://flowforge.local/api/docs",
        "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "age": 28,
        "balance": 1500.50,
        "is_active": True,
        "roles": ["admin", "auditor"],
    }

    schema = inferrer.infer_payload_schema(payload)

    assert schema["type"] == "object"
    props = schema["properties"]

    assert props["user_uuid"]["type"] == "string"
    assert props["user_uuid"]["format"] == "uuid"

    assert props["email_addr"]["type"] == "string"
    assert props["email_addr"]["format"] == "email"

    assert props["registered_at"]["type"] == "string"
    assert props["registered_at"]["format"] == "date-time"

    assert props["birth_date"]["type"] == "string"
    assert props["birth_date"]["format"] == "date"

    assert props["server_ip"]["type"] == "string"
    assert props["server_ip"]["format"] == "ipv4"

    assert props["api_docs_url"]["type"] == "string"
    assert props["api_docs_url"]["format"] == "uri"

    assert props["jwt_token"]["type"] == "string"
    assert props["jwt_token"]["format"] == "jwt"

    assert props["age"]["type"] == "integer"
    assert props["age"]["minimum"] == 28
    assert props["age"]["maximum"] == 28

    assert props["balance"]["type"] == "number"
    assert props["balance"]["minimum"] == 1500.50
    assert props["balance"]["maximum"] == 1500.50

    assert props["is_active"]["type"] == "boolean"

    assert props["roles"]["type"] == "array"
    assert props["roles"]["items"]["type"] == "string"


# ============================================================================
# 2. SchemaInferrer: Type Unions & Numeric Promotion
# ============================================================================

def test_schema_inferrer_type_unions_and_polymorphic_mutations():
    """Verify SchemaInferrer correctly unifies disparate types into unions and promotes numbers."""
    inferrer = SchemaInferrer()

    # Case A: Integer to String produces ['integer', 'string']
    s1 = inferrer.infer_payload_schema({"param": 42})
    s2 = inferrer.infer_payload_schema({"param": "forty-two"})
    merged_a = inferrer.merge_schemas(s1, s2, sample_count=2)

    param_type_a = merged_a["properties"]["param"]["type"]
    assert isinstance(param_type_a, list)
    assert sorted(param_type_a) == ["integer", "string"]

    # Case B: Multi-step union expansion
    s3 = inferrer.infer_payload_schema({"param": True})
    merged_b = inferrer.merge_schemas(merged_a, s3, sample_count=3)
    param_type_b = merged_b["properties"]["param"]["type"]
    assert sorted(param_type_b) == ["boolean", "integer", "string"]

    # Case C: Numeric promotion (integer + number -> number)
    s_int = inferrer.infer_payload_schema({"score": 100})
    s_flt = inferrer.infer_payload_schema({"score": 98.5})
    merged_c = inferrer.merge_schemas(s_int, s_flt, sample_count=2)
    assert merged_c["properties"]["score"]["type"] == "number"
    assert merged_c["properties"]["score"]["minimum"] == 98.5
    assert merged_c["properties"]["score"]["maximum"] == 100


# ============================================================================
# 3. SchemaInferrer: Required vs Optional & Field Frequency Tracking
# ============================================================================

def test_schema_inferrer_cumulative_frequency_and_optional_fields():
    """Verify cumulative schema evolution tracks required/optional fields and observation frequencies."""
    inferrer = SchemaInferrer()

    flow1_payload = {
        "user_id": 1001,
        "username": "alice",
        "is_admin": True,
        "created_at": "2026-08-22T10:00:00Z",
    }
    flow2_payload = {
        "user_id": 1002,
        "username": "bob",
        "email": "bob@corp.internal",
    }
    flow3_payload = {
        "user_id": 1003,
        "username": "charlie",
        "phone": "+1-555-0199",
    }
    flow4_payload = {
        "user_id": 1004,
        "username": "dave",
        "avatar_url": "https://cdn.flowforge.local/avatars/dave.png",
    }

    s1 = inferrer.infer_payload_schema(flow1_payload)
    s2 = inferrer.infer_payload_schema(flow2_payload)
    s3 = inferrer.infer_payload_schema(flow3_payload)
    s4 = inferrer.infer_payload_schema(flow4_payload)

    # Stepwise evolution
    cum_schema = inferrer.merge_schemas(None, s1, sample_count=1)
    assert cum_schema["required"] == ["created_at", "is_admin", "user_id", "username"]

    cum_schema = inferrer.merge_schemas(cum_schema, s2, sample_count=2)
    assert cum_schema["required"] == ["user_id", "username"]

    cum_schema = inferrer.merge_schemas(cum_schema, s3, sample_count=3)
    assert cum_schema["required"] == ["user_id", "username"]

    cum_schema = inferrer.merge_schemas(cum_schema, s4, sample_count=4)

    props = cum_schema["properties"]
    assert "user_id" in props
    assert "username" in props
    assert "is_admin" in props
    assert "created_at" in props
    assert "email" in props
    assert "phone" in props
    assert "avatar_url" in props

    # Required fields must only contain properties observed in 100% of flows
    assert cum_schema["required"] == ["user_id", "username"]

    # Frequencies and counts
    assert props["user_id"]["x-flowforge-observed-count"] == 4
    assert props["user_id"]["x-flowforge-frequency"] == 1.0

    assert props["username"]["x-flowforge-observed-count"] == 4
    assert props["username"]["x-flowforge-frequency"] == 1.0

    assert props["is_admin"]["x-flowforge-observed-count"] == 1
    assert props["is_admin"]["x-flowforge-frequency"] == 0.25

    assert props["email"]["x-flowforge-observed-count"] == 1
    assert props["email"]["x-flowforge-frequency"] == 0.25

    assert props["phone"]["x-flowforge-observed-count"] == 1
    assert props["phone"]["x-flowforge-frequency"] == 0.25

    assert props["avatar_url"]["x-flowforge-observed-count"] == 1
    assert props["avatar_url"]["x-flowforge-frequency"] == 0.25


# ============================================================================
# 4. SchemaInferrer: Nested Objects & Array Items Merging
# ============================================================================

def test_schema_inferrer_nested_objects_and_array_merging():
    """Verify recursive merging of deeply nested objects and heterogeneous array items."""
    inferrer = SchemaInferrer()

    payload_a = {
        "id": 1,
        "profile": {
            "name": "Alice",
            "address": {
                "city": "Austin",
                "zip": 78701,
            },
        },
        "tags": ["admin", "core"],
    }

    payload_b = {
        "id": 2,
        "profile": {
            "name": "Bob",
            "address": {
                "city": "Denver",
                "state": "CO",
            },
        },
        "tags": [999, "support"],
    }

    s_a = inferrer.infer_payload_schema(payload_a)
    s_b = inferrer.infer_payload_schema(payload_b)

    merged = inferrer.merge_schemas(s_a, s_b, sample_count=2)

    assert merged["type"] == "object"
    assert "profile" in merged["properties"]
    prof = merged["properties"]["profile"]
    assert prof["type"] == "object"

    addr = prof["properties"]["address"]
    assert addr["type"] == "object"
    assert "city" in addr["properties"]
    assert "zip" in addr["properties"]
    assert "state" in addr["properties"]
    # city was in both -> required in address
    assert addr["required"] == ["city"]
    # zip and state were only in one -> optional
    assert "zip" not in addr["required"]
    assert "state" not in addr["required"]

    # Tags array unified items
    tags = merged["properties"]["tags"]
    assert tags["type"] == "array"
    assert sorted(tags["items"]["type"]) == ["integer", "string"]


# ============================================================================
# 5. SchemaInferrer: Dual Request/Response Schema Merging
# ============================================================================

def test_schema_inferrer_dual_request_response_schemas():
    """Verify dual schema dictionary with request and response keys merges cleanly."""
    inferrer = SchemaInferrer()

    flow1_dual = {
        "request": inferrer.infer_payload_schema({"search": "query1", "limit": 10}),
        "response": inferrer.infer_payload_schema({"results": [{"id": 1, "name": "Item A"}], "total": 1}),
    }

    flow2_dual = {
        "request": inferrer.infer_payload_schema({"search": "query2", "offset": 20}),
        "response": inferrer.infer_payload_schema({"results": [{"id": 2, "sku": "SKU-B"}], "total": 2}),
    }

    merged = inferrer.merge_schemas(flow1_dual, flow2_dual, sample_count=2)

    assert "request" in merged
    assert "response" in merged

    req = merged["request"]
    assert req["required"] == ["search"]
    assert "limit" in req["properties"]
    assert "offset" in req["properties"]

    resp = merged["response"]
    assert resp["required"] == ["results", "total"]
    results_items = resp["properties"]["results"]["items"]["properties"]
    assert "id" in results_items
    assert "name" in results_items
    assert "sku" in results_items


# ============================================================================
# 6. Addon & SQLite Persistence Integration
# ============================================================================

async def test_addon_endpoint_and_parameter_sqlite_ingestion():
    """Verify FlowForgeInterceptorAddon writes endpoints and parameters to SQLite and accumulates schema."""
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        await init_db(db_path)
        db_writer = AsyncDBWriter(db_path=db_path)
        await db_writer.start()
        broadcaster = EventBroadcaster()
        repo = FlowRepository(db_path=db_path)

        addon = FlowForgeInterceptorAddon(
            db_writer=db_writer,
            broadcaster=broadcaster,
            triage_callback=default_pipeline.process_flow_sync,
        )

        # Flow 1
        flow1 = FlowRecord(
            id="flow-dyn-001",
            timestamp_start=time.time(),
            timestamp_end=time.time() + 0.05,
            duration_ms=50.0,
            server_host="api.flowforge.local",
            server_port=443,
            scheme="https",
            request=RequestModel(
                method="POST",
                url="https://api.flowforge.local/api/v1/users?role=member",
                path="/api/v1/users",
                query_params={"role": "member"},
                headers={"content-type": "application/json"},
                body=json.dumps({"username": "user1", "tier": "free", "active": True}),
            ),
            response=ResponseModel(
                status_code=201,
                headers={"content-type": "application/json"},
                body=json.dumps({"id": 101, "username": "user1", "status": "created"}),
            ),
        )

        # Flow 2 (Evolving schema: new field 'quota', missing 'active')
        flow2 = FlowRecord(
            id="flow-dyn-002",
            timestamp_start=time.time() + 1.0,
            timestamp_end=time.time() + 1.05,
            duration_ms=50.0,
            server_host="api.flowforge.local",
            server_port=443,
            scheme="https",
            request=RequestModel(
                method="POST",
                url="https://api.flowforge.local/api/v1/users?role=admin",
                path="/api/v1/users",
                query_params={"role": "admin"},
                headers={"content-type": "application/json"},
                body=json.dumps({"username": "user2", "tier": "enterprise", "quota": 10000}),
            ),
            response=ResponseModel(
                status_code=201,
                headers={"content-type": "application/json"},
                body=json.dumps({"id": 102, "username": "user2", "status": "created"}),
            ),
        )

        # Enqueue flows to persistence queue so flows table satisfies FK constraint
        await db_writer.enqueue_insert_flow(flow1)
        triage_1 = default_pipeline.process_flow_sync(flow1)
        await addon._process_endpoint_and_schema(flow1, triage_1)

        await db_writer.enqueue_insert_flow(flow2)
        triage_2 = default_pipeline.process_flow_sync(flow2)
        await addon._process_endpoint_and_schema(flow2, triage_2)

        # Flush writer
        await db_writer.flush()
        await db_writer.stop()

        # Verify DB Endpoints Table
        endpoints, total_ep = await repo.list_endpoints()
        assert total_ep >= 1
        ep = next((e for e in endpoints if e.path_pattern == "/api/v1/users" and e.method == "POST"), None)
        assert ep is not None
        assert ep.host == "api.flowforge.local"
        assert ep.request_count >= 2

        # Verify Cumulative Schema Summary
        schema = ep.schema_summary
        assert "request" in schema
        req_schema = schema["request"]
        assert "username" in req_schema["properties"]
        assert "tier" in req_schema["properties"]
        assert "active" in req_schema["properties"]
        assert "quota" in req_schema["properties"]

        # 'username' and 'tier' were in both -> required
        assert "username" in req_schema["required"]
        assert "tier" in req_schema["required"]
        # 'active' and 'quota' were only in one -> not required
        assert "active" not in req_schema.get("required", [])
        assert "quota" not in req_schema.get("required", [])

        # Verify DB Parameters Table
        params, total_params = await repo.list_parameters(endpoint_hash=ep.endpoint_hash)
        assert total_params >= 2
        param_names = [p.name for p in params]
        assert "role" in param_names
        assert "username" in param_names

        # Verify single endpoint hash query
        ep_detail = await repo.get_endpoint_by_hash(ep.endpoint_hash)
        assert ep_detail is not None
        assert ep_detail.endpoint_hash == ep.endpoint_hash
        assert len(ep_detail.parameters) >= 2
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


# ============================================================================
# 7. Target Dossier REST Routes & Aliases
# ============================================================================

def test_dossier_rest_endpoints_and_aliases():
    """Verify /api/v1/dossier and /api/v1/dossiers REST endpoints with genuine models."""
    app = create_app()
    client = TestClient(app)

    # 1. Fetch dossiers (singular & plural aliases)
    res_singular = client.get("/api/v1/dossier")
    assert res_singular.status_code == 200
    data_sing = res_singular.json()
    assert "hosts" in data_sing
    assert "total_endpoints" in data_sing
    assert "total_parameters" in data_sing

    res_plural = client.get("/api/v1/dossiers")
    assert res_plural.status_code == 200
    data_plur = res_plural.json()
    assert "hosts" in data_plur
    assert "total_endpoints" in data_plur

    # 2. Paginated Endpoints Route
    res_endpoints = client.get("/api/v1/endpoints?page=1&page_size=10")
    assert res_endpoints.status_code == 200
    data_eps = res_endpoints.json()
    assert "items" in data_eps
    assert "total" in data_eps
    assert "page" in data_eps

    # 3. Parameters Route
    res_params = client.get("/api/v1/parameters?page=1&page_size=10")
    assert res_params.status_code == 200
    data_params = res_params.json()
    assert "items" in data_params
    assert "total" in data_params

    # 4. Detail Endpoint Route (Non-existent hash -> 404)
    res_404 = client.get("/api/v1/dossiers/nonexistenthash00")
    assert res_404.status_code == 404
    assert "not found" in res_404.json()["detail"].lower()

    res_404_sing = client.get("/api/v1/dossier/nonexistenthash00")
    assert res_404_sing.status_code == 404


# ============================================================================
# 8. Real-Time WebSocket Schema Evolution Broadcast
# ============================================================================

async def test_websocket_schema_updated_broadcast():
    """Verify EventBroadcaster correctly emits SCHEMA_UPDATED event with cumulative schema data."""
    broadcaster = EventBroadcaster()
    queue = await broadcaster.subscribe("test-subscriber")

    inferrer = SchemaInferrer()
    s1 = inferrer.infer_payload_schema({"action": "subscribe", "tier": "gold"})

    ep_hash = compute_endpoint_hash("POST", "flowforge.local", "/api/v1/billing")
    broadcaster.broadcast_schema_updated(
        endpoint_hash=ep_hash,
        host="flowforge.local",
        path_pattern="/api/v1/billing",
        method="POST",
        schema_summary={"request": s1},
        parameters=[
            {"name": "tier", "location": "body_json", "data_type": "string"}
        ],
        category="MUTATION_ACTION",
        request_count=1,
    )

    event = await asyncio.wait_for(queue.get(), timeout=2.0)
    assert event.event == EventType.SCHEMA_UPDATED.value
    assert event.data["endpoint_hash"] == ep_hash
    assert event.data["host"] == "flowforge.local"
    assert event.data["path_pattern"] == "/api/v1/billing"
    assert event.data["method"] == "POST"
    assert "request" in event.data["schema_summary"]
    assert len(event.data["parameters"]) == 1

    await broadcaster.unsubscribe(queue)
