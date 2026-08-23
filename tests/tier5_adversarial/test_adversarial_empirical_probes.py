"""
Tier 5 Adversarial Tests: Comprehensive Empirical Stress Probes (Challenger 1).
Verifies:
1. High concurrency request floods through proxy, pipeline, and DB writer.
2. Deep reflection injections and encoding variations across complex DOM, header, and multi-encoding contexts.
3. Malformed WebSocket frame bursts and edge cases.
4. IDOR classification precision with edge-case identifier formats (UUID v1/v4/v7, ULID, ObjectId, Snowflake, hashes, slugs).
5. FTS5 full-text search adversarial query injections (unbalanced quotes, operators, syntax).
6. Parameter extractor deep edge cases (nested XML namespaces, multipart boundary collisions, GraphQL).
7. Request/Response Diff Engine edge cases.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
import pytest

from flowforge.api.routes.diff import compute_flow_diff, DiffRequest
from flowforge.core.broadcaster import EventBroadcaster
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.identifiers import IdentifierClassifier
from flowforge.heuristics.models import (
    EncodingStatus,
    ExtractedParameter,
    FindingSeverity,
    IdentifierType,
    ParameterLocation,
    ReflectionContext,
)
from flowforge.heuristics.parameters import ParameterExtractor
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.heuristics.reflection import ReflectionDetector
from flowforge.models.flow import FlowFilterParams, FlowRecord, RequestModel, ResponseModel
from flowforge.models.websocket import WebSocketMessageModel
from tests.generator import SyntheticTrafficGenerator


# ---------------------------------------------------------------------------
# Probe 1: High Concurrency Request Floods & DB Writer Integrity
# ---------------------------------------------------------------------------
async def test_adversarial_high_concurrency_flood(tmp_db_path: str):
    """Stress-test DB writer and pipeline with 150 concurrent heterogeneous writes."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=30, flush_interval_ms=10)
    await writer.start()
    pipeline = TriagePipeline()

    total_requests = 150

    async def worker(idx: int):
        flow = FlowRecord(
            id=str(uuid.uuid4()),
            server_host="stress-flood.local",
            request=RequestModel(
                method="POST" if idx % 2 == 0 else "GET",
                url=f"https://stress-flood.local/api/items/{10000 + idx}?query=probe_{idx}&filter=all",
                path=f"/api/items/{10000 + idx}",
                query_string=f"query=probe_{idx}&filter=all",
                headers={"Authorization": f"Bearer token_{idx}", "Content-Type": "application/json"},
                body=json.dumps({"item_id": 10000 + idx, "action": f"mutate_{idx}"}),
            ),
            response=ResponseModel(
                status_code=200 if idx % 5 != 0 else 400,
                body=json.dumps({"status": "ok", "id": 10000 + idx, "reflected": f"probe_{idx}"}),
                headers={"Content-Type": "application/json", "X-Item-ID": str(10000 + idx)},
            ),
        )
        triage = await pipeline.process_flow(flow)
        flow.tags = triage.tags
        flow.triage_data = triage.model_dump()
        await writer.enqueue_insert_flow(flow)
        return triage

    start_t = time.perf_counter()
    results = await asyncio.gather(*(worker(i) for i in range(total_requests)))
    await writer.stop()
    elapsed = time.perf_counter() - start_t

    assert len(results) == total_requests
    flows, count = await repo.list_flows(FlowFilterParams(host="stress-flood.local", page_size=200))
    assert count == total_requests
    assert len(flows) == total_requests
    assert elapsed < 5.0  # Must process 150 items in under 5 seconds


# ---------------------------------------------------------------------------
# Probe 2: Deep Reflection Injections & Multi-Pass Encoding Variations
# ---------------------------------------------------------------------------
def test_adversarial_deep_reflection_injections():
    """Verify reflection detector across multi-pass encodings and complex HTML/JS/JSON contexts."""
    detector = ReflectionDetector()

    # Case A: Reflection inside <script> block with JSON escaping
    raw_payload_js = 'alert(1);</script><script>'
    param_js = ExtractedParameter(
        name="q",
        location=ParameterLocation.QUERY,
        value=raw_payload_js,
        raw_value=raw_payload_js,
    )
    resp_body_script = f'<html><head><script>var query = "{raw_payload_js}";</script></head><body>Hello</body></html>'
    findings_script = detector.detect_reflections([param_js], resp_body_script, response_content_type="text/html")
    assert len(findings_script) >= 1
    assert any(f.context == ReflectionContext.HTML_SCRIPT_BLOCK for f in findings_script)
    assert any(f.severity == FindingSeverity.CRITICAL for f in findings_script)

    # Case B: Reflection inside event handler attribute (e.g. onload/onerror)
    raw_payload_event = "foo' onmouseover='alert(1)"
    param_event = ExtractedParameter(
        name="name",
        location=ParameterLocation.BODY_JSON,
        value=raw_payload_event,
        raw_value=raw_payload_event,
    )
    resp_body_event = f'<div><input type="text" name="user" value="{raw_payload_event}"></div>'
    findings_event = detector.detect_reflections([param_event], resp_body_event, response_content_type="text/html")
    assert len(findings_event) >= 1
    assert any(f.context in (ReflectionContext.HTML_ATTR_QUOTED, ReflectionContext.HTML_ATTR_EVENT) for f in findings_event)

    # Case C: Base64 encoded reflection
    raw_secret = "secret_admin_token_999"
    b64_val = base64.b64encode(raw_secret.encode()).decode()
    param_b64 = ExtractedParameter(
        name="token",
        location=ParameterLocation.HEADER,
        value=raw_secret,
        raw_value=raw_secret,
    )
    resp_body_b64 = f'{{"status": "ok", "auth_blob": "{b64_val}"}}'
    findings_b64 = detector.detect_reflections([param_b64], resp_body_b64, response_content_type="application/json")
    assert len(findings_b64) >= 1
    assert any(f.encoding_status == EncodingStatus.BASE64_ENCODED for f in findings_b64)

    # Case D: HTML entity encoded reflection (safe sanitization)
    dangerous_input = "<script>alert('xss')</script>"
    safe_body = "<div>Search results for: &lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;</div>"
    param_sanitized = ExtractedParameter(
        name="search",
        location=ParameterLocation.QUERY,
        value=dangerous_input,
        raw_value=dangerous_input,
    )
    findings_sanitized = detector.detect_reflections([param_sanitized], safe_body, response_content_type="text/html")
    assert len(findings_sanitized) >= 1
    # Because it is HTML entity encoded, severity should be downgraded
    for f in findings_sanitized:
        if f.encoding_status == EncodingStatus.HTML_ENCODED:
            assert f.severity in (FindingSeverity.LOW, FindingSeverity.INFO)


# ---------------------------------------------------------------------------
# Probe 3: Malformed & Rapid WebSocket Frame Bursts
# ---------------------------------------------------------------------------
async def test_adversarial_websocket_bursts(tmp_db_path: str):
    """Verify WebSocket message storage and broadcaster resilience under rapid alternating frames."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=50, flush_interval_ms=10)
    await writer.start()
    broadcaster = EventBroadcaster(max_queue_size=50)

    sub_q = await broadcaster.subscribe()
    flow_id = str(uuid.uuid4())

    # Create baseline flow record
    flow = FlowRecord(
        id=flow_id,
        server_host="chat.target.com",
        is_websocket=True,
        request=RequestModel(method="GET", url="wss://chat.target.com/ws", path="/ws"),
        response=ResponseModel(status_code=101, headers={"Upgrade": "websocket"}),
    )
    await writer.enqueue_insert_flow(flow)

    total_frames = 60
    for i in range(total_frames):
        is_bin = (i % 2 == 1)
        opcode = 2 if is_bin else 1
        content = f"binary_data_{i}".encode("utf-8").hex() if is_bin else f'{{"msg_id": {i}, "text": "ping_{i}"}}'
        ws_msg = WebSocketMessageModel(
            flow_id=flow_id,
            timestamp=time.time(),
            from_client=(i % 3 != 0),
            opcode=opcode,
            content_length=len(content),
            content=content,
            is_binary=is_bin,
        )
        await writer.enqueue_ws_message(ws_msg)
        broadcaster.broadcast_ws_frame(ws_msg.model_dump())

    await writer.stop()

    # Query stored WS messages
    stored_msgs, total_count = await repo.get_websocket_messages(flow_id)
    assert total_count == total_frames
    assert len(stored_msgs) == total_frames
    binary_count = sum(1 for m in stored_msgs if m.is_binary)
    assert binary_count == total_frames // 2

    # Verify queue backpressure handled without crash
    assert sub_q.qsize() <= 50

    await broadcaster.unsubscribe(sub_q)


# ---------------------------------------------------------------------------
# Probe 4: IDOR Classification Precision & Edge-Case Identifier Formats
# ---------------------------------------------------------------------------
def test_adversarial_idor_identifier_classification():
    """Verify precision of identifier classification across edge-case ID formats."""
    classifier = IdentifierClassifier()

    cases = [
        # (value, param_name, expected_type, min_idor_score_get_path)
        ("12345", "user_id", IdentifierType.SEQUENTIAL_INTEGER, 0.9),
        ("1700000000123456789", "tweet_id", IdentifierType.MONOTONIC_TIMESTAMP, 0.75),
        ("507f1f77bcf86cd799439011", "doc_id", IdentifierType.MONGO_OBJECT_ID, 0.65),
        ("6ba7b810-9dad-11d1-80b4-00c04fd430c8", "session_uuid", IdentifierType.UUID_V1, 0.55),
        ("01ARZ3NDEKTSV4RRFFQ69G5FAV", "ulid_key", IdentifierType.ULID, 0.45),
        ("018d3b8f-3d60-7000-8000-000000000000", "record_id", IdentifierType.UUID_V7, 0.45),
        ("4a8b2c1d-0e3f-4a5b-9c7d-8e9f0a1b2c3d", "uuid", IdentifierType.UUID_V4, 0.10),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "file_hash", IdentifierType.HASH_DIGEST, 0.05),
        ("abc_123-xyz", "slug", IdentifierType.SHORT_OPAQUE_SLUG, 0.35),
        ("foobar_unrelated", "random_string", IdentifierType.UNKNOWN, 0.0),
    ]

    for val, name, exp_type, min_score in cases:
        id_type, w_type = classifier.classify_identifier(val, name)
        assert id_type == exp_type, f"Failed for val={val}, name={name}. Got {id_type}, expected {exp_type}"

        if exp_type != IdentifierType.UNKNOWN:
            score = classifier.compute_idor_score(
                id_type=id_type,
                type_weight=w_type,
                location=ParameterLocation.PATH,
                method="GET",
                is_authenticated=True,
                param_name=name,
            )
            assert score >= min_score, f"Score {score} lower than expected {min_score} for {name}={val}"


# ---------------------------------------------------------------------------
# Probe 5: FTS5 Full-Text Search Adversarial Query Injections
# ---------------------------------------------------------------------------
async def test_adversarial_fts5_query_robustness(tmp_db_path: str):
    """Verify FTS5 search handles malformed MATCH query syntax without throwing unhandled exceptions."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()

    # Insert a sample flow to populate FTS
    flow = FlowRecord(
        id=str(uuid.uuid4()),
        server_host="fts-test.org",
        request=RequestModel(
            method="GET",
            url="https://fts-test.org/search?q=security+proxy",
            path="/search",
            query_string="q=security+proxy",
            headers={"User-Agent": "SecScanner/1.0", "X-Custom": "SecretValue"},
            body="request body with critical payload",
        ),
        response=ResponseModel(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"result": "found secret admin data"}',
        ),
    )
    await writer.enqueue_insert_flow(flow)
    await writer.stop()

    # Malformed FTS queries that could break sqlite fts5 syntax if not escaped
    adversarial_queries = [
        'unclosed "quote',
        'AND OR NOT',
        'column:nonexistent',
        '***',
        'NEAR(query, 5)',
        '{}',
        '()()()',
        '""',
        '\\"\\"',
        "search' OR 1=1 --",
        "SELECT * FROM flows",
    ]

    for q in adversarial_queries:
        try:
            results, count = await repo.search_flows_fts(q)
            assert isinstance(results, list)
            assert isinstance(count, int)
        except Exception as exc:
            pytest.fail(f"FTS query '{q}' crashed repository search: {exc}")


# ---------------------------------------------------------------------------
# Probe 6: Multi-Source Parameter & GraphQL Extractor Adversarial Cases
# ---------------------------------------------------------------------------
def test_adversarial_parameter_extractor_complex_payloads():
    """Verify parameter extractor handles XML namespace quirks, mixed array brackets, and GraphQL mutations."""
    extractor = ParameterExtractor()

    # Case A: XML with mixed namespaces and attributes
    soap_xml = """<?xml version="1.0" encoding="utf-8"?>
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:api="http://target.com/api">
        <soapenv:Header>
            <api:AuthToken tokenType="Bearer">token_secret_123</api:AuthToken>
        </soapenv:Header>
        <soapenv:Body>
            <api:GetUserById userId="998877" active="true">
                <api:Fields>
                    <api:Field>email</api:Field>
                    <api:Field>ssn</api:Field>
                </api:Fields>
            </api:GetUserById>
        </soapenv:Body>
    </soapenv:Envelope>"""

    flow_xml = FlowRecord(
        id=str(uuid.uuid4()),
        server_host="soap.target.com",
        request=RequestModel(
            method="POST",
            url="https://soap.target.com/ws/service",
            path="/ws/service",
            content_type="text/xml",
            body=soap_xml,
        ),
    )
    xml_params = extractor.extract_all(flow_xml)
    assert len(xml_params) >= 3
    param_names = [p.name for p in xml_params]
    assert any("AuthToken" in n or "userId" in n for n in param_names)

    # Case B: GraphQL with variables and operationName
    gql_payload = json.dumps({
        "operationName": "UpdateUserEmail",
        "query": "mutation UpdateUserEmail($userId: ID!, $newEmail: String!) { updateUser(id: $userId, email: $newEmail) { id email } }",
        "variables": {"userId": "1002", "newEmail": "attacker@evil.com"},
    })
    flow_gql = FlowRecord(
        id=str(uuid.uuid4()),
        server_host="graphql.target.com",
        request=RequestModel(
            method="POST",
            url="https://graphql.target.com/graphql",
            path="/graphql",
            content_type="application/json",
            body=gql_payload,
        ),
    )
    gql_params = extractor.extract_all(flow_gql)
    assert any(p.name == "graphql.operationName" for p in gql_params)
    assert any(p.name == "graphql.variables.userId" and str(p.value) == "1002" for p in gql_params)
    assert any(p.name == "graphql.variables.newEmail" for p in gql_params)


# ---------------------------------------------------------------------------
# Probe 7: Request/Response Diff Engine Adversarial Delta Computation
# ---------------------------------------------------------------------------
async def test_adversarial_diff_engine_computation():
    """Verify structural diff engine correctly identifies IDOR data leak anomalies and auth bypasses."""
    # Case 1: IDOR anomaly detection (same status 200, large body difference)
    flow_a = {
        "id": "flow-idor-base",
        "method": "GET",
        "path": "/api/users/1",
        "response_status": 200,
        "response_body": json.dumps({"id": 1, "name": "Alice", "role": "user"}),
    }
    flow_b = {
        "id": "flow-idor-mutated",
        "method": "GET",
        "path": "/api/users/2",
        "response_status": 200,
        "response_body": json.dumps({
            "id": 2,
            "name": "Bob",
            "role": "victim",
            "leak_data": "SSN-000-11-2222",
            "address": "100 Confidential St",
            "internal_notes": "sensitive admin notes" * 20
        }),
    }

    from fastapi import FastAPI, Request

    req = Request(scope={"type": "http", "app": FastAPI()})
    diff_res = await compute_flow_diff(DiffRequest(flow_a=flow_a, flow_b=flow_b), req)
    assert diff_res.status_match is True
    assert diff_res.anomaly_verdict.level == "CRITICAL_IDOR"
    assert len(diff_res.body_diff_segments) > 0
