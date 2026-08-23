"""
Adversarial Stress Testing & Empirical Verification Matrix (Challenger 1).

Covers:
1. Decoders: cyclic layers, nested JWTs, extreme recursion, huge hex dumps, non-ASCII binary unquoting.
2. Rule Engine: ReDoS safety, invalid YAML/JSON syntax, large condition lists, complex boolean logic, high-entropy tokens.
3. Database Telemetry Persistence: high concurrency, boundary payloads, WAL mode invariants, FTS5 robustness.
4. Curation Pruning & Recommendations: conflicting regexes, pin protection, error cases, context-aware strategy ranking.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import html
import json
import os
import time
import urllib.parse
import uuid
import pytest
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.db.connection import get_connection, init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.recommendations import StrategyRecommendationEngine
from flowforge.heuristics.rule_engine import (
    ConditionEvaluator,
    FlowInspectionContext,
    RuleEngine,
    calculate_shannon_entropy,
)
from flowforge.models.curation import (
    CreateGroupRequest,
    CreatePayloadRequest,
    CurationImportRequest,
    PruneFilterRequest,
    RecommendStrategiesRequest,
)
from flowforge.models.flow import FlowFilterParams, FlowRecord, RequestModel, ResponseModel
from flowforge.models.rules import (
    MatchRule,
    RuleCondition,
    RuleOperator,
    RuleSeverity,
)
from flowforge.models.telemetry import (
    BandwidthTelemetry,
    FlowTelemetry,
    TimingTelemetry,
    TLSTelemetry,
)
from flowforge.utils.decoders import (
    _is_probable_base64,
    _is_probable_hex,
    _is_probable_jwt,
    decode_base64,
    decode_content,
    decode_hex,
    decode_html_entities,
    decode_url,
    encode_base64,
    encode_hex,
    encode_html_entities,
    encode_url,
    hex_dump,
    inspect_jwt,
    multi_layer_decode,
)


# ===========================================================================
# 1. DECODERS ADVERSARIAL STRESS SUITE
# ===========================================================================

def test_adversarial_cyclic_layers_and_depth_bounds():
    """Verify recursive auto-decoding terminates at max_depth on cyclic or deep encodings."""
    # 1. Base64 30-layer deep recursion
    s = "adversarial_secret_root_payload"
    for _ in range(30):
        s = base64.b64encode(s.encode()).decode()

    res = multi_layer_decode(s, max_depth=5)
    assert res.status == "success"
    assert len(res.layers) == 5
    assert res.detected_type == "base64"

    # 2. URL percent 10-layer recursion
    s_url = "CONFIDENTIAL_KEY"
    for _ in range(10):
        s_url = urllib.parse.quote(s_url, safe="")
    unquoted, passes = decode_url(s_url, multi_pass=True, max_passes=6)
    assert passes <= 6

    # 3. Alternating cyclic encodings (Base64 -> URL -> HTML)
    cyclic = "INIT_PAYLOAD_1337"
    for i in range(12):
        if i % 3 == 0:
            cyclic = base64.b64encode(cyclic.encode()).decode()
        elif i % 3 == 1:
            cyclic = urllib.parse.quote(cyclic, safe="")
        else:
            cyclic = html.escape(cyclic)

    res_cyclic = multi_layer_decode(cyclic, max_depth=10)
    assert res_cyclic.status == "success"
    assert len(res_cyclic.layers) <= 10


def test_adversarial_deep_nested_and_malformed_jwts():
    """Verify deep JWT inspection across multi-tier nested tokens, security flags, and malformed structures."""
    now = time.time()
    # Level 3: Unsecured alg: none token
    h3 = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    p3 = base64.urlsafe_b64encode(b'{"tier":3,"secret":"sub_secret","exp":9999999999}').decode().rstrip("=")
    jwt3 = f"{h3}.{p3}."

    # Level 2: HMAC symmetric token containing Level 3
    h2 = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    p2_json = json.dumps({"tier": 2, "embedded_token": jwt3, "exp": now - 3600})
    p2 = base64.urlsafe_b64encode(p2_json.encode()).decode().rstrip("=")
    jwt2 = f"{h2}.{p2}.signature2"

    # Level 1: RSA token with directory traversal in kid containing Level 2
    h1 = base64.urlsafe_b64encode(b'{"alg":"RS256","kid":"../../../../etc/passwd"}').decode().rstrip("=")
    p1_json = json.dumps({"tier": 1, "nested": jwt2, "role": "admin", "nbf": now + 7200})
    p1 = base64.urlsafe_b64encode(p1_json.encode()).decode().rstrip("=")
    jwt1 = f"{h1}.{p1}.signature1"

    # Test Level 1 inspection
    res1 = inspect_jwt(jwt1)
    assert res1.valid is True
    assert "KID_DIR_TRAVERSAL" in res1.security_flags
    assert "TOKEN_NOT_YET_VALID" in res1.security_flags
    assert res1.algorithm == "RS256"
    assert "role:admin" in res1.roles

    # Test Level 2 inspection from custom claim
    res2 = inspect_jwt(res1.custom_claims["nested"])
    assert res2.valid is True
    assert "SYMMETRIC_HMAC_ALGORITHM" in res2.security_flags
    assert "TOKEN_EXPIRED" in res2.security_flags

    # Test Level 3 inspection from custom claim
    res3 = inspect_jwt(res2.custom_claims["embedded_token"])
    assert res3.valid is True
    assert "ALG_NONE_UNSECURED" in res3.security_flags
    assert res3.payload["secret"] == "sub_secret"

    # Test Malformed JWTs
    assert inspect_jwt("not.a.jwt.token").valid is False
    assert inspect_jwt("eyJhbGciOiJIUzI1NiJ9.broken_payload.sig").valid is False
    assert inspect_jwt("").valid is False


def test_adversarial_extreme_hex_dump_performance():
    """Verify hex dumper produces exact 16-byte offset formatting at scale."""
    for size_kb in (50, 200, 1024):
        raw = bytes((i % 256 for i in range(size_kb * 1024)))
        t0 = time.perf_counter()
        dump = hex_dump(raw, bytes_per_line=16)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        lines = dump.split("\n")
        assert len(lines) == size_kb * 64
        assert lines[0].startswith("00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f")
        assert elapsed_ms < 500  # Must be fast (< 500ms even for 1MB)


def test_adversarial_non_ascii_binary_unquoting():
    """Verify lossless decoding and binary detection for null bytes, emojis, and Latin-1 fallback."""
    # Astral plane emojis and control characters
    complex_text = "🛡️_FLOWFORGE_⚡_\x00\x01\x1f\n\t_🚀"
    b64_str = encode_base64(complex_text)
    decoded, is_bin, raw_bytes = decode_base64(b64_str)
    assert decoded == complex_text
    assert is_bin is True
    assert raw_bytes == complex_text.encode("utf-8")

    # Hex formats
    hex_colon = "48:65:6c:6c:6f:20:57:6f:72:6c:64"
    h_dec, _, _ = decode_hex(hex_colon)
    assert h_dec == "Hello World"

    hex_prefix = "\\x48\\x65\\x6c\\x6c\\x6f"
    hp_dec, _, _ = decode_hex(hex_prefix)
    assert hp_dec == "Hello"

    # HTML numeric and hex entities
    html_ent = "&#60;script&#62;alert(&#x27;&#x58;&#x53;&#x53;&#x27;)&#60;/script&#62;"
    assert decode_html_entities(html_ent) == "<script>alert('XSS')</script>"


# ===========================================================================
# 2. RULE MATCHING ENGINE ADVERSARIAL STRESS SUITE
# ===========================================================================

def test_adversarial_rule_redos_and_bounded_input():
    """Verify ConditionEvaluator bounded input safety prevents hangs on huge strings."""
    evaluator = ConditionEvaluator(max_regex_length=5000)

    # 100KB input string with anchored evil regex
    evil_input = "a" * 100_000 + "X"
    cond = RuleCondition(field="body", operator=RuleOperator.REGEX, value=r"^(a+)+$")
    ctx = FlowInspectionContext(response_body=evil_input)

    t0 = time.perf_counter()
    matched, _ = evaluator.evaluate(cond, ctx)
    el_ms = (time.perf_counter() - t0) * 1000

    assert matched is False
    assert el_ms < 200

    # Uncompilable regex should not crash
    cond_bad = RuleCondition(field="body", operator=RuleOperator.REGEX, value="(?i)[unclosed")
    matched_bad, _ = evaluator.evaluate(cond_bad, ctx)
    assert matched_bad is False


def test_adversarial_invalid_yaml_json_ingestion():
    """Verify RuleEngine handles corrupted, empty, and invalid YAML/JSON rule documents gracefully."""
    engine = RuleEngine(load_defaults=False)

    # Broken YAML documents
    imp, upd, errs, _ = engine.import_from_yaml("invalid: yaml: [syntax")
    assert imp == 0
    assert len(errs) > 0

    # Broken JSON documents
    imp_j, upd_j, errs_j, _ = engine.import_from_json('{"name": "unclosed')
    assert imp_j == 0
    assert len(errs_j) > 0

    # Non-dictionary JSON root
    with pytest.raises(ValueError):
        RuleEngine.parse_rule_from_json('["not", "a", "dict"]')


def test_adversarial_large_condition_lists_scaling():
    """Verify rule engine efficiently evaluates rules with 1,000 atomic conditions."""
    engine = RuleEngine(load_defaults=False)
    conds = [
        RuleCondition(
            field="request_header",
            target=f"x-perf-{i}",
            operator=RuleOperator.EQUALS,
            value=f"perf-val-{i}",
        )
        for i in range(1000)
    ]
    rule = MatchRule(
        id="rule-perf-1000",
        name="1000 Conditions Performance Rule",
        severity=RuleSeverity.MEDIUM,
        condition_combinator="any",
        conditions=conds,
    )
    engine.register_rule(rule)

    # Match condition #999
    ctx = FlowInspectionContext(request_headers={"x-perf-999": "perf-val-999"})
    t0 = time.perf_counter()
    res = engine.evaluate_rule(rule, ctx)
    duration_ms = (time.perf_counter() - t0) * 1000

    assert res.matched is True
    assert duration_ms < 50.0


def test_adversarial_complex_nested_boolean_logic():
    """Verify nested boolean combinators (all + any + not) across multiple truth permutations."""
    engine = RuleEngine(load_defaults=False)
    rule = MatchRule(
        id="rule-bool-matrix",
        name="Boolean Matrix Rule",
        severity=RuleSeverity.HIGH,
        nested_conditions={
            "all": [
                RuleCondition(field="method", operator=RuleOperator.EQUALS, value="POST"),
                RuleCondition(field="status_code", operator=RuleOperator.EQUALS, value=200),
            ],
            "any": [
                RuleCondition(field="request_header", target="x-role", operator=RuleOperator.EQUALS, value="admin"),
                RuleCondition(field="request_header", target="x-role", operator=RuleOperator.EQUALS, value="manager"),
            ],
            "not": [
                RuleCondition(field="request_header", target="x-bot", operator=RuleOperator.EQUALS, value="true"),
            ],
        },
    )

    # Permutation 1: True (POST, 200, role=admin, no bot)
    ctx1 = FlowInspectionContext(method="POST", status_code=200, request_headers={"x-role": "admin"})
    assert engine.evaluate_rule(rule, ctx1).matched is True

    # Permutation 2: False (GET instead of POST)
    ctx2 = FlowInspectionContext(method="GET", status_code=200, request_headers={"x-role": "admin"})
    assert engine.evaluate_rule(rule, ctx2).matched is False

    # Permutation 3: False (Status 403 instead of 200)
    ctx3 = FlowInspectionContext(method="POST", status_code=403, request_headers={"x-role": "admin"})
    assert engine.evaluate_rule(rule, ctx3).matched is False

    # Permutation 4: False (role=guest not in any list)
    ctx4 = FlowInspectionContext(method="POST", status_code=200, request_headers={"x-role": "guest"})
    assert engine.evaluate_rule(rule, ctx4).matched is False

    # Permutation 5: False (x-bot=true triggers NOT block)
    ctx5 = FlowInspectionContext(method="POST", status_code=200, request_headers={"x-role": "admin", "x-bot": "true"})
    assert engine.evaluate_rule(rule, ctx5).matched is False


def test_adversarial_shannon_entropy_boundary_tokens():
    """Verify Shannon entropy mathematical invariants."""
    assert calculate_shannon_entropy(None) == 0.0
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("AAAAAAAAAA") == 0.0

    # 16 distinct chars -> log2(16) = 4.0
    ent_16 = calculate_shannon_entropy("0123456789abcdef")
    assert abs(ent_16 - 4.0) < 0.01

    # 256 distinct bytes -> log2(256) = 8.0
    ent_256 = calculate_shannon_entropy(bytes(range(256)))
    assert abs(ent_256 - 8.0) < 0.01


# ===========================================================================
# 3. DATABASE TELEMETRY & CONCURRENCY ADVERSARIAL STRESS SUITE
# ===========================================================================

async def test_adversarial_high_concurrency_db_persistence(tmp_db_path: str):
    """Verify 100 concurrent flows with telemetry are written and queried under load without database locks."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=20, flush_interval_ms=10)
    await writer.start()

    total_flows = 100
    flow_ids = [str(uuid.uuid4()) for _ in range(total_flows)]

    try:
        # Producer: enqueue 100 flows with rich telemetry
        async def insert_task():
            for i, fid in enumerate(flow_ids):
                flow = FlowRecord(
                    id=fid,
                    server_host="concurrency.target.com",
                    duration_ms=42.5 + i,
                    request=RequestModel(
                        method="POST",
                        url=f"https://concurrency.target.com/api/v1/item/{i}",
                        path=f"/api/v1/item/{i}",
                        body=f"telemetry_item_content_{i}",
                    ),
                    response=ResponseModel(status_code=200, body=f'{{"status":"ok","id":{i}}}'),
                    telemetry=FlowTelemetry(
                        tls=TLSTelemetry(version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384"),
                        timings=TimingTelemetry(ttfb_ms=21.0 + i, total_duration_ms=42.5 + i),
                        bandwidth=BandwidthTelemetry(total_bytes=1024 + i),
                    ),
                )
                await writer.enqueue_flow(flow)
                if i % 10 == 0:
                    await asyncio.sleep(0.002)

        # Reader: concurrent list and search queries
        async def read_task():
            for _ in range(10):
                await repo.list_flows(FlowFilterParams(host="concurrency.target.com"))
                await repo.search_flows_fts("telemetry_item_content")
                await asyncio.sleep(0.005)

        await asyncio.gather(insert_task(), read_task())
        await writer.flush()

        # Verify all 100 flows persisted
        _, count = await repo.list_flows(FlowFilterParams(host="concurrency.target.com"))
        assert count == total_flows

        # Verify telemetry roundtrip on sampled record
        sample = await repo.get_flow_by_id(flow_ids[50])
        assert sample is not None
        assert sample.telemetry is not None
        assert sample.telemetry.tls.cipher_suite == "TLS_AES_256_GCM_SHA384"
        assert sample.telemetry.timings.ttfb_ms == 71.0
    finally:
        await writer.stop()


async def test_adversarial_boundary_telemetry_payloads(tmp_db_path: str):
    """Verify extreme timing, bandwidth, and TLS connection parameters persist losslessly."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, flush_interval_ms=10)
    await writer.start()

    fid = str(uuid.uuid4())
    extreme_telemetry = FlowTelemetry(
        tls=TLSTelemetry(
            version="TLSv1.3",
            cipher_suite="ECDHE-ECDSA-AES256-GCM-SHA384",
            sni="extremely.long.subdomain.target.internal.domain.local",
            alpn="h2",
            resumed=True,
        ),
        timings=TimingTelemetry(
            dns_ms=0.001,
            tcp_connect_ms=0.05,
            tls_handshake_ms=0.12,
            request_send_ms=0.01,
            ttfb_ms=9999999.99,
            response_transfer_ms=0.005,
            total_duration_ms=10000000.18,
        ),
        bandwidth=BandwidthTelemetry(
            request_headers_bytes=10000,
            request_body_bytes=5000000,
            response_headers_bytes=10000,
            response_body_bytes=50000000,
            total_bytes=55020000,
        ),
    )

    flow = FlowRecord(
        id=fid,
        server_host="extreme.target.com",
        request=RequestModel(method="GET", url="https://extreme.target.com/boundary", path="/boundary"),
        response=ResponseModel(status_code=200),
        telemetry=extreme_telemetry,
    )

    try:
        await writer.enqueue_flow(flow)
        await writer.flush()

        retrieved = await repo.get_flow_by_id(fid)
        assert retrieved is not None
        assert retrieved.telemetry.timings.ttfb_ms == 9999999.99
        assert retrieved.telemetry.bandwidth.total_bytes == 55020000
        assert retrieved.telemetry.tls.resumed is True
    finally:
        await writer.stop()


# ===========================================================================
# 4. PAYLOAD CURATION & SELECTIVE PRUNING ADVERSARIAL STRESS SUITE
# ===========================================================================

async def test_adversarial_curation_conflicting_filters_and_pin_protection(tmp_dir: str):
    """Verify pinned/starred items are never deleted even when matching aggressive pruning filters."""
    settings = Settings(db_path=f"{tmp_dir}/curation_pin_stress.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create dedicated group for pin protection testing
        g_resp = await client.post("/api/v1/curation/groups", json={"id": "grp-pin-stress", "name": "Pin Stress Group"})
        assert g_resp.status_code == 200

        # Create 10 items in this group: 5 unstarred, 5 starred with matching status 'FAILED'
        for i in range(10):
            is_starred = (i % 2 == 0)
            await client.post(
                "/api/v1/curation/payloads",
                json={
                    "group_id": "grp-pin-stress",
                    "name": f"Pin Probe #{i}",
                    "category": "IDOR_SEQUENTIAL",
                    "status": "FAILED",
                    "mutated_value": f"val_{i}",
                    "starred": is_starred,
                },
            )

        # Prune with aggressive status filter 'FAILED' and preserve_starred=True inside this group
        resp_prune = await client.post(
            "/api/v1/curation/groups/grp-pin-stress/prune",
            json={
                "statuses_to_delete": ["FAILED"],
                "preserve_starred": True,
            },
        )
        assert resp_prune.status_code == 200
        data = resp_prune.json()
        assert data["deleted_count"] == 5
        assert data["preserved_count"] == 5

        # Verify all remaining items in this group are starred
        resp_list = await client.get("/api/v1/curation/payloads?group_id=grp-pin-stress")
        items = resp_list.json()
        assert len(items) == 5
        assert all(item["starred"] is True for item in items)


async def test_adversarial_curation_edge_cases_and_error_handling(tmp_dir: str):
    """Verify HTTP status codes on boundary operations (delete default, duplicate ID, bad regex)."""
    settings = Settings(db_path=f"{tmp_dir}/curation_err_stress.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Delete default group -> HTTP 400
        resp_del_def = await client.delete("/api/v1/curation/groups/default")
        assert resp_del_def.status_code == 400

        # 2. Duplicate group ID -> HTTP 400
        await client.post("/api/v1/curation/groups", json={"id": "grp-fixed-id", "name": "Fixed Group"})
        resp_dup = await client.post("/api/v1/curation/groups", json={"id": "grp-fixed-id", "name": "Dup Group"})
        assert resp_dup.status_code == 400

        # 3. Non-existent lookups -> HTTP 404
        assert (await client.get("/api/v1/curation/groups/nonexistent_group_xyz")).status_code == 404
        assert (await client.get("/api/v1/curation/payloads/nonexistent_payload_xyz")).status_code == 404

        # 4. Invalid Regex Prune Filter -> HTTP 400
        resp_bad_regex = await client.post(
            "/api/v1/curation/prune",
            json={"regex_filter": "(?i)[unclosed_bracket", "preserve_starred": True},
        )
        assert resp_bad_regex.status_code == 400


async def test_adversarial_curation_export_import_fidelity(tmp_dir: str):
    """Verify full JSON export and re-import preserves all groups and payloads."""
    settings = Settings(db_path=f"{tmp_dir}/curation_export_stress.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create group and payload
        g_resp = await client.post("/api/v1/curation/groups", json={"name": "Export Group", "description": "Desc"})
        gid = g_resp.json()["id"]

        await client.post(
            "/api/v1/curation/payloads",
            json={
                "group_id": gid,
                "name": "Exported Probe",
                "category": "AUTH_STRIPPING",
                "starred": True,
            },
        )

        # Export
        exp_resp = await client.get("/api/v1/curation/export")
        assert exp_resp.status_code == 200
        exp_data = exp_resp.json()
        assert len(exp_data["groups"]) >= 2
        assert len(exp_data["payloads"]) >= 1

        # Re-import with overwrite
        imp_resp = await client.post("/api/v1/curation/import", json={"groups": exp_data["groups"], "payloads": exp_data["payloads"], "overwrite": True})
        assert imp_resp.status_code == 200
        imp_data = imp_resp.json()
        assert imp_data["imported_payloads_count"] >= 1


def test_adversarial_context_aware_recommendation_ranking():
    """Verify recommendation engine dynamically ranks mutation strategies for distinct endpoint profiles."""
    engine = StrategyRecommendationEngine()

    # Profile 1: Reflection detected -> REFLECTION_CONTEXT must be #1
    rec1 = engine.recommend(
        method="GET",
        path="/search",
        parameters=[{"name": "q", "value": "<script>"}],
        reflections=[{"param": "q", "context": "HTML_TAG"}],
    )
    assert rec1.top_recommended.strategy_id == "REFLECTION_CONTEXT"
    assert rec1.top_recommended.badge == "#1 (Recommended)"

    # Profile 2: Sequential integer in path -> IDOR_SEQUENTIAL must be #1
    rec2 = engine.recommend(
        method="GET",
        path="/api/v1/users/4029/profile",
        parameters=[{"name": "user_id", "value": 4029, "id_type": "sequential_integer", "idor_score": 0.85}],
    )
    assert rec2.top_recommended.strategy_id == "IDOR_SEQUENTIAL"
    assert rec2.top_recommended.badge == "#1 (Recommended)"

    # Profile 3: File download parameter -> PATH_TRAVERSAL must be #1
    rec3 = engine.recommend(
        method="GET",
        path="/download",
        parameters=[{"name": "filename", "value": "report.pdf"}],
        category="FILE_TRANSFER",
    )
    assert rec3.top_recommended.strategy_id == "PATH_TRAVERSAL"
    assert rec3.top_recommended.badge == "#1 (Recommended)"

    # Profile 4: JWT token in auth header -> JWT_FORGERY_PROBES must be #1
    rec4 = engine.recommend(
        method="GET",
        path="/api/v1/dashboard",
        triage_tags=["jwt", "auth"],
        parameters=[{"name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "inferred_format": "jwt"}],
    )
    assert rec4.top_recommended.strategy_id == "JWT_FORGERY_PROBES"
    assert rec4.top_recommended.badge == "#1 (Recommended)"
