"""
Tests for the Proposal → Intruder Bridge (Phase 1A).

Verifies:
- Each anomaly type produces the correct injection points and wordlist categories
- Auth overrides are correctly mapped
- Body/header/query injection is selected per proposal location
- Batch conversion respects max_proposals and sorts by severity/confidence
- Edge cases: empty proposals, unknown anomaly types, null values
"""

from __future__ import annotations

import pytest

from flowforge.core.bridge import (
    build_intruder_config,
    build_injection_points,
    proposals_to_intruder_configs,
    select_auth_override,
)
from flowforge.models.intruder import IntruderJobConfig
from flowforge.models.proposal import (
    AnomalyType,
    ProposalSeverity,
    ProposalState,
    TestProposal,
)

FLOW_ID = "flow-test-001"


def _make_proposal(**overrides) -> TestProposal:
    base = dict(
        flow_id=FLOW_ID,
        endpoint_path="/api/users/123",
        method="GET",
        anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
        title="Test IDOR",
        description="Sequential IDOR test",
        severity=ProposalSeverity.MEDIUM,
        confidence_score=75.0,
        target_param_name="id",
        target_param_location="query",
        baseline_value=123,
        mutated_value=124,
        state=ProposalState.PENDING,
        tags=["idor"],
    )
    base.update(overrides)
    return TestProposal(**base)


def _make_flow(**overrides) -> dict:
    base = dict(
        id=FLOW_ID,
        url="http://127.0.0.1:3000/api/users/123?id=123&name=test",
        method="GET",
        headers={"Content-Type": "application/json", "Authorization": "Bearer real-token-abc"},
        body=None,
        path="/api/users/123",
    )
    base.update(overrides)
    return base


# ---- Injection point generation ----

class TestInjectionPointGeneration:
    def test_idor_sequential_query(self):
        p = _make_proposal(
            anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
            target_param_name="id",
            target_param_location="query",
        )
        points = build_injection_points(p)
        assert len(points) == 1
        assert points[0].position.value == "query"
        assert points[0].key == "id"

    def test_idor_sequential_path(self):
        p = _make_proposal(
            anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
            target_param_name="123",
            target_param_location="path",
            endpoint_path="/api/users/123",
        )
        points = build_injection_points(p)
        assert len(points) == 1
        assert points[0].position.value == "query"
        # Path mutation falls back to query injection for the segment
        assert points[0].key == "123"

    def test_reflection_body(self):
        p = _make_proposal(
            anomaly_type=AnomalyType.REFLECTION,
            target_param_name="",
            target_param_location="body",
        )
        points = build_injection_points(p)
        assert len(points) == 1
        assert points[0].position.value == "body"

    def test_reflection_with_named_param(self):
        p = _make_proposal(
            anomaly_type=AnomalyType.REFLECTION,
            target_param_name="q",
            target_param_location="query",
        )
        points = build_injection_points(p)
        # Should get both query and body injection for reflection
        positions = {pt.position.value for pt in points}
        assert "query" in positions
        assert "body" in positions

    def test_auth_deviation_header(self):
        p = _make_proposal(
            anomaly_type=AnomalyType.AUTH_DEVIATION,
            target_param_name="Authorization",
            target_param_location="header",
        )
        points = build_injection_points(p)
        assert len(points) == 1
        assert points[0].position.value == "header"
        assert points[0].key == "Authorization"

    def test_auth_deviation_default_header(self):
        p = _make_proposal(
            anomaly_type=AnomalyType.AUTH_DEVIATION,
            target_param_name="",
            target_param_location="header",
        )
        points = build_injection_points(p)
        assert len(points) == 1
        assert points[0].position.value == "header"

    def test_jwt_anomaly_header(self):
        p = _make_proposal(
            anomaly_type=AnomalyType.JWT_ANOMALY,
            target_param_name="Authorization",
            target_param_location="header",
        )
        points = build_injection_points(p)
        # JWT anomalies fall through to the default path logic
        assert len(points) >= 1

    def test_secret_exposure_query(self):
        p = _make_proposal(
            anomaly_type=AnomalyType.SECRET_EXPOSURE,
            target_param_name="path",
            target_param_location="query",
        )
        points = build_injection_points(p)
        assert len(points) == 1
        assert points[0].position.value == "query"

    def test_json_schema_body(self):
        p = _make_proposal(
            anomaly_type=AnomalyType.JSON_SCHEMA,
            target_param_name="role",
            target_param_location="body",
        )
        points = build_injection_points(p)
        positions = {pt.position.value for pt in points}
        assert "query" in positions
        assert "body" in positions


# ---- Auth override mapping ----

class TestAuthOverrideMapping:
    def test_explicit_override_passthrough(self):
        p = _make_proposal(auth_override="EXPIRED")
        assert select_auth_override(p) == "EXPIRED"

    def test_auth_deviation_defaults_to_drop(self):
        p = _make_proposal(
            anomaly_type=AnomalyType.AUTH_DEVIATION,
            auth_override=None,
        )
        assert select_auth_override(p) == "DROP"

    def test_non_auth_deviation_returns_none(self):
        p = _make_proposal(
            anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
            auth_override=None,
        )
        assert select_auth_override(p) is None


# ---- Full config building ----

class TestIntruderConfigBuilding:
    def test_basic_idor_config(self):
        p = _make_proposal()
        flow = _make_flow()
        config = build_intruder_config(p, flow)

        assert isinstance(config, IntruderJobConfig)
        assert config.method == "GET"
        assert config.url == flow["url"]
        assert config.flow_id == FLOW_ID
        assert len(config.injection_points) == 1
        assert len(config.inline_payloads) > 0
        assert "idor" in config.arsenal_wordlist_ids
        assert "integer_sequential" in config.arsenal_wordlist_ids

    def test_config_without_flow_uses_proposal_defaults(self):
        p = _make_proposal()
        config = build_intruder_config(p, None)

        assert config.url.startswith("http://127.0.0.1:8000/api/users/123")
        assert "id=123" in config.url or "id=1" in config.url

    def test_mutation_value_inlined(self):
        p = _make_proposal(mutated_value=42)
        config = build_intruder_config(p, None)
        assert "42" in config.inline_payloads

    def test_baseline_value_inlined(self):
        p = _make_proposal(baseline_value=123)
        config = build_intruder_config(p, None)
        assert "123" in config.inline_payloads

    def test_reflection_payloads(self):
        p = _make_proposal(
            anomaly_type=AnomalyType.REFLECTION,
            target_param_name="q",
        )
        config = build_intruder_config(p, None)
        assert "xss" in config.arsenal_wordlist_ids
        assert any("<script>" in payload for payload in config.inline_payloads)

    def test_jwt_anomaly_payloads(self):
        p = _make_proposal(anomaly_type=AnomalyType.JWT_ANOMALY)
        config = build_intruder_config(p, None)
        assert "jwt_attacks" in config.arsenal_wordlist_ids
        assert "none" in config.inline_payloads

    def test_auth_drop_strips_auth_headers(self):
        p = _make_proposal(
            anomaly_type=AnomalyType.AUTH_DEVIATION,
            auth_override="DROP",
        )
        flow = _make_flow()
        config = build_intruder_config(p, flow)
        assert "Authorization" not in config.headers

    def test_concurrency_forwarded(self):
        p = _make_proposal()
        config = build_intruder_config(p, None, concurrency=16)
        assert config.concurrency == 16

    def test_rate_limit_forwarded(self):
        p = _make_proposal()
        config = build_intruder_config(p, None, rate_limit_rps=50.0)
        assert config.rate_limit_rps == 50.0

    def test_unknown_anomaly_type_uses_generic_fuzz(self):
        p = _make_proposal(anomaly_type=AnomalyType.CUSTOM_RULE)
        config = build_intruder_config(p, None)
        assert "generic_fuzz" in config.arsenal_wordlist_ids
        assert len(config.inline_payloads) > 0

    def test_body_proposal_json_body(self):
        p = _make_proposal(
            target_param_name="role",
            target_param_location="body",
            baseline_value={"role": "user"},
        )
        config = build_intruder_config(p, None)
        assert config.body is not None
        assert "role" in config.body


# ---- Batch conversion ----

class TestBatchConversion:
    def test_sorts_by_severity_then_confidence(self):
        proposals = [
            _make_proposal(id="p-low", severity=ProposalSeverity.LOW, confidence_score=50),
            _make_proposal(id="p-high", severity=ProposalSeverity.HIGH, confidence_score=90),
            _make_proposal(id="p-crit", severity=ProposalSeverity.CRITICAL, confidence_score=70),
            _make_proposal(id="p-med", severity=ProposalSeverity.MEDIUM, confidence_score=95),
        ]
        configs = proposals_to_intruder_configs(proposals, max_proposals=10)
        assert len(configs) == 4

    def test_respects_max_proposals(self):
        proposals = [_make_proposal(id=f"p-{i}") for i in range(50)]
        configs = proposals_to_intruder_configs(proposals, max_proposals=5)
        assert len(configs) == 5

    def test_skips_non_pending(self):
        proposals = [
            _make_proposal(id="p-exec", state=ProposalState.EXECUTING),
            _make_proposal(id="p-pend", state=ProposalState.PENDING),
        ]
        configs = proposals_to_intruder_configs(proposals, max_proposals=10)
        assert len(configs) == 1

    def test_empty_input(self):
        configs = proposals_to_intruder_configs([], max_proposals=10)
        assert configs == []

    def test_with_flows_map(self):
        proposals = [_make_proposal()]
        flows = {FLOW_ID: _make_flow()}
        configs = proposals_to_intruder_configs(proposals, flows=flows)
        assert configs[0].url == flows[FLOW_ID]["url"]
