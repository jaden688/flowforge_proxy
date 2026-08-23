"""
Tier 1 Feature Tests: Custom YAML/JSON Rule Engine, Condition Matching Operators,
CRUD/Test REST APIs, and Triage Pipeline Integration (Features F11–F14).
"""

from __future__ import annotations

import json
import uuid
import pytest
import yaml
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.heuristics.rule_engine import (
    ConditionEvaluator,
    FlowInspectionContext,
    RuleEngine,
    calculate_shannon_entropy,
    get_rule_engine,
)
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.rules import (
    MatchRule,
    RuleCondition,
    RuleOperator,
    RuleSeverity,
)


# ===========================================================================
# F11: Custom Rule Engine Schema (YAML/JSON Parsing) Tests
# ===========================================================================

def test_f11_yaml_rule_parsing_and_schema():
    """Verify parsing single and multiple MatchRule instances from YAML."""
    yaml_content = """
id: rule-cve-2026-auth
name: Spring4Shell ClassLoader Probe
description: Detects Spring4Shell exploit probes in query string or headers
severity: CRITICAL
category: RCE
tags:
  - spring4shell
  - rce
  - zeroday
enabled: true
condition_combinator: any
conditions:
  - field: query_string
    operator: contains
    value: "class.module.classLoader"
  - field: header
    target: "x-spring-exploit"
    operator: exists
"""
    rule = RuleEngine.parse_rule_from_yaml(yaml_content)
    assert rule.id == "rule-cve-2026-auth"
    assert rule.name == "Spring4Shell ClassLoader Probe"
    assert rule.severity == RuleSeverity.CRITICAL
    assert rule.category == "RCE"
    assert "spring4shell" in rule.tags
    assert rule.condition_combinator == "any"
    assert len(rule.conditions) == 2
    assert rule.conditions[0].operator == RuleOperator.CONTAINS


def test_f11_json_rule_parsing_nested_combinators():
    """Verify parsing MatchRule from JSON dictionary with nested conditions."""
    data = {
        "id": "rule-admin-debug",
        "name": "Unauthenticated Admin Debug",
        "severity": "HIGH",
        "category": "AUTH",
        "tags": ["admin", "debug", "auth_bypass"],
        "enabled": True,
        "condition_combinator": "all",
        "conditions": [
            {"field": "path", "operator": "starts_with", "value": "/admin"},
            {"field": "status", "operator": "equals", "value": 200},
            {"field": "header", "target": "authorization", "operator": "not_exists"},
        ],
    }
    rule = RuleEngine.parse_rule_from_dict(data)
    assert rule.id == "rule-admin-debug"
    assert rule.severity == RuleSeverity.HIGH
    assert len(rule.conditions) == 3
    assert rule.conditions[2].operator == RuleOperator.NOT_EXISTS


# ===========================================================================
# F12: Rule Match Engine & 18 Condition Operators Tests
# ===========================================================================

def test_f12_shannon_entropy_calculation():
    """Verify Shannon entropy calculation accuracy across low and high entropy inputs."""
    # Low entropy (single repeating character or empty)
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("AAAAAAA") == 0.0
    assert calculate_shannon_entropy("ABABABAB") <= 1.0

    # High entropy (random base64 / hex key / UUID)
    high_ent_key = "dGVzdF9rZXlfMTIzNDU2Nzg5MDEyMzQ1Njc4OTA="
    ent = calculate_shannon_entropy(high_ent_key)
    assert ent >= 4.0


def test_f12_condition_operators_string_and_regex():
    """Verify string and regex operators (equals, contains, starts_with, regex, etc.)."""
    evaluator = ConditionEvaluator()
    ctx = FlowInspectionContext(
        method="POST",
        url="https://target.com/api/v1/users/admin/reset?token=secret123",
        path="/api/v1/users/admin/reset",
        status_code=200,
        request_headers={"x-api-key": "FF-DEV-9988", "content-type": "application/json"},
        response_body='{"error": "Unauthorized Access Denied", "code": 401}',
        query_params={"token": "secret123"},
    )

    # 1. Equals (case-insensitive by default)
    cond1 = RuleCondition(field="method", operator=RuleOperator.EQUALS, value="post")
    assert evaluator.evaluate(cond1, ctx)[0] is True

    # 2. Contains
    cond2 = RuleCondition(field="url", operator=RuleOperator.CONTAINS, value="users/admin")
    assert evaluator.evaluate(cond2, ctx)[0] is True

    # 3. Starts With
    cond3 = RuleCondition(field="path", operator=RuleOperator.STARTS_WITH, value="/api/v1")
    assert evaluator.evaluate(cond3, ctx)[0] is True

    # 4. Regex matching
    cond4 = RuleCondition(field="header", target="x-api-key", operator=RuleOperator.REGEX, value=r"^FF-DEV-\d{4}$")
    assert evaluator.evaluate(cond4, ctx)[0] is True

    # 5. Not Regex
    cond5 = RuleCondition(field="path", operator=RuleOperator.NOT_REGEX, value=r"\.php$")
    assert evaluator.evaluate(cond5, ctx)[0] is True


def test_f12_condition_operators_numeric_and_entropy():
    """Verify numeric comparisons (gt, lt, gte, lte, status) and entropy operators."""
    evaluator = ConditionEvaluator()
    ctx = FlowInspectionContext(
        status_code=500,
        duration_ms=1250.0,
        ttfb_ms=850.0,
        response_body="Random high entropy secret payload: 8f7e6d5c4b3a2109fedcba9876543210",
    )

    # 1. Status GT 400
    cond1 = RuleCondition(field="status", operator=RuleOperator.GT, value=400)
    assert evaluator.evaluate(cond1, ctx)[0] is True

    # 2. Duration GT 1000ms
    cond2 = RuleCondition(field="duration_ms", operator=RuleOperator.GTE, value=1000)
    assert evaluator.evaluate(cond2, ctx)[0] is True

    # 3. Entropy GT 3.5 on response body
    cond3 = RuleCondition(field="entropy", operator=RuleOperator.ENTROPY_GT, value=3.5)
    assert evaluator.evaluate(cond3, ctx)[0] is True


def test_f12_condition_operators_lists_and_existence():
    """Verify in_list, not_in_list, exists, and not_exists operators."""
    evaluator = ConditionEvaluator()
    ctx = FlowInspectionContext(
        method="PUT",
        status_code=403,
        request_headers={"x-tenant-id": "t-1001"},
    )

    # 1. In list
    cond1 = RuleCondition(field="method", operator=RuleOperator.IN_LIST, value=["POST", "PUT", "PATCH"])
    assert evaluator.evaluate(cond1, ctx)[0] is True

    # 2. Not in list
    cond2 = RuleCondition(field="status", operator=RuleOperator.NOT_IN_LIST, value=[200, 201, 204])
    assert evaluator.evaluate(cond2, ctx)[0] is True

    # 3. Exists header
    cond3 = RuleCondition(field="header", target="x-tenant-id", operator=RuleOperator.EXISTS)
    assert evaluator.evaluate(cond3, ctx)[0] is True

    # 4. Not Exists header
    cond4 = RuleCondition(field="header", target="x-missing-header", operator=RuleOperator.NOT_EXISTS)
    assert evaluator.evaluate(cond4, ctx)[0] is True


# ===========================================================================
# F13: Custom Rules REST API Endpoints Tests
# ===========================================================================

async def test_f13_rules_api_crud_and_toggle(tmp_dir: str):
    """Verify CRUD endpoints: list, create, update, get, delete, toggle."""
    settings = Settings(db_path=f"{tmp_dir}/test_rules_crud.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Create a custom rule
        new_rule_data = {
            "id": "rule-sql-injection-probe",
            "name": "SQL Injection Probe Detector",
            "description": "Flags SQLi patterns in query params",
            "severity": "CRITICAL",
            "category": "INJECTION",
            "tags": ["sqli", "injection"],
            "enabled": True,
            "condition_combinator": "any",
            "conditions": [
                {"field": "query_string", "operator": "contains", "value": "' OR '1'='1"},
                {"field": "query_string", "operator": "contains", "value": "UNION SELECT"},
            ],
        }
        resp = await client.post("/api/v1/rules", json=new_rule_data)
        assert resp.status_code == 201
        created = resp.json()
        assert created["rule_id"] == "rule-sql-injection-probe"

        # 2. Get rule by ID
        resp_get = await client.get("/api/v1/rules/rule-sql-injection-probe")
        assert resp_get.status_code == 200
        assert resp_get.json()["rule"]["name"] == "SQL Injection Probe Detector"

        # 3. Toggle rule active state
        resp_toggle = await client.post("/api/v1/rules/rule-sql-injection-probe/toggle", json={"enabled": False})
        assert resp_toggle.status_code == 200
        assert resp_toggle.json()["rule"]["enabled"] is False

        # 4. List rules
        resp_list = await client.get("/api/v1/rules")
        assert resp_list.status_code == 200
        assert resp_list.json()["total"] >= 1

        # 5. Delete rule
        resp_del = await client.delete("/api/v1/rules/rule-sql-injection-probe")
        assert resp_del.status_code == 200
        assert resp_del.json()["status"] == "deleted"


async def test_f13_rules_api_dry_run_test_endpoint(tmp_dir: str):
    """Verify POST /api/v1/rules/test dry-run rule matching against sample flow payload."""
    settings = Settings(db_path=f"{tmp_dir}/test_rules_dryrun.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        test_payload = {
            "rule": {
                "id": "rule-test-cors",
                "name": "CORS Origin Reflection",
                "severity": "HIGH",
                "conditions": [
                    {"field": "response_header", "target": "access-control-allow-origin", "operator": "equals", "value": "*"},
                ],
            },
            "sample_flow": {
                "method": "GET",
                "url": "http://target.com/api/data",
                "response_status": 200,
                "response_headers": {"access-control-allow-origin": "*"},
            },
        }

        resp = await client.post("/api/v1/rules/test", json=test_payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["matched"] is True
        assert len(data["results"]) == 1
        assert data["results"][0]["matched"] is True


async def test_f13_rules_api_export_and_import(tmp_dir: str):
    """Verify exporting rules to YAML and importing rules from YAML payload."""
    settings = Settings(db_path=f"{tmp_dir}/test_rules_io.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Export rules
        resp_exp = await client.get("/api/v1/rules/export?format=yaml")
        assert resp_exp.status_code == 200
        exp_data = resp_exp.json()
        assert exp_data["format"] == "yaml"
        assert len(exp_data["content"]) > 0

        # Import new rule
        import_yaml = """
- id: rule-imported-log4j
  name: Log4j JNDI Lookup
  severity: CRITICAL
  tags: [log4j, jndi, rce]
  conditions:
    - field: body
      operator: contains
      value: "${jndi:"
"""
        resp_imp = await client.post(
            "/api/v1/rules/import",
            json={"content": import_yaml, "format": "yaml", "overwrite": False},
        )
        assert resp_imp.status_code == 200
        imp_res = resp_imp.json()
        assert imp_res["imported_count"] >= 1


# ===========================================================================
# F14: Rule Triage Pipeline Integration Tests
# ===========================================================================

def test_f14_triage_pipeline_rule_matching_and_tagging():
    """Verify TriagePipeline evaluates custom rules and attaches tags and high priority flag."""
    engine = RuleEngine(load_defaults=False)
    # Register custom rule
    rule = MatchRule(
        id="rule-ssrf-metadata",
        name="AWS Metadata Access Attempt",
        severity=RuleSeverity.CRITICAL,
        tags=["ssrf", "aws_metadata"],
        conditions=[
            RuleCondition(field="url", operator=RuleOperator.CONTAINS, value="169.254.169.254"),
        ],
    )
    engine.register_rule(rule)

    pipeline = TriagePipeline(rule_engine=engine)

    flow = FlowRecord(
        id=str(uuid.uuid4()),
        server_host="internal.service",
        request=RequestModel(
            method="GET",
            url="http://internal.service/proxy?url=http://169.254.169.254/latest/meta-data/",
            path="/proxy",
        ),
        response=ResponseModel(status_code=200, body='{"ami-id": "ami-12345"}'),
    )

    triage_summary = pipeline.process_flow_sync(flow)
    assert "ssrf" in triage_summary.tags
    assert "aws_metadata" in triage_summary.tags
    assert triage_summary.has_high_priority_anomalies is True
    assert len(triage_summary.rule_matches) >= 1
    assert triage_summary.rule_matches[0].rule_id == "rule-ssrf-metadata"
