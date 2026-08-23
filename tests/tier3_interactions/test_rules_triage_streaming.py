"""
Tier 3 Cross-Feature Interaction Tests: Flow Ingestion -> Custom Rule Evaluation ->
Triage Tagging -> EventBroadcaster Dispatch -> Streaming WebSocket Broadcast.
"""

from __future__ import annotations

import asyncio
import time
import uuid
import pytest

from flowforge.core.broadcaster import EventBroadcaster
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.heuristics.rule_engine import RuleEngine
from flowforge.models.events import FlowEvent
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.rules import MatchRule, RuleCondition, RuleOperator, RuleSeverity


async def test_t3_rules_evaluation_to_triage_tagging_and_broadcasting():
    """Verify live flow matching custom rule triggers triage annotation and broadcaster dispatch."""
    broadcaster = EventBroadcaster(max_queue_size=100)
    rule_engine = RuleEngine(load_defaults=False)

    # Register custom rule targeting internal API key header
    rule = MatchRule(
        id="rule-internal-key-leak",
        name="Internal API Key Leak",
        severity=RuleSeverity.CRITICAL,
        tags=["secret_leak", "critical_auth"],
        conditions=[
            RuleCondition(field="response_header", target="x-internal-secret", operator=RuleOperator.EXISTS),
        ],
    )
    rule_engine.register_rule(rule)

    pipeline = TriagePipeline(rule_engine=rule_engine)

    # Subscribe client queue to broadcaster
    client_queue = await broadcaster.subscribe("client-ws-1")

    flow = FlowRecord(
        id=str(uuid.uuid4()),
        server_host="internal.corp",
        request=RequestModel(method="GET", url="http://internal.corp/admin/debug", path="/admin/debug"),
        response=ResponseModel(
            status_code=200,
            headers={"x-internal-secret": "PROD_SECRET_KEY_9988"},
            body='{"status": "ok"}',
        ),
    )

    # Process through pipeline
    triage_summary = pipeline.process_flow_sync(flow)
    assert "secret_leak" in triage_summary.tags
    assert "critical_auth" in triage_summary.tags
    assert triage_summary.has_high_priority_anomalies is True

    # Broadcast triage annotation
    broadcaster.broadcast_triage_annotated(flow.id, triage_summary)

    # Verify event received in client queue
    event: FlowEvent = await asyncio.wait_for(client_queue.get(), timeout=1.0)
    assert event.event_type == "triage_annotated"
    assert event.flow_id == flow.id
    assert "secret_leak" in event.data["tags"]

    await broadcaster.unsubscribe("client-ws-1")


async def test_t3_dynamic_rule_registration_and_immediate_flow_matching():
    """Verify newly registered rules evaluate immediately against subsequent traffic without restarting."""
    rule_engine = RuleEngine(load_defaults=False)
    pipeline = TriagePipeline(rule_engine=rule_engine)

    flow_baseline = FlowRecord(
        id="flow-1",
        server_host="api.test.com",
        request=RequestModel(method="POST", url="http://api.test.com/v1/graphql", path="/v1/graphql", body='{"query": "mutation { deleteUser }"}'),
        response=ResponseModel(status_code=200, body='{"data": {"deleteUser": true}}'),
    )

    # Baseline before rule
    triage_1 = pipeline.process_flow_sync(flow_baseline)
    assert "graphql_destructive_mutation" not in triage_1.tags

    # Dynamically register 0-day GraphQL destructive rule
    rule_engine.register_rule(MatchRule(
        id="rule-graphql-destructive",
        name="GraphQL Destructive Mutation",
        severity=RuleSeverity.HIGH,
        tags=["graphql_destructive_mutation"],
        conditions=[
            RuleCondition(field="request_body", operator=RuleOperator.CONTAINS, value="deleteUser"),
        ],
    ))

    # Second flow evaluated immediately
    triage_2 = pipeline.process_flow_sync(flow_baseline)
    assert "graphql_destructive_mutation" in triage_2.tags
    assert len(triage_2.rule_matches) == 1


async def test_t3_multi_rule_composite_tagging_and_severity_resolution():
    """Verify multiple matching rules concurrently attach tags and propagate highest severity."""
    rule_engine = RuleEngine(load_defaults=False)
    rule_engine.register_rule(MatchRule(
        id="rule-low",
        name="Low Info Rule",
        severity=RuleSeverity.LOW,
        tags=["info_tag"],
        conditions=[RuleCondition(field="status", operator=RuleOperator.EQUALS, value=200)],
    ))
    rule_engine.register_rule(MatchRule(
        id="rule-critical",
        name="Critical Exploit Rule",
        severity=RuleSeverity.CRITICAL,
        tags=["critical_tag"],
        conditions=[RuleCondition(field="path", operator=RuleOperator.CONTAINS, value="shell.jsp")],
    ))

    pipeline = TriagePipeline(rule_engine=rule_engine)

    flow = FlowRecord(
        id="flow-multi",
        server_host="target.com",
        request=RequestModel(method="GET", url="http://target.com/shell.jsp", path="/shell.jsp"),
        response=ResponseModel(status_code=200, body="root:x:0:0"),
    )

    triage = pipeline.process_flow_sync(flow)
    assert "info_tag" in triage.tags
    assert "critical_tag" in triage.tags
    assert triage.has_high_priority_anomalies is True


async def test_t3_rule_triage_streaming_with_multiple_subscribers():
    """Verify multi-subscriber broadcast fanout of rule-annotated triage events."""
    broadcaster = EventBroadcaster()
    q1 = await broadcaster.subscribe("sub-1")
    q2 = await broadcaster.subscribe("sub-2")

    triage_data = {"flow_id": "f-100", "tags": ["tagA", "tagB"]}
    broadcaster.broadcast_triage_annotated("f-100", triage_data)

    ev1 = await asyncio.wait_for(q1.get(), timeout=1.0)
    ev2 = await asyncio.wait_for(q2.get(), timeout=1.0)

    assert ev1.flow_id == "f-100"
    assert ev2.flow_id == "f-100"
    assert ev1.data["tags"] == ["tagA", "tagB"]

    await broadcaster.unsubscribe("sub-1")
    await broadcaster.unsubscribe("sub-2")
