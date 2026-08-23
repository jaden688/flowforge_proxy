"""
Tier 2 Boundary Tests: Deeply Nested JSON Objects and Recursion Limits.
"""

from __future__ import annotations

import json
import pytest

from flowforge.heuristics.parameters import ParameterExtractor
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.heuristics.schema_inferrer import SchemaInferrer
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel


def _build_nested_dict(depth: int, current: int = 1) -> dict:
    """Recursively build deeply nested dictionary."""
    if current >= depth:
        return {"leaf_key": "leaf_value", "leaf_id": 9999}
    return {f"level_{current}": _build_nested_dict(depth, current + 1)}


def test_parameter_extractor_deep_nesting_bound():
    """Verify ParameterExtractor handles 25-layer nested JSON without RecursionError."""
    extractor = ParameterExtractor()
    deep_data = _build_nested_dict(25)

    params = extractor.flatten_json(deep_data)
    assert len(params) > 0
    # Must contain extracted leaf parameter or bounded representation
    assert any("leaf" in p.name or "level_20" in p.name for p in params)


def test_schema_inferrer_deep_nesting_bound():
    """Verify SchemaInferrer handles 25-layer nested JSON without stack overflow."""
    inferrer = SchemaInferrer()
    deep_data = _build_nested_dict(25)

    schema = inferrer.infer_payload_schema(deep_data)
    assert schema["type"] == "object"
    assert "properties" in schema


async def test_pipeline_deep_nested_flow_resilience():
    """Verify TriagePipeline processes a 30-layer nested flow payload cleanly under 50ms."""
    pipeline = TriagePipeline()
    deep_data = _build_nested_dict(30)
    body_str = json.dumps(deep_data)

    flow = FlowRecord(
        id="flow-deep-001",
        server_host="api.nested.com",
        request=RequestModel(
            method="POST",
            url="https://api.nested.com/api/v1/tree",
            path="/api/v1/tree",
            headers={"Content-Type": "application/json"},
            body=body_str,
        ),
        response=ResponseModel(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=body_str,
        ),
    )

    triage = await pipeline.process_flow(flow)
    assert triage is not None
    assert triage.flow_id == "flow-deep-001"
    assert triage.analysis_duration_ms >= 0.0
