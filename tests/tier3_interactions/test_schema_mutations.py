"""
Tests for Phase 2A: Schema-aware mutations in the proposal synthesizer.
"""

from __future__ import annotations

import json
import pytest
from flowforge.heuristics.models import (
    EndpointCategory,
    ExtractedParameter,
    IdentifierFinding,
    IdentifierType,
    ParameterLocation,
    ReflectionFinding,
    ReflectionContext,
    TriageSummary,
)
from flowforge.heuristics.proposal_synthesizer import ProposalSynthesizer
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.proposal import AnomalyType

TRIAGE_DEFAULTS = dict(
    flow_id="flow-schema-test-001",
    canonical_endpoint="/api/data",
    endpoint_category=EndpointCategory.DATA_READ,
)


def _make_flow(body: str = "", content_type: str = "application/json", method: str = "POST", path: str = "/api/data") -> FlowRecord:
    return FlowRecord(
        id="flow-schema-test-001",
        timestamp_start=1000.0,
        timestamp_end=1001.0,
        duration_ms=100.0,
        client_ip="127.0.0.1",
        client_port=12345,
        server_host="127.0.0.1",
        server_port=3000,
        scheme="http",
        http_version="1.1",
        request=RequestModel(
            method=method,
            url=f"http://127.0.0.1:3000{path}",
            path=path,
            query_string="",
            query_params={},
            headers={"content-type": content_type},
            content_type=content_type,
            content_length=len(body),
            body=body,
            cookies={},
        ),
        response=ResponseModel(
            status_code=200,
            reason="OK",
            headers={},
            content_type=content_type,
            content_length=len(body),
            body=body,
            cookies={},
        ),
    )


class TestSchemaAwareMutations:
    def test_bool_to_int_confusion(self):
        body = json.dumps({"active": True, "name": "test"})
        flow = _make_flow(body=body)
        triage = TriageSummary(**TRIAGE_DEFAULTS, tags=["json_body"],
            parameters=[
                ExtractedParameter(name="active", location=ParameterLocation.BODY_JSON, value=True),
                ExtractedParameter(name="name", location=ParameterLocation.BODY_JSON, value="test"),
            ],
        )
        synth = ProposalSynthesizer()
        proposals = synth.synthesize(flow, triage)
        type_confusion = [p for p in proposals if "Bool→Int" in p.title]
        assert len(type_confusion) >= 1
        assert type_confusion[0].mutated_value is not None

    def test_int_to_string_overflow_confusion(self):
        body = json.dumps({"user_id": 42, "count": 100})
        flow = _make_flow(body=body)
        triage = TriageSummary(**TRIAGE_DEFAULTS, tags=["json_body"],
            parameters=[
                ExtractedParameter(name="user_id", location=ParameterLocation.BODY_JSON, value=42),
                ExtractedParameter(name="count", location=ParameterLocation.BODY_JSON, value=100),
            ],
        )
        synth = ProposalSynthesizer()
        proposals = synth.synthesize_schema(flow, triage)
        int_confusion = [p for p in proposals if "Int→" in p.title]
        assert len(int_confusion) >= 1

    def test_string_to_injection_confusion(self):
        body = json.dumps({"email": "user@example.com"})
        flow = _make_flow(body=body)
        triage = TriageSummary(**TRIAGE_DEFAULTS, tags=["json_body"],
            parameters=[
                ExtractedParameter(name="email", location=ParameterLocation.BODY_JSON, value="user@example.com"),
            ],
        )
        synth = ProposalSynthesizer()
        proposals = synth.synthesize(flow, triage)
        inj = [p for p in proposals if "String→" in p.title and p.target_param_name == "email"]
        tags = {t for p in inj for t in p.tags}
        assert "injection_sql" in tags
        assert "injection_path_traversal" in tags

    def test_query_param_type_confusion(self):
        flow = _make_flow(body="", content_type="text/html", method="GET", path="/api/items?id=123")
        flow.request.query_params = {"id": "123"}
        triage = TriageSummary(**TRIAGE_DEFAULTS, tags=[],
            parameters=[
                ExtractedParameter(name="id", location=ParameterLocation.QUERY, value="123"),
            ],
        )
        synth = ProposalSynthesizer()
        proposals = synth.synthesize(flow, triage)
        query_conf = [p for p in proposals if "Query Type Confusion" in p.title]
        assert len(query_conf) >= 1

    def test_no_new_proposals_for_non_json_body(self):
        flow = _make_flow(body="plain text body", content_type="text/plain", method="POST")
        triage = TriageSummary(**TRIAGE_DEFAULTS, tags=[],
            parameters=[],
        )
        synth = ProposalSynthesizer()
        proposals = synth.synthesize(flow, triage)
        # No schema-aware body mutations for non-JSON content
        schema_props = [p for p in proposals if p.anomaly_type == AnomalyType.JSON_SCHEMA]
        assert len(schema_props) == 0

    def test_existing_mass_assignment_still_works(self):
        body = json.dumps({"name": "test", "email": "test@test.com"})
        flow = _make_flow(body=body)
        triage = TriageSummary(**TRIAGE_DEFAULTS, tags=["json_body"],
            parameters=[
                ExtractedParameter(name="name", location=ParameterLocation.BODY_JSON, value="test"),
            ],
        )
        synth = ProposalSynthesizer()
        proposals = synth.synthesize(flow, triage)
        mass_assign = [p for p in proposals if "Mass Assignment" in p.title]
        assert len(mass_assign) >= 1

    def test_no_array_wrapping_below_3_params(self):
        body = json.dumps({"x": 1})
        flow = _make_flow(body=body)
        triage = TriageSummary(**TRIAGE_DEFAULTS, tags=["json_body"],
            parameters=[
                ExtractedParameter(name="x", location=ParameterLocation.BODY_JSON, value=1),
            ],
        )
        synth = ProposalSynthesizer()
        proposals = synth.synthesize(flow, triage)
        arr_wrap = [p for p in proposals if "Array Wrapping" in p.title]
        # Only 1 param, should still get array wrapping
        assert len(arr_wrap) == 1
