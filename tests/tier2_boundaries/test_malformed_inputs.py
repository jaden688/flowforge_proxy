"""
Tier 2 Boundary Tests: Malformed Payloads, Broken Syntaxes, and Encoding Edge Cases.
"""

from __future__ import annotations

import base64
import pytest

from flowforge.heuristics.parameters import ParameterExtractor
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.heuristics.schema_inferrer import SchemaInferrer
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel


def test_malformed_json_fallback():
    """Verify ParameterExtractor and SchemaInferrer gracefully handle truncated or invalid JSON."""
    extractor = ParameterExtractor()
    inferrer = SchemaInferrer()

    broken_json = '{"user": {"id": 101, "name": "Alice", "tags": ['

    # ParameterExtractor should not raise exception
    params = extractor.extract_body_params(broken_json, "application/json")
    assert isinstance(params, list)

    # SchemaInferrer should fallback to string schema
    schema = inferrer.infer_payload_schema(broken_json)
    assert schema["type"] == "string"


def test_broken_xml_resilience():
    """Verify XML extractor falls back to regex matching on broken or unclosed XML elements."""
    extractor = ParameterExtractor()

    broken_xml = '<soap:Envelope><soap:Body><user id="1099"><name>Incomplete'
    params = extractor.extract_xml_params(broken_xml)

    assert isinstance(params, list)
    # Should safely extract matched fragments or return empty without crashing
    assert not any(p.value is None for p in params)


def test_null_byte_and_binary_strings_in_parameters():
    """Verify parameters containing embedded null bytes or raw non-printable bytes do not crash triage."""
    extractor = ParameterExtractor()

    # URL-encoded null byte
    form_with_null = "filename=avatar.png%00.php&status=active%00hidden"
    params = extractor.extract_form_params(form_with_null)

    p_map = {p.name: p for p in params}
    assert "filename" in p_map
    assert "\x00" in str(p_map["filename"].value) or "%00" in str(p_map["filename"].raw_value)


async def test_pipeline_non_utf8_binary_payload():
    """Verify TriagePipeline processes flows containing arbitrary non-UTF-8 binary bytes without crash."""
    pipeline = TriagePipeline()

    raw_bad_bytes = b"\x80\x81\xff\xfe\x00\x01\xaa\xbb\xcc\xdd\xee"
    b64_str = base64.b64encode(raw_bad_bytes).decode("utf-8")

    flow = FlowRecord(
        id="flow-bad-bytes-001",
        server_host="binary.target.com",
        request=RequestModel(
            method="POST",
            url="https://binary.target.com/upload",
            path="/upload",
            content_type="application/octet-stream",
            body=b64_str,
            body_is_binary=True,
        ),
        response=ResponseModel(
            status_code=200,
            content_type="application/octet-stream",
            body=b64_str,
            body_is_binary=True,
        ),
    )

    triage = await pipeline.process_flow(flow)
    assert triage is not None
    assert triage.flow_id == "flow-bad-bytes-001"
