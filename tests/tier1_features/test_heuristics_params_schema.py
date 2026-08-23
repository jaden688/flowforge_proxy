"""
Tier 1 Feature Isolation Tests: Multi-Source Parameter Extraction & Schema Inference (Requirement R2).
"""

from __future__ import annotations

import json
import pytest

from flowforge.heuristics.models import ParameterLocation
from flowforge.heuristics.parameters import ParameterExtractor
from flowforge.heuristics.schema_inferrer import SchemaInferrer


def test_query_and_path_parameter_extraction():
    """Verify extraction of query strings (arrays, bracket notation, nested keys) and dynamic path slugs."""
    extractor = ParameterExtractor()

    # Query strings
    qs = "filter[status]=active&filter[user][id]=101&tags[]=xss&tags[]=idor&page=1"
    query_params = extractor.extract_query_params(qs)

    param_map = {p.name: p for p in query_params}
    assert "filter.status" in param_map
    assert param_map["filter.status"].value == "active"
    assert "filter.user.id" in param_map
    assert param_map["filter.user.id"].inferred_type == "integer"
    assert "tags" in param_map
    assert param_map["tags"].is_array is True
    assert param_map["tags"].value == ["xss", "idor"]

    # Dynamic path slugs
    path = "/api/v1/organizations/42/members/550e8400-e29b-41d4-a716-446655440000/roles"
    path_params = extractor.extract_path_params(path)

    path_map = {p.name: p for p in path_params}
    assert "organizations_id" in path_map or "organizations" in path_map
    assert any(p.value == 42 and p.inferred_type == "integer" for p in path_params)
    assert any(p.inferred_format == "uuid" for p in path_params)


def test_json_and_form_body_parameter_flattening():
    """Verify recursive depth-first flattening of nested JSON objects and arrays, and form-urlencoded bodies."""
    extractor = ParameterExtractor()

    # Nested JSON
    json_data = {
        "user": {
            "name": "Alice",
            "profile": {
                "age": 30,
                "emails": ["alice@example.com", "admin@company.com"],
            },
        },
        "is_admin": False,
    }
    json_params = extractor.flatten_json(json_data, location=ParameterLocation.BODY_JSON)
    j_map = {p.name: p for p in json_params}

    assert "user.name" in j_map and j_map["user.name"].value == "Alice"
    assert "user.profile.age" in j_map and j_map["user.profile.age"].inferred_type == "integer"
    assert "user.profile.emails[0]" in j_map and j_map["user.profile.emails[0]"].inferred_format == "email"
    assert "is_admin" in j_map and j_map["is_admin"].inferred_type == "boolean"

    # Form URL-encoded
    form_str = "user[name]=Bob&user[email]=bob@target.com&role=admin"
    form_params = extractor.extract_form_params(form_str)
    f_map = {p.name: p for p in form_params}
    assert "user.name" in f_map
    assert f_map["user.name"].value == "Bob"
    assert "role" in f_map


def test_multipart_and_xml_parameter_extraction():
    """Verify multipart form boundary parsing, file metadata extraction, and XML tag/attribute parsing."""
    extractor = ParameterExtractor()

    # Multipart form-data
    boundary = "---------------------------974767299852498929531610575"
    content_type = f"multipart/form-data; boundary={boundary}"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="username"\r\n\r\n'
        "charlie\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="avatar"; filename="photo.png"\r\n'
        "Content-Type: image/png\r\n\r\n"
        "\x89PNG\r\n\x1a\nFakePngData\r\n"
        f"--{boundary}--\r\n"
    )
    mp_params = extractor.extract_multipart_params(body, content_type)
    mp_map = {p.name: p for p in mp_params}

    assert "username" in mp_map and mp_map["username"].value == "charlie"
    assert "avatar" in mp_map
    assert mp_map["avatar"].inferred_type == "file"
    assert mp_map["avatar"].value["filename"] == "photo.png"

    # XML / SOAP
    xml_data = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Body>
            <getUser id="1042" role="admin">
                <email>user@xmltest.com</email>
            </getUser>
        </soapenv:Body>
    </soapenv:Envelope>"""
    xml_params = extractor.extract_xml_params(xml_data)
    assert any("id" in p.name and p.value == "1042" for p in xml_params)
    assert any("email" in p.name and "user@xmltest.com" in str(p.value) for p in xml_params)


def test_dynamic_json_schema_inference():
    """Verify SchemaInferrer correctly identifies primitive types, nested objects, arrays, and string formats."""
    inferrer = SchemaInferrer()

    payload = {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "email": "test@example.com",
        "created_at": "2026-08-22T05:00:00Z",
        "count": 42,
        "score": 98.6,
        "active": True,
        "tags": ["sec", "audit"],
        "metadata": {"source": "proxy"},
    }

    schema = inferrer.infer_payload_schema(payload)

    assert schema["type"] == "object"
    props = schema["properties"]
    assert props["id"]["type"] == "string"
    assert props["id"]["format"] == "uuid"
    assert props["email"]["format"] == "email"
    assert props["created_at"]["format"] == "date-time"
    assert props["count"]["type"] == "integer"
    assert props["score"]["type"] == "number"
    assert props["active"]["type"] == "boolean"
    assert props["tags"]["type"] == "array"
    assert props["tags"]["items"]["type"] == "string"
    assert props["metadata"]["type"] == "object"


def test_multi_flow_schema_synthesis_and_enums():
    """Verify multi-flow schema merger detects common required fields, type unions, and enum candidates."""
    inferrer = SchemaInferrer()

    # Observation 1
    s1 = inferrer.infer_payload_schema({"status": "active", "code": 100, "extra": "foo"})
    # Observation 2
    s2 = inferrer.infer_payload_schema({"status": "pending", "code": 200})
    # Observation 3
    s3 = inferrer.infer_payload_schema({"status": "active", "code": "300"})

    merged = inferrer.synthesize_endpoint_schema([s1, s2, s3])

    assert merged["type"] == "object"
    props = merged["properties"]
    # "status" and "code" were in all three -> required
    assert "status" in merged["required"]
    assert "code" in merged["required"]
    # "extra" was only in s1 -> not required
    assert "extra" not in merged.get("required", [])
    # "code" was integer in s1, s2 and string in s3 -> unified union type
    assert "integer" in props["code"]["type"] or "string" in props["code"]["type"]
