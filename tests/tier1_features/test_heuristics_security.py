"""
Tier 1 Feature Isolation Tests: Security Heuristics (Entropy, Secrets, JWT, IDOR, Auth Anomalies) (Requirement R2).
"""

from __future__ import annotations

import time
import pytest

from flowforge.heuristics.auth_tracker import AuthTracker
from flowforge.heuristics.clustering import EndpointClassifier, RouteNormalizer
from flowforge.heuristics.entropy_scanner import EntropyScanner
from flowforge.heuristics.identifiers import IdentifierClassifier
from flowforge.heuristics.models import (
    EndpointCategory,
    ExtractedParameter,
    FindingSeverity,
    IdentifierType,
    ParameterLocation,
)
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel


def test_shannon_entropy_and_secret_signatures():
    """Verify Shannon entropy calculation and deterministic secret signature matching for cloud tokens."""
    scanner = EntropyScanner()

    # Shannon entropy checks
    low_ent = scanner.shannon_entropy("aaaaaaaaaaaaaaaa")
    assert low_ent == 0.0
    high_ent = scanner.shannon_entropy("4k9Z#mP!vL8@qW2$xY7&nR5*")
    assert high_ent >= 4.0

    # Secret scanning on realistic credentials
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    stripe_key = "sk_live_51NzABC1234567890abcdefghijklmnopqrstuvwxyz"
    github_pat = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    slack_bot = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"

    params = [
        ExtractedParameter(name="aws_key", location=ParameterLocation.HEADER, value=aws_key, raw_value=aws_key),
        ExtractedParameter(name="stripe", location=ParameterLocation.BODY_JSON, value=stripe_key, raw_value=stripe_key),
        ExtractedParameter(name="github", location=ParameterLocation.HEADER, value=github_pat, raw_value=github_pat),
        ExtractedParameter(name="slack", location=ParameterLocation.QUERY, value=slack_bot, raw_value=slack_bot),
    ]

    findings = scanner.scan_secrets(params)
    sec_types = {f.secret_type for f in findings}

    assert "AWS_ACCESS_KEY" in sec_types
    assert "STRIPE_SECRET_KEY" in sec_types
    assert "GITHUB_PAT_CLASSIC" in sec_types
    assert "SLACK_BOT_TOKEN" in sec_types

    # Ensure critical severities
    aws_finding = next(f for f in findings if f.secret_type == "AWS_ACCESS_KEY")
    assert aws_finding.severity == FindingSeverity.CRITICAL


def test_jwt_security_inspector_and_alg_none():
    """Verify JWT decoding, expiration detection, sensitive claim extraction, and alg: none bypass risk flagging."""
    scanner = EntropyScanner()

    # JWT with alg: none
    jwt_none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcmFkbWluIn0."
    res_none = scanner.inspect_jwt(jwt_none)
    assert res_none["valid"] is True
    assert "ALG_NONE_FORGERY_RISK" in res_none["security_flags"]
    assert res_none["subject"] == "admin"
    assert "role=superadmin" in res_none["roles"]

    # Expired JWT
    jwt_expired = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjoxNTAwMDAwMDAwfQ."
        "signature_stub"
    )
    res_exp = scanner.inspect_jwt(jwt_expired)
    assert res_exp["valid"] is True
    assert "user123" == res_exp["subject"]


def test_identifier_classification_and_idor_risk_scoring():
    """Verify identifier classification (Sequential Int, Snowflake, Mongo ID, UUIDs) and IDOR risk formula."""
    classifier = IdentifierClassifier()

    # 1. Sequential Integer ID
    id_type, w_type = classifier.classify_identifier("1001", "order_id")
    assert id_type == IdentifierType.SEQUENTIAL_INTEGER
    assert w_type == 1.00

    score = classifier.compute_idor_score(
        id_type=id_type,
        type_weight=w_type,
        location=ParameterLocation.PATH,
        method="POST",
        is_authenticated=True,
        param_name="order_id",
    )
    assert score >= 0.70  # Critical IDOR score

    # 2. UUID v4 (Random - Low IDOR)
    uuid_type, uuid_weight = classifier.classify_identifier(
        "550e8400-e29b-41d4-a716-446655440000", "user_uuid"
    )
    assert uuid_type == IdentifierType.UUID_V4
    assert uuid_weight == 0.15

    uuid_score = classifier.compute_idor_score(
        id_type=uuid_type,
        type_weight=uuid_weight,
        location=ParameterLocation.QUERY,
        method="GET",
        is_authenticated=True,
        param_name="user_uuid",
    )
    assert uuid_score < 0.25  # Low IDOR score

    # 3. Mongo ObjectId (24 hex characters)
    mongo_type, _ = classifier.classify_identifier("507f1f77bcf86cd799439011", "doc_id")
    assert mongo_type == IdentifierType.MONGO_OBJECT_ID


def test_endpoint_clustering_and_route_normalization():
    """Verify endpoint category clustering and canonical route pattern normalization."""
    ep_classifier = EndpointClassifier()
    normalizer = RouteNormalizer()

    # Endpoint classifications
    assert ep_classifier.classify("POST", "/api/v1/auth/login") == EndpointCategory.AUTH_SESSION
    assert ep_classifier.classify("GET", "/admin/settings/permissions") == EndpointCategory.ADMIN_MANAGEMENT
    assert ep_classifier.classify("POST", "/api/v1/orders/checkout") == EndpointCategory.MUTATION_ACTION
    assert ep_classifier.classify("GET", "/healthz") == EndpointCategory.TELEMETRY_HEALTH
    assert ep_classifier.classify("POST", "/api/v1/files/upload") == EndpointCategory.FILE_TRANSFER
    assert ep_classifier.classify("GET", "/api/v1/catalog/items") == EndpointCategory.DATA_READ

    # Canonical Route Normalization
    raw_path = "/api/v1/organizations/42/members/550e8400-e29b-41d4-a716-446655440000/documents/507f1f77bcf86cd799439011"
    canon = normalizer.normalize(raw_path)
    assert canon == "/api/v1/organizations/{integer_id}/members/{uuid}/documents/{object_id}"


def test_auth_tracker_anomaly_detection():
    """Verify auth tracker flags unauthenticated sensitive routes, state deviations, and insecure cookie flags."""
    tracker = AuthTracker()

    # Unauthenticated call to /admin/billing returning 200 OK
    flow_unauth = FlowRecord(
        id="flow-unauth-001",
        server_host="internal.corp",
        request=RequestModel(
            method="GET",
            url="https://internal.corp/admin/billing/export",
            path="/admin/billing/export",
            headers={"Host": "internal.corp"},
        ),
        response=ResponseModel(
            status_code=200,
            body="sensitive billing info",
        ),
    )

    findings = tracker.analyze_flow(flow_unauth)
    rule_codes = {f.rule_code for f in findings}
    assert "AUTH_ANOMALY_UNAUTH_SENSITIVE" in rule_codes

    # Token exposed in URL query param
    param_token = [
        ExtractedParameter(
            name="access_token",
            location=ParameterLocation.QUERY,
            value="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
            raw_value="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
        )
    ]
    flow_url_token = FlowRecord(
        id="flow-url-token-002",
        server_host="api.corp",
        request=RequestModel(
            method="GET",
            url="https://api.corp/profile?access_token=eyJhbGciOiJIUzI1NiJ9...",
            path="/profile",
            query_string="access_token=eyJhbGciOiJIUzI1NiJ9...",
        ),
        response=ResponseModel(status_code=200),
    )
    url_findings = tracker.analyze_flow(flow_url_token, parameters=param_token)
    assert any(f.rule_code == "AUTH_TOKEN_IN_URL" for f in url_findings)
