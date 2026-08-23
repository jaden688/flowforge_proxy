"""
Tier 2 Boundary Tests: Adversarial JWT Payloads (alg: none, jku SSRF, kid Path Traversal, Expiry).
"""

from __future__ import annotations

import base64
import json
import pytest

from flowforge.heuristics.auth_tracker import AuthTracker
from flowforge.heuristics.entropy_scanner import EntropyScanner
from flowforge.heuristics.models import FindingSeverity
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel


def _forge_jwt(header: dict, payload: dict, signature: str = "") -> str:
    """Helper to assemble raw JWT string."""
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).decode("utf-8").rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    return f"{h_b64}.{p_b64}.{signature}"


def test_jwt_alg_none_variants():
    """Verify detection of various casing of alg: none / None / NONE with empty signature."""
    scanner = EntropyScanner()

    for alg_val in ["none", "None", "NONE", "nOnE"]:
        jwt_token = _forge_jwt({"alg": alg_val, "typ": "JWT"}, {"sub": "admin_user", "role": "root"}, "")
        res = scanner.inspect_jwt(jwt_token)
        assert res["valid"] is True
        assert "ALG_NONE_FORGERY_RISK" in res["security_flags"]
        assert res["subject"] == "admin_user"


def test_jwt_jku_ssrf_and_kid_traversal_detection():
    """Verify flagging of jku SSRF URLs and directory traversal in kid headers."""
    scanner = EntropyScanner()

    # jku SSRF payload
    jwt_jku = _forge_jwt(
        {"alg": "RS256", "jku": "http://attacker-controlled.com/keys.json", "kid": "key1"},
        {"sub": "victim_user"},
        "fake_sig",
    )
    res_jku = scanner.inspect_jwt(jwt_jku)
    assert "JKU_HEADER_INJECTION_RISK" in res_jku["security_flags"]

    # kid Path Traversal
    jwt_kid = _forge_jwt(
        {"alg": "HS256", "kid": "../../../../../dev/null"},
        {"sub": "victim_user"},
        "fake_sig",
    )
    res_kid = scanner.inspect_jwt(jwt_kid)
    assert "KID_INJECTION_RISK" in res_kid["security_flags"]


def test_auth_tracker_expired_jwt_anomaly():
    """Verify AuthTracker flags accepted requests using expired JWTs."""
    tracker = AuthTracker()

    past_epoch = 1600000000  # Year 2020
    jwt_expired = _forge_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "legacy_user", "exp": past_epoch},
        "valid_looking_signature",
    )

    flow = FlowRecord(
        id="flow-jwt-exp-001",
        server_host="auth.target.com",
        request=RequestModel(
            method="GET",
            url="https://auth.target.com/api/v1/protected/data",
            path="/api/v1/protected/data",
            headers={"Authorization": f"Bearer {jwt_expired}"},
        ),
        response=ResponseModel(
            status_code=200,
            body='{"data": "sensitive_profile"}',
        ),
    )

    findings = tracker.analyze_flow(flow)
    assert any(f.rule_code == "AUTH_JWT_EXPIRED" for f in findings)
