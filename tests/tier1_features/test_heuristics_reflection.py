"""
Tier 1 Feature Isolation Tests: Input Reflection Detector & Context Classifier (Requirement R2).
"""

from __future__ import annotations

import base64
import pytest

from flowforge.heuristics.models import (
    EncodingStatus,
    ExtractedParameter,
    FindingSeverity,
    ParameterLocation,
    ReflectionContext,
)
from flowforge.heuristics.reflection import ReflectionDetector


def test_html_body_and_attribute_reflection_detection():
    """Verify reflection detection and context classification in HTML body and input attributes."""
    detector = ReflectionDetector()

    params = [
        ExtractedParameter(
            name="q",
            location=ParameterLocation.QUERY,
            value="ReflectedKeyword123",
            raw_value="ReflectedKeyword123",
        ),
        ExtractedParameter(
            name="theme",
            location=ParameterLocation.QUERY,
            value="dark_mode_attr",
            raw_value="dark_mode_attr",
        ),
    ]

    html_body = """
    <html>
        <body>
            <h1>Results for: <span>ReflectedKeyword123</span></h1>
            <input type="text" name="theme" value="dark_mode_attr" />
        </body>
    </html>
    """

    findings = detector.detect_reflections(params, html_body, response_content_type="text/html")
    assert len(findings) >= 2

    body_finding = next((f for f in findings if f.parameter_name == "q"), None)
    assert body_finding is not None
    assert body_finding.context == ReflectionContext.HTML_BODY_TEXT
    assert body_finding.start_offset > 0
    assert body_finding.matched_in == "body"

    attr_finding = next((f for f in findings if f.parameter_name == "theme"), None)
    assert attr_finding is not None
    assert attr_finding.context == ReflectionContext.HTML_ATTR_QUOTED


def test_script_tag_and_event_handler_critical_reflections():
    """Verify reflections landing inside <script> blocks and inline event handlers are classified as CRITICAL."""
    detector = ReflectionDetector()

    params = [
        ExtractedParameter(
            name="callback",
            location=ParameterLocation.QUERY,
            value="payload_in_js_var",
            raw_value="payload_in_js_var",
        ),
        ExtractedParameter(
            name="onclick_val",
            location=ParameterLocation.QUERY,
            value="alert_click_event",
            raw_value="alert_click_event",
        ),
    ]

    html_body = """
    <html>
        <body>
            <button onclick="handleClick('alert_click_event')">Click Me</button>
            <script>
                var userCallback = "payload_in_js_var";
            </script>
        </body>
    </html>
    """

    findings = detector.detect_reflections(params, html_body, response_content_type="text/html")

    js_finding = next((f for f in findings if f.parameter_name == "callback"), None)
    assert js_finding is not None
    assert js_finding.context == ReflectionContext.HTML_SCRIPT_BLOCK
    assert js_finding.severity == FindingSeverity.CRITICAL

    event_finding = next((f for f in findings if f.parameter_name == "onclick_val"), None)
    assert event_finding is not None
    assert event_finding.context == ReflectionContext.HTML_ATTR_EVENT
    assert event_finding.severity == FindingSeverity.CRITICAL


def test_response_header_reflection_detection():
    """Verify reflection detection when request parameters land in response headers (e.g. Location redirect)."""
    detector = ReflectionDetector()

    params = [
        ExtractedParameter(
            name="redirect_url",
            location=ParameterLocation.QUERY,
            value="https://auth.company.com/oauth/callback",
            raw_value="https://auth.company.com/oauth/callback",
        )
    ]

    headers = {
        "Content-Type": "text/html",
        "Location": "https://auth.company.com/oauth/callback?client_id=123",
    }

    findings = detector.detect_reflections(params, response_body="", response_headers=headers)
    assert len(findings) == 1
    assert findings[0].matched_in == "Location"
    assert findings[0].context == ReflectionContext.RESPONSE_HEADER
    assert findings[0].severity == FindingSeverity.MEDIUM


def test_multi_pass_transformations_url_and_base64():
    """Verify multi-pass reflection matching for URL-decoded and Base64-encoded transformations."""
    detector = ReflectionDetector()

    # Case 1: Request param was URL-encoded `%3Cimg%20src=x%3E`, response has raw `<img src=x>`
    raw_payload = "<img src=x>"
    params = [
        ExtractedParameter(
            name="avatar",
            location=ParameterLocation.QUERY,
            value="%3Cimg%20src=x%3E",
            raw_value="%3Cimg%20src=x%3E",
        )
    ]

    html_body = "<div>User Avatar: <img src=x></div>"
    findings = detector.detect_reflections(params, html_body, response_content_type="text/html")
    assert len(findings) >= 1
    assert findings[0].reflected_value == raw_payload

    # Case 2: Request param was plaintext string, response contains Base64 of it
    secret_text = "SensitiveToken12345"
    b64_val = base64.b64encode(secret_text.encode("utf-8")).decode("utf-8")
    param_b64 = [
        ExtractedParameter(
            name="token",
            location=ParameterLocation.BODY_JSON,
            value=secret_text,
            raw_value=secret_text,
        )
    ]
    json_resp = f'{{"encrypted_session": "{b64_val}"}}'
    findings_b64 = detector.detect_reflections(param_b64, json_resp, response_content_type="application/json")
    assert len(findings_b64) >= 1
    assert findings_b64[0].reflected_value == b64_val
    assert findings_b64[0].encoding_status == EncodingStatus.BASE64_ENCODED


def test_false_positive_suppression():
    """Verify stopwords, boolean literals, nulls, and short trivial numbers are suppressed to prevent noise."""
    detector = ReflectionDetector()

    noisy_params = [
        ExtractedParameter(name="page", location=ParameterLocation.QUERY, value="1", raw_value="1"),
        ExtractedParameter(name="status", location=ParameterLocation.QUERY, value="true", raw_value="true"),
        ExtractedParameter(name="order", location=ParameterLocation.QUERY, value="order", raw_value="order"),
        ExtractedParameter(name="null_val", location=ParameterLocation.QUERY, value="null", raw_value="null"),
    ]

    body = "<div>Order Status: True, Page 1 of 10, order list</div>"
    findings = detector.detect_reflections(noisy_params, body, response_content_type="text/html")
    assert len(findings) == 0
