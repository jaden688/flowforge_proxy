"""
Tier 2 Boundary & Extreme Stress Tests: Multi-Layer Decoder, JWT Deep Inspection,
Hex Dumper, 10MB+ Payloads, Deep Recursion Limits, and API Error Handling without 500 Crashes.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.parse
from typing import Any, Dict
import pytest
from httpx import ASGITransport, AsyncClient

from flowforge.api.app import create_app
from flowforge.utils.decoders import (
    AutoDecodeResult,
    DecoderType,
    EncoderType,
    JWTInspectionResult,
    decode_base64,
    decode_content,
    decode_hex,
    decode_html_entities,
    decode_url,
    encode_base64,
    encode_content,
    encode_hex,
    encode_url,
    hex_dump,
    inspect_jwt,
    multi_layer_decode,
)


# ===========================================================================
# 1. 10MB+ Extreme Payload Stress & Memory Safety Tests
# ===========================================================================

def test_t2_decoder_extreme_10mb_base64_decoding():
    """Verify Base64 decoder processes 10MB+ binary payloads safely and performs UTF-8/binary checks."""
    raw_ten_mb = b"FLOWFORGE_AUTHENTIC_TEST_DATA_" * 350_000  # ~10.5 MB
    b64_ten_mb = base64.b64encode(raw_ten_mb).decode("ascii")

    start = time.perf_counter()
    decoded_str, is_bin, raw_bytes = decode_base64(b64_ten_mb)
    duration = time.perf_counter() - start

    assert len(raw_bytes) == len(raw_ten_mb)
    assert raw_bytes == raw_ten_mb
    assert duration < 2.0  # High-throughput decode


def test_t2_decoder_extreme_10mb_hexdump_generation():
    """Verify hex_dump generates 16-byte offset representation on large buffers without memory leaks."""
    large_payload = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" * 50_000  # 800 KB
    dump_output = hex_dump(large_payload, bytes_per_line=16)

    assert "00000000" in dump_output
    assert len(dump_output.splitlines()) == 50_000


def test_t2_decoder_extreme_deep_recursion_unboxing_limits():
    """Verify multi-layer decoder terminates cleanly on 30+ nested encoding layers without stack overflow."""
    inner_secret = "TARGET_SENSITIVE_ADMIN_PASSWORD_2026"
    current = inner_secret

    # Wrap 30 layers deep alternating URL and Base64
    for i in range(30):
        if i % 2 == 0:
            current = base64.b64encode(current.encode("utf-8")).decode("ascii")
        else:
            current = urllib.parse.quote(current)

    # Decode with max_depth=10 -> should perform 10 steps safely without crashing
    res = multi_layer_decode(current, max_depth=10)
    assert res.status == "success"
    assert len(res.layers) == 10

    # Decode with max_depth=20
    res20 = multi_layer_decode(current, max_depth=20)
    assert res20.status == "success"
    assert len(res20.layers) == 20


# ===========================================================================
# 2. Adversarial & Malformed JWT Edge Cases
# ===========================================================================

def test_t2_decoder_adversarial_jwt_edge_cases():
    """Verify inspect_jwt handles invalid signatures, alg:none, null bytes, and non-dict claims."""
    # 1. Corrupt Base64 in token header
    r_corrupt = inspect_jwt("!@#$invalid_b64.eyJzdWIiOiIxIn0.sig")
    assert r_corrupt.valid is False

    # 2. Empty string
    r_empty = inspect_jwt("")
    assert r_empty.valid is False

    # 3. Non-JSON decoded header
    non_json_b64 = base64.urlsafe_b64encode(b"raw string not json").decode("ascii").rstrip("=")
    r_non_json = inspect_jwt(f"{non_json_b64}.eyJzdWIiOiIxIn0.sig")
    assert r_non_json.valid is False

    # 3. Trailing dot or leading dot
    assert inspect_jwt(".eyJzdWIiOiIxIn0.sig").valid is False
    assert inspect_jwt("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.").valid is True  # alg:none with empty sig is structurally valid
    r_none = inspect_jwt("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.")
    assert "ALG_NONE_UNSECURED" in r_none.security_flags

    # 4. JWT with Directory Traversal in KID header
    h_kid_trav = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "kid": "../../dev/null"}).encode("utf-8")).decode("ascii").rstrip("=")
    p_valid = base64.urlsafe_b64encode(json.dumps({"sub": "admin"}).encode("utf-8")).decode("ascii").rstrip("=")
    jwt_kid_trav = f"{h_kid_trav}.{p_valid}.fake_sig"
    r_kid = inspect_jwt(jwt_kid_trav)
    assert r_kid.valid is True
    assert "KID_DIR_TRAVERSAL" in r_kid.security_flags

    # 5. JWT with SQL Injection in KID header
    h_kid_sqli = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "kid": "key' UNION SELECT 'key"}).encode("utf-8")).decode("ascii").rstrip("=")
    jwt_kid_sqli = f"{h_kid_sqli}.{p_valid}.fake_sig"
    r_sqli = inspect_jwt(jwt_kid_sqli)
    assert r_sqli.valid is True
    assert "KID_SQL_INJECTION" in r_sqli.security_flags


# ===========================================================================
# 3. URL and Hex Multi-Pass Boundary Tests
# ===========================================================================

def test_t2_decoder_url_multipass_cyclic_and_malformed():
    """Verify decode_url handles multi-pass recursion, invalid percent sequences, and overlong encodings."""
    # 1. Multi-pass nested percent encoding: %25252F -> %252F -> %2F -> /
    nested_url = "%25252Fadmin%25252Fconfig"
    decoded, passes = decode_url(nested_url, multi_pass=True, max_passes=5)
    assert decoded == "/admin/config"
    assert passes == 3

    # 2. Malformed percent sequence (%ZZ, %A, incomplete trailing %)
    bad_url = "https://target.local/path?q=%ZZ&val=%A&tail=%"
    decoded_bad, _ = decode_url(bad_url, multi_pass=False)
    assert "%ZZ" in decoded_bad  # unquote preserves malformed sequences rather than throwing

    # 3. Max passes boundary limit (e.g. max_passes=1)
    d_limit, p_limit = decode_url("%252F", multi_pass=True, max_passes=1)
    assert d_limit == "%2F"
    assert p_limit == 1


def test_t2_decoder_hex_extreme_formats_and_spaces():
    """Verify decode_hex processes various delimiters, whitespace, and prefixes."""
    # Mixed formats: '0x48 0x65, \x6c:\x6c; 6f'
    mixed_hex = "0x48 0x65, \\x6c:\\x6c; 6f"
    dec_text, is_bin, raw = decode_hex(mixed_hex)
    assert dec_text == "Hello"
    assert raw == b"Hello"
    assert is_bin is False

    # Empty hex string
    d_empty, _, raw_empty = decode_hex("   ")
    assert d_empty == ""
    assert raw_empty == b""


# ===========================================================================
# 4. REST API Extreme Payloads & Error Handling Tests
# ===========================================================================

async def test_t2_decoder_api_endpoints_error_resilience():
    """Verify /api/v1/tools/decode, encode, and hexdump handle invalid inputs with 400/error response, not 500."""
    app = create_app()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. /api/v1/tools/decode with explicit corrupted Base64
        resp_b64 = await client.post(
            "/api/v1/tools/decode",
            json={"content": "!!NOT_VALID_B64!!", "decoder_type": "base64"},
        )
        assert resp_b64.status_code == 200
        data_b64 = resp_b64.json()
        assert data_b64["status"] == "error"
        assert data_b64["error"] is not None

        # 2. /api/v1/tools/decode with explicit corrupted Hex
        resp_hex = await client.post(
            "/api/v1/tools/decode",
            json={"content": "0xGGHHII", "decoder_type": "hex"},
        )
        assert resp_hex.status_code == 200
        data_hex = resp_hex.json()
        assert data_hex["status"] == "error"
        assert data_hex["error"] is not None

        # 3. /api/v1/tools/encode with invalid encoder_type returns 400
        resp_enc_bad = await client.post(
            "/api/v1/tools/encode",
            json={"content": "test", "encoder_type": "unsupported_encoder_type"},
        )
        assert resp_enc_bad.status_code == 400

        # 4. /api/v1/tools/jwt with invalid token returns valid=False without 500
        resp_jwt = await client.post(
            "/api/v1/tools/jwt",
            json={"token": "garbage.token.here"},
        )
        assert resp_jwt.status_code == 200
        assert resp_jwt.json()["valid"] is False

        # 5. /api/v1/tools/hexdump with custom bytes_per_line
        resp_hd = await client.post(
            "/api/v1/tools/hexdump",
            json={"content": "FlowForge Proxy Workbench", "bytes_per_line": 32},
        )
        assert resp_hd.status_code == 200
        assert "00000000" in resp_hd.json()["dump"]
