"""
Tier 1 Feature Tests: Decoders, Encoders, Hex Dumper, JWT Claims Inspector,
Multi-Layer Auto-Decoder Pipeline, and Tools REST API (Features F01–F07).
"""

from __future__ import annotations

import base64
import datetime
import html
import json
import time
import urllib.parse
import pytest
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.config import Settings
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
    encode_html_entities,
    encode_url,
    hex_dump,
    inspect_jwt,
    multi_layer_decode,
)


# ===========================================================================
# F01: Base64 Multi-Format Decoder & Encoder Tests
# ===========================================================================

def test_f01_base64_standard_rfc4648_decoding():
    """Verify standard Base64 encoding and decoding with UTF-8 printable output."""
    raw_text = "FlowForge Security Testing Workbench"
    encoded = base64.b64encode(raw_text.encode("utf-8")).decode("ascii")

    decoded_text, is_binary, raw_bytes = decode_base64(encoded, url_safe=False)
    assert decoded_text == raw_text
    assert is_binary is False
    assert raw_bytes == raw_text.encode("utf-8")


def test_f01_base64_url_safe_and_padding_auto_repair():
    """Verify URL-safe Base64 with '-' and '_' characters and stripped '=' padding."""
    raw_text = "Security>>>???Payloads"
    # urlsafe encode without padding
    url_b64 = base64.urlsafe_b64encode(raw_text.encode("utf-8")).decode("ascii").rstrip("=")

    decoded_text, is_binary, _ = decode_base64(url_b64, url_safe=True)
    assert decoded_text == raw_text
    assert is_binary is False


def test_f01_base64_binary_content_detection():
    """Verify binary byte payload detection when decoding Base64."""
    binary_bytes = bytes([0x00, 0xFF, 0xFE, 0x01, 0x02, 0x03, 0x7F, 0x80])
    b64_str = base64.b64encode(binary_bytes).decode("ascii")

    decoded_text, is_binary, raw_bytes = decode_base64(b64_str)
    assert is_binary is True
    assert raw_bytes == binary_bytes


def test_f01_base64_encoder_variants():
    """Verify standard and URL-safe Base64 encoding output."""
    data = "admin:secret+/=?key"
    std_encoded = encode_base64(data, url_safe=False)
    url_encoded = encode_base64(data, url_safe=True)

    assert "+" in std_encoded or "/" in std_encoded or "=" in std_encoded
    assert "+" not in url_encoded
    assert "/" not in url_encoded
    # Verify both decode back cleanly
    assert decode_base64(std_encoded)[0] == data
    assert decode_base64(url_encoded, url_safe=True)[0] == data


def test_f01_base64_empty_and_whitespace_handling():
    """Verify empty string and whitespace handling in Base64 decoders."""
    assert decode_base64("")[0] == ""
    assert decode_base64("   \n\t  ")[0] == ""
    assert encode_base64("") == ""


# ===========================================================================
# F02: URL Multi-Pass Percent Decoder & Encoder Tests
# ===========================================================================

def test_f02_url_single_pass_decoding():
    """Verify standard single-pass percent decoding preserving UTF-8."""
    raw = "user=admin&redirect=/dashboard?id=123"
    encoded = urllib.parse.quote(raw)

    decoded, passes = decode_url(encoded, multi_pass=False)
    assert decoded == raw
    assert passes == 1


def test_f02_url_multi_pass_recursive_decoding():
    """Verify multi-pass recursive decoding for double/triple encoded inputs."""
    target = "../../../../etc/passwd"
    # Double URL encode
    pass1 = urllib.parse.quote(target, safe="")
    pass2 = urllib.parse.quote(pass1, safe="")
    pass3 = urllib.parse.quote(pass2, safe="")

    # Decode with multi_pass=True
    decoded, passes = decode_url(pass3, multi_pass=True, max_passes=5)
    assert decoded == target
    assert passes == 3


def test_f02_url_encoding_safe_characters():
    """Verify URL encoding preserves and encodes special characters correctly."""
    special = "hello world / ? & = #"
    encoded = encode_url(special, safe="")
    assert " " not in encoded
    assert "%20" in encoded
    assert "%2F" in encoded
    assert "%3F" in encoded

    decoded, _ = decode_url(encoded, multi_pass=False)
    assert decoded == special


def test_f02_url_unicode_multibyte_decoding():
    """Verify percent decoding handles multi-byte UTF-8 sequences (emojis, CJK)."""
    raw = "🔥 FlowForge 漏洞 測試"
    encoded = urllib.parse.quote(raw)

    decoded, passes = decode_url(encoded, multi_pass=False)
    assert decoded == raw
    assert passes == 1


def test_f02_url_noop_on_plain_text():
    """Verify plain unencoded string passes through with 1 pass."""
    plain = "plain_string_without_percent"
    decoded, passes = decode_url(plain, multi_pass=True)
    assert decoded == plain
    assert passes == 1


# ===========================================================================
# F03: Hex Decoder, Encoder & 16-Byte Offset Dumper Tests
# ===========================================================================

def test_f03_hex_decode_contiguous_and_spaced():
    """Verify hex decoding for contiguous, spaced, and \\x prefixed formats."""
    raw = "AdminAuth"
    contiguous_hex = raw.encode("utf-8").hex()  # "41646d696e41757468"
    spaced_hex = "41 64 6d 69 6e 41 75 74 68"
    prefixed_hex = "\\x41\\x64\\x6d\\x69\\x6e\\x41\\x75\\x74\\x68"
    ox_colon_hex = "0x41:0x64:0x6d:0x69:0x6e:0x41:0x75:0x74:0x68"

    assert decode_hex(contiguous_hex)[0] == raw
    assert decode_hex(spaced_hex)[0] == raw
    assert decode_hex(prefixed_hex)[0] == raw
    assert decode_hex(ox_colon_hex)[0] == raw


def test_f03_hex_encode_with_separators():
    """Verify hex encoding with customizable separators."""
    data = "TEST"
    assert encode_hex(data, separator="") == "54455354"
    assert encode_hex(data, separator=" ") == "54 45 53 54"
    assert encode_hex(data, separator=":") == "54:45:53:54"


def test_f03_hex_dump_16_byte_offset_format():
    """Verify 16-byte offset hex dump generation with offset, hex columns, and ASCII representation."""
    data = b"Hello FlowForge Proxy Operator! Testing hex dumper 1234567890"
    dump = hex_dump(data, bytes_per_line=16)

    lines = dump.split("\n")
    assert len(lines) >= 4
    # First line offset 00000000
    assert lines[0].startswith("00000000  ")
    assert "48 65 6c 6c 6f 20 46 6c" in lines[0]  # "Hello Fl"
    assert "|Hello FlowForge |" in lines[0]
    # Second line offset 00000010
    assert lines[1].startswith("00000010  ")
    assert "|Proxy Operator! |" in lines[1]


def test_f03_hex_dump_binary_unprintable_characters():
    """Verify unprintable binary bytes are rendered as '.' in the ASCII column."""
    binary_data = bytes([0x00, 0x01, 0x02, 0x41, 0x42, 0x1F, 0x7F, 0xFF])
    dump = hex_dump(binary_data, bytes_per_line=16)

    assert "...AB..." in dump


def test_f03_hex_decode_empty():
    """Verify empty string returns empty result."""
    assert decode_hex("")[0] == ""
    assert hex_dump(b"").startswith("00000000")


# ===========================================================================
# F04: HTML Entity Decoder & Encoder Tests
# ===========================================================================

def test_f04_html_entities_named_decimal_hex_decoding():
    """Verify decoding of named, decimal, and hexadecimal HTML entities."""
    test_input = "&lt;script&gt;alert(&quot;xss&#34; &#x27;test&#x27;)&amp;&lt;/script&gt;"
    expected = "<script>alert(\"xss\" 'test')&</script>"

    decoded = decode_html_entities(test_input)
    assert decoded == expected


def test_f04_html_entities_encoding():
    """Verify escaping of HTML special characters to HTML entities."""
    raw = "<div class=\"admin\" id='root'>&test</div>"
    encoded = encode_html_entities(raw)

    assert "<" not in encoded
    assert ">" not in encoded
    assert "&lt;div" in encoded
    assert "&quot;" in encoded or "&#x22;" in encoded
    assert decode_html_entities(encoded) == raw


def test_f04_html_entities_mixed_text():
    """Verify HTML entities decode correctly within surrounding text."""
    mixed = "Price: &pound;100 &euro;50 &amp; &copy; 2026 FlowForge"
    decoded = decode_html_entities(mixed)
    assert "£100" in decoded
    assert "€50" in decoded
    assert "&" in decoded
    assert "© 2026 FlowForge" in decoded


# ===========================================================================
# F05: Deep JWT Claim Inspector Tests
# ===========================================================================

def _generate_test_jwt(header: dict, payload: dict, signature: str = "ref_sig") -> str:
    """Helper to synthesize test JWT string."""
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h_b64}.{p_b64}.{signature}"


def test_f05_jwt_inspector_valid_claims_and_expiration():
    """Verify JWT inspection extracts header, claims, expiration countdown, and roles."""
    now = time.time()
    future_exp = now + 3600  # expires in 1 hour
    iat = now - 60

    header = {"alg": "RS256", "typ": "JWT", "kid": "key-2026-auth"}
    payload = {
        "sub": "user_42",
        "iss": "https://auth.flowforge.dev",
        "aud": ["api.flowforge.dev", "console.flowforge.dev"],
        "exp": future_exp,
        "iat": iat,
        "role": "security_admin",
        "org_id": "tenant_99",
        "permissions": ["flows:read", "matrix:execute"],
    }
    jwt_str = _generate_test_jwt(header, payload)

    result = inspect_jwt(jwt_str)
    assert result.valid is True
    assert result.algorithm == "RS256"
    assert result.subject == "user_42"
    assert result.issuer == "https://auth.flowforge.dev"
    assert result.is_expired is False
    assert result.expires_in_seconds is not None and result.expires_in_seconds > 0
    assert result.expires_at_iso is not None
    assert "role:security_admin" in result.roles
    assert "permissions:flows:read" in result.roles
    assert result.custom_claims.get("org_id") == "tenant_99"


def test_f05_jwt_inspector_expired_token_warning():
    """Verify expired JWTs trigger TOKEN_EXPIRED flag and calculate expired_ago_seconds."""
    now = time.time()
    past_exp = now - 7200  # expired 2 hours ago

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "victim_user", "exp": past_exp}
    jwt_str = _generate_test_jwt(header, payload)

    result = inspect_jwt(jwt_str)
    assert result.valid is True
    assert result.is_expired is True
    assert result.expired_ago_seconds is not None and result.expired_ago_seconds >= 7000
    assert "TOKEN_EXPIRED" in result.security_flags
    assert "SYMMETRIC_HMAC_ALGORITHM" in result.security_flags


def test_f05_jwt_inspector_alg_none_and_kid_traversal_flags():
    """Verify security warning flags for alg:none, missing signatures, and kid directory traversal."""
    header = {"alg": "none", "typ": "JWT", "kid": "../../etc/shadow"}
    payload = {"sub": "root", "admin": True}
    jwt_str = _generate_test_jwt(header, payload, signature="")

    result = inspect_jwt(jwt_str)
    assert result.valid is True
    assert "ALG_NONE_UNSECURED" in result.security_flags
    assert "KID_DIR_TRAVERSAL" in result.security_flags
    assert "MISSING_EXPIRATION" in result.security_flags
    assert "admin:True" in result.roles or "admin:true" in result.roles


def test_f05_jwt_inspector_bearer_prefix_stripping():
    """Verify Authorization 'Bearer <token>' prefix is automatically handled."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "bearer_test", "role": "operator"}
    raw_jwt = _generate_test_jwt(header, payload)
    bearer_token = f"Bearer {raw_jwt}"

    result = inspect_jwt(bearer_token)
    assert result.valid is True
    assert result.subject == "bearer_test"


# ===========================================================================
# F06: Multi-Layer Recursive Auto-Decoder Pipeline Tests
# ===========================================================================

def test_f06_multi_layer_auto_decoder_nested_pipeline():
    """Verify recursive auto-decoding pipeline through Base64 -> URL -> HTML -> Plaintext."""
    original = "<script>alert('flowforge')</script>"
    html_ent = encode_html_entities(original)
    url_enc = encode_url(html_ent)
    b64_enc = encode_base64(url_enc)

    res = multi_layer_decode(b64_enc, max_depth=5)
    assert res.status == "success"
    assert res.detected_type in ("base64", "base64_url")
    assert res.result == original
    assert len(res.layers) >= 3
    layer_types = [l.type for l in res.layers]
    assert "BASE64" in layer_types or "BASE64_URL" in layer_types
    assert "URL" in layer_types
    assert "HTML" in layer_types


def test_f06_multi_layer_auto_decoder_jwt_detection():
    """Verify auto-decoding immediately detects and unboxes JWT payloads."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user_id": 999, "role": "admin"}
    jwt_token = _generate_test_jwt(header, payload)

    res = multi_layer_decode(jwt_token)
    assert res.status == "success"
    assert res.detected_type == "jwt"
    assert res.jwt_claims is not None
    assert res.jwt_claims.valid is True
    assert "999" in res.result or 999 in json.loads(res.result).get("user_id", 0)


def test_f06_decode_content_dispatcher_modes():
    """Verify decode_content helper dispatches explicitly and by auto-detection."""
    # Test explicit base64
    b64_val = encode_base64("hello_world")
    res_b64 = decode_content(b64_val, decoder_type="base64")
    assert res_b64.result == "hello_world"

    # Test explicit hex
    hex_val = encode_hex("hello_hex")
    res_hex = decode_content(hex_val, decoder_type="hex")
    assert res_hex.result == "hello_hex"

    # Test explicit URL multi-pass
    url_val = "%252Fadmin%252Fconfig"
    res_url = decode_content(url_val, decoder_type="url", multi_pass=True)
    assert res_url.result == "/admin/config"


# ===========================================================================
# F07: Tools REST API Endpoints Tests
# ===========================================================================

async def test_f07_tools_api_decode_endpoint(tmp_dir: str):
    """Verify POST /api/v1/tools/decode with auto and explicit decoder types."""
    settings = Settings(db_path=f"{tmp_dir}/test_tools_api.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Test Base64 decode
        b64_payload = base64.b64encode(b"API_Tools_Test").decode("ascii")
        resp = await client.post(
            "/api/v1/tools/decode",
            json={"content": b64_payload, "decoder_type": "base64"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["result"] == "API_Tools_Test"

        # 2. Test Multi-pass URL decode
        url_payload = "%252Fapi%252Fv1%252Fadmin"
        resp2 = await client.post(
            "/api/v1/tools/decode",
            json={"content": url_payload, "decoder_type": "url", "multi_pass": True},
        )
        assert resp2.status_code == 200
        assert resp2.json()["result"] == "/api/v1/admin"


async def test_f07_tools_api_encode_endpoint(tmp_dir: str):
    """Verify POST /api/v1/tools/encode with various encoder types."""
    settings = Settings(db_path=f"{tmp_dir}/test_tools_api2.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Base64 encode
        resp_b64 = await client.post(
            "/api/v1/tools/encode",
            json={"content": "EncodeMe123", "encoder_type": "base64"},
        )
        assert resp_b64.status_code == 200
        assert resp_b64.json()["result"] == encode_base64("EncodeMe123")

        # 2. Hex encode with separator
        resp_hex = await client.post(
            "/api/v1/tools/encode",
            json={"content": "HEX", "encoder_type": "hex", "hex_separator": ":"},
        )
        assert resp_hex.status_code == 200
        assert resp_hex.json()["result"] == "48:45:58"

        # 3. HTML escape
        resp_html = await client.post(
            "/api/v1/tools/encode",
            json={"content": "<script>alert(1)</script>", "encoder_type": "html"},
        )
        assert resp_html.status_code == 200
        assert "&lt;script&gt;" in resp_html.json()["result"]


async def test_f07_tools_api_hexdump_and_jwt_inspect(tmp_dir: str):
    """Verify POST /api/v1/tools/hexdump and POST /api/v1/tools/jwt/inspect endpoints."""
    settings = Settings(db_path=f"{tmp_dir}/test_tools_api3.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Hexdump endpoint
        resp_hd = await client.post(
            "/api/v1/tools/hexdump",
            json={"content": "FlowForge Proxy 16 Byte Dump Test", "bytes_per_line": 16},
        )
        assert resp_hd.status_code == 200
        hd_data = resp_hd.json()
        assert hd_data["status"] == "success"
        assert "00000000  " in hd_data["hex_dump"]
        assert "|FlowForge Proxy |" in hd_data["hex_dump"]

        # 2. JWT inspect endpoint
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "api_user", "role": "auditor", "exp": time.time() + 3600}
        jwt_token = _generate_test_jwt(header, payload)

        resp_jwt = await client.post(
            "/api/v1/tools/jwt/inspect",
            json={"token": jwt_token},
        )
        assert resp_jwt.status_code == 200
        jwt_data = resp_jwt.json()
        assert jwt_data["valid"] is True
        assert jwt_data["subject"] == "api_user"
        assert "role:auditor" in jwt_data["roles"]
