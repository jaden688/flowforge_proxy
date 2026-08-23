"""
Tier 2 Boundary & Corner Case Tests: Decoders, Encoders, Recursion Limits,
Cyclic Encodings, Corrupt Inputs, and Malformed JWTs (Features F01–F07).
"""

from __future__ import annotations

import base64
import json
import pytest

from flowforge.utils.decoders import (
    AutoDecodeResult,
    decode_base64,
    decode_content,
    decode_hex,
    decode_html_entities,
    decode_url,
    hex_dump,
    inspect_jwt,
    multi_layer_decode,
)


def test_t2_decoders_corrupt_base64_handling():
    """Verify decode_base64 raises ValueError on invalid base64 and decode_content handles gracefully."""
    corrupt_input = "@@@@!!!NotBase64***"

    with pytest.raises(ValueError):
        decode_base64(corrupt_input)

    # decode_content with explicit base64 should return status='error' with error detail
    res = decode_content(corrupt_input, decoder_type="base64")
    assert res.status == "error"
    assert res.error is not None
    assert res.result == corrupt_input


def test_t2_decoders_corrupt_hex_handling():
    """Verify decode_hex raises ValueError on invalid characters and decode_content returns error status."""
    corrupt_hex = "ZZZZGGGG123"

    with pytest.raises(ValueError):
        decode_hex(corrupt_hex)

    res = decode_content(corrupt_hex, decoder_type="hex")
    assert res.status == "error"
    assert res.error is not None


def test_t2_decoders_hex_odd_length_auto_padding():
    """Verify hex decoder handles odd number of hex digits by left-padding '0'."""
    # "0x1" -> "01" -> byte 1
    decoded_str, is_bin, raw_bytes = decode_hex("0x1")
    assert len(raw_bytes) == 1
    assert raw_bytes == bytes([0x01])


def test_t2_decoders_recursion_depth_bound():
    """Verify multi-layer decoder respects max_depth limit without infinite loops."""
    # Create 10 layers of Base64 wrapping
    current = "deep_secret_token"
    for _ in range(10):
        current = base64.b64encode(current.encode("utf-8")).decode("ascii")

    # Limit depth to 3
    res = multi_layer_decode(current, max_depth=3)
    assert res.status == "success"
    assert len(res.layers) == 3


def test_t2_decoders_cyclic_and_idempotent_encodings():
    """Verify decoders terminate when input reaches fixed-point idempotent state."""
    # Already fully decoded plaintext
    plain = "FlowForge Plaintext String"
    res = multi_layer_decode(plain, max_depth=5)
    assert res.status == "success"
    assert res.result == plain
    assert len(res.layers) == 0


def test_t2_decoders_massive_payload_resilience():
    """Verify decoders process large (50KB+) payloads without memory or CPU exhaustion."""
    large_text = "A" * 50_000
    b64_large = base64.b64encode(large_text.encode("utf-8")).decode("ascii")

    decoded, is_binary, raw = decode_base64(b64_large)
    assert len(decoded) == 50_000
    assert decoded == large_text
    assert is_binary is False

    # Large hex dump
    dump = hex_dump(large_text[:1000])
    assert len(dump) > 0


def test_t2_decoders_malformed_jwt_variations():
    """Verify inspect_jwt handles 1-segment, 2-segment, 4-segment, and non-JSON payloads safely."""
    # 1. Only 1 part
    r1 = inspect_jwt("only_one_part")
    assert r1.valid is False
    assert "Invalid JWT structure" in (r1.error or "")

    # 2. Only 2 parts
    r2 = inspect_jwt("header.payload")
    assert r2.valid is False

    # 3. 4 parts
    r3 = inspect_jwt("part1.part2.part3.part4")
    assert r3.valid is False

    # 4. Valid parts count but header is corrupt base64
    r4 = inspect_jwt("!@#$.eyJzdWIiOiIxIn0.sig")
    assert r4.valid is False
    assert "header" in (r4.error or "").lower()

    # 5. Header is valid base64 but not valid JSON
    not_json_b64 = base64.b64encode(b"not a json object").decode("ascii")
    r5 = inspect_jwt(f"{not_json_b64}.eyJzdWIiOiIxIn0.sig")
    assert r5.valid is False

    # 6. Payload is valid JSON array instead of dict
    array_b64 = base64.b64encode(b"[1, 2, 3]").decode("ascii")
    r6 = inspect_jwt(f"eyJhbGciOiJub25lIn0.{array_b64}.")
    assert r6.valid is False
    assert "not a JSON object" in (r6.error or "")
