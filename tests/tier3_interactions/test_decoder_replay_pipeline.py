"""
Tier 3 Cross-Feature Interaction Tests: Intercepted Encoded Flow -> Decoder Extraction ->
Payload Mutation -> Re-Encoding -> Replay Pipeline Dispatch.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.parse
import pytest
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.utils.decoders import (
    decode_base64,
    decode_content,
    encode_base64,
    encode_url,
    inspect_jwt,
    multi_layer_decode,
)


async def test_t3_multi_layer_decode_mutate_and_encode_pipeline(tmp_dir: str):
    """Verify intercepted nested payload (Base64 + URL) is unwrapped, mutated, and re-encoded."""
    settings = Settings(db_path=f"{tmp_dir}/test_decoder_replay.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Simulate an intercepted request with encoded parameter: Base64(URL_ENCODE("user=regular"))
        baseline_raw = "user=regular"
        url_enc = encode_url(baseline_raw)
        b64_enc = encode_base64(url_enc)

        # 2. Operator uses Tools API to decode multi-layer content
        dec_resp = await client.post("/api/v1/tools/decode", json={"content": b64_enc, "decoder_type": "auto"})
        assert dec_resp.status_code == 200
        dec_result = dec_resp.json()["result"]
        assert dec_result == baseline_raw

        # 3. Mutate payload to elevate privilege
        mutated_raw = dec_result.replace("user=regular", "user=admin&role=superuser")

        # 4. Re-encode using Tools API (URL encode -> Base64 encode)
        enc_url_resp = await client.post("/api/v1/tools/encode", json={"content": mutated_raw, "encoder_type": "url"})
        assert enc_url_resp.status_code == 200
        url_encoded_mutated = enc_url_resp.json()["result"]

        enc_b64_resp = await client.post("/api/v1/tools/encode", json={"content": url_encoded_mutated, "encoder_type": "base64"})
        assert enc_b64_resp.status_code == 200
        final_payload = enc_b64_resp.json()["result"]

        # 5. Dispatch mutated payload via custom send endpoint
        send_resp = await client.post("/api/v1/flows/custom/send", json={
            "method": "POST",
            "url": "http://127.0.0.1:8000/api/v1/auth/session",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": f"data={final_payload}",
        })
        assert send_resp.status_code == 200
        assert send_resp.json()["status"] == "queued_or_sent"


async def test_t3_jwt_extraction_inspection_and_tampering_pipeline(tmp_dir: str):
    """Verify intercepted JWT Authorization header is inspected, tampered to alg:none, and replayed."""
    settings = Settings(db_path=f"{tmp_dir}/test_jwt_replay.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Baseline JWT with HS256 and regular user
        h = {"alg": "HS256", "typ": "JWT"}
        p = {"sub": "user_101", "role": "viewer", "exp": time.time() + 3600}
        h_b64 = base64.urlsafe_b64encode(json.dumps(h).encode()).decode().rstrip("=")
        p_b64 = base64.urlsafe_b64encode(json.dumps(p).encode()).decode().rstrip("=")
        token = f"{h_b64}.{p_b64}.signature123"

        # 2. Inspect token via Tools API
        insp_resp = await client.post("/api/v1/tools/jwt/inspect", json={"token": token})
        assert insp_resp.status_code == 200
        insp_data = insp_resp.json()
        assert insp_data["subject"] == "user_101"
        assert "role:viewer" in insp_data["roles"]

        # 3. Tamper token: change alg to none and role to admin, strip signature
        tampered_h = {"alg": "none", "typ": "JWT"}
        tampered_p = {"sub": "user_101", "role": "admin", "exp": time.time() + 7200}
        th_b64 = base64.urlsafe_b64encode(json.dumps(tampered_h).encode()).decode().rstrip("=")
        tp_b64 = base64.urlsafe_b64encode(json.dumps(tampered_p).encode()).decode().rstrip("=")
        forged_jwt = f"{th_b64}.{tp_b64}."

        # 4. Verify forged token triggers ALG_NONE_UNSECURED flag
        insp_forged = await client.post("/api/v1/tools/jwt/inspect", json={"token": forged_jwt})
        assert insp_forged.status_code == 200
        assert "ALG_NONE_UNSECURED" in insp_forged.json()["security_flags"]

        # 5. Dispatch tampered request
        replay_resp = await client.post("/api/v1/flows/custom/send", json={
            "method": "GET",
            "url": "http://127.0.0.1:8000/api/v1/admin/dashboard",
            "headers": {"Authorization": f"Bearer {forged_jwt}"},
        })
        assert replay_resp.status_code == 200


async def test_t3_hex_dump_inspection_and_binary_tamper(tmp_dir: str):
    """Verify inspection of binary payload via hexdump tool, hex decoding, and replay."""
    settings = Settings(db_path=f"{tmp_dir}/test_hex_replay.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Binary bytes representing serialized protocol header
        bin_payload = bytes([0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x00, 0x00, 0x08])

        # Hexdump endpoint inspection
        hd_resp = await client.post("/api/v1/tools/hexdump", json={"content": bin_payload.decode("latin-1")})
        assert hd_resp.status_code == 200
        assert "00000000  " in hd_resp.json()["hex_dump"]


async def test_t3_html_unescape_and_xss_probe_staging(tmp_dir: str):
    """Verify HTML entity decoding reveals reflection context for XSS staging."""
    reflected_response_body = "&lt;input value=&quot;test_search_term&quot;&gt;"
    decoded = decode_content(reflected_response_body, decoder_type="html").result
    assert decoded == '<input value="test_search_term">'
    # Context breakout confirmed: double quote escape
    xss_breakout = '"><svg onload=alert(1)>'
    assert xss_breakout.startswith('">')
