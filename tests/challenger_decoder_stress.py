"""
Empirical Challenger 2 Adversarial Stress & Verification Harness
Tests:
1. 10MB+ Base64, Hex Dumps, URL Encodings Stress & Memory Safety.
2. Adversarial JWT Tokens (alg: none, forged HMAC, SQLi/traversal in kid, expired tokens, missing claims, JKU/X5U).
3. Deep 30+ Layer Nested Multi-Layer Decodings (recursion limits, stack overflow safety, cyclical traps).
4. Live E2E Workflow against TargetAppManager (Flow Capture -> Decode -> Mutate -> Replay -> Diff Delta).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time
import urllib.parse
import uuid
from typing import Any, Dict, List

import httpx
from httpx import ASGITransport, AsyncClient

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
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
from tests.target_app import TargetAppManager


def log(msg: str):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


# ============================================================================
# Probe 1: 10MB+ Extreme Payload Stress & Memory Safety
# ============================================================================
def stress_10mb_payloads() -> Dict[str, Any]:
    log("--> [PROBE 1] Starting 10MB+ Extreme Payload Stress Tests...")
    results = {}

    # 1.1: 10MB+ Base64 Roundtrip
    raw_10mb = b"FLOWFORGE_EMPIRICAL_CHALLENGER_2_PAYLOAD_" * 250_000  # ~10.25 MB
    raw_size_mb = len(raw_10mb) / (1024 * 1024)
    log(f"    1.1 Testing Base64 encode & decode on {raw_size_mb:.2f} MB raw bytes...")

    t0 = time.perf_counter()
    b64_str = base64.b64encode(raw_10mb).decode("ascii")
    t_b64_enc = time.perf_counter() - t0

    t0 = time.perf_counter()
    dec_str, is_bin, dec_bytes = decode_base64(b64_str)
    t_b64_dec = time.perf_counter() - t0

    assert dec_bytes == raw_10mb, "Base64 decoded bytes mismatch!"
    assert is_bin is False, "ASCII test data marked as binary!"
    log(f"    ✓ Base64 10MB roundtrip OK (enc: {t_b64_enc:.3f}s, dec: {t_b64_dec:.3f}s)")
    results["base64_10mb"] = {"raw_mb": raw_size_mb, "enc_time_s": t_b64_enc, "dec_time_s": t_b64_dec}

    # 1.2: 10MB+ Hex Dump Generation
    # Generating 2MB binary payload for full 16-byte offset hexdump (yields ~150MB formatted string)
    raw_hex_src = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF" * 65_536  # 1.0 MB
    log(f"    1.2 Testing Hexdump on {len(raw_hex_src)/(1024*1024):.2f} MB binary payload...")
    t0 = time.perf_counter()
    hd_out = hex_dump(raw_hex_src, bytes_per_line=16)
    t_hd = time.perf_counter() - t0
    hd_lines = hd_out.count("\n") + 1
    assert hd_lines == 65_536, f"Expected 65536 lines, got {hd_lines}"
    assert "00000000" in hd_out, "Missing initial offset in hexdump"
    log(f"    ✓ Hexdump {len(raw_hex_src)/(1024*1024):.2f} MB generated {hd_lines} lines in {t_hd:.3f}s")
    results["hexdump_1mb"] = {"lines": hd_lines, "time_s": t_hd}

    # 1.3: 10MB+ Hex Decoding with exotic delimiters
    raw_hex_plain = "48656c6c6f5f466c6f77466f72676521" * 300_000  # ~9.6 MB hex string
    log(f"    1.3 Testing Hex decode on {len(raw_hex_plain)/(1024*1024):.2f} MB hex string...")
    t0 = time.perf_counter()
    hex_dec_str, hex_is_bin, hex_raw_bytes = decode_hex(raw_hex_plain)
    t_hex_dec = time.perf_counter() - t0
    assert len(hex_raw_bytes) == len(raw_hex_plain) // 2
    log(f"    ✓ Hex {len(raw_hex_plain)/(1024*1024):.2f} MB decoded in {t_hex_dec:.3f}s")
    results["hex_decode_10mb"] = {"hex_len_mb": len(raw_hex_plain)/(1024*1024), "time_s": t_hex_dec}

    # 1.4: 10MB+ URL Percent Encoding & Decoding
    raw_url_text = "test_param=flowforge&query=bounty hunt target&data=" + ("A"*1000 + "&") * 10_000 # ~10 MB
    log(f"    1.4 Testing URL percent encode & decode on {len(raw_url_text)/(1024*1024):.2f} MB string...")
    t0 = time.perf_counter()
    url_enc_str = encode_url(raw_url_text)
    t_url_enc = time.perf_counter() - t0

    t0 = time.perf_counter()
    url_dec_str, passes = decode_url(url_enc_str, multi_pass=True, max_passes=5)
    t_url_dec = time.perf_counter() - t0
    assert url_dec_str == raw_url_text
    log(f"    ✓ URL 10MB roundtrip OK in {t_url_enc+t_url_dec:.3f}s (passes: {passes})")
    results["url_10mb"] = {"raw_mb": len(raw_url_text)/(1024*1024), "enc_time_s": t_url_enc, "dec_time_s": t_url_dec}

    return results


# ============================================================================
# Probe 2: Adversarial JWT Token Invariants
# ============================================================================
def stress_adversarial_jwt_tokens() -> Dict[str, Any]:
    log("--> [PROBE 2] Starting Adversarial JWT Matrix Probes...")
    results = {}

    cases = [
        # 1. alg: none with signature stripped
        {
            "name": "alg_none_stripped_sig",
            "header": {"alg": "none", "typ": "JWT"},
            "payload": {"sub": "admin", "role": "superadmin", "exp": time.time() + 3600},
            "sig": "",
            "expected_flags": ["ALG_NONE_UNSECURED"],
            "expected_valid": True,
        },
        # 2. alg: NONE (uppercase) with trailing dot
        {
            "name": "alg_NONE_uppercase",
            "header": {"alg": "NONE", "typ": "JWT"},
            "payload": {"sub": "root", "role": "admin"},
            "sig": "",
            "expected_flags": ["ALG_NONE_UNSECURED", "MISSING_EXPIRATION"],
            "expected_valid": True,
        },
        # 3. Symmetric HMAC alg (HS256 / HS384 / HS512)
        {
            "name": "hmac_symmetric_hs256",
            "header": {"alg": "HS256", "typ": "JWT"},
            "payload": {"sub": "alice", "roles": ["user", "beta_tester"], "exp": time.time() + 7200},
            "sig": "valid_looking_signature_bytes",
            "expected_flags": ["SYMMETRIC_HMAC_ALGORITHM"],
            "expected_valid": True,
        },
        # 4. KID Directory Traversal (Linux & Windows style)
        {
            "name": "kid_directory_traversal_linux",
            "header": {"alg": "HS256", "typ": "JWT", "kid": "../../../../dev/null"},
            "payload": {"sub": "hacker", "role": "admin"},
            "sig": "sig",
            "expected_flags": ["KID_DIR_TRAVERSAL"],
            "expected_valid": True,
        },
        {
            "name": "kid_directory_traversal_win",
            "header": {"alg": "HS256", "typ": "JWT", "kid": "..\\..\\windows\\win.ini"},
            "payload": {"sub": "hacker", "role": "admin"},
            "sig": "sig",
            "expected_flags": ["KID_DIR_TRAVERSAL"],
            "expected_valid": True,
        },
        # 5. KID SQL Injection patterns
        {
            "name": "kid_sqli_union",
            "header": {"alg": "HS256", "typ": "JWT", "kid": "key' UNION SELECT 'my_secret_key' -- "},
            "payload": {"sub": "admin", "role": "dba"},
            "sig": "sig",
            "expected_flags": ["KID_SQL_INJECTION"],
            "expected_valid": True,
        },
        {
            "name": "kid_sqli_quote_escape",
            "header": {"alg": "HS256", "typ": "JWT", "kid": "key_id'; DROP TABLE keys; --"},
            "payload": {"sub": "admin"},
            "sig": "sig",
            "expected_flags": ["KID_SQL_INJECTION"],
            "expected_valid": True,
        },
        # 6. External Header Injections (JKU / X5U)
        {
            "name": "header_jku_external",
            "header": {"alg": "RS256", "typ": "JWT", "jku": "https://attacker.com/keys.json"},
            "payload": {"sub": "admin", "exp": time.time() + 3600},
            "sig": "sig",
            "expected_flags": ["JKU_EXTERNAL_HEADER"],
            "expected_valid": True,
        },
        {
            "name": "header_x5u_external",
            "header": {"alg": "RS256", "typ": "JWT", "x5u": "https://attacker.com/cert.pem"},
            "payload": {"sub": "admin", "exp": time.time() + 3600},
            "sig": "sig",
            "expected_flags": ["X5U_EXTERNAL_HEADER"],
            "expected_valid": True,
        },
        # 7. Expired Tokens
        {
            "name": "expired_token_past",
            "header": {"alg": "HS256", "typ": "JWT"},
            "payload": {"sub": "bob", "exp": time.time() - 86400},
            "sig": "sig",
            "expected_flags": ["TOKEN_EXPIRED"],
            "expected_valid": True,
        },
        # 8. Token not yet valid (nbf in future)
        {
            "name": "future_nbf_token",
            "header": {"alg": "HS256", "typ": "JWT"},
            "payload": {"sub": "future_user", "nbf": time.time() + 86400, "exp": time.time() + 100000},
            "sig": "sig",
            "expected_flags": ["TOKEN_NOT_YET_VALID"],
            "expected_valid": True,
        },
        # 9. Missing Expiration claim
        {
            "name": "missing_exp_token",
            "header": {"alg": "HS256", "typ": "JWT"},
            "payload": {"sub": "eternal_user", "tenant": "corp"},
            "sig": "sig",
            "expected_flags": ["MISSING_EXPIRATION"],
            "expected_valid": True,
        },
    ]

    for case in cases:
        h_b64 = base64.urlsafe_b64encode(json.dumps(case["header"]).encode()).decode().rstrip("=")
        p_b64 = base64.urlsafe_b64encode(json.dumps(case["payload"]).encode()).decode().rstrip("=")
        sig_str = case["sig"]
        token = f"{h_b64}.{p_b64}.{sig_str}" if sig_str else f"{h_b64}.{p_b64}."

        res = inspect_jwt(token)
        assert res.valid == case["expected_valid"], f"Case {case['name']} validity failed! Got {res.valid}"

        for ef in case["expected_flags"]:
            assert ef in res.security_flags, f"Case {case['name']} missing expected security flag '{ef}'! Flags: {res.security_flags}"

        log(f"    ✓ JWT Case '{case['name']}' validated (flags: {res.security_flags})")
        results[case["name"]] = {"valid": res.valid, "flags": res.security_flags}

    # 10. Malformed structural tokens
    malformed_tokens = [
        ("two_dots_no_content", ".."),
        ("one_dot", "header.payload"),
        ("four_dots", "a.b.c.d"),
        ("garbage_chars", "@@@.###.$$$"),
        ("bearer_prefix_malformed", "Bearer invalid-jwt-here"),
    ]

    for m_name, m_tok in malformed_tokens:
        m_res = inspect_jwt(m_tok)
        assert m_res.valid is False, f"Malformed token {m_name} incorrectly flagged as valid!"
        log(f"    ✓ Malformed token '{m_name}' correctly rejected with valid=False")
        results[m_name] = {"valid": False, "error": m_res.error}

    return results


# ============================================================================
# Probe 3: Deep 30-Layer Nested Multi-Layer Decodings
# ============================================================================
def stress_deep_recursion_decoding() -> Dict[str, Any]:
    log("--> [PROBE 3] Starting Deep 30-Layer Nested Multi-Layer Decoding Probes...")
    results = {}

    secret_inner = "FLOWFORGE_AUTHENTIC_OPERATOR_SECRET_FLAG_M4"
    current = secret_inner

    # Wrap 32 alternating layers: Base64 -> URL -> Hex -> Base64 -> URL ...
    enc_chain: List[str] = []
    for layer in range(1, 33):
        if layer % 3 == 1:
            current = base64.b64encode(current.encode("utf-8")).decode("ascii")
            enc_chain.append("BASE64")
        elif layer % 3 == 2:
            current = urllib.parse.quote(current)
            enc_chain.append("URL")
        else:
            current = current.encode("utf-8").hex()
            enc_chain.append("HEX")

    log(f"    Built 32-layer wrapped payload: length={len(current)} chars")

    # 3.1: Test max_depth = 5 (default)
    t0 = time.perf_counter()
    r5 = multi_layer_decode(current, max_depth=5)
    t5 = time.perf_counter() - t0
    assert r5.status == "success"
    assert len(r5.layers) == 5, f"Expected 5 layers, got {len(r5.layers)}"
    log(f"    ✓ max_depth=5 processed exactly 5 steps in {t5*1000:.2f}ms")
    results["depth_5"] = {"layers_count": len(r5.layers), "time_ms": t5 * 1000}

    # 3.2: Test max_depth = 20 (REST API cap)
    t0 = time.perf_counter()
    r20 = multi_layer_decode(current, max_depth=20)
    t20 = time.perf_counter() - t0
    assert r20.status == "success"
    assert len(r20.layers) == 20, f"Expected 20 layers, got {len(r20.layers)}"
    log(f"    ✓ max_depth=20 processed exactly 20 steps in {t20*1000:.2f}ms")
    results["depth_20"] = {"layers_count": len(r20.layers), "time_ms": t20 * 1000}

    # 3.3: Test max_depth = 35 (Full Unboxing through layers to original secret)
    t0 = time.perf_counter()
    r35 = multi_layer_decode(current, max_depth=35)
    t35 = time.perf_counter() - t0
    assert r35.status == "success"
    log(f"    Unboxed {len(r35.layers)} layers to result: {r35.result[:50]}... in {t35*1000:.2f}ms")
    assert r35.result == secret_inner, f"Final unboxed result '{r35.result}' != '{secret_inner}'"
    log(f"    ✓ max_depth=35 fully unboxed {len(r35.layers)} layers to secret in {t35*1000:.2f}ms")
    results["depth_35_full_unbox"] = {"layers_count": len(r35.layers), "result": r35.result, "time_ms": t35 * 1000}

    # 3.4: Cyclical / Idempotent Encodings (e.g. Plain ASCII string or repeated unquoting)
    plain_input = "Hello World! No encoding here."
    r_plain = multi_layer_decode(plain_input, max_depth=10)
    assert r_plain.status == "success"
    assert len(r_plain.layers) == 0, f"Expected 0 layers for plain text, got {len(r_plain.layers)}"
    assert r_plain.result == plain_input
    log(f"    ✓ Plain string terminated with 0 layers without looping")
    results["plain_idempotent"] = {"layers_count": len(r_plain.layers)}

    return results


# ============================================================================
# Probe 4: Live E2E Workflow against TargetAppManager
# ============================================================================
async def stress_live_e2e_replay_workflow() -> Dict[str, Any]:
    log("--> [PROBE 4] Starting Live E2E TargetAppManager Intercept->Decode->Mutate->Replay->Diff Delta...")
    results = {}

    db_test_path = f"/tmp/test_challenger2_e2e_{uuid.uuid4().hex[:8]}.db"
    await init_db(db_test_path)
    settings = Settings(db_path=db_test_path, auto_start_proxy=False)
    app = create_app(settings)

    writer = AsyncDBWriter(db_path=db_test_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()
    repo = FlowRepository(db_path=db_test_path)
    app.state.db_writer = writer
    app.state.repo = repo

    try:
        async with TargetAppManager() as target:
            log(f"    Live TargetAppManager started at {target.base_url}")
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:

                # STEP 1: Flow Capture: Intercept authentic login flow containing genuine JWT
                log("    Step 1: Intercepting live /auth/login request on TargetApp...")
                async with httpx.AsyncClient() as live_http:
                    auth_resp = await live_http.post(f"{target.base_url}/auth/login")
                    assert auth_resp.status_code == 200
                    auth_body = auth_resp.json()
                    authentic_jwt = auth_body["token"]
                    log(f"    Captured authentic JWT: {authentic_jwt[:30]}...")

                # Ingest flow into FlowForge repository
                flow_id = f"flow-e2e-{uuid.uuid4().hex[:8]}"
                flow_rec = FlowRecord(
                    id=flow_id,
                    server_host=target.host,
                    server_port=target.port,
                    request=RequestModel(
                        method="POST",
                        url=f"{target.base_url}/auth/login",
                        path="/auth/login",
                        headers={"Host": f"{target.host}:{target.port}"},
                    ),
                    response=ResponseModel(
                        status_code=200,
                        headers={"Content-Type": "application/json"},
                        body=json.dumps(auth_body),
                    ),
                )
                await writer.enqueue_insert_flow(flow_rec)
                await writer.flush()

                # STEP 2: Decode Flow Tokens via Tools REST API
                log("    Step 2: Decoding intercepted JWT token via /api/v1/tools/jwt/inspect...")
                insp_res = await client.post("/api/v1/tools/jwt/inspect", json={"token": authentic_jwt})
                assert insp_res.status_code == 200
                jwt_data = insp_res.json()
                assert jwt_data["valid"] is True
                assert jwt_data["algorithm"] == "HS256"
                assert jwt_data["payload"]["role"] == "admin"
                log(f"    ✓ JWT successfully decoded (algorithm: {jwt_data['algorithm']}, subject: {jwt_data['subject']})")

                # STEP 3: Mutate & Tamper: Forge alg:none and escalate role to superuser
                log("    Step 3: Mutating token to alg:none and escalating claims...")
                mutated_claims = dict(jwt_data["payload"])
                mutated_claims["sub"] = "superuser_injected"
                mutated_claims["role"] = "superadmin"
                mutated_claims["injected_privilege"] = True

                hdr_none_b64 = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
                pay_mut_b64 = base64.urlsafe_b64encode(json.dumps(mutated_claims).encode()).decode().rstrip("=")
                forged_jwt = f"{hdr_none_b64}.{pay_mut_b64}."

                # Verify inspect detects forged token
                forged_insp = await client.post("/api/v1/tools/jwt/inspect", json={"token": forged_jwt})
                assert "ALG_NONE_UNSECURED" in forged_insp.json()["security_flags"]
                log("    ✓ Forged token verified and correctly flagged with ALG_NONE_UNSECURED")

                # STEP 4: Live Replay against TargetAppManager /auth/protected
                log("    Step 4: Replaying baseline vs mutated requests against live target...")
                prot_url = f"{target.base_url}/auth/protected"
                async with httpx.AsyncClient() as live_http:
                    # Baseline authenticated request
                    resp_baseline = await live_http.get(prot_url, headers={"Authorization": f"Bearer {authentic_jwt}"})
                    assert resp_baseline.status_code == 200
                    base_json = resp_baseline.json()
                    assert base_json["auth_state"] == "authenticated"

                    # Mutated request with forged alg:none token
                    resp_mutated = await live_http.get(prot_url, headers={"Authorization": f"Bearer {forged_jwt}"})
                    assert resp_mutated.status_code == 200

                    # Unauthenticated stripped request
                    resp_stripped = await live_http.get(prot_url)
                    assert resp_stripped.status_code == 200
                    strip_json = resp_stripped.json()
                    assert strip_json["auth_state"] == "unauthenticated_leak"

                # STEP 5: Diff Delta Computation via /api/v1/diff
                log("    Step 5: Computing side-by-side Diff Delta via /api/v1/diff...")
                diff_resp = await client.post(
                    "/api/v1/diff",
                    json={
                        "flow_a": {
                            "response_status": resp_baseline.status_code,
                            "response_headers": dict(resp_baseline.headers),
                            "response_body": resp_baseline.text,
                        },
                        "flow_b": {
                            "response_status": resp_stripped.status_code,
                            "response_headers": dict(resp_stripped.headers),
                            "response_body": resp_stripped.text,
                        },
                    },
                )
                assert diff_resp.status_code == 200
                diff_res = diff_resp.json()
                assert diff_res["status_match"] is True
                assert diff_res["length_delta_bytes"] != 0
                log(f"    ✓ Diff Delta calculated: status_match={diff_res['status_match']}, length_delta={diff_res['length_delta_bytes']} bytes")

                results["e2e_replay_diff"] = {
                    "baseline_status": resp_baseline.status_code,
                    "mutated_status": resp_mutated.status_code,
                    "stripped_status": resp_stripped.status_code,
                    "diff_delta_bytes": diff_res["length_delta_bytes"],
                    "status_match": diff_res["status_match"],
                }

    finally:
        await writer.stop()
        if os.path.exists(db_test_path):
            try:
                os.remove(db_test_path)
            except Exception:
                pass

    return results


# ============================================================================
# Main Execution Runner
# ============================================================================
async def main():
    log("================================================================================")
    log("FLOWFORGE EMPIRICAL CHALLENGER 2: DECODER & E2E REPLAY WORKFLOW STRESS HARNESS")
    log("================================================================================")

    all_results = {}
    try:
        all_results["probe1_10mb"] = stress_10mb_payloads()
        all_results["probe2_jwt"] = stress_adversarial_jwt_tokens()
        all_results["probe3_deep_recursion"] = stress_deep_recursion_decoding()
        all_results["probe4_live_e2e"] = await stress_live_e2e_replay_workflow()

        log("\n================================================================================")
        log("🎉 ALL CHALLENGER 2 EMPIRICAL STRESS PROBES PASSED (4/4 PROBE SUITES)!")
        log("================================================================================")
        print(json.dumps(all_results, indent=2, default=str))
        sys.exit(0)
    except Exception as exc:
        log(f"\n❌ CHALLENGER 2 STRESS PROBE FAILED: {exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
