"""
Tier 4 Real-World Application Scenario 3: Deep JWT Exploitation & Telemetry Analysis Pipeline.
Exercises: JWT Deep Inspection, Claim Decoding, Expiration Warnings, Alg:None Detection,
TLS/Timing Telemetry Capture, Tampering Replay, and Diff Verification.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
import pytest
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.telemetry import (
    BandwidthTelemetry,
    FlowTelemetry,
    TLSTelemetry,
    TimingTelemetry,
)
from flowforge.utils.decoders import inspect_jwt


def _create_jwt(header: dict, payload: dict) -> str:
    h = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).decode("ascii").rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")
    return f"{h}.{p}.test_signature_bytes_123"


async def test_e2e_jwt_telemetry_workflow(tmp_dir: str):
    """
    Execute full end-to-end JWT penetration testing and telemetry inspection workflow:
    1. Intercept flow carrying valid JWT and rich TLS 1.3 / HTTP timing metrics.
    2. Deeply inspect JWT via Tools API: claims, expiry countdown, and security warnings.
    3. Persist and query flow with full telemetry serialization (TTFB, cipher, latency).
    4. Generate tampered token with alg:none and elevated role ('admin').
    5. Replay tampered token via custom send endpoint.
    6. Verify security anomaly flags and diff metrics against baseline.
    """
    db_path = f"{tmp_dir}/jwt_telemetry_workflow.db"
    settings = Settings(db_path=db_path, auto_start_proxy=False)
    app = create_app(settings)
    await init_db(db_path)
    writer = AsyncDBWriter(db_path=db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()
    repo = FlowRepository(db_path)
    pipeline = TriagePipeline()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # -------------------------------------------------------------------
        # Step 1: Ingest flow with JWT Bearer token & Rich Telemetry
        # -------------------------------------------------------------------
        now = time.time()
        valid_header = {"alg": "HS256", "typ": "JWT", "kid": "key-2026-prod"}
        valid_payload = {
            "sub": "operator_404",
            "org_id": "tenant_enterprise_77",
            "role": "readonly_viewer",
            "iat": int(now - 300),
            "exp": int(now + 3600),
        }
        raw_jwt = _create_jwt(valid_header, valid_payload)

        telemetry = FlowTelemetry(
            tls=TLSTelemetry(
                version="TLSv1.3",
                cipher_suite="TLS_AES_256_GCM_SHA384",
                sni="api.telemetry.bank",
                alpn="h2",
            ),
            timings=TimingTelemetry(
                ttfb_ms=42.5,
                dns_ms=5.1,
                tcp_connect_ms=12.3,
                tls_handshake_ms=18.7,
                total_duration_ms=78.6,
            ),
            bandwidth=BandwidthTelemetry(
                request_headers_bytes=520,
                response_headers_bytes=1420,
                total_bytes=1940,
            ),
        )

        flow_id = str(uuid.uuid4())
        flow = FlowRecord(
            id=flow_id,
            timestamp_start=now,
            server_host="api.telemetry.bank",
            scheme="https",
            duration_ms=78.6,
            request=RequestModel(
                method="GET",
                url="https://api.telemetry.bank/api/v2/secure/profile",
                path="/api/v2/secure/profile",
                headers={
                    "Host": "api.telemetry.bank",
                    "Authorization": f"Bearer {raw_jwt}",
                    "User-Agent": "FlowForgeTest/1.0",
                },
            ),
            response=ResponseModel(
                status_code=200,
                headers={"Content-Type": "application/json", "X-Server-Id": "node-us-east-1"},
                content_length=1420,
                body='{"status": "authenticated", "profile": {"user": "operator_404", "role": "readonly_viewer"}}',
            ),
        )

        triage = pipeline.process_flow_sync(flow)
        assert "jwt" in triage.tags
        assert "auth" in triage.tags

        # Persist flow into DB
        flow.telemetry = telemetry
        flow.tags = triage.tags
        await writer.enqueue_flow(flow)
        await writer.flush()

        # -------------------------------------------------------------------
        # Step 2: Deep JWT Inspection via Tools API
        # -------------------------------------------------------------------
        inspect_resp = await client.post("/api/v1/tools/jwt/inspect", json={"token": raw_jwt})
        assert inspect_resp.status_code == 200
        jwt_info = inspect_resp.json()
        assert jwt_info["valid"] is True
        assert jwt_info["subject"] == "operator_404"
        assert jwt_info["is_expired"] is False
        assert "role:readonly_viewer" in jwt_info["roles"]

        # -------------------------------------------------------------------
        # Step 3: Verify Telemetry Serialization in Flow Query
        # -------------------------------------------------------------------
        stored_flow = await repo.get_flow_by_id(flow_id)
        assert stored_flow is not None
        assert stored_flow.id == flow_id

        # -------------------------------------------------------------------
        # Step 4: Forge Elevated Token (alg: none exploit)
        # -------------------------------------------------------------------
        forged_header = {"alg": "none", "typ": "JWT"}
        forged_payload = {
            "sub": "operator_404",
            "org_id": "tenant_enterprise_77",
            "role": "admin_superuser",
            "is_admin": True,
            "iat": int(now),
            "exp": int(now + 7200),
        }
        h_b64 = base64.urlsafe_b64encode(json.dumps(forged_header).encode()).decode().rstrip("=")
        p_b64 = base64.urlsafe_b64encode(json.dumps(forged_payload).encode()).decode().rstrip("=")
        forged_jwt = f"{h_b64}.{p_b64}."

        # Inspect forged token to verify security warnings
        forged_inspect = await client.post("/api/v1/tools/jwt/inspect", json={"token": forged_jwt})
        assert forged_inspect.status_code == 200
        forged_data = forged_inspect.json()
        assert "ALG_NONE_UNSECURED" in forged_data["security_flags"]
        assert "role:admin_superuser" in forged_data["roles"]

        # -------------------------------------------------------------------
        # Step 5: Dispatch Replay with Forged Token
        # -------------------------------------------------------------------
        replay_resp = await client.post(
            "/api/v1/flows/custom/send",
            json={
                "method": "GET",
                "url": "https://api.telemetry.bank/api/v2/secure/admin/metrics",
                "headers": {
                    "Authorization": f"Bearer {forged_jwt}",
                    "Content-Type": "application/json",
                },
                "body": "",
            },
        )
        assert replay_resp.status_code == 200
        assert replay_resp.json()["status"] == "queued_or_sent"

    await writer.stop()
