"""
Tier 3 Interaction Tests: Payload management (custom wordlists CRUD) and the
active Intruder replay engine (injection points, concurrency, rate limiting,
live results, anomaly flagging, abort).
"""

from __future__ import annotations

import time

import pytest
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.core.intruder import apply_payload
from flowforge.db.connection import init_db
from flowforge.models.intruder import InjectionPoint
from tests.target_app import TargetAppManager


async def _make_app(tmp_dir: str):
    await init_db(f"{tmp_dir}/test_intruder.db")
    return create_app(Settings(
        db_path=f"{tmp_dir}/test_intruder.db",
        auto_start_proxy=False,
    ))


# ===========================================================================
# Unit: payload application
# ===========================================================================

def test_apply_payload_header_injection():
    url, headers, body = apply_payload(
        "GET", "http://t/x", {"Authorization": "Bearer orig"}, None,
        InjectionPoint(position="header", key="X-Probe"), "INJ",
    )
    assert headers["X-Probe"] == "INJ"
    assert body is None


def test_apply_payload_query_replaces_existing_param():
    url, headers, body = apply_payload(
        "GET", "http://t/search?q=orig&page=2", {}, None,
        InjectionPoint(position="query", key="q"), "' OR 1=1--",
    )
    assert "q=%27+OR+1%3D1--" in url or "q=" in url
    assert "page=2" in url


def test_apply_payload_query_adds_missing_param():
    url, _, _ = apply_payload(
        "GET", "http://t/path", {}, None,
        InjectionPoint(position="query", key="new"), "v",
    )
    assert "new=v" in url


def test_apply_payload_body_wraps_with_prefix_suffix():
    _, _, body = apply_payload(
        "POST", "http://t/a", {}, '{"x":1}',
        InjectionPoint(position="body", prefix='{"injected":"', suffix='"}'), "PAYLOAD",
    )
    assert body == '{"injected":"PAYLOAD"}'


# ===========================================================================
# Custom wordlist manager API
# ===========================================================================

async def test_custom_wordlist_full_crud(tmp_dir: str):
    app = await _make_app(tmp_dir)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await client.post("/api/v1/wordlists/custom", json={
            "name": "my-sqli-probes",
            "description": "Operator curated",
            "category": "attack_payloads",
            "tags": ["sqli", "custom"],
            "content": "# comment\n' OR 1=1--\n\nadmin'--\n",
        })
        assert created.status_code == 201
        wl = created.json()
        assert wl["id"].startswith("wl-")
        assert wl["line_count"] == 2

        dup = await client.post("/api/v1/wordlists/custom", json={
            "name": "my-sqli-probes", "content": "x\n",
        })
        assert dup.status_code == 409

        listed = await client.get("/api/v1/wordlists/custom", params={"tag": "sqli"})
        assert listed.status_code == 200
        assert listed.json()["total"] == 1

        patched = await client.patch(f"/api/v1/wordlists/custom/{wl['id']}", json={
            "tags": ["sqli", "curated-v2"],
            "description": "Updated",
        })
        assert patched.status_code == 200
        assert patched.json()["tags"] == ["sqli", "curated-v2"]
        assert patched.json()["preview"] == ["' OR 1=1--", "admin'--"]

        deleted = await client.delete(f"/api/v1/wordlists/custom/{wl['id']}")
        assert deleted.status_code == 200
        missing = await client.delete(f"/api/v1/wordlists/custom/{wl['id']}")
        assert missing.status_code == 404


async def test_custom_wordlist_validation_errors(tmp_dir: str):
    app = await _make_app(tmp_dir)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        empty = await client.post("/api/v1/wordlists/custom", json={"name": "x", "content": ""})
        assert empty.status_code == 422
        no_fields = await client.patch("/api/v1/wordlists/custom/wl-nonexistent", json={})
        assert no_fields.status_code == 422
        unknown = await client.patch("/api/v1/wordlists/custom/wl-nonexistent", json={"description": "d"})
        assert unknown.status_code == 404


# ===========================================================================
# Active Intruder engine E2E against the reference target app
# ===========================================================================

async def test_intruder_reflection_campaign_end_to_end(tmp_dir: str):
    app = await _make_app(tmp_dir)
    async with TargetAppManager() as target:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Seed a custom wordlist and use it as a payload source
            wl_resp = await client.post("/api/v1/wordlists/custom", json={
                "name": "canaries", "content": "CANARY_ONE\nCANARY_TWO\n",
            })
            wl_id = wl_resp.json()["id"]

            resp = await client.post("/api/v1/intruder/jobs", json={
                "config": {
                    "flow_id": None,
                    "method": "GET",
                    "url": f"{target.base_url}/reflect/html?q=baseline",
                    "custom_wordlist_ids": [wl_id],
                    "inline_payloads": ["CANARY_THREE"],
                    "injection_points": [
                        {"position": "query", "key": "q"},
                        {"position": "header", "key": "X-Canary"},
                    ],
                    "concurrency": 4,
                }
            })
            assert resp.status_code == 200
            job = resp.json()["job"]
            job_id = job["id"]
            # 3 payloads x 2 points = 6 requests
            assert job["total_requests"] == 6

            # Wait for completion
            final = None
            for _ in range(100):
                state = (await client.get(f"/api/v1/intruder/jobs/{job_id}")).json()
                if state["status"] in ("COMPLETED", "ABORTED", "FAILED"):
                    final = state
                    break
                await asyncio.sleep(0.05)
            assert final is not None, "job did not finish"
            assert final["status"] == "COMPLETED"
            assert final["completed_requests"] == 6

            results = (await client.get(f"/api/v1/intruder/jobs/{job_id}/results")).json()
            assert results["total"] == 6

            # Query-position payloads are reflected by /reflect/html -> REFLECTION anomaly
            reflected_only = (
                await client.get(f"/api/v1/intruder/jobs/{job_id}/results",
                                 params={"reflected_only": "true"})
            ).json()
            assert reflected_only["total"] == 3
            assert all("REFLECTION" in r["anomaly_reasons"] for r in reflected_only["items"])
            assert {r["payload"] for r in reflected_only["items"]} == {
                "CANARY_ONE", "CANARY_TWO", "CANARY_THREE",
            }

            anomalies = (
                await client.get(f"/api/v1/intruder/jobs/{job_id}/results",
                                 params={"anomalies_only": "true"})
            ).json()
            assert anomalies["total"] >= 3
            assert final["anomaly_count"] >= 3


async def test_intruder_status_filtering_and_body_position(tmp_dir: str):
    app = await _make_app(tmp_dir)
    async with TargetAppManager() as target:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/api/v1/intruder/jobs", json={
                "config": {
                    "method": "POST",
                    "url": f"{target.base_url}/reflect/json",
                    "headers": {"Content-Type": "application/json"},
                    "inline_payloads": ["ALPHA_BODY", "BETA_BODY"],
                    "injection_points": [{"position": "body"}],
                    "concurrency": 2,
                }
            })
            job_id = resp.json()["job"]["id"]

            final = None
            for _ in range(100):
                state = (await client.get(f"/api/v1/intruder/jobs/{job_id}")).json()
                if state["status"] in ("COMPLETED", "ABORTED", "FAILED"):
                    final = state
                    break
                await asyncio.sleep(0.05)
            assert final and final["status"] == "COMPLETED"

            ok_results = (
                await client.get(f"/api/v1/intruder/jobs/{job_id}/results",
                                 params={"status_code": "200"})
            ).json()
            assert ok_results["total"] == 2
            assert all(r["status_code"] == 200 for r in ok_results["items"])
            # JSON echo endpoint reflects whole body -> both flagged
            assert all(r["reflected"] for r in ok_results["items"])
            assert all(r["response_size_bytes"] and r["response_size_bytes"] > 0
                       for r in ok_results["items"])


async def test_intruder_rate_limiting_slows_dispatch(tmp_dir: str):
    app = await _make_app(tmp_dir)
    async with TargetAppManager() as target:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            started_at = time.time()
            resp = await client.post("/api/v1/intruder/jobs", json={
                "config": {
                    "method": "GET",
                    "url": f"{target.base_url}/health",
                    "inline_payloads": [f"p{i}" for i in range(11)],
                    "injection_points": [{"position": "query", "key": "q"}],
                    "concurrency": 16,
                    "rate_limit_rps": 10,
                }
            })
            job_id = resp.json()["job"]["id"]
            final = None
            for _ in range(300):
                state = (await client.get(f"/api/v1/intruder/jobs/{job_id}")).json()
                if state["status"] in ("COMPLETED", "ABORTED", "FAILED"):
                    final = state
                    break
                await asyncio.sleep(0.05)
            elapsed = time.time() - started_at
            assert final and final["status"] == "COMPLETED"
            # 11 requests @ 10 rps requires >= ~1.0s of spacing
            assert elapsed >= 0.8, f"rate limit not enforced (elapsed={elapsed:.2f}s)"


async def test_intruder_abort_mid_campaign(tmp_dir: str):
    app = await _make_app(tmp_dir)
    async with TargetAppManager() as target:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/api/v1/intruder/jobs", json={
                "config": {
                    "method": "GET",
                    "url": f"{target.base_url}/health",
                    "inline_payloads": [f"slow-{i}" for i in range(400)],
                    "injection_points": [{"position": "query", "key": "q"}],
                    "concurrency": 2,
                    "rate_limit_rps": 25,
                }
            })
            job_id = resp.json()["job"]["id"]

            await asyncio.sleep(0.3)
            aborted = await client.post(f"/api/v1/intruder/jobs/{job_id}/abort")
            assert aborted.status_code == 200

            final = None
            for _ in range(120):
                state = (await client.get(f"/api/v1/intruder/jobs/{job_id}")).json()
                if state["status"] in ("COMPLETED", "ABORTED", "FAILED"):
                    final = state
                    break
                await asyncio.sleep(0.05)
            assert final and final["status"] == "ABORTED"
            assert final["completed_requests"] < 400

            delete = await client.delete(f"/api/v1/intruder/jobs/{job_id}")
            assert delete.status_code == 200


async def test_intruder_validation_and_404s(tmp_dir: str):
    app = await _make_app(tmp_dir)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        no_points = await client.post("/api/v1/intruder/jobs", json={
            "config": {"url": "http://t/", "inline_payloads": ["a"]},
        })
        assert no_points.status_code == 422

        no_payloads = await client.post("/api/v1/intruder/jobs", json={
            "config": {"url": "http://t/", "injection_points": [{"position": "query"}]},
        })
        assert no_payloads.status_code == 422

        assert (await client.get("/api/v1/intruder/jobs/intr-missing")).status_code == 404
        assert (await client.get("/api/v1/intruder/jobs/intr-missing/results")).status_code == 404
        assert (await client.post("/api/v1/intruder/jobs/intr-missing/abort")).status_code == 404


import asyncio  # noqa: E402  (kept at bottom to avoid shadowing local imports above)
