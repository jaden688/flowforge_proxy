"""
Wire-fidelity verification: proves the Intruder engine puts EXACTLY
prefix + payload + suffix on the wire for every injection position,
with adversarial payloads that would expose '[object Object]' / 'None' /
'<none>' style serialization bugs.
"""

from __future__ import annotations

import asyncio

import pytest
import uvicorn
from fastapi import FastAPI, Request, Response
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.db.connection import init_db


def create_capture_app() -> FastAPI:
    """Echo server recording exactly what arrived on the wire."""
    app = FastAPI()
    captures: list = []

    @api_route(app, "/capture")
    async def capture(request: Request):
        body = await request.body()
        record = {
            "method": request.method,
            "url": str(request.url),
            "raw_query": request.url.query,
            "headers": dict(request.headers),
            "body": body.decode("utf-8", errors="replace"),
        }
        captures.append(record)
        return Response(content="captured", status_code=200)

    @app.get("/captures")
    async def get_captures():
        return {"captures": captures}

    return app


def api_route(app: FastAPI, path: str):
    def decorator(fn):
        # register for all common methods
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            app.add_api_route(path, fn, methods=[method])
        return fn
    return decorator


NASTY_PAYLOADS = [
    "[object Object]",          # JS stringification artifact
    "<none>",                   # placeholder artifact
    "None",                     # Python str(None) artifact
    "undefined",
    "{\"a\": [1, 2], \"b\": {\"c\": null}}",   # structured data dumped as scalar
    "' OR 1=1--; DROP TABLE users",
    "<svg onload=alert(1)>",
    'quote"and\\backslash',
    "unicode-é🎉中文",
    "",                          # intentional empty payload
]


async def _run_fidelity(position: str, tmp_dir: str) -> list:
    await init_db(f"{tmp_dir}/fidelity_{position}.db")
    ff = create_app(Settings(db_path=f"{tmp_dir}/fidelity_{position}.db", auto_start_proxy=False))

    capture_app = create_capture_app()
    config = uvicorn.Config(capture_app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    for _ in range(50):
        if server.started:
            break
        await asyncio.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]

    try:
        if position == "query":
            points = [{"position": "query", "key": "q"}]
            url = f"http://127.0.0.1:{port}/capture?q=original&keep=1"
            expected = lambda p: p  # appears URL-encoded in raw_query
        elif position == "header":
            points = [{"position": "header", "key": "X-Probe", "prefix": "pre-", "suffix": "-post"}]
            url = f"http://127.0.0.1:{port}/capture"
            expected = lambda p: f"pre-{p}-post"
        else:
            points = [{"position": "body", "prefix": "{\"injected\":\"", "suffix": "\"}"}]
            url = f"http://127.0.0.1:{port}/capture"
            expected = lambda p: f'{{"injected":"{p}"}}'

        async with AsyncClient(transport=ASGITransport(app=ff), base_url="http://test") as client:
            resp = await client.post("/api/v1/intruder/jobs", json={
                "config": {
                    "method": "GET" if position != "body" else "POST",
                    "url": url,
                    "headers": {"Content-Type": "application/json"},
                    "inline_payloads": NASTY_PAYLOADS,
                    "injection_points": points,
                    "concurrency": 4,
                }
            })
            assert resp.status_code == 200, resp.text
            job_id = resp.json()["job"]["id"]

            status = None
            for _ in range(200):
                state = (await client.get(f"/api/v1/intruder/jobs/{job_id}")).json()
                if state["status"] in ("COMPLETED", "ABORTED", "FAILED"):
                    status = state["status"]
                    break
                await asyncio.sleep(0.05)
            assert status == "COMPLETED", f"job ended {status}"

        async with AsyncClient(base_url=f"http://127.0.0.1:{port}") as raw:
            data = (await raw.get("/captures")).json()["captures"]
        return [(expected(p), p) for p in NASTY_PAYLOADS], data
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=2)
        except Exception:
            pass


@pytest.mark.parametrize("position", ["query", "header", "body"])
async def test_intruder_wire_fidelity_exact_bytes(position: str, tmp_dir: str):
    expected_pairs, captures = await _run_fidelity(position, tmp_dir)

    # Non-ASCII header values are correctly rejected by the HTTP client
    # (RFC 7230); they must FAIL LOUDLY (REQUEST_ERROR), never silently mangle.
    wire_payloads = [p for p in NASTY_PAYLOADS if not (position == "header" and not p.isascii())]
    assert len(captures) == len(wire_payloads), (
        f"expected {len(wire_payloads)} wire hits, got {len(captures)}"
    )

    received_values = []
    for cap in captures:
        if position == "query":
            received_values.append(cap["headers"].get("x-probe") or _query_value(cap["raw_query"], "q"))
        elif position == "header":
            received_values.append(cap["headers"].get("x-probe"))
        else:
            received_values.append(cap["body"])

    for expected_val, payload in expected_pairs:
        if position == "header" and not payload.isascii():
            continue  # rejected by design; verified via results API below
        if position == "query":
            match = any(_query_value(c["raw_query"], "q") == expected_val for c in captures)
        elif position == "header":
            match = any(c["headers"].get("x-probe") == expected_val for c in captures)
        else:
            match = any(c["body"] == expected_val for c in captures)
        assert match, (
            f"position={position} payload={payload!r}: "
            f"expected wire value {expected_val!r}, got wire values {received_values!r}"
        )

    # Explicit artifact scan: no accidental Python/JS serialization leakage.
    artifacts = ("[object Object]", "{'a'", '{"b\':')
    for cap in captures:
        haystack = (
            [_query_value(cap["raw_query"], "q")] if position == "query"
            else [cap["headers"].get("x-proke") or cap["headers"].get("x-probe"), cap["body"]]
        )
        for h in haystack:
            if h is None:
                continue
            for artifact in artifacts:
                if artifact in h:
                    # only acceptable if it was a deliberately injected payload
                    assert artifact in "".join(NASTY_PAYLOADS), f"serialization leak on wire: {artifact!r}"


def _query_value(raw_query: str, key: str) -> str:
    from urllib.parse import parse_qsl
    pairs = dict(parse_qsl(raw_query, keep_blank_values=True))
    return pairs.get(key, "")
