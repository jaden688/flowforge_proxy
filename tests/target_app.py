"""
Reference Target App for FlowForge Automated Verification (Requirement R4).
Provides deterministic HTTP endpoints for synthetic security testing scenarios.
"""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any, AsyncGenerator, Dict, Optional
from fastapi import FastAPI, Header, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
import uvicorn


def create_target_app() -> FastAPI:
    """Creates a standalone FastAPI reference target application with deterministic responses."""
    app = FastAPI(title="FlowForge Reference Target App", version="1.0.0")

    @app.get("/health")
    async def health_check():
        return {"status": "ok", "service": "flowforge-reference-target"}

    @app.get("/reflect/html", response_class=HTMLResponse)
    async def reflect_html(
        q: Optional[str] = Query(None),
        attr: Optional[str] = Query(None),
        script: Optional[str] = Query(None)
    ):
        q_val = q or "default_query"
        attr_val = attr or "default_attr"
        script_val = script or "default_script"
        html_content = f"""<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
    <h1>Search results for: <span class="query-echo">{q_val}</span></h1>
    <form action="/search">
        <input type="text" name="attr" value="{attr_val}" />
    </form>
    <script>
        var debugScriptParam = "{script_val}";
    </script>
</body>
</html>"""
        return HTMLResponse(content=html_content, status_code=200)

    @app.post("/reflect/json")
    async def reflect_json(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {"raw": (await request.body()).decode("utf-8", errors="replace")}
        return JSONResponse(
            content={
                "status": "success",
                "echoed_data": body,
                "message": f"Processed user input: {body.get('user', 'anonymous') if isinstance(body, dict) else 'non-json'}"
            },
            status_code=200
        )

    @app.get("/reflect/header")
    async def reflect_header(x_custom_tracking: Optional[str] = Header(None, alias="X-Custom-Tracking")):
        response = JSONResponse(content={"status": "header_processed", "tracking": x_custom_tracking or "none"})
        if x_custom_tracking:
            response.headers["X-Echoed-Tracking"] = x_custom_tracking
            response.headers["Location"] = f"https://target.com/callback?track={x_custom_tracking}"
        return response

    @app.post("/auth/login")
    async def auth_login(request: Request):
        # Deterministic JWT and API secret for entropy / signature verification
        # Header: {"alg":"HS256","typ":"JWT"}, Payload: {"sub":"admin","role":"admin","iat":1700000000}
        jwt_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0."
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        )
        stripe_key = "sk_live_51NzABC1234567890abcdefghijklmnopqrstuvwxyz"
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        return JSONResponse(
            content={
                "status": "authenticated",
                "token": jwt_token,
                "api_key": stripe_key,
                "aws_key_id": aws_key,
                "user": {"id": 1, "username": "admin", "role": "superuser"}
            },
            status_code=200
        )

    @app.get("/auth/protected")
    async def auth_protected(authorization: Optional[str] = Header(None)):
        # Deliberately returns 200 OK even when authorization is absent to test anomaly detection
        auth_status = "authenticated" if authorization else "unauthenticated_leak"
        return JSONResponse(
            content={
                "status": "ok",
                "auth_state": auth_status,
                "sensitive_account_data": {
                    "account_number": "ACC-998877",
                    "balance": 15420.50,
                    "ssn_last4": "1234"
                }
            },
            status_code=200
        )

    @app.get("/orders/{order_id}")
    async def get_order(order_id: str):
        # Deterministic orders for sequential IDOR tests
        orders_db = {
            "1001": {"order_id": 1001, "owner": "alice@example.com", "total": 49.99, "status": "shipped"},
            "1002": {"order_id": 1002, "owner": "bob@example.com", "total": 1290.00, "status": "pending"},
            "1003": {"order_id": 1003, "owner": "carol@example.com", "total": 85.00, "status": "delivered"},
        }
        if order_id in orders_db:
            return JSONResponse(content=orders_db[order_id], status_code=200)
        elif order_id.isdigit():
            return JSONResponse(
                content={"order_id": int(order_id), "owner": f"user_{order_id}@example.com", "total": 100.0, "status": "custom"},
                status_code=200
            )
        return JSONResponse(content={"error": "Order not found"}, status_code=404)

    @app.get("/users/{user_uuid}")
    async def get_user_by_uuid(user_uuid: str):
        return JSONResponse(
            content={
                "user_id": user_uuid,
                "username": f"user_{user_uuid[:8]}",
                "email": f"user_{user_uuid[:8]}@example.com",
                "is_active": True
            },
            status_code=200
        )

    @app.post("/orders/checkout")
    async def orders_checkout(request: Request):
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        return JSONResponse(
            content={
                "order_id": 1004,
                "status": "created",
                "received_payload": payload,
                "total_charged": 199.99
            },
            status_code=201
        )

    @app.get("/admin/users")
    async def admin_users():
        return JSONResponse(
            content={
                "role": "admin",
                "total_users": 3,
                "users": [
                    {"id": 1, "username": "admin", "role": "superadmin"},
                    {"id": 2, "username": "alice", "role": "user"},
                    {"id": 3, "username": "bob", "role": "user"},
                ]
            },
            status_code=200
        )

    @app.get("/binary/image")
    async def binary_image():
        # Minimal valid 1x1 PNG transparent pixel
        png_bytes = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05"
            b"\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        return Response(content=png_bytes, media_type="image/png")

    @app.get("/stream/events")
    async def stream_events():
        async def event_generator() -> AsyncGenerator[str, None]:
            for i in range(3):
                yield f"data: {json.dumps({'event_num': i, 'msg': f'tick_{i}'})}\n\n"
                await asyncio.sleep(0.01)
        return StreamingResponse(event_generator(), media_type="text/event-stream")

    return app


def get_free_port() -> int:
    """Finds an available ephemeral port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TargetAppManager:
    """Manages lifecycle of in-process uvicorn reference target server."""
    def __init__(self, host: str = "127.0.0.1", port: Optional[int] = None):
        self.host = host
        self.port = port or get_free_port()
        self.app = create_target_app()
        self.server: Optional[uvicorn.Server] = None
        self._task: Optional[asyncio.Task] = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    async def start(self):
        config = uvicorn.Config(
            app=self.app,
            host=self.host,
            port=self.port,
            log_level="warning",
            access_log=False
        )
        self.server = uvicorn.Server(config)
        self._task = asyncio.create_task(self.server.serve())
        
        # Wait until server is listening
        import httpx
        for _ in range(50):
            try:
                async with httpx.AsyncClient(timeout=0.2) as client:
                    res = await client.get(f"{self.base_url}/health")
                    if res.status_code == 200:
                        return
            except Exception:
                await asyncio.sleep(0.05)
    async def stop(self):
        if self.server:
            self.server.should_exit = True
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=2.0)
            except Exception:
                pass

    async def __aenter__(self) -> "TargetAppManager":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()
