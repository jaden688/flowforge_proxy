"""
Real-time WebSocket and Server-Sent Events (SSE) live streaming endpoints.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncGenerator
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sse_starlette.sse import EventSourceResponse

from flowforge.core.broadcaster import EventBroadcaster, get_broadcaster
from flowforge.utils.serializers import json_dumps

logger = logging.getLogger("flowforge.api.routes.streaming")

router = APIRouter(tags=["Streaming"])


@router.websocket("/api/v1/ws/traffic")
async def websocket_traffic_stream(websocket: WebSocket) -> None:
    """Bi-directional WebSocket streaming live flow events and WS frames to web workbench."""
    await websocket.accept()
    broadcaster = get_broadcaster()
    queue = await broadcaster.subscribe()

    async def sender_task() -> None:
        try:
            while True:
                event = await queue.get()
                payload = json_dumps(event.model_dump())
                await websocket.send_text(payload)
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass
        except Exception as exc:
            logger.debug("WS sender error: %s", exc)

    async def receiver_task() -> None:
        try:
            while True:
                data = await websocket.receive_text()
                try:
                    msg = json.loads(data)
                    action = msg.get("action")
                    if action == "ping":
                        await websocket.send_text(json.dumps({"event": "pong"}))
                except Exception:
                    pass
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass
        except Exception as exc:
            logger.debug("WS receiver error: %s", exc)

    s_task = asyncio.create_task(sender_task())
    r_task = asyncio.create_task(receiver_task())

    try:
        done, pending = await asyncio.wait(
            [s_task, r_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
    finally:
        await broadcaster.unsubscribe(queue)
        try:
            await websocket.close()
        except Exception:
            pass


@router.get("/api/v1/stream/traffic")
@router.get("/api/v1/stream/sse")
async def sse_traffic_stream() -> EventSourceResponse:
    """Server-Sent Events (SSE) endpoint providing unidirectional event streaming."""
    broadcaster = get_broadcaster()

    async def event_generator() -> AsyncGenerator[dict, None]:
        queue = await broadcaster.subscribe()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield {
                        "event": event.event,
                        "data": json_dumps(event.data),
                    }
                except asyncio.TimeoutError:
                    # Send periodic keepalive ping
                    yield {
                        "event": "ping",
                        "data": json.dumps({"status": "keepalive"}),
                    }
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            await broadcaster.unsubscribe(queue)

    return EventSourceResponse(event_generator())
