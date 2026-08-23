"""
Tier 1 Feature Isolation Tests: WebSocket Frame Interception & Event Broadcaster (Requirement R1).
"""

from __future__ import annotations

import asyncio
import time
import uuid
import pytest

from flowforge.core.broadcaster import EventBroadcaster
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.models.events import EventType, FlowEvent
from flowforge.models.flow import FlowRecord, RequestModel
from flowforge.models.websocket import WebSocketMessageModel


async def test_websocket_message_persistence_and_retrieval(tmp_db_path: str):
    """Verify WebSocket text and binary frames are stored with timestamps, directions, and retrieved in order."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()

    try:
        flow_id = str(uuid.uuid4())
        flow = FlowRecord(
            id=flow_id,
            server_host="ws.target.com",
            scheme="ws",
            is_websocket=True,
            request=RequestModel(method="GET", url="ws://ws.target.com/v1/feed", path="/v1/feed"),
        )
        await writer.enqueue_insert_flow(flow)

        # Add client message (Text)
        msg_client = WebSocketMessageModel(
            flow_id=flow_id,
            timestamp=time.time(),
            from_client=True,
            opcode=1,
            content_length=15,
            content='{"action":"sub"}',
            is_binary=False,
        )
        # Add server message (Binary base64)
        msg_server = WebSocketMessageModel(
            flow_id=flow_id,
            timestamp=time.time() + 0.01,
            from_client=False,
            opcode=2,
            content_length=4,
            content="AQIDBA==",
            is_binary=True,
        )

        await writer.enqueue_ws_message(msg_client)
        await writer.enqueue_ws_message(msg_server)
        await writer.flush()

        # Query all messages
        messages, total = await repo.get_websocket_messages(flow_id)
        assert total == 2
        assert messages[0].from_client is True
        assert messages[0].content == '{"action":"sub"}'
        assert messages[1].from_client is False
        assert messages[1].is_binary is True

        # Query client-only direction
        client_msgs, client_total = await repo.get_websocket_messages(flow_id, direction="client")
        assert client_total == 1
        assert client_msgs[0].opcode == 1

        # Check updated websocket_message_count on parent flow
        updated_flow = await repo.get_flow_by_id(flow_id)
        assert updated_flow is not None
        assert updated_flow.websocket_message_count == 2
    finally:
        await writer.stop()


async def test_event_broadcaster_pubsub_dispatch():
    """Verify EventBroadcaster delivers structured real-time events to active subscribers."""
    broadcaster = EventBroadcaster(max_queue_size=100)
    q1 = await broadcaster.subscribe()
    q2 = await broadcaster.subscribe()

    assert broadcaster.active_subscribers_count == 2

    # 1. Flow Created
    broadcaster.broadcast_flow_created({"id": "flow-101", "method": "GET", "url": "http://test.com"})
    ev1_a = await asyncio.wait_for(q1.get(), timeout=1.0)
    ev1_b = await asyncio.wait_for(q2.get(), timeout=1.0)
    assert ev1_a.event == EventType.FLOW_CREATED.value
    assert ev1_b.data["id"] == "flow-101"

    # 2. Flow Completed
    broadcaster.broadcast_flow_completed({"id": "flow-101", "status_code": 200, "duration_ms": 32.5})
    ev2 = await asyncio.wait_for(q1.get(), timeout=1.0)
    assert ev2.event == EventType.FLOW_COMPLETED.value
    assert ev2.data["status_code"] == 200

    # 3. Triage Annotated
    broadcaster.broadcast_triage_annotated("flow-101", {"tags": ["idor", "reflection"]})
    ev3 = await asyncio.wait_for(q1.get(), timeout=1.0)
    assert ev3.event == EventType.TRIAGE_ANNOTATED.value
    assert ev3.data["flow_id"] == "flow-101"

    # 4. Proxy Stats
    broadcaster.broadcast_stats({"uptime": 12.0, "active_flows": 5})
    ev4 = await asyncio.wait_for(q1.get(), timeout=1.0)
    assert ev4.event == EventType.PROXY_STATS.value

    # Unsubscribe
    await broadcaster.unsubscribe(q1)
    await broadcaster.unsubscribe(q2)
    assert broadcaster.active_subscribers_count == 0


async def test_event_broadcaster_backpressure_eviction():
    """Verify bounded subscriber queues drop the oldest event when full, avoiding memory leaks and proxy blocking."""
    broadcaster = EventBroadcaster(max_queue_size=3)
    q = await broadcaster.subscribe()

    # Publish 5 events (capacity is 3)
    for i in range(5):
        broadcaster.publish({"event": "tick", "data": {"index": i}})

    assert q.qsize() == 3

    # The oldest items (0, 1) should have been evicted; remaining items should be 2, 3, 4
    item1 = q.get_nowait()
    item2 = q.get_nowait()
    item3 = q.get_nowait()

    assert item1.data["index"] == 2
    assert item2.data["index"] == 3
    assert item3.data["index"] == 4

    await broadcaster.unsubscribe(q)
