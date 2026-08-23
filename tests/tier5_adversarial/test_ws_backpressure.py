"""
Tier 5 Adversarial Tests: WebSocket Pub/Sub Backpressure and Slow Consumer Queue Eviction.
"""

from __future__ import annotations

import asyncio
import time
import pytest

from flowforge.core.broadcaster import EventBroadcaster
from flowforge.models.events import EventType, FlowEvent


async def test_slow_consumer_queue_eviction_under_flood():
    """Verify broadcaster drops oldest messages when consumer is slow without blocking publisher."""
    capacity = 5
    broadcaster = EventBroadcaster(max_queue_size=capacity)

    slow_queue = await broadcaster.subscribe()
    fast_queue = await broadcaster.subscribe()

    # Fast consumer task reading continuously
    fast_consumed = []

    async def fast_consumer():
        for _ in range(30):
            ev = await fast_queue.get()
            fast_consumed.append(ev)

    fast_task = asyncio.create_task(fast_consumer())

    # Publisher floods 30 events rapidly
    start_ts = time.perf_counter()
    for idx in range(30):
        broadcaster.broadcast_flow_created({"index": idx, "token": f"flood_{idx}"})
        await asyncio.sleep(0.001)

    await asyncio.wait_for(fast_task, timeout=2.0)
    elapsed = time.perf_counter() - start_ts

    # Fast consumer got all 30
    assert len(fast_consumed) == 30
    assert fast_consumed[0].data["index"] == 0
    assert fast_consumed[-1].data["index"] == 29

    # Slow consumer never read: queue size must be capped at capacity (5)
    assert slow_queue.qsize() == capacity

    # The 5 remaining items must be the newest ones (25, 26, 27, 28, 29)
    drained = []
    while not slow_queue.empty():
        drained.append(slow_queue.get_nowait())

    assert len(drained) == 5
    indices = [d.data["index"] for d in drained]
    assert indices == [25, 26, 27, 28, 29]

    await broadcaster.unsubscribe(slow_queue)
    await broadcaster.unsubscribe(fast_queue)


async def test_subscriber_cancellation_resilience():
    """Verify broadcaster gracefully handles unexpected subscriber queue disposal / task cancellations."""
    broadcaster = EventBroadcaster(max_queue_size=10)
    q = await broadcaster.subscribe()

    # Broadcast event
    broadcaster.broadcast_stats({"memory_mb": 42.5})
    assert q.qsize() == 1

    # Unsubscribe
    await broadcaster.unsubscribe(q)

    # Subsequent broadcasts do not error
    broadcaster.broadcast_stats({"memory_mb": 45.0})
    assert broadcaster.active_subscribers_count == 0
