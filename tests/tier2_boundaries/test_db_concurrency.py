"""
Tier 2 Boundary Tests: SQLite WAL Concurrency & High-Frequency Batch Contention.
"""

from __future__ import annotations

import asyncio
import time
import uuid
import pytest

from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.models.flow import FlowFilterParams, FlowRecord, RequestModel, ResponseModel


async def test_concurrent_writer_and_reader_contention(tmp_db_path: str):
    """Verify simultaneous high-frequency concurrent writes and read queries execute without SQLite locks."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()

    total_flows = 60
    flow_ids = [str(uuid.uuid4()) for _ in range(total_flows)]

    try:
        # Producer: enqueue flows concurrently
        async def producer():
            for idx, fid in enumerate(flow_ids):
                flow = FlowRecord(
                    id=fid,
                    server_host="stress.target.com",
                    request=RequestModel(
                        method="GET",
                        url=f"https://stress.target.com/item/{idx}",
                        path=f"/item/{idx}",
                        body=f"stress_item_payload_{idx}",
                    ),
                    response=ResponseModel(status_code=200, body=f"stress_response_{idx}"),
                )
                await writer.enqueue_insert_flow(flow)
                if idx % 5 == 0:
                    await asyncio.sleep(0.005)

        # Consumer/Reader: concurrently read and search FTS during write phase
        async def reader():
            read_count = 0
            for _ in range(15):
                _, count = await repo.list_flows(FlowFilterParams(host="stress.target.com"))
                _, fts_count = await repo.search_flows_fts("stress_item_payload")
                read_count += count + fts_count
                await asyncio.sleep(0.01)
            return read_count

        # Run producer and reader concurrently
        await asyncio.gather(producer(), reader())
        await writer.flush()

        # Final verification: all 60 flows must be safely committed
        _, total_in_db = await repo.list_flows(FlowFilterParams(host="stress.target.com"))
        assert total_in_db == total_flows
    finally:
        await writer.stop()
