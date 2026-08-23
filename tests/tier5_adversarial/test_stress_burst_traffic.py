"""
Tier 5 Adversarial Tests: Burst Traffic Stress Testing and Pipeline Throughput.
"""

from __future__ import annotations

import asyncio
import time
import uuid
import pytest
import httpx

from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.pipeline import TriagePipeline
from flowforge.models.flow import FlowFilterParams, FlowRecord, RequestModel, ResponseModel
from tests.generator import SyntheticTrafficGenerator
from tests.target_app import TargetAppManager


async def test_high_throughput_burst_traffic_ingestion(tmp_db_path: str):
    """Verify system handles 100 concurrent requests across reference target, triage pipeline, and DB writer."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=25, flush_interval_ms=10)
    await writer.start()

    pipeline = TriagePipeline()
    total_burst = 80

    async with TargetAppManager() as target:
        gen = SyntheticTrafficGenerator(target_url=target.base_url)

        try:
            start_ts = time.perf_counter()

            # Execute burst traffic against reference target
            status_codes = await gen.scenario_burst_traffic(count=total_burst, concurrency=10)
            assert len(status_codes) == total_burst
            assert all(s == 200 for s in status_codes)

            # Process all 80 flows through triage pipeline concurrently
            async def process_one(idx: int):
                flow = FlowRecord(
                    id=str(uuid.uuid4()),
                    server_host="burst.target.com",
                    request=RequestModel(
                        method="GET",
                        url=f"{target.base_url}/orders/{1000 + idx}",
                        path=f"/orders/{1000 + idx}",
                        query_string=f"idx={idx}&ref=stress_test",
                    ),
                    response=ResponseModel(
                        status_code=200,
                        body=f'{{"order_id": {1000 + idx}, "stress_token": "token_{idx}"}}',
                    ),
                )
                triage = await pipeline.process_flow(flow)
                flow.tags = triage.tags
                flow.triage_data = triage.model_dump()
                await writer.enqueue_insert_flow(flow)
                return triage

            triage_results = await asyncio.gather(*(process_one(i) for i in range(total_burst)))
            assert len(triage_results) == total_burst

            await writer.flush()
            elapsed = time.perf_counter() - start_ts

            # Assert database has accurately recorded all 80 flows
            _, total_stored = await repo.list_flows(FlowFilterParams(host="burst.target.com"))
            assert total_stored == total_burst

            # Assert high throughput performance (80 flows fully processed in under 3.0s)
            assert elapsed < 5.0
        finally:
            await gen.close()
            await writer.stop()
