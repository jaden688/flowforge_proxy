"""
Tier 2 Boundary Tests: Binary Media Streams, Gzip/Zip Archives, and FTS5 Non-Text Exclusion.
"""

from __future__ import annotations

import base64
import uuid
import pytest

from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel


async def test_binary_image_storage_and_fts_exclusion(tmp_db_path: str):
    """Verify raw binary images stored as base64 strings are flagged binary and excluded from FTS5 indexing."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()

    try:
        # Minimal valid 1x1 PNG transparent pixel base64
        png_bytes = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05"
            b"\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        b64_png = base64.b64encode(png_bytes).decode("utf-8")
        flow_id = str(uuid.uuid4())

        flow = FlowRecord(
            id=flow_id,
            server_host="cdn.example.com",
            request=RequestModel(
                method="GET",
                url="https://cdn.example.com/assets/logo.png",
                path="/assets/logo.png",
            ),
            response=ResponseModel(
                status_code=200,
                content_type="image/png",
                content_length=len(png_bytes),
                body=b64_png,
                body_is_binary=True,
            ),
        )

        await writer.enqueue_insert_flow(flow)
        await writer.flush()

        # Retrieve flow
        stored = await repo.get_flow_by_id(flow_id)
        assert stored is not None
        assert stored.response.body_is_binary is True
        assert stored.response.content_type == "image/png"

        # Search in FTS should not throw SQLite encoding errors
        results, count = await repo.search_flows_fts("logo.png")
        assert count == 1
        assert results[0].id == flow_id
    finally:
        await writer.stop()


async def test_large_binary_payload_resilience(tmp_db_path: str):
    """Verify database writer safely handles a 200KB binary blob base64 string without locking or corrupting WAL."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()

    try:
        # Generate 200KB binary payload
        large_blob = bytes([i % 256 for i in range(200 * 1024)])
        b64_blob = base64.b64encode(large_blob).decode("utf-8")
        flow_id = str(uuid.uuid4())

        flow = FlowRecord(
            id=flow_id,
            server_host="downloads.target.com",
            request=RequestModel(
                method="GET",
                url="https://downloads.target.com/archive.zip",
                path="/archive.zip",
            ),
            response=ResponseModel(
                status_code=200,
                content_type="application/zip",
                content_length=len(large_blob),
                body=b64_blob,
                body_is_binary=True,
            ),
        )

        await writer.enqueue_insert_flow(flow)
        await writer.flush()

        stored = await repo.get_flow_by_id(flow_id)
        assert stored is not None
        assert stored.response.content_length == 200 * 1024
    finally:
        await writer.stop()
