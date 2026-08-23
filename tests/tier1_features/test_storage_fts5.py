"""
Tier 1 Feature Isolation Tests: SQLite WAL & FTS5 Full-Text Search Engine (Requirement R1).
"""

from __future__ import annotations

import asyncio
import time
import uuid
import pytest

from flowforge.db.connection import get_connection, init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.models.flow import FlowFilterParams, FlowRecord, RequestModel, ResponseModel
from flowforge.models.parameter import DiscoveredEndpointModel, ExtractedParameterModel


async def test_db_schema_initialization_and_wal(tmp_db_path: str):
    """Verify SQLite database initializes schema, B-tree indexes, WAL mode, and FTS5 table."""
    await init_db(tmp_db_path)

    async with get_connection(tmp_db_path) as conn:
        async with conn.execute("PRAGMA journal_mode;") as cursor:
            row = await cursor.fetchone()
            assert row[0].lower() == "wal"

        # Verify tables exist
        async with conn.execute("SELECT name FROM sqlite_master WHERE type='table';") as cursor:
            tables = {r[0] for r in await cursor.fetchall()}
            assert "flows" in tables
            assert "websocket_messages" in tables
            assert "parameters" in tables
            assert "endpoints" in tables
            assert "flows_fts" in tables


async def test_flow_crud_and_filtering(tmp_db_path: str, sample_flow_record: FlowRecord):
    """Verify flow creation, retrieval, filtering, notes update, and favorite toggling."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()

    try:
        # Write flow via batch writer
        await writer.enqueue_insert_flow(sample_flow_record)
        await writer.flush()

        # Fetch by ID
        flow = await repo.get_flow_by_id(sample_flow_record.id)
        assert flow is not None
        assert flow.id == sample_flow_record.id
        assert flow.request.method == "POST"
        assert flow.response is not None
        assert flow.response.status_code == 201

        # Filter flows
        summaries, total = await repo.list_flows(FlowFilterParams(method="POST", host="api.target.com"))
        assert total == 1
        assert summaries[0].id == sample_flow_record.id

        # Toggle favorite
        await repo.set_favorite(sample_flow_record.id, True)
        updated = await repo.get_flow_by_id(sample_flow_record.id)
        assert updated is not None and updated.is_favorite is True

        # Update notes
        await repo.update_notes(sample_flow_record.id, "Verified IDOR candidate")
        updated_notes = await repo.get_flow_by_id(sample_flow_record.id)
        assert updated_notes is not None and updated_notes.notes == "Verified IDOR candidate"
    finally:
        await writer.stop()


async def test_fts5_full_text_search_indexing(tmp_db_path: str):
    """Verify FTS5 automatic trigger synchronization over URLs, headers, and request/response bodies."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()

    try:
        unique_keyword = f"SecretToken_{uuid.uuid4().hex[:6]}"
        flow = FlowRecord(
            id=str(uuid.uuid4()),
            server_host="security.audit.com",
            request=RequestModel(
                method="POST",
                url=f"https://security.audit.com/api/v2/verify?token={unique_keyword}",
                path="/api/v2/verify",
                headers={"X-Security-Scan": "AutomatedFTSCheck"},
                body=f'{{"diagnostic_flag": "{unique_keyword}_payload"}}',
            ),
            response=ResponseModel(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=f'{{"status": "ok", "echo": "{unique_keyword}_response"}}',
            ),
        )

        await writer.enqueue_insert_flow(flow)
        await writer.flush()

        # Search by token in URL/Query
        results, count = await repo.search_flows_fts(unique_keyword)
        assert count >= 1
        assert results[0].id == flow.id

        # Search by request body token
        results_body, count_body = await repo.search_flows_fts(f"{unique_keyword}_payload")
        assert count_body >= 1
        assert results_body[0].id == flow.id

        # Search by response body token
        results_resp, count_resp = await repo.search_flows_fts(f"{unique_keyword}_response")
        assert count_resp >= 1
        assert results_resp[0].id == flow.id
    finally:
        await writer.stop()


async def test_fts5_update_and_delete_triggers(tmp_db_path: str):
    """Verify FTS5 triggers correctly delete old entries on UPDATE and clean up on DELETE."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()

    try:
        token_v1 = f"VersionOneToken_{uuid.uuid4().hex[:6]}"
        token_v2 = f"VersionTwoToken_{uuid.uuid4().hex[:6]}"
        flow_id = str(uuid.uuid4())

        flow = FlowRecord(
            id=flow_id,
            server_host="service.local",
            request=RequestModel(
                method="GET",
                url="http://service.local/search",
                path="/search",
                body="",
            ),
            response=ResponseModel(status_code=200, body=token_v1),
        )

        await writer.enqueue_insert_flow(flow)
        await writer.flush()

        # Confirm v1 exists
        res1, c1 = await repo.search_flows_fts(token_v1)
        assert c1 == 1

        # Update flow with token_v2 in response body
        flow.response.body = token_v2
        await writer.enqueue_update_flow(flow)
        await writer.flush()

        # Search v2 should match, v1 should no longer match
        res2, c2 = await repo.search_flows_fts(token_v2)
        assert c2 == 1
        res1_after, c1_after = await repo.search_flows_fts(token_v1)
        assert c1_after == 0

        # Delete flow
        deleted = await repo.delete_flow(flow_id)
        assert deleted is True

        # Search v2 should now return 0
        res2_after, c2_after = await repo.search_flows_fts(token_v2)
        assert c2_after == 0
    finally:
        await writer.stop()


async def test_endpoint_and_parameter_catalog_persistence(tmp_db_path: str):
    """Verify persistence and querying of discovered endpoints and extracted parameters."""
    await init_db(tmp_db_path)
    repo = FlowRepository(tmp_db_path)
    writer = AsyncDBWriter(db_path=tmp_db_path, max_batch_size=10, flush_interval_ms=10)
    await writer.start()

    try:
        ep_hash = "sha256_reference_endpoint_hash_001"
        flow_id = str(uuid.uuid4())

        # Create parent flow first to satisfy foreign key constraint
        parent_flow = FlowRecord(
            id=flow_id,
            server_host="api.target.com",
            request=RequestModel(method="POST", url="https://api.target.com/api/v1/orders/1001", path="/api/v1/orders/1001"),
        )
        await writer.enqueue_insert_flow(parent_flow)

        endpoint = DiscoveredEndpointModel(
            endpoint_hash=ep_hash,
            method="POST",
            host="api.target.com",
            path_pattern="/api/v1/orders/{order_id}",
            first_seen=time.time(),
            last_seen=time.time(),
            category="MUTATION_ACTION",
            schema_summary={"properties": {"order_id": {"type": "integer"}}},
        )
        param = ExtractedParameterModel(
            flow_id=flow_id,
            endpoint_hash=ep_hash,
            location="path",
            name="order_id",
            value="1001",
            data_type="integer",
            is_identifier=True,
            timestamp=time.time(),
        )

        await writer.enqueue_endpoint(endpoint)
        await writer.enqueue_parameter(param)
        await writer.flush()

        # Query endpoints
        endpoints, total_ep = await repo.list_endpoints(host="api.target.com")
        assert total_ep >= 1
        assert any(e.endpoint_hash == ep_hash for e in endpoints)

        # Query endpoint details with attached parameters
        ep_detail = await repo.get_endpoint_by_hash(ep_hash)
        assert ep_detail is not None
        assert len(ep_detail.parameters) >= 1
        assert ep_detail.parameters[0].name == "order_id"
        assert ep_detail.parameters[0].is_identifier is True
    finally:
        await writer.stop()
