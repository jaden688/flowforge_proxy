"""
Asynchronous single-writer batch ingestion queue for SQLite persistence.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any, List, Optional

from flowforge.config import get_settings
from flowforge.db.connection import get_connection
from flowforge.models.flow import FlowRecord
from flowforge.models.parameter import DiscoveredEndpointModel, ExtractedParameterModel
from flowforge.models.proposal import TestProposal
from flowforge.models.websocket import WebSocketMessageModel
from flowforge.utils.serializers import json_dumps

logger = logging.getLogger("flowforge.db.writer")


@dataclass
class WriteOp:
    """Represents an atomic write operation to the database."""
    op_type: str  # 'insert_flow', 'update_flow', 'upsert_flow', 'insert_ws', 'insert_param', 'upsert_endpoint'
    data: Any


class AsyncDBWriter:
    """Single-writer batch ingestion engine to eliminate SQLite write contention."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        max_batch_size: int = 50,
        flush_interval_ms: int = 50,
    ) -> None:
        self.db_path = db_path
        self.max_batch_size = max_batch_size
        self.flush_interval = flush_interval_ms / 1000.0
        self.queue: asyncio.Queue[WriteOp] = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task[None]] = None
        self._running = False
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Start the background ingestion batch worker."""
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._flush_loop(), name="flowforge_db_writer")
        logger.info("AsyncDBWriter started.")

    async def stop(self) -> None:
        """Gracefully drain the ingestion queue and stop background worker."""
        if not self._running:
            return
        self._running = False
        # Flush remaining items
        await self.flush()
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("AsyncDBWriter stopped.")

    async def enqueue_insert_flow(self, flow: FlowRecord) -> None:
        """Enqueue initial flow creation write."""
        await self.queue.put(WriteOp(op_type="insert_flow", data=flow))

    async def enqueue_update_flow(self, flow: FlowRecord) -> None:
        """Enqueue completed/updated flow write."""
        await self.queue.put(WriteOp(op_type="update_flow", data=flow))

    async def enqueue_upsert_flow(self, flow: FlowRecord) -> None:
        """Enqueue flow upsert."""
        await self.queue.put(WriteOp(op_type="upsert_flow", data=flow))

    async def enqueue_flow(self, flow: FlowRecord) -> None:
        """Enqueue flow write (alias for enqueue_upsert_flow)."""
        await self.enqueue_upsert_flow(flow)

    async def enqueue_ws_message(self, msg: WebSocketMessageModel) -> None:
        """Enqueue WebSocket frame write."""
        await self.queue.put(WriteOp(op_type="insert_ws", data=msg))

    async def enqueue_parameter(self, param: ExtractedParameterModel) -> None:
        """Enqueue parameter catalog write."""
        await self.queue.put(WriteOp(op_type="insert_param", data=param))

    async def enqueue_endpoint(self, endpoint: DiscoveredEndpointModel) -> None:
        """Enqueue discovered endpoint catalog write."""
        await self.queue.put(WriteOp(op_type="upsert_endpoint", data=endpoint))

    async def enqueue_insert_proposal(self, proposal: TestProposal) -> None:
        """Enqueue proposal insertion write."""
        await self.queue.put(WriteOp(op_type="insert_proposal", data=proposal))

    async def enqueue_update_proposal(self, proposal: TestProposal) -> None:
        """Enqueue proposal update write."""
        await self.queue.put(WriteOp(op_type="update_proposal", data=proposal))

    async def enqueue_proposals_batch(self, proposals: List[TestProposal]) -> None:
        """Enqueue multiple proposals for atomic batch persistence."""
        for p in proposals:
            await self.queue.put(WriteOp(op_type="insert_proposal", data=p))

    async def flush(self) -> None:
        """Force immediate synchronous flush of all queued write operations."""
        while not self.queue.empty():
            batch: List[WriteOp] = []
            while len(batch) < self.max_batch_size and not self.queue.empty():
                try:
                    batch.append(self.queue.get_nowait())
                    self.queue.task_done()
                except asyncio.QueueEmpty:
                    break
            if batch:
                await self._process_batch(batch)

    async def _flush_loop(self) -> None:
        """Background loop continuously consuming and batching queued writes."""
        while self._running:
            try:
                batch: List[WriteOp] = []
                try:
                    # Wait for first item with timeout
                    first_op = await asyncio.wait_for(self.queue.get(), timeout=self.flush_interval)
                    batch.append(first_op)
                    self.queue.task_done()

                    # Drain up to max_batch_size items without blocking
                    while len(batch) < self.max_batch_size and not self.queue.empty():
                        batch.append(self.queue.get_nowait())
                        self.queue.task_done()
                except asyncio.TimeoutError:
                    continue

                if batch:
                    await self._process_batch(batch)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in AsyncDBWriter flush loop: %s", exc, exc_info=True)
                await asyncio.sleep(0.01)

    async def _process_batch(self, batch: List[WriteOp]) -> None:
        """Execute a batch of writes within a single SQLite transaction."""
        if not batch:
            return

        async with self._lock:
            db_path = self.db_path or get_settings().db_path
            async with get_connection(db_path) as conn:
                try:
                    await conn.execute("BEGIN IMMEDIATE")
                    for op in batch:
                        if op.op_type in ("insert_flow", "upsert_flow"):
                            await self._write_upsert_flow(conn, op.data)
                        elif op.op_type == "update_flow":
                            await self._write_update_flow(conn, op.data)
                        elif op.op_type == "insert_ws":
                            await self._write_ws_message(conn, op.data)
                        elif op.op_type == "insert_param":
                            await self._write_parameter(conn, op.data)
                        elif op.op_type == "upsert_endpoint":
                            await self._write_endpoint(conn, op.data)
                        elif op.op_type in ("insert_proposal", "update_proposal", "upsert_proposal"):
                            await self._write_upsert_proposal(conn, op.data)
                    await conn.commit()
                except Exception as exc:
                    await conn.rollback()
                    logger.error("Failed to commit DB batch of size %d: %s", len(batch), exc, exc_info=True)

    async def _write_upsert_flow(self, conn: Any, flow: FlowRecord) -> None:
        """Insert or replace full flow record."""
        sql = """
        INSERT INTO flows (
            id, timestamp_start, timestamp_end, duration_ms,
            client_ip, client_port, server_host, server_port, scheme, http_version,
            method, url, path, query_string, query_params,
            request_headers, request_content_type, request_content_length, request_body, request_body_is_binary, request_cookies,
            response_status_code, response_reason, response_headers, response_content_type, response_content_length, response_body, response_body_is_binary, response_cookies,
            error_message, is_websocket, websocket_message_count,
            tags, triage_data, is_intercepted, is_favorite, notes, telemetry
        ) VALUES (
            ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?, ?, ?
        )
        ON CONFLICT(id) DO UPDATE SET
            timestamp_end = excluded.timestamp_end,
            duration_ms = excluded.duration_ms,
            response_status_code = excluded.response_status_code,
            response_reason = excluded.response_reason,
            response_headers = excluded.response_headers,
            response_content_type = excluded.response_content_type,
            response_content_length = excluded.response_content_length,
            response_body = excluded.response_body,
            response_body_is_binary = excluded.response_body_is_binary,
            response_cookies = excluded.response_cookies,
            error_message = excluded.error_message,
            websocket_message_count = excluded.websocket_message_count,
            tags = excluded.tags,
            triage_data = excluded.triage_data,
            is_intercepted = excluded.is_intercepted,
            is_favorite = excluded.is_favorite,
            notes = excluded.notes,
            telemetry = excluded.telemetry;
        """
        resp = flow.response
        params = (
            flow.id,
            flow.timestamp_start,
            flow.timestamp_end,
            flow.duration_ms,
            flow.client_ip,
            flow.client_port,
            flow.server_host,
            flow.server_port,
            flow.scheme,
            flow.http_version,
            flow.request.method,
            flow.request.url,
            flow.request.path,
            flow.request.query_string,
            json_dumps(flow.request.query_params),
            json_dumps(flow.request.headers),
            flow.request.content_type,
            flow.request.content_length,
            flow.request.body,
            1 if flow.request.body_is_binary else 0,
            json_dumps(flow.request.cookies),
            resp.status_code if resp else None,
            resp.reason if resp else None,
            json_dumps(resp.headers) if resp else "{}",
            resp.content_type if resp else None,
            resp.content_length if resp else 0,
            resp.body if resp else None,
            1 if (resp and resp.body_is_binary) else 0,
            json_dumps(resp.cookies) if resp else "{}",
            flow.error_message,
            1 if flow.is_websocket else 0,
            flow.websocket_message_count,
            json_dumps(flow.tags),
            json_dumps(flow.triage_data),
            1 if flow.is_intercepted else 0,
            1 if flow.is_favorite else 0,
            flow.notes,
            json_dumps(flow.telemetry.model_dump()) if flow.telemetry else "{}",
        )
        await conn.execute(sql, params)

    async def _write_update_flow(self, conn: Any, flow: FlowRecord) -> None:
        """Update existing flow record with completion / response information."""
        sql = """
        UPDATE flows SET
            timestamp_end = ?,
            duration_ms = ?,
            response_status_code = ?,
            response_reason = ?,
            response_headers = ?,
            response_content_type = ?,
            response_content_length = ?,
            response_body = ?,
            response_body_is_binary = ?,
            response_cookies = ?,
            error_message = ?,
            websocket_message_count = ?,
            tags = ?,
            triage_data = ?,
            is_intercepted = ?,
            is_favorite = ?,
            notes = ?,
            telemetry = ?
        WHERE id = ?;
        """
        resp = flow.response
        params = (
            flow.timestamp_end,
            flow.duration_ms,
            resp.status_code if resp else None,
            resp.reason if resp else None,
            json_dumps(resp.headers) if resp else "{}",
            resp.content_type if resp else None,
            resp.content_length if resp else 0,
            resp.body if resp else None,
            1 if (resp and resp.body_is_binary) else 0,
            json_dumps(resp.cookies) if resp else "{}",
            flow.error_message,
            flow.websocket_message_count,
            json_dumps(flow.tags),
            json_dumps(flow.triage_data),
            1 if flow.is_intercepted else 0,
            1 if flow.is_favorite else 0,
            flow.notes,
            json_dumps(flow.telemetry.model_dump()) if flow.telemetry else "{}",
            flow.id,
        )
        await conn.execute(sql, params)

    async def _write_ws_message(self, conn: Any, msg: WebSocketMessageModel) -> None:
        """Insert WebSocket frame message."""
        sql = """
        INSERT INTO websocket_messages (
            flow_id, timestamp, from_client, opcode, content_length, content, is_binary
        ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """
        params = (
            msg.flow_id,
            msg.timestamp,
            1 if msg.from_client else 0,
            msg.opcode,
            msg.content_length,
            msg.content,
            1 if msg.is_binary else 0,
        )
        await conn.execute(sql, params)

        # Increment flow websocket message count
        await conn.execute(
            "UPDATE flows SET websocket_message_count = websocket_message_count + 1 WHERE id = ?;",
            (msg.flow_id,),
        )

    async def _write_parameter(self, conn: Any, param: ExtractedParameterModel) -> None:
        """Insert extracted parameter."""
        sql = """
        INSERT INTO parameters (
            flow_id, endpoint_hash, location, name, value, data_type, is_entropy_token, is_identifier, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        params = (
            param.flow_id,
            param.endpoint_hash,
            param.location,
            param.name,
            param.value,
            param.data_type,
            1 if param.is_entropy_token else 0,
            1 if param.is_identifier else 0,
            param.timestamp,
        )
        await conn.execute(sql, params)

    async def _write_endpoint(self, conn: Any, endpoint: DiscoveredEndpointModel) -> None:
        """Insert or update discovered endpoint catalog."""
        sql = """
        INSERT INTO endpoints (
            endpoint_hash, method, host, path_pattern, first_seen, last_seen, request_count, category, schema_summary
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(endpoint_hash) DO UPDATE SET
            last_seen = excluded.last_seen,
            request_count = endpoints.request_count + 1,
            category = coalesce(excluded.category, endpoints.category),
            schema_summary = excluded.schema_summary;
        """
        params = (
            endpoint.endpoint_hash,
            endpoint.method,
            endpoint.host,
            endpoint.path_pattern,
            endpoint.first_seen,
            endpoint.last_seen,
            endpoint.request_count,
            endpoint.category,
            json_dumps(endpoint.schema_summary),
        )
        await conn.execute(sql, params)

    async def _write_upsert_proposal(self, conn: Any, proposal: TestProposal) -> None:
        """Insert or update test proposal record."""
        sql = """
        INSERT INTO proposals (
            id, flow_id, endpoint_hash, endpoint_path, method,
            anomaly_type, title, description, severity, confidence_score,
            target_param_name, target_param_location, baseline_value, mutated_value, auth_override,
            state, tags, execution_result, executed_flow_id, created_at, updated_at
        ) VALUES (
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?
        )
        ON CONFLICT(id) DO UPDATE SET
            endpoint_hash = excluded.endpoint_hash,
            endpoint_path = excluded.endpoint_path,
            method = excluded.method,
            anomaly_type = excluded.anomaly_type,
            title = excluded.title,
            description = excluded.description,
            severity = excluded.severity,
            confidence_score = excluded.confidence_score,
            target_param_name = excluded.target_param_name,
            target_param_location = excluded.target_param_location,
            baseline_value = excluded.baseline_value,
            mutated_value = excluded.mutated_value,
            auth_override = excluded.auth_override,
            state = excluded.state,
            tags = excluded.tags,
            execution_result = excluded.execution_result,
            executed_flow_id = excluded.executed_flow_id,
            updated_at = excluded.updated_at;
        """
        baseline_str = (
            json_dumps(proposal.baseline_value)
            if isinstance(proposal.baseline_value, (dict, list))
            else (str(proposal.baseline_value) if proposal.baseline_value is not None else None)
        )
        mutated_str = (
            json_dumps(proposal.mutated_value)
            if isinstance(proposal.mutated_value, (dict, list))
            else (str(proposal.mutated_value) if proposal.mutated_value is not None else None)
        )
        exec_res_str = (
            json_dumps(proposal.execution_result.model_dump())
            if proposal.execution_result
            else "{}"
        )
        params = (
            proposal.id,
            proposal.flow_id,
            proposal.endpoint_hash,
            proposal.endpoint_path,
            proposal.method,
            proposal.anomaly_type.value if hasattr(proposal.anomaly_type, "value") else str(proposal.anomaly_type),
            proposal.title,
            proposal.description,
            proposal.severity.value if hasattr(proposal.severity, "value") else str(proposal.severity),
            proposal.confidence_score,
            proposal.target_param_name,
            proposal.target_param_location,
            baseline_str,
            mutated_str,
            proposal.auth_override,
            proposal.state.value if hasattr(proposal.state, "value") else str(proposal.state),
            json_dumps(proposal.tags),
            exec_res_str,
            proposal.executed_flow_id,
            proposal.created_at,
            proposal.updated_at,
        )
        await conn.execute(sql, params)

