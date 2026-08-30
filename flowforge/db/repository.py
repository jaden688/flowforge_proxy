"""
Asynchronous repository query layer for Flows, Endpoints, Parameters, and Full-Text Search.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple

from flowforge.config import get_settings
from flowforge.db.connection import get_connection
from flowforge.models.flow import (
    FlowFilterParams,
    FlowRecord,
    FlowSummary,
    RequestModel,
    ResponseModel,
)
from flowforge.models.telemetry import FlowTelemetry
from flowforge.models.parameter import DiscoveredEndpointModel, ExtractedParameterModel
from flowforge.models.proposal import (
    AnomalyType,
    ProposalExecutionResult,
    ProposalSeverity,
    ProposalState,
    TestProposal,
)
from flowforge.models.websocket import WebSocketMessageModel
from flowforge.utils.serializers import json_dumps, json_loads


def _row_to_flow_record(row: Any) -> FlowRecord:
    """Convert SQLite row to full FlowRecord instance."""
    q_params = json_loads(row["query_params"]) if row["query_params"] else {}
    req_headers = json_loads(row["request_headers"]) if row["request_headers"] else {}
    req_cookies = json_loads(row["request_cookies"]) if row["request_cookies"] else {}

    request = RequestModel(
        method=row["method"],
        url=row["url"],
        path=row["path"],
        query_string=row["query_string"] or "",
        query_params=q_params,
        headers=req_headers,
        content_type=row["request_content_type"],
        content_length=row["request_content_length"] or 0,
        body=row["request_body"],
        body_is_binary=bool(row["request_body_is_binary"]),
        cookies=req_cookies,
    )

    response: Optional[ResponseModel] = None
    if row["response_status_code"] is not None:
        resp_headers = json_loads(row["response_headers"]) if row["response_headers"] else {}
        resp_cookies = json_loads(row["response_cookies"]) if row["response_cookies"] else {}
        response = ResponseModel(
            status_code=row["response_status_code"],
            reason=row["response_reason"],
            headers=resp_headers,
            content_type=row["response_content_type"],
            content_length=row["response_content_length"] or 0,
            body=row["response_body"],
            body_is_binary=bool(row["response_body_is_binary"]),
            cookies=resp_cookies,
        )

    tags = json_loads(row["tags"]) if row["tags"] else []
    triage_data = json_loads(row["triage_data"]) if row["triage_data"] else {}

    telemetry: Optional[FlowTelemetry] = None
    try:
        if "telemetry" in row.keys() and row["telemetry"]:
            t_data = json_loads(row["telemetry"]) if isinstance(row["telemetry"], str) else row["telemetry"]
            if isinstance(t_data, dict) and t_data:
                telemetry = FlowTelemetry.model_validate(t_data)
    except Exception:
        telemetry = None

    return FlowRecord(
        id=row["id"],
        timestamp_start=row["timestamp_start"],
        timestamp_end=row["timestamp_end"],
        duration_ms=row["duration_ms"],
        client_ip=row["client_ip"],
        client_port=row["client_port"],
        server_host=row["server_host"],
        server_port=row["server_port"],
        scheme=row["scheme"],
        http_version=row["http_version"],
        request=request,
        response=response,
        error_message=row["error_message"],
        is_websocket=bool(row["is_websocket"]),
        websocket_message_count=row["websocket_message_count"] or 0,
        tags=tags,
        triage_data=triage_data,
        is_intercepted=bool(row["is_intercepted"]),
        is_favorite=bool(row["is_favorite"]),
        notes=row["notes"],
        telemetry=telemetry,
    )


def _row_to_flow_summary(row: Any) -> FlowSummary:
    """Convert SQLite row to FlowSummary instance."""
    tags = json_loads(row["tags"]) if row["tags"] else []

    telemetry: Optional[FlowTelemetry] = None
    try:
        if "telemetry" in row.keys() and row["telemetry"]:
            t_data = json_loads(row["telemetry"]) if isinstance(row["telemetry"], str) else row["telemetry"]
            if isinstance(t_data, dict) and t_data:
                telemetry = FlowTelemetry.model_validate(t_data)
    except Exception:
        telemetry = None

    ttfb_ms = telemetry.timings.ttfb_ms if (telemetry and telemetry.timings) else None
    req_len = row["request_content_length"] or 0
    resp_len = row["response_content_length"] or 0
    total_bytes = telemetry.bandwidth.total_bytes if (telemetry and telemetry.bandwidth and telemetry.bandwidth.total_bytes) else (req_len + resp_len)
    tls_version = telemetry.tls.version if (telemetry and telemetry.tls) else None
    cipher_suite = telemetry.tls.cipher_suite if (telemetry and telemetry.tls) else None

    return FlowSummary(
        id=row["id"],
        timestamp_start=row["timestamp_start"],
        timestamp_end=row["timestamp_end"],
        duration_ms=row["duration_ms"],
        method=row["method"],
        url=row["url"],
        host=row["server_host"],
        path=row["path"],
        scheme=row["scheme"],
        status_code=row["response_status_code"],
        request_content_length=req_len,
        response_content_length=resp_len,
        response_content_type=row["response_content_type"],
        is_websocket=bool(row["is_websocket"]),
        tags=tags,
        is_favorite=bool(row["is_favorite"]),
        has_error=bool(row["error_message"]),
        error_message=row["error_message"],
        ttfb_ms=ttfb_ms,
        total_bytes=total_bytes,
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        telemetry=telemetry,
    )


def _row_to_proposal(row: Any) -> TestProposal:
    """Convert SQLite row to TestProposal instance."""
    tags = json_loads(row["tags"]) if row["tags"] else []

    baseline_val = row["baseline_value"]
    if baseline_val is not None:
        try:
            baseline_val = json_loads(baseline_val)
        except Exception:
            pass

    mutated_val = row["mutated_value"]
    if mutated_val is not None:
        try:
            mutated_val = json_loads(mutated_val)
        except Exception:
            pass

    exec_result: Optional[ProposalExecutionResult] = None
    if row["execution_result"]:
        try:
            er_data = (
                json_loads(row["execution_result"])
                if isinstance(row["execution_result"], str)
                else row["execution_result"]
            )
            if isinstance(er_data, dict) and er_data:
                exec_result = ProposalExecutionResult.model_validate(er_data)
        except Exception:
            exec_result = None

    anomaly_type_val = row["anomaly_type"]
    try:
        anomaly_type_enum = AnomalyType(anomaly_type_val)
    except Exception:
        anomaly_type_enum = AnomalyType.CUSTOM_RULE

    severity_val = row["severity"]
    try:
        severity_enum = ProposalSeverity(severity_val)
    except Exception:
        severity_enum = ProposalSeverity.MEDIUM

    state_val = row["state"]
    try:
        state_enum = ProposalState(state_val)
    except Exception:
        state_enum = ProposalState.PENDING

    return TestProposal(
        id=row["id"],
        flow_id=row["flow_id"],
        endpoint_hash=row["endpoint_hash"],
        endpoint_path=row["endpoint_path"],
        method=row["method"],
        anomaly_type=anomaly_type_enum,
        title=row["title"],
        description=row["description"],
        severity=severity_enum,
        confidence_score=row["confidence_score"] if row["confidence_score"] is not None else 70.0,
        target_param_name=row["target_param_name"] or "",
        target_param_location=row["target_param_location"] or "query",
        baseline_value=baseline_val,
        mutated_value=mutated_val,
        auth_override=row["auth_override"],
        state=state_enum,
        tags=tags,
        execution_result=exec_result,
        executed_flow_id=row["executed_flow_id"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class FlowRepository:
    """Database repository for querying and managing flow state."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path

    async def get_flow_by_id(self, flow_id: str) -> Optional[FlowRecord]:
        """Fetch complete flow record by ID."""
        sql = "SELECT * FROM flows WHERE id = ?;"
        try:
            async with get_connection(self.db_path) as conn:
                async with conn.execute(sql, (flow_id,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        return None
                    return _row_to_flow_record(row)
        except Exception:
            return None

    async def list_flows(
        self,
        params: Optional[FlowFilterParams] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Tuple[List[FlowSummary], int]:
        """List flows with filtering and pagination."""
        if params is None:
            p = FlowFilterParams(
                page_size=limit if limit is not None else 50,
                page=1 if offset is None else ((offset // (limit or 50)) + 1),
            )
        else:
            p = params
        conditions: List[str] = []
        sql_params: List[Any] = []


        if p.host:
            conditions.append("(server_host = ? OR server_host LIKE ?)")
            sql_params.extend([p.host, f"%{p.host}%"])
        if p.method:
            conditions.append("method = ?")
            sql_params.append(p.method.upper())
        if p.status_code is not None:
            conditions.append("response_status_code = ?")
            sql_params.append(p.status_code)
        if p.status_min is not None:
            conditions.append("response_status_code >= ?")
            sql_params.append(p.status_min)
        if p.status_max is not None:
            conditions.append("response_status_code <= ?")
            sql_params.append(p.status_max)
        if p.scheme:
            conditions.append("scheme = ?")
            sql_params.append(p.scheme.lower())
        if p.is_websocket is not None:
            conditions.append("is_websocket = ?")
            sql_params.append(1 if p.is_websocket else 0)
        if p.is_favorite is not None:
            conditions.append("is_favorite = ?")
            sql_params.append(1 if p.is_favorite else 0)
        if p.since is not None:
            conditions.append("timestamp_start >= ?")
            sql_params.append(p.since)
        if p.tag:
            conditions.append("tags LIKE ?")
            sql_params.append(f'%"{p.tag}"%')
        if p.search:
            conditions.append("(url LIKE ? OR path LIKE ? OR server_host LIKE ?)")
            term = f"%{p.search}%"
            sql_params.extend([term, term, term])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        # Order clause
        valid_order_columns = {"timestamp_start", "duration_ms", "response_status_code", "url", "method"}
        order_col = p.order_by if p.order_by in valid_order_columns else "timestamp_start"
        order_dir = "DESC" if p.desc else "ASC"
        order_clause = f"ORDER BY {order_col} {order_dir}"

        offset = max(0, (p.page - 1) * p.page_size)
        limit = max(1, p.page_size)

        async with get_connection(self.db_path) as conn:
            # Get total count
            count_sql = f"SELECT COUNT(*) AS cnt FROM flows {where_clause};"
            async with conn.execute(count_sql, sql_params) as cursor:
                row = await cursor.fetchone()
                total = row["cnt"] if row else 0

            # Get rows
            query_sql = f"""
            SELECT id, timestamp_start, timestamp_end, duration_ms,
                   method, url, server_host, path, scheme,
                   response_status_code, request_content_length, response_content_length,
                   response_content_type, is_websocket, tags, is_favorite, error_message, telemetry
            FROM flows
            {where_clause}
            {order_clause}
            LIMIT ? OFFSET ?;
            """
            exec_params = sql_params + [limit, offset]
            async with conn.execute(query_sql, exec_params) as cursor:
                rows = await cursor.fetchall()
                summaries = [_row_to_flow_summary(r) for r in rows]

        return summaries, total

    async def search_flows_fts(
        self,
        query: str,
        page: int = 1,
        page_size: int = 50,
        filter_column: str = "all",
    ) -> Tuple[List[FlowSummary], int]:
        """Perform sub-second full-text search against flows_fts virtual table."""
        offset = max(0, (page - 1) * page_size)
        limit = max(1, page_size)

        # Sanitize / wrap FTS query if needed
        clean_query = query.strip().replace('"', '""')
        if not clean_query:
            return await self.list_flows(FlowFilterParams(page=page, page_size=page_size))

        if filter_column == "url":
            fts_match = f"url : {clean_query}"
        elif filter_column == "request":
            fts_match = f"request_headers : {clean_query} OR request_body : {clean_query}"
        elif filter_column == "response":
            fts_match = f"response_headers : {clean_query} OR response_body : {clean_query}"
        else:
            fts_match = clean_query

        count_sql = """
        SELECT COUNT(*) AS cnt
        FROM flows f
        JOIN flows_fts ON flows_fts.rowid = f.rowid
        WHERE flows_fts MATCH ?;
        """

        query_sql = """
        SELECT f.id, f.timestamp_start, f.timestamp_end, f.duration_ms,
               f.method, f.url, f.server_host, f.path, f.scheme,
               f.response_status_code, f.request_content_length, f.response_content_length,
               f.response_content_type, f.is_websocket, f.tags, f.is_favorite, f.error_message, f.telemetry
        FROM flows f
        JOIN flows_fts ON flows_fts.rowid = f.rowid
        WHERE flows_fts MATCH ?
        ORDER BY f.timestamp_start DESC
        LIMIT ? OFFSET ?;
        """

        async with get_connection(self.db_path) as conn:
            try:
                async with conn.execute(count_sql, (fts_match,)) as cursor:
                    row = await cursor.fetchone()
                    total = row["cnt"] if row else 0

                async with conn.execute(query_sql, (fts_match, limit, offset)) as cursor:
                    rows = await cursor.fetchall()
                    summaries = [_row_to_flow_summary(r) for r in rows]
                return summaries, total
            except Exception:
                # If syntax error in FTS expression, fallback to simple escaped term
                escaped = f'"{clean_query}"'
                async with conn.execute(count_sql, (escaped,)) as cursor:
                    row = await cursor.fetchone()
                    total = row["cnt"] if row else 0

                async with conn.execute(query_sql, (escaped, limit, offset)) as cursor:
                    rows = await cursor.fetchall()
                    summaries = [_row_to_flow_summary(r) for r in rows]
                return summaries, total

    async def insert_flow(self, flow: FlowRecord) -> bool:
        """Insert or replace full flow record directly in SQLite."""
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
            tags = excluded.tags,
            triage_data = excluded.triage_data;
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
            json.dumps(flow.request.query_params or {}),
            json.dumps(flow.request.headers or {}),
            flow.request.content_type,
            flow.request.content_length,
            flow.request.body,
            1 if flow.request.body_is_binary else 0,
            json.dumps(flow.request.cookies or {}),
            resp.status_code if resp else None,
            resp.reason if resp else None,
            json.dumps(resp.headers or {}) if resp else None,
            resp.content_type if resp else None,
            resp.content_length if resp else None,
            resp.body if resp else None,
            1 if (resp and resp.body_is_binary) else 0,
            json.dumps(resp.cookies or {}) if resp else None,
            flow.error_message,
            1 if flow.is_websocket else 0,
            flow.websocket_message_count,
            json.dumps(flow.tags or []),
            json.dumps(flow.triage_data or {}),
            1 if flow.is_intercepted else 0,
            1 if flow.is_favorite else 0,
            flow.notes,
            json.dumps(flow.telemetry.model_dump()) if flow.telemetry else None,
        )
        async with get_connection(self.db_path) as conn:
            res = await conn.execute(sql, params)
            await conn.commit()
            return res.rowcount > 0

    async def delete_flow(self, flow_id: str) -> bool:
        """Delete flow by ID (cascades to websocket_messages & parameters)."""
        async with get_connection(self.db_path) as conn:
            res = await conn.execute("DELETE FROM flows WHERE id = ?;", (flow_id,))
            await conn.commit()
            return res.rowcount > 0

    async def clear_flows(self, host_filter: Optional[str] = None) -> int:
        """Purge captured flows, optionally filtered by host."""
        async with get_connection(self.db_path) as conn:
            if host_filter:
                res = await conn.execute("DELETE FROM flows WHERE server_host = ?;", (host_filter,))
            else:
                res = await conn.execute("DELETE FROM flows;")
            await conn.commit()
            return res.rowcount

    async def update_flow_triage(
        self,
        flow_id: str,
        tags: List[str],
        triage_data: Dict[str, Any],
    ) -> bool:
        """Update triage metadata and tags for a flow."""
        sql = "UPDATE flows SET tags = ?, triage_data = ? WHERE id = ?;"
        async with get_connection(self.db_path) as conn:
            res = await conn.execute(sql, (json.dumps(tags), json.dumps(triage_data), flow_id))
            await conn.commit()
            return res.rowcount > 0

    async def set_favorite(self, flow_id: str, is_favorite: bool) -> bool:
        """Toggle favorite bookmark flag on a flow."""
        sql = "UPDATE flows SET is_favorite = ? WHERE id = ?;"
        async with get_connection(self.db_path) as conn:
            res = await conn.execute(sql, (1 if is_favorite else 0, flow_id))
            await conn.commit()
            return res.rowcount > 0

    async def update_notes(self, flow_id: str, notes: str) -> bool:
        """Update operator notes for a flow."""
        sql = "UPDATE flows SET notes = ? WHERE id = ?;"
        async with get_connection(self.db_path) as conn:
            res = await conn.execute(sql, (notes, flow_id))
            await conn.commit()
            return res.rowcount > 0

    async def get_websocket_messages(
        self,
        flow_id: str,
        page: int = 1,
        page_size: int = 100,
        direction: str = "all",
    ) -> Tuple[List[WebSocketMessageModel], int]:
        """Fetch frame-by-frame WebSocket message history for a flow."""
        offset = max(0, (page - 1) * page_size)
        limit = max(1, page_size)

        conditions = ["flow_id = ?"]
        params: List[Any] = [flow_id]

        if direction == "client":
            conditions.append("from_client = 1")
        elif direction == "server":
            conditions.append("from_client = 0")

        where_str = f"WHERE {' AND '.join(conditions)}"

        async with get_connection(self.db_path) as conn:
            count_sql = f"SELECT COUNT(*) AS cnt FROM websocket_messages {where_str};"
            async with conn.execute(count_sql, params) as cursor:
                row = await cursor.fetchone()
                total = row["cnt"] if row else 0

            query_sql = f"""
            SELECT id, flow_id, timestamp, from_client, opcode, content_length, content, is_binary
            FROM websocket_messages
            {where_str}
            ORDER BY timestamp ASC
            LIMIT ? OFFSET ?;
            """
            exec_params = params + [limit, offset]
            async with conn.execute(query_sql, exec_params) as cursor:
                rows = await cursor.fetchall()
                messages = [
                    WebSocketMessageModel(
                        id=r["id"],
                        flow_id=r["flow_id"],
                        timestamp=r["timestamp"],
                        from_client=bool(r["from_client"]),
                        opcode=r["opcode"],
                        content_length=r["content_length"],
                        content=r["content"],
                        is_binary=bool(r["is_binary"]),
                    )
                    for r in rows
                ]

        return messages, total

    async def list_endpoints(
        self,
        host: Optional[str] = None,
        category: Optional[str] = None,
        search: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Tuple[List[DiscoveredEndpointModel], int]:
        """List discovered endpoints from the Target Dossier."""
        conditions: List[str] = []
        params: List[Any] = []

        if host:
            conditions.append("host = ?")
            params.append(host)
        if category:
            conditions.append("category = ?")
            params.append(category)
        if search:
            conditions.append("(path_pattern LIKE ? OR host LIKE ?)")
            term = f"%{search}%"
            params.extend([term, term])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        async with get_connection(self.db_path) as conn:
            count_sql = f"SELECT COUNT(*) AS cnt FROM endpoints {where_clause};"
            async with conn.execute(count_sql, params) as cursor:
                row = await cursor.fetchone()
                total = row["cnt"] if row else 0

            limit_clause = ""
            query_params = list(params)
            if limit is not None:
                limit_clause = "LIMIT ? OFFSET ?"
                query_params.extend([limit, offset or 0])

            query_sql = f"""
            SELECT endpoint_hash, method, host, path_pattern, first_seen, last_seen, request_count, category, schema_summary
            FROM endpoints
            {where_clause}
            ORDER BY last_seen DESC
            {limit_clause};
            """
            async with conn.execute(query_sql, query_params) as cursor:
                rows = await cursor.fetchall()
                endpoints: List[DiscoveredEndpointModel] = []
                for r in rows:
                    schema_sum = json_loads(r["schema_summary"]) if r["schema_summary"] else {}
                    endpoints.append(
                        DiscoveredEndpointModel(
                            endpoint_hash=r["endpoint_hash"],
                            method=r["method"],
                            host=r["host"],
                            path_pattern=r["path_pattern"],
                            first_seen=r["first_seen"],
                            last_seen=r["last_seen"],
                            request_count=r["request_count"],
                            category=r["category"],
                            schema_summary=schema_sum,
                        )
                    )

        return endpoints, total

    async def get_endpoint_by_hash(self, endpoint_hash: str) -> Optional[DiscoveredEndpointModel]:
        """Fetch endpoint details by hash along with cataloged parameters."""
        sql = "SELECT * FROM endpoints WHERE endpoint_hash = ?;"
        async with get_connection(self.db_path) as conn:
            async with conn.execute(sql, (endpoint_hash,)) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                schema_sum = json_loads(row["schema_summary"]) if row["schema_summary"] else {}
                endpoint = DiscoveredEndpointModel(
                    endpoint_hash=row["endpoint_hash"],
                    method=row["method"],
                    host=row["host"],
                    path_pattern=row["path_pattern"],
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"],
                    request_count=row["request_count"],
                    category=row["category"],
                    schema_summary=schema_sum,
                )

            # Attach parameters
            param_sql = "SELECT * FROM parameters WHERE endpoint_hash = ? ORDER BY name ASC;"
            async with conn.execute(param_sql, (endpoint_hash,)) as cursor:
                param_rows = await cursor.fetchall()
                endpoint.parameters = [
                    ExtractedParameterModel(
                        id=pr["id"],
                        flow_id=pr["flow_id"],
                        endpoint_hash=pr["endpoint_hash"],
                        location=pr["location"],
                        name=pr["name"],
                        value=pr["value"],
                        data_type=pr["data_type"],
                        is_entropy_token=bool(pr["is_entropy_token"]),
                        is_identifier=bool(pr["is_identifier"]),
                        timestamp=pr["timestamp"],
                    )
                    for pr in param_rows
                ]

        return endpoint

    async def list_parameters(
        self,
        endpoint_hash: Optional[str] = None,
        name: Optional[str] = None,
        location: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Tuple[List[ExtractedParameterModel], int]:
        """List parameters across observed traffic."""
        conditions: List[str] = []
        params: List[Any] = []

        if endpoint_hash:
            conditions.append("endpoint_hash = ?")
            params.append(endpoint_hash)
        if name:
            conditions.append("name LIKE ?")
            params.append(f"%{name}%")
        if location:
            conditions.append("location = ?")
            params.append(location)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        async with get_connection(self.db_path) as conn:
            count_sql = f"SELECT COUNT(*) AS cnt FROM parameters {where_clause};"
            async with conn.execute(count_sql, params) as cursor:
                row = await cursor.fetchone()
                total = row["cnt"] if row else 0

            limit_val = limit if limit is not None else 500
            offset_val = offset if offset is not None else 0
            query_params = list(params) + [limit_val, offset_val]

            query_sql = f"""
            SELECT id, flow_id, endpoint_hash, location, name, value, data_type, is_entropy_token, is_identifier, timestamp
            FROM parameters
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?;
            """
            async with conn.execute(query_sql, query_params) as cursor:
                rows = await cursor.fetchall()
                params_list = [
                    ExtractedParameterModel(
                        id=r["id"],
                        flow_id=r["flow_id"],
                        endpoint_hash=r["endpoint_hash"],
                        location=r["location"],
                        name=r["name"],
                        value=r["value"],
                        data_type=r["data_type"],
                        is_entropy_token=bool(r["is_entropy_token"]),
                        is_identifier=bool(r["is_identifier"]),
                        timestamp=r["timestamp"],
                    )
                    for r in rows
                ]

        return params_list, total

    async def get_stats(self) -> Dict[str, Any]:
        """Fetch summary statistics across the entire database."""
        async with get_connection(self.db_path) as conn:
            async with conn.execute("SELECT COUNT(*) AS cnt FROM flows;") as c:
                flow_count = (await c.fetchone())["cnt"]
            async with conn.execute("SELECT COUNT(*) AS cnt FROM endpoints;") as c:
                endpoint_count = (await c.fetchone())["cnt"]
            async with conn.execute("SELECT COUNT(*) AS cnt FROM parameters;") as c:
                param_count = (await c.fetchone())["cnt"]
            async with conn.execute("SELECT COUNT(*) AS cnt FROM websocket_messages;") as c:
                ws_count = (await c.fetchone())["cnt"]

        return {
            "total_flows": flow_count,
            "total_endpoints": endpoint_count,
            "total_parameters": param_count,
            "total_websocket_messages": ws_count,
        }

    async def get_proposal_by_id(self, proposal_id: str) -> Optional[TestProposal]:
        """Fetch test proposal record by ID."""
        sql = "SELECT * FROM proposals WHERE id = ?;"
        async with get_connection(self.db_path) as conn:
            async with conn.execute(sql, (proposal_id,)) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                return _row_to_proposal(row)

    async def list_proposals(
        self,
        flow_id: Optional[str] = None,
        state: Optional[str] = None,
        anomaly_type: Optional[str] = None,
        severity: Optional[str] = None,
        min_confidence: Optional[float] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Tuple[List[TestProposal], int]:
        """List proposals with multi-criteria filtering and pagination."""
        conditions: List[str] = []
        sql_params: List[Any] = []

        if flow_id:
            conditions.append("flow_id = ?")
            sql_params.append(flow_id)
        if state:
            conditions.append("state = ?")
            sql_params.append(state.upper())
        if anomaly_type:
            conditions.append("anomaly_type = ?")
            sql_params.append(anomaly_type.upper())
        if severity:
            conditions.append("severity = ?")
            sql_params.append(severity.upper())
        if min_confidence is not None:
            conditions.append("confidence_score >= ?")
            sql_params.append(min_confidence)
        if search:
            conditions.append("(title LIKE ? OR description LIKE ? OR target_param_name LIKE ? OR endpoint_path LIKE ?)")
            term = f"%{search}%"
            sql_params.extend([term, term, term, term])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        offset = max(0, (page - 1) * page_size)
        limit = max(1, page_size)

        async with get_connection(self.db_path) as conn:
            count_sql = f"SELECT COUNT(*) AS cnt FROM proposals {where_clause};"
            async with conn.execute(count_sql, sql_params) as cursor:
                row = await cursor.fetchone()
                total = row["cnt"] if row else 0

            query_sql = f"""
            SELECT * FROM proposals
            {where_clause}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?;
            """
            exec_params = sql_params + [limit, offset]
            async with conn.execute(query_sql, exec_params) as cursor:
                rows = await cursor.fetchall()
                proposals = [_row_to_proposal(r) for r in rows]

        return proposals, total

    async def update_proposal_state(
        self,
        proposal_id: str,
        state: ProposalState,
        execution_result: Optional[ProposalExecutionResult] = None,
        executed_flow_id: Optional[str] = None,
    ) -> bool:
        """Update lifecycle state and optional execution result of a proposal."""
        state_str = state.value if hasattr(state, "value") else str(state)
        now = time.time()

        async with get_connection(self.db_path) as conn:
            if execution_result is not None or executed_flow_id is not None:
                exec_str = json_dumps(execution_result.model_dump()) if execution_result else "{}"
                sql = """
                UPDATE proposals SET
                    state = ?,
                    execution_result = ?,
                    executed_flow_id = coalesce(?, executed_flow_id),
                    updated_at = ?
                WHERE id = ?;
                """
                res = await conn.execute(sql, (state_str, exec_str, executed_flow_id, now, proposal_id))
            else:
                sql = "UPDATE proposals SET state = ?, updated_at = ? WHERE id = ?;"
                res = await conn.execute(sql, (state_str, now, proposal_id))
            await conn.commit()
            return res.rowcount > 0

    async def delete_proposal(self, proposal_id: str) -> bool:
        """Delete a proposal by ID."""
        sql = "DELETE FROM proposals WHERE id = ?;"
        async with get_connection(self.db_path) as conn:
            res = await conn.execute(sql, (proposal_id,))
            await conn.commit()
            return res.rowcount > 0

    async def batch_update_proposals(self, proposal_ids: List[str], state: ProposalState) -> int:
        """Update the state of multiple proposals in a single transaction."""
        if not proposal_ids:
            return 0
        state_str = state.value if hasattr(state, "value") else str(state)
        now = time.time()
        placeholders = ",".join("?" for _ in proposal_ids)
        sql = f"UPDATE proposals SET state = ?, updated_at = ? WHERE id IN ({placeholders});"
        params = [state_str, now] + proposal_ids
        async with get_connection(self.db_path) as conn:
            res = await conn.execute(sql, params)
            await conn.commit()
            return res.rowcount

    async def get_proposal_stats(self) -> Dict[str, int]:
        """Fetch summary statistics of proposal counts by state."""
        stats = {
            "total": 0,
            "pending": 0,
            "approved": 0,
            "executing": 0,
            "completed": 0,
            "dismissed": 0,
        }
        sql = "SELECT state, COUNT(*) AS cnt FROM proposals GROUP BY state;"
        async with get_connection(self.db_path) as conn:
            async with conn.execute(sql) as cursor:
                rows = await cursor.fetchall()
                total = 0
                for r in rows:
                    st = str(r["state"]).lower()
                    cnt = r["cnt"]
                    total += cnt
                    if st in stats:
                        stats[st] = cnt
                stats["total"] = total
        return stats

