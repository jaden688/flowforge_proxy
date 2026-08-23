"""
Mitmproxy Addon intercepting HTTP/1.1, HTTP/2, and WebSocket traffic streams.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import time
import uuid
from typing import Any, Callable, Dict, Optional

from mitmproxy import http

from flowforge.config import get_settings
from flowforge.core.broadcaster import EventBroadcaster, get_broadcaster
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.models import IdentifierType
from flowforge.heuristics.proposal_synthesizer import ProposalSynthesizer
from flowforge.heuristics.schema_inferrer import SchemaInferrer
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.parameter import DiscoveredEndpointModel, ExtractedParameterModel
from flowforge.models.telemetry import BandwidthTelemetry, FlowTelemetry, TLSTelemetry, TimingTelemetry
from flowforge.models.websocket import WebSocketMessageModel
from flowforge.utils.http_parser import decode_body, parse_cookies, parse_query_params

logger = logging.getLogger("flowforge.core.addon")


def compute_endpoint_hash(method: str, host: str, path_pattern: str) -> str:
    """Compute deterministic SHA256 endpoint hash."""
    key = f"{method.upper()}:{host.lower()}:{path_pattern}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class FlowForgeInterceptorAddon:
    """Mitmproxy event hook handler converting wire traffic into FlowForge persistence events."""

    def __init__(
        self,
        db_writer: Optional[AsyncDBWriter] = None,
        broadcaster: Optional[EventBroadcaster] = None,
        triage_callback: Optional[Callable[[FlowRecord], Any]] = None,
    ) -> None:
        self.db_writer = db_writer
        self.broadcaster = broadcaster or get_broadcaster()
        self.triage_callback = triage_callback
        self.proposal_synthesizer = ProposalSynthesizer()
        self.settings = get_settings()
        self.schema_inferrer = SchemaInferrer()
        self._endpoint_schemas: Dict[str, Dict[str, Any]] = {}
        self._endpoint_counts: Dict[str, int] = {}

    def _get_flow_id(self, flow: http.HTTPFlow) -> str:
        """Retrieve existing FlowForge ID or assign a new UUID."""
        if "flowforge_id" not in flow.metadata:
            flow.metadata["flowforge_id"] = str(uuid.uuid4())
        return flow.metadata["flowforge_id"]

    def _extract_telemetry(self, flow: http.HTTPFlow, flow_record: Optional[FlowRecord] = None, duration_ms: float = 0.0) -> FlowTelemetry:
        """Extract TLS parameters, lifecycle timings, and bandwidth metrics from mitmproxy HTTPFlow."""
        tls_telemetry: Optional[TLSTelemetry] = None
        server_conn = getattr(flow, "server_conn", None)
        client_conn = getattr(flow, "client_conn", None)

        tls_version = None
        cipher_suite = None
        sni = None
        alpn = None
        resumed = False

        conn = server_conn or client_conn
        if conn:
            tls_version = getattr(conn, "tls_version", None)
            cipher_suite = getattr(conn, "cipher_name", None) or getattr(conn, "cipher", None)
            sni = getattr(conn, "sni", None)
            raw_alpn = getattr(conn, "alpn", None)
            if isinstance(raw_alpn, bytes):
                alpn = raw_alpn.decode("ascii", errors="replace")
            elif isinstance(raw_alpn, str):
                alpn = raw_alpn
            resumed = bool(getattr(conn, "tls_established", False) and getattr(conn, "resumed", False))

        if tls_version or cipher_suite or sni or alpn:
            tls_telemetry = TLSTelemetry(
                version=str(tls_version) if tls_version else None,
                cipher_suite=str(cipher_suite) if cipher_suite else None,
                sni=str(sni) if sni else None,
                alpn=str(alpn) if alpn else None,
                resumed=resumed,
            )

        req = getattr(flow, "request", None)
        resp = getattr(flow, "response", None)

        dns_ms = None
        tcp_connect_ms = None
        tls_handshake_ms = None
        request_send_ms = None
        ttfb_ms = None
        response_transfer_ms = None

        if server_conn:
            t_start = getattr(server_conn, "timestamp_start", None)
            t_tcp = getattr(server_conn, "timestamp_tcp_setup", None)
            t_tls = getattr(server_conn, "timestamp_tls_setup", None)
            if t_start and t_tcp:
                tcp_connect_ms = max(0.0, (t_tcp - t_start) * 1000.0)
            if t_tcp and t_tls:
                tls_handshake_ms = max(0.0, (t_tls - t_tcp) * 1000.0)

        if req:
            t_req_start = getattr(req, "timestamp_start", None)
            t_req_end = getattr(req, "timestamp_end", None)
            if t_req_start and t_req_end:
                request_send_ms = max(0.0, (t_req_end - t_req_start) * 1000.0)

        if resp:
            t_resp_start = getattr(resp, "timestamp_start", None)
            t_resp_end = getattr(resp, "timestamp_end", None)
            t_req_end = getattr(req, "timestamp_end", None) if req else None
            t_req_start = getattr(req, "timestamp_start", None) if req else None

            if t_resp_start and t_req_end:
                ttfb_ms = max(0.0, (t_resp_start - t_req_end) * 1000.0)
            elif t_resp_start and t_req_start:
                ttfb_ms = max(0.0, (t_resp_start - t_req_start) * 1000.0)
            elif duration_ms > 0:
                ttfb_ms = max(0.0, duration_ms * 0.75)

            if t_resp_start and t_resp_end:
                response_transfer_ms = max(0.0, (t_resp_end - t_resp_start) * 1000.0)

        timing_telemetry = TimingTelemetry(
            dns_ms=dns_ms,
            tcp_connect_ms=tcp_connect_ms,
            tls_handshake_ms=tls_handshake_ms,
            request_send_ms=request_send_ms,
            ttfb_ms=ttfb_ms,
            response_transfer_ms=response_transfer_ms,
            total_duration_ms=max(0.0, duration_ms),
        )

        req_hdr_bytes = 0
        if req and hasattr(req, "headers"):
            try:
                req_hdr_bytes = len(req.headers.as_bytes())
            except Exception:
                req_hdr_bytes = sum(len(k) + len(v) + 4 for k, v in req.headers.items())

        req_body_bytes = len(req.raw_content) if (req and req.raw_content) else 0

        resp_hdr_bytes = 0
        if resp and hasattr(resp, "headers"):
            try:
                resp_hdr_bytes = len(resp.headers.as_bytes())
            except Exception:
                resp_hdr_bytes = sum(len(k) + len(v) + 4 for k, v in resp.headers.items())

        resp_body_bytes = len(resp.raw_content) if (resp and resp.raw_content) else 0

        bandwidth_telemetry = BandwidthTelemetry(
            request_headers_bytes=req_hdr_bytes,
            request_body_bytes=req_body_bytes,
            response_headers_bytes=resp_hdr_bytes,
            response_body_bytes=resp_body_bytes,
            total_bytes=req_hdr_bytes + req_body_bytes + resp_hdr_bytes + resp_body_bytes,
        )

        return FlowTelemetry(
            tls=tls_telemetry,
            timings=timing_telemetry,
            bandwidth=bandwidth_telemetry,
        )

    def request(self, flow: http.HTTPFlow) -> None:
        """Lifecycle hook invoked when request headers and body have arrived."""
        try:
            # Handle requests sent directly to the proxy's own port (e.g., http://127.0.0.1:8080/ or http://mitm.it)
            if flow.request.pretty_host in ("127.0.0.1", "localhost", "flowforge.local", "mitm.it") and flow.request.port == self.settings.proxy_port:
                html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>FlowForge Proxy Active</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1120; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
.card {{ background: #1e293b; padding: 2.5rem; border-radius: 1rem; border: 1px solid #334155; max-width: 520px; text-align: center; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }}
h1 {{ color: #38bdf8; font-size: 1.75rem; margin: 0.5rem 0; font-family: monospace; }}
p {{ color: #94a3b8; font-size: 0.95rem; line-height: 1.6; margin-bottom: 1.5rem; }}
.badge {{ display: inline-block; background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); padding: 0.3rem 0.85rem; border-radius: 9999px; font-weight: 600; font-size: 0.8rem; font-family: monospace; }}
.btn {{ display: inline-block; background: #0284c7; color: white; padding: 0.75rem 1.5rem; border-radius: 0.5rem; text-decoration: none; font-weight: 600; font-size: 0.9rem; transition: background 0.2s; }}
.btn:hover {{ background: #0369a1; }}
.info {{ background: #0f172a; padding: 0.75rem; border-radius: 0.5rem; font-family: monospace; font-size: 0.8rem; color: #64748b; margin-top: 1.5rem; border: 1px solid #1e293b; }}
</style>
</head>
<body>
<div class="card">
<div class="badge">● PROXY READY & INTERCEPTING</div>
<h1>FLOWFORGE PROXY</h1>
<p>Your browser is properly connected to the FlowForge Interception Engine. All HTTP/HTTPS traffic from this browser is now being analyzed, triaged, and streamed live to the Cockpit.</p>
<a href="http://127.0.0.1:{self.settings.api_port}" class="btn">Open Operator Cockpit</a>
<div class="info">Proxy: 127.0.0.1:{self.settings.proxy_port} | API: 127.0.0.1:{self.settings.api_port}</div>
</div>
</body>
</html>"""
                flow.response = http.Response.make(
                    200,
                    html.encode("utf-8"),
                    {"Content-Type": "text/html; charset=utf-8"}
                )
                return

            flow_id = self._get_flow_id(flow)
            req = flow.request

            # Extract headers as dictionary
            headers = {k: v for k, v in req.headers.items()}
            content_type = req.headers.get("content-type", "")
            raw_body = req.raw_content

            # Decode request body
            decoded_body, is_binary = decode_body(
                raw_body,
                content_type=content_type,
                max_size=self.settings.max_body_size,
            )

            # Parse query params & cookies
            query_params = parse_query_params(req.url)
            cookies = parse_cookies(req.headers.get("cookie"))

            # Determine scheme & client
            scheme = req.scheme.lower()
            client_ip = flow.client_conn.address[0] if flow.client_conn and flow.client_conn.address else "127.0.0.1"
            client_port = flow.client_conn.address[1] if flow.client_conn and flow.client_conn.address else None

            request_model = RequestModel(
                method=req.method.upper(),
                url=req.url,
                path=req.path or "/",
                query_string=req.query.encode() if hasattr(req, "query") and req.query else (req.path.split("?", 1)[1] if "?" in req.path else ""),
                query_params=query_params,
                headers=headers,
                content_type=content_type or None,
                content_length=len(raw_body) if raw_body else 0,
                body=decoded_body,
                body_is_binary=is_binary,
                cookies=cookies,
            )

            flow_record = FlowRecord(
                id=flow_id,
                timestamp_start=req.timestamp_start or time.time(),
                client_ip=client_ip,
                client_port=client_port,
                server_host=req.host,
                server_port=req.port,
                scheme=scheme,
                http_version=req.http_version or "HTTP/1.1",
                request=request_model,
                response=None,
                is_websocket=bool(flow.websocket),
                telemetry=self._extract_telemetry(flow, None, 0.0),
            )

            flow.metadata["flowforge_record"] = flow_record

            # Push to persistence queue
            if self.db_writer:
                asyncio.create_task(self.db_writer.enqueue_insert_flow(flow_record))

            # Broadcast creation event
            self.broadcaster.broadcast_flow_created(flow_record.to_summary())
        except Exception as exc:
            logger.error("Error in mitmproxy request hook: %s", exc, exc_info=True)

    def response(self, flow: http.HTTPFlow) -> None:
        """Lifecycle hook invoked when response headers and body have completed."""
        try:
            flow_id = self._get_flow_id(flow)
            resp = flow.response
            if not resp:
                return

            flow_record: Optional[FlowRecord] = flow.metadata.get("flowforge_record")
            if not flow_record:
                # In case request hook was skipped or initialized late
                self.request(flow)
                flow_record = flow.metadata.get("flowforge_record")

            headers = {k: v for k, v in resp.headers.items()}
            content_type = resp.headers.get("content-type", "")
            raw_body = resp.raw_content

            decoded_body, is_binary = decode_body(
                raw_body,
                content_type=content_type,
                max_size=self.settings.max_body_size,
            )

            cookies = parse_cookies(resp.headers.get("set-cookie"))

            response_model = ResponseModel(
                status_code=resp.status_code,
                reason=resp.reason,
                headers=headers,
                content_type=content_type or None,
                content_length=len(raw_body) if raw_body else 0,
                body=decoded_body,
                body_is_binary=is_binary,
                cookies=cookies,
            )

            timestamp_end = resp.timestamp_end or time.time()
            duration_ms = (timestamp_end - flow_record.timestamp_start) * 1000.0 if flow_record else 0.0

            flow_record.response = response_model
            flow_record.timestamp_end = timestamp_end
            flow_record.duration_ms = max(0.0, duration_ms)
            flow_record.is_websocket = bool(flow.websocket)
            flow_record.telemetry = self._extract_telemetry(flow, flow_record, flow_record.duration_ms)

            # Invoke passive heuristic triage callback if registered
            if self.triage_callback:
                try:
                    if asyncio.iscoroutinefunction(self.triage_callback):
                        asyncio.create_task(self._run_async_triage(flow_record))
                    else:
                        triage_result = self.triage_callback(flow_record)
                        if triage_result:
                            self._apply_triage(flow_record, triage_result)
                            asyncio.create_task(self._process_endpoint_and_schema(flow_record, triage_result))
                            try:
                                proposals = self.proposal_synthesizer.synthesize(flow_record, triage_result)
                                if proposals:
                                    if self.db_writer:
                                        asyncio.create_task(self.db_writer.enqueue_proposals_batch(proposals))
                                    self.broadcaster.broadcast_proposal_created(flow_record.id, proposals)
                            except Exception as p_exc:
                                logger.warning("Sync proposal synthesis failed: %s", p_exc)
                except Exception as t_exc:
                    logger.warning("Error running triage callback: %s", t_exc)

            # Push update to DB
            if self.db_writer:
                asyncio.create_task(self.db_writer.enqueue_update_flow(flow_record))

            # Broadcast completion event
            self.broadcaster.broadcast_flow_completed(flow_record.to_summary())
        except Exception as exc:
            logger.error("Error in mitmproxy response hook: %s", exc, exc_info=True)

    async def _run_async_triage(self, flow_record: FlowRecord) -> None:
        """Run async triage pipeline, synthesize proposals, and broadcast annotation."""
        try:
            if not self.triage_callback:
                return
            triage_summary = await self.triage_callback(flow_record)
            if triage_summary:
                self._apply_triage(flow_record, triage_summary)
                if self.db_writer:
                    await self.db_writer.enqueue_update_flow(flow_record)
                self.broadcaster.broadcast_triage_annotated(flow_record.id, triage_summary)

                # Process endpoint discovery and cumulative schema evolution
                await self._process_endpoint_and_schema(flow_record, triage_summary)

                # Synthesize automated test proposals
                try:
                    proposals = self.proposal_synthesizer.synthesize(flow_record, triage_summary)
                    if proposals:
                        if self.db_writer:
                            await self.db_writer.enqueue_proposals_batch(proposals)
                        self.broadcaster.broadcast_proposal_created(flow_record.id, proposals)
                except Exception as p_exc:
                    logger.warning("Async proposal synthesis failed: %s", p_exc)
        except Exception as exc:
            logger.warning("Async triage pipeline failed: %s", exc)

    async def _process_endpoint_and_schema(self, flow_record: FlowRecord, triage_summary: Any) -> None:
        """Extract canonical endpoint, accumulate cumulative JSON schema, persist records, and broadcast update."""
        try:
            req = flow_record.request
            method = (req.method if req and req.method else "GET").upper()
            host = flow_record.server_host or "localhost"
            canonical_raw = getattr(triage_summary, "canonical_endpoint", None) or (req.path if req and req.path else "/") or "/"
            if " " in canonical_raw:
                canonical_path = canonical_raw.split(" ", 1)[1]
            else:
                canonical_path = canonical_raw
            ep_hash = compute_endpoint_hash(method, host, canonical_path)

            self._endpoint_counts[ep_hash] = self._endpoint_counts.get(ep_hash, 0) + 1
            sample_count = self._endpoint_counts[ep_hash]

            schema_inferred = getattr(triage_summary, "schema_inferred", {}) or {}
            if isinstance(schema_inferred, dict):
                existing_schema = self._endpoint_schemas.get(ep_hash, {})
                merged_schema = self.schema_inferrer.merge_schemas(existing_schema, schema_inferred, sample_count=sample_count)
            else:
                merged_schema = self._endpoint_schemas.get(ep_hash, {})

            self._endpoint_schemas[ep_hash] = merged_schema

            ep_cat = getattr(triage_summary, "endpoint_category", "DATA_READ")
            cat_str = ep_cat.value if hasattr(ep_cat, "value") else str(ep_cat)

            params_list = getattr(triage_summary, "parameters", []) or []

            # Update in-memory registry
            try:
                record_endpoint_observation(
                    method=method,
                    host=host,
                    path_pattern=canonical_path,
                    category=cat_str,
                    parameters=params_list,
                    schema=merged_schema,
                )
            except Exception as reg_exc:
                logger.debug("Failed to record in-memory observation: %s", reg_exc)

            # Persist endpoint in DB
            endpoint_model = DiscoveredEndpointModel(
                endpoint_hash=ep_hash,
                method=method,
                host=host,
                path_pattern=canonical_path,
                first_seen=flow_record.timestamp_start,
                last_seen=flow_record.timestamp_end or time.time(),
                request_count=sample_count,
                category=cat_str,
                schema_summary=merged_schema,
            )
            if self.db_writer:
                await self.db_writer.enqueue_endpoint(endpoint_model)

                # Persist extracted parameters in DB
                for p in params_list:
                    loc = getattr(p, "location", "query")
                    loc_str = loc.value if hasattr(loc, "value") else str(loc)
                    raw_val = getattr(p, "raw_value", None)
                    if raw_val is None:
                        raw_val = str(getattr(p, "value", ""))
                    inf_type = getattr(p, "inferred_type", "string")
                    entropy = float(getattr(p, "entropy", 0.0) or 0.0)
                    id_type = getattr(p, "identifier_type", None)
                    is_id = bool(id_type and str(id_type) != "unknown" and id_type != IdentifierType.UNKNOWN)

                    param_model = ExtractedParameterModel(
                        flow_id=flow_record.id,
                        endpoint_hash=ep_hash,
                        location=loc_str,
                        name=getattr(p, "name", "unknown"),
                        value=str(raw_val)[:500] if raw_val is not None else None,
                        data_type=inf_type,
                        is_entropy_token=entropy >= 4.2,
                        is_identifier=is_id,
                        timestamp=flow_record.timestamp_start,
                    )
                    await self.db_writer.enqueue_parameter(param_model)

            # Broadcast real-time schema & dossier update
            self.broadcaster.broadcast_schema_updated(
                endpoint_hash=ep_hash,
                host=host,
                path_pattern=canonical_path,
                method=method,
                schema_summary=merged_schema,
                parameters=params_list,
                category=cat_str,
                request_count=sample_count,
            )
        except Exception as ep_exc:
            logger.warning("Error processing endpoint and schema evolution: %s", ep_exc, exc_info=True)

    def _apply_triage(self, flow_record: FlowRecord, triage_result: Any) -> None:
        """Apply triage tags and data to flow record."""
        if hasattr(triage_result, "tags"):
            flow_record.tags = list(set(flow_record.tags + list(triage_result.tags)))
        elif isinstance(triage_result, dict) and "tags" in triage_result:
            flow_record.tags = list(set(flow_record.tags + list(triage_result["tags"])))

        if hasattr(triage_result, "model_dump"):
            flow_record.triage_data = triage_result.model_dump()
        elif isinstance(triage_result, dict):
            flow_record.triage_data = triage_result

    def error(self, flow: http.HTTPFlow) -> None:
        """Lifecycle hook invoked when network or SSL connection fails."""
        try:
            flow_record: Optional[FlowRecord] = flow.metadata.get("flowforge_record")
            if not flow_record:
                self.request(flow)
                flow_record = flow.metadata.get("flowforge_record")

            err_msg = flow.error.msg if flow.error else "Unknown network error"
            if flow_record:
                flow_record.error_message = err_msg
                flow_record.timestamp_end = time.time()
                if flow_record.timestamp_start:
                    flow_record.duration_ms = max(0.0, (flow_record.timestamp_end - flow_record.timestamp_start) * 1000.0)

                if self.db_writer:
                    asyncio.create_task(self.db_writer.enqueue_update_flow(flow_record))

                self.broadcaster.broadcast_flow_completed(flow_record.to_summary())
        except Exception as exc:
            logger.error("Error in mitmproxy error hook: %s", exc, exc_info=True)

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Lifecycle hook invoked on every incoming/outgoing WebSocket frame."""
        try:
            if not flow.websocket or not flow.websocket.messages:
                return

            flow_id = self._get_flow_id(flow)
            last_msg = flow.websocket.messages[-1]

            from_client = bool(last_msg.from_client)
            raw_content = last_msg.content
            is_binary = isinstance(raw_content, bytes) and last_msg.type == 2

            if isinstance(raw_content, bytes):
                if is_binary:
                    content_str = base64.b64encode(raw_content).decode("ascii")
                else:
                    try:
                        content_str = raw_content.decode("utf-8")
                    except UnicodeDecodeError:
                        content_str = base64.b64encode(raw_content).decode("ascii")
                        is_binary = True
            else:
                content_str = str(raw_content)

            ws_msg = WebSocketMessageModel(
                flow_id=flow_id,
                timestamp=last_msg.timestamp or time.time(),
                from_client=from_client,
                opcode=int(last_msg.type),
                content_length=len(raw_content) if raw_content else 0,
                content=content_str,
                is_binary=is_binary,
            )

            if self.db_writer:
                asyncio.create_task(self.db_writer.enqueue_ws_message(ws_msg))

            self.broadcaster.broadcast_ws_frame(ws_msg)
        except Exception as exc:
            logger.error("Error in mitmproxy websocket_message hook: %s", exc, exc_info=True)
