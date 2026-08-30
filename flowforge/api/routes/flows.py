"""
REST API endpoints for Flow querying, FTS5 search, inspection, modification, replay, and deletion.
"""

from __future__ import annotations

import math
import time
from typing import Any, Dict, List, Optional
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel

from flowforge.config import Settings, get_settings
from flowforge.db.repository import FlowRepository
from flowforge.models.flow import (
    CustomSendRequest,
    FlowFilterParams,
    FlowRecord,
    FlowReplayRequest,
    FlowSummary,
)
from flowforge.models.websocket import WebSocketMessageModel
from flowforge.utils.http_parser import format_raw_request, format_raw_response

router = APIRouter(prefix="/api/v1/flows", tags=["Flows"])


def get_repository() -> FlowRepository:
    """Dependency provider for FlowRepository."""
    return FlowRepository()


class PaginatedFlowResponse(BaseModel):
    items: List[FlowSummary]
    total: int
    page: int
    page_size: int
    pages: int


class PaginatedWSResponse(BaseModel):
    items: List[WebSocketMessageModel]
    total: int
    page: int
    page_size: int
    pages: int


class FavoriteUpdateRequest(BaseModel):
    is_favorite: bool


class NotesUpdateRequest(BaseModel):
    notes: str


@router.get("", response_model=PaginatedFlowResponse)
async def list_flows(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
    host: Optional[str] = Query(None, description="Filter by server host"),
    method: Optional[str] = Query(None, description="Filter by HTTP method"),
    status_code: Optional[int] = Query(None, description="Filter by exact HTTP status code"),
    status_min: Optional[int] = Query(None, description="Filter by minimum HTTP status code"),
    status_max: Optional[int] = Query(None, description="Filter by maximum HTTP status code"),
    scheme: Optional[str] = Query(None, description="Filter by scheme (http, https, ws, wss)"),
    tag: Optional[str] = Query(None, description="Filter by triage tag"),
    is_websocket: Optional[bool] = Query(None, description="Filter websocket flows only"),
    is_favorite: Optional[bool] = Query(None, description="Filter favorite flows only"),
    search: Optional[str] = Query(None, description="Search term in URL, path, or host"),
    since: Optional[float] = Query(None, description="Filter flows captured after epoch timestamp"),
    order_by: str = Query("timestamp_start", description="Field to sort by"),
    desc: bool = Query(True, description="Sort descending if true"),
    repo: FlowRepository = Depends(get_repository),
) -> PaginatedFlowResponse:
    """Retrieve paginated flows matching optional filtering criteria."""
    params = FlowFilterParams(
        page=page,
        page_size=page_size,
        host=host,
        method=method,
        status_code=status_code,
        status_min=status_min,
        status_max=status_max,
        scheme=scheme,
        tag=tag,
        is_websocket=is_websocket,
        is_favorite=is_favorite,
        search=search,
        since=since,
        order_by=order_by,
        desc=desc,
    )
    items, total = await repo.list_flows(params)
    pages = max(1, math.ceil(total / page_size)) if total > 0 else 1
    return PaginatedFlowResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/search", response_model=PaginatedFlowResponse)
async def search_flows(
    q: str = Query(..., min_length=1, description="FTS5 query expression"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
    filter_column: str = Query("all", description="Search target: 'all', 'url', 'request', 'response'"),
    repo: FlowRepository = Depends(get_repository),
) -> PaginatedFlowResponse:
    """Execute high-speed full-text search against URL, headers, and bodies."""
    items, total = await repo.search_flows_fts(
        query=q,
        page=page,
        page_size=page_size,
        filter_column=filter_column,
    )
    pages = max(1, math.ceil(total / page_size)) if total > 0 else 1
    return PaginatedFlowResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{flow_id}", response_model=FlowRecord)
async def get_flow(
    flow_id: str,
    repo: FlowRepository = Depends(get_repository),
) -> FlowRecord:
    """Retrieve complete flow representation including decoded bodies and triage findings."""
    flow = await repo.get_flow_by_id(flow_id)
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flow with ID '{flow_id}' not found.",
        )
    return flow


@router.get("/{flow_id}/raw", response_class=Response)
async def get_raw_flow(
    flow_id: str,
    type: str = Query("request", pattern="^(request|response)$", description="'request' or 'response'"),
    repo: FlowRepository = Depends(get_repository),
) -> Response:
    """Return raw HTTP wire representation for request or response."""
    flow = await repo.get_flow_by_id(flow_id)
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flow with ID '{flow_id}' not found.",
        )

    if type == "request":
        raw_text = format_raw_request(
            method=flow.request.method,
            path=flow.request.path,
            http_version=flow.http_version,
            headers=flow.request.headers,
            body=flow.request.body,
            body_is_binary=flow.request.body_is_binary,
        )
    else:
        if not flow.response:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Flow has no completed response to display.",
            )
        raw_text = format_raw_response(
            http_version=flow.http_version,
            status_code=flow.response.status_code,
            reason=flow.response.reason,
            headers=flow.response.headers,
            body=flow.response.body,
            body_is_binary=flow.response.body_is_binary,
        )

    return Response(content=raw_text, media_type="text/plain; charset=utf-8")


@router.get("/{flow_id}/ws-messages", response_model=PaginatedWSResponse)
async def get_websocket_messages(
    flow_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    direction: str = Query("all", pattern="^(all|client|server)$"),
    repo: FlowRepository = Depends(get_repository),
) -> PaginatedWSResponse:
    """Retrieve frame-by-frame WebSocket conversation for the specified flow."""
    items, total = await repo.get_websocket_messages(
        flow_id=flow_id,
        page=page,
        page_size=page_size,
        direction=direction,
    )
    pages = max(1, math.ceil(total / page_size)) if total > 0 else 1
    return PaginatedWSResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.delete("/{flow_id}")
async def delete_flow(
    flow_id: str,
    repo: FlowRepository = Depends(get_repository),
) -> Dict[str, Any]:
    """Delete a single flow and its associated frames and parameters."""
    success = await repo.delete_flow(flow_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flow with ID '{flow_id}' not found.",
        )
    return {"ok": True, "id": flow_id}


@router.delete("")
async def clear_all_flows(
    host: Optional[str] = Query(None, description="Optional host filter to purge"),
    repo: FlowRepository = Depends(get_repository),
) -> Dict[str, Any]:
    """Purge all stored flows (or flows matching specified host)."""
    deleted_count = await repo.clear_flows(host_filter=host)
    return {"ok": True, "deleted": deleted_count}


@router.patch("/{flow_id}/favorite")
async def toggle_favorite(
    flow_id: str,
    payload: FavoriteUpdateRequest,
    repo: FlowRepository = Depends(get_repository),
) -> Dict[str, Any]:
    """Update favorite bookmark status on a flow."""
    success = await repo.set_favorite(flow_id, payload.is_favorite)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flow with ID '{flow_id}' not found.",
        )
    return {"ok": True, "id": flow_id, "is_favorite": payload.is_favorite}


@router.patch("/{flow_id}/notes")
async def update_notes(
    flow_id: str,
    payload: NotesUpdateRequest,
    repo: FlowRepository = Depends(get_repository),
) -> Dict[str, Any]:
    """Update operator notes on a flow."""
    success = await repo.update_notes(flow_id, payload.notes)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flow with ID '{flow_id}' not found.",
        )
    return {"ok": True, "id": flow_id, "notes": payload.notes}


@router.post("/{flow_id}/replay")
async def replay_flow(
    flow_id: str,
    payload: Optional[FlowReplayRequest] = None,
    repo: FlowRepository = Depends(get_repository),
) -> Dict[str, Any]:
    """Replay an intercepted request through HTTP client with optional modifications."""
    flow = await repo.get_flow_by_id(flow_id)
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flow with ID '{flow_id}' not found.",
        )

    req = flow.request
    method = (payload and payload.override_method) or req.method
    url = (payload and payload.override_url) or req.url
    if url.startswith("/"):
        scheme = flow.scheme or "http"
        host = flow.server_host
        port = flow.server_port
        port_str = f":{port}" if (port and port not in (80, 443)) else ""
        url = f"{scheme}://{host}{port_str}{url}"

    headers = dict(req.headers)
    if payload and payload.override_headers:
        headers.update(payload.override_headers)

    body = (payload and payload.override_body) if (payload and payload.override_body is not None) else req.body

    # Remove hop-by-hop headers
    headers.pop("host", None)
    headers.pop("Host", None)
    headers.pop("content-length", None)
    headers.pop("Content-Length", None)

    settings = get_settings()
    proxy_url = f"http://{settings.proxy_host}:{settings.proxy_port}" if settings.auto_start_proxy else None

    start_time = time.time()
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            verify=False,
            timeout=30.0,
            follow_redirects=False,
        ) as client:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body.encode("utf-8") if body else None,
            )
            duration_ms = (time.time() - start_time) * 1000.0

            return {
                "ok": True,
                "replayed_flow_id": flow_id,
                "status_code": resp.status_code,
                "reason": resp.reason_phrase,
                "headers": dict(resp.headers),
                "duration_ms": duration_ms,
                "body": resp.text[:100000],
                "content_length": len(resp.content),
            }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Replay request failed: {str(exc)}",
        )


@router.post("/send")
@router.post("/custom/send")
async def send_custom_request(payload: CustomSendRequest) -> Dict[str, Any]:
    """Send an arbitrary custom HTTP request from the operator canvas."""
    settings = get_settings()
    proxy_url = f"http://{settings.proxy_host}:{settings.proxy_port}" if settings.auto_start_proxy else None

    headers = dict(payload.headers or {})
    headers.pop("host", None)
    headers.pop("Host", None)
    headers.pop("content-length", None)
    headers.pop("Content-Length", None)

    start_time = time.time()
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            verify=False,
            timeout=5.0,
            follow_redirects=False,
        ) as client:
            resp = await client.request(
                method=payload.method.upper(),
                url=payload.url,
                headers=headers,
                content=payload.body.encode("utf-8") if payload.body else None,
            )
            duration_ms = (time.time() - start_time) * 1000.0

            return {
                "ok": True,
                "status": "queued_or_sent",
                "status_code": resp.status_code,
                "reason": resp.reason_phrase,
                "headers": dict(resp.headers),
                "duration_ms": duration_ms,
                "body": resp.text[:100000],
                "content_length": len(resp.content),
            }
    except Exception as exc:
        return {
            "ok": False,
            "status": "queued_or_sent",
            "status_code": 0,
            "error": str(exc),
            "detail": f"Dispatch failed: {exc}",
            "headers": headers,
            "body": payload.body or "",
            "duration_ms": (time.time() - start_time) * 1000.0,
        }
