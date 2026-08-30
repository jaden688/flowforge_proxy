"""Active Intruder REST routes: campaign creation, execution control, and result querying."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import ValidationError

from flowforge.core.intruder import IntruderEngine
from flowforge.db.payload_repository import PayloadRepository
from flowforge.models.intruder import IntruderJobConfig

router = APIRouter(prefix="/api/v1/intruder", tags=["Intruder"])


def get_payload_repo(request: Request) -> PayloadRepository:
    repo = getattr(request.app.state, "payload_repo", None)
    if repo is None:
        from flowforge.config import get_settings
        repo = PayloadRepository(get_settings().db_path)
        request.app.state.payload_repo = repo
    return repo


def get_engine(request: Request) -> IntruderEngine:
    engine = getattr(request.app.state, "intruder_engine", None)
    if engine is None:
        engine = IntruderEngine(
            payload_repo=get_payload_repo(request),
            broadcaster=request.app.state.broadcaster,
        )
        request.app.state.intruder_engine = engine
    return engine


@router.get("/suggestions")
async def get_suggestions(request: Request) -> Dict[str, Any]:
    """Auto-assembled fill suggestions mined from captured traffic history.

    Feeds the Intruder UI dropdowns: recent URLs, observed header names,
    query parameter names, body field names, and known endpoints.
    """
    from flowforge.db.repository import FlowRepository
    repo = FlowRepository()

    async def _rows(sql: str, params: tuple = ()) -> list:
        from flowforge.db.connection import get_connection
        async with get_connection() as conn:
            async with conn.execute(sql, params) as cursor:
                return [dict(r) for r in await cursor.fetchall()]

    urls = await _rows(
        """
        SELECT method, url, path FROM flows
        WHERE path NOT LIKE '/api/v1/%' AND path NOT LIKE '/docs%' AND path NOT LIKE '/openapi.json%'
        GROUP BY url ORDER BY MAX(timestamp_start) DESC LIMIT 150;
        """
    )
    # If no external target flows match filter, fall back to all captured flows
    if not urls:
        urls = await _rows(
            """
            SELECT method, url, path FROM flows
            GROUP BY url ORDER BY MAX(timestamp_start) DESC LIMIT 150;
            """
        )
    header_names = [
        r["name"] for r in await _rows(
            """
            SELECT je.key AS name, COUNT(*) AS c
            FROM flows, json_each(flows.request_headers) je
            GROUP BY je.key ORDER BY c DESC LIMIT 60;
            """
        )
        if r["name"] and r["name"].lower() not in ("host", "content-length")
    ]
    query_params = [
        r["name"] for r in await _rows(
            """
            SELECT name, COUNT(*) AS c FROM parameters
            WHERE location = 'query'
            GROUP BY name ORDER BY c DESC LIMIT 60;
            """
        )
    ]
    body_fields = [
        r["name"] for r in await _rows(
            """
            SELECT name, COUNT(*) AS c FROM parameters
            WHERE location IN ('json_body', 'form_body')
            GROUP BY name ORDER BY c DESC LIMIT 60;
            """
        )
    ]
    endpoints = await _rows(
        """
        SELECT method, host, path_pattern, category FROM endpoints
        ORDER BY last_seen DESC LIMIT 100;
        """
    )
    hosts = [r["host"] for r in await _rows(
        "SELECT server_host AS host, COUNT(*) AS c FROM flows GROUP BY host ORDER BY c DESC LIMIT 30;"
    )]

    return {
        "urls": [{"method": u["method"], "url": u["url"], "path": u["path"]} for u in urls],
        "header_names": header_names,
        "query_params": query_params,
        "body_fields": body_fields,
        "endpoints": endpoints,
        "hosts": hosts,
    }


@router.post("/jobs")
async def create_job(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """Create and launch an intruder campaign from a job configuration."""
    # Accept either a bare config object or {"config": {...}} wrapper.
    raw = payload.get("config") if isinstance(payload, dict) and "config" in payload else payload
    try:
        config = IntruderJobConfig.model_validate(raw)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if not config.injection_points:
        raise HTTPException(status_code=422, detail="At least one injection_point is required")
    if not (config.custom_wordlist_ids or config.arsenal_wordlist_ids or config.inline_payloads):
        raise HTTPException(status_code=422, detail="At least one payload source is required")

    engine = get_engine(request)
    job = await engine.start_job(config)
    return {"job": job.model_dump(mode="json")}


@router.get("/jobs")
async def list_jobs(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """List recent intruder campaigns."""
    repo = get_payload_repo(request)
    jobs = await repo.list_intruder_jobs(limit=limit)
    return {"items": [j.model_dump(mode="json") for j in jobs], "total": len(jobs)}


@router.get("/jobs/{job_id}")
async def get_job(job_id: str, request: Request) -> Dict[str, Any]:
    repo = get_payload_repo(request)
    job = await repo.get_intruder_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Intruder job '{job_id}' not found")
    return job.model_dump(mode="json")


@router.post("/jobs/{job_id}/abort")
async def abort_job(job_id: str, request: Request) -> Dict[str, Any]:
    engine = get_engine(request)
    aborted = await engine.abort_job(job_id)
    if not aborted:
        raise HTTPException(status_code=404, detail=f"Running intruder job '{job_id}' not found")
    repo = get_payload_repo(request)
    job = await repo.get_intruder_job(job_id)
    return {"ok": True, "job": job.model_dump(mode="json") if job else None}


@router.get("/jobs/{job_id}/results")
async def get_results(
    job_id: str,
    request: Request,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=5000),
    anomalies_only: bool = Query(False),
    reflected_only: bool = Query(False),
    status_code: Optional[int] = Query(None),
    min_size: Optional[int] = Query(None),
    max_size: Optional[int] = Query(None),
    min_time_ms: Optional[float] = Query(None),
    max_time_ms: Optional[float] = Query(None),
    payload_search: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Query stored results with anomaly/size/timing/reflection filters."""
    repo = get_payload_repo(request)
    job = await repo.get_intruder_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Intruder job '{job_id}' not found")

    filters: Dict[str, Any] = {
        "offset": offset,
        "limit": limit,
        "anomalies_only": anomalies_only,
        "reflected_only": reflected_only,
        "status_code": status_code,
        "min_size": min_size,
        "max_size": max_size,
        "min_time_ms": min_time_ms,
        "max_time_ms": max_time_ms,
        "payload_search": payload_search,
    }
    results, total = await repo.get_results(job_id, filters=filters)
    return {
        "job_id": job_id,
        "job_status": job.status.value,
        "items": [r.model_dump() for r in results],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.delete("/jobs/{job_id}")
async def delete_job(job_id: str, request: Request) -> Dict[str, Any]:
    repo = get_payload_repo(request)
    deleted = await repo.delete_job_with_results(job_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Intruder job '{job_id}' not found")
    return {"ok": True, "id": job_id}
