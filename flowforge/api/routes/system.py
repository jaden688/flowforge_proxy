"""System maintenance routes: engagement data wipe, selective clear, and storage stats."""

from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, Query, Request

from flowforge.db.connection import get_connection
from flowforge.db.payload_repository import PayloadRepository

router = APIRouter(prefix="/api/v1/system", tags=["System"])


def _repo(request: Request) -> PayloadRepository:
    repo = getattr(request.app.state, "payload_repo", None)
    if repo is None:
        from flowforge.config import get_settings
        repo = PayloadRepository(get_settings().db_path)
        request.app.state.payload_repo = repo
    return repo


class ClearFlags(BaseModel):
    """Granular flags controlling which data categories to clear."""
    flows: bool = Field(False, description="Delete all captured flows (cascades to WS messages, parameters, proposals)")
    endpoints: bool = Field(False, description="Delete discovered endpoint catalog")
    proposals: bool = Field(False, description="Delete test proposals / auto-findings")
    intruder_jobs: bool = Field(False, description="Delete intruder jobs and their results")
    wordlists: bool = Field(False, description="Delete operator-uploaded custom wordlists")
    curated_payloads: bool = Field(False, description="Delete curated payload groups (in-memory only)")


@router.get("/stats")
async def get_system_stats(request: Request):
    """Return per-table row counts for the clear dialog."""
    repo = _repo(request)
    db_path = repo.db_path
    counts: dict = {}
    tables = [
        "flows", "endpoints", "parameters", "proposals",
        "intruder_jobs", "intruder_results", "websocket_messages",
        "custom_wordlists",
    ]
    async with get_connection(db_path) as conn:
        for table in tables:
            try:
                async with conn.execute(f"SELECT COUNT(*) AS cnt FROM {table};") as c:
                    counts[table] = (await c.fetchone())["cnt"]
            except Exception:
                counts[table] = 0
    return counts


@router.post("/clear")
async def clear_data(request: Request, flags: ClearFlags):
    """Selectively clear captured data by category. Only deletes what is flagged."""
    repo = _repo(request)
    db_path = repo.db_path
    counts: dict = {}

    # Flush the AsyncDBWriter first to prevent re-insertion race
    db_writer = getattr(request.app.state, "db_writer", None)
    if db_writer is not None:
        await db_writer.flush()

    async with get_connection(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON;")

        # Delete in dependency order (children before parents)
        if flags.flows:
            for table in ("websocket_messages", "parameters", "proposals", "flows"):
                try:
                    cursor = await conn.execute(f"DELETE FROM {table};")
                    counts[table] = cursor.rowcount or 0
                except Exception:
                    counts[table] = -1
        elif flags.proposals:
            try:
                cursor = await conn.execute("DELETE FROM proposals;")
                counts["proposals"] = cursor.rowcount or 0
            except Exception:
                counts["proposals"] = -1

        if flags.endpoints:
            try:
                cursor = await conn.execute("DELETE FROM endpoints;")
                counts["endpoints"] = cursor.rowcount or 0
            except Exception:
                counts["endpoints"] = -1

        if flags.intruder_jobs:
            for table in ("intruder_results", "intruder_jobs"):
                try:
                    cursor = await conn.execute(f"DELETE FROM {table};")
                    counts[table] = cursor.rowcount or 0
                except Exception:
                    counts[table] = -1

        if flags.wordlists:
            try:
                cursor = await conn.execute("DELETE FROM custom_wordlists;")
                counts["custom_wordlists"] = cursor.rowcount or 0
            except Exception:
                counts["custom_wordlists"] = -1

        # VACUUM only if we actually deleted something
        if any(v > 0 for v in counts.values() if isinstance(v, int)):
            try:
                await conn.execute("VACUUM;")
            except Exception:
                pass

        await conn.commit()

    # Clear in-memory stores on the server side
    if flags.curated_payloads:
        try:
            from flowforge.api.routes.curation import _groups_store, _payloads_store
            _groups_store.clear()
            _payloads_store.clear()
            counts["curated_payloads_groups"] = 0
        except Exception:
            counts["curated_payloads_groups"] = -1

    if flags.flows:
        try:
            from flowforge.api.routes.matrix import _matrix_jobs
            _matrix_jobs.clear()
        except Exception:
            pass

    return {"ok": True, "cleared": counts}


@router.post("/wipe")
async def wipe_data(
    request: Request,
    include_wordlists: bool = Query(False, description="Also delete operator-uploaded wordlists"),
):
    """Wipe all stored engagement data: flows, findings/proposals, endpoints,
    extracted parameters, WebSocket captures, and intruder jobs/results."""
    counts = await _repo(request).wipe_engagement_data(include_wordlists=include_wordlists)

    # Reset in-memory frontend state mirrors on the server side where present
    try:
        from flowforge.api.routes.matrix import _matrix_jobs
        _matrix_jobs.clear()
    except Exception:
        pass

    return {"ok": True, "wiped": counts, "wordlists_included": include_wordlists}
