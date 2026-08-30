"""Wordlist Arsenal REST routes: browse, search, preview, and stream offensive testing wordlists."""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Request

from flowforge.config import get_settings
from flowforge.db.payload_repository import PayloadRepository
from flowforge.models.intruder import CustomWordlistUpload, CustomWordlistUpdate
from flowforge.wordlists import get_wordlist_loader, reset_wordlist_loader

router = APIRouter(prefix="/api/v1/wordlists", tags=["Wordlist Arsenal"])


def _get_payload_repo(request: Request) -> PayloadRepository:
    """Return the shared PayloadRepository, lazily bound to the app state."""
    repo = getattr(request.app.state, "payload_repo", None)
    if repo is None:
        repo = PayloadRepository(get_settings().db_path)
        request.app.state.payload_repo = repo
    return repo


@router.get("")
async def list_wordlists(
    category: Optional[str] = Query(None, description="Filter by category or tag"),
    search: Optional[str] = Query(None, description="Substring filter on name/collection"),
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=2000),
    include_counts: bool = Query(False, description="Count lines per list (slower)"),
):
    """List indexed wordlists with optional category/tag filtering and pagination."""
    loader = get_wordlist_loader()
    items = loader.list_wordlists(
        category=category,
        search=search,
        offset=offset,
        limit=limit,
        include_counts=include_counts,
    )
    return {
        "items": [e.model_dump() for e in items],
        "total": loader.count_total(category=category, search=search),
        "offset": offset,
        "limit": limit,
        "roots": loader.roots,
        "categories": loader.category_counts(),
    }


@router.get("/categories")
async def get_categories():
    """Aggregate indexed wordlist counts per arsenal category."""
    loader = get_wordlist_loader()
    return {"categories": loader.category_counts(), "total_lists": sum(loader.category_counts().values())}


@router.post("/refresh")
async def refresh_index():
    """Force a full rescan of all configured wordlist roots."""
    reset_wordlist_loader()
    loader = get_wordlist_loader()
    total = loader.refresh()
    return {
        "status": "ok",
        "indexed_lists": total,
        "roots": loader.roots,
        "categories": loader.category_counts(),
    }


@router.get("/custom")
async def list_custom_wordlists(
    tag: Optional[str] = Query(None, description="Filter by operator tag"),
    search: Optional[str] = Query(None, description="Substring filter on name/description"),
    category: Optional[str] = Query(None, description="Filter by category"),
    request: Request = None,
):
    """List operator-uploaded wordlists stored in SQLite."""
    repo = _get_payload_repo(request)
    items = await repo.list_custom_wordlists(tag=tag, search=search, category=category)
    return {"items": [w.model_dump() for w in items], "total": len(items)}


@router.post("/custom", status_code=201)
async def upload_custom_wordlist(payload: CustomWordlistUpload, request: Request):
    """Create a new operator wordlist (raw newline-separated content)."""
    if len(payload.content.encode("utf-8")) > 8_000_000:
        raise HTTPException(status_code=413, detail="Wordlist content exceeds 8 MB limit")
    repo = _get_payload_repo(request)
    existing = await repo.list_custom_wordlists(search=payload.name)
    if any(w.name == payload.name for w in existing):
        raise HTTPException(status_code=409, detail=f"Wordlist named '{payload.name}' already exists")
    created = await repo.create_custom_wordlist(
        name=payload.name,
        content=payload.content,
        description=payload.description,
        category=payload.category,
        tags=payload.tags,
    )
    return created.model_dump()


@router.patch("/custom/{list_id}")
async def update_custom_wordlist(list_id: str, payload: CustomWordlistUpdate, request: Request):
    """Update name, description, category, tags, or content of an operator wordlist."""
    updates = payload.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=422, detail="No updatable fields provided")
    repo = _get_payload_repo(request)
    updated = await repo.update_custom_wordlist(list_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Custom wordlist not found")
    detail = await repo.get_custom_wordlist(list_id)
    return detail.model_dump()


@router.delete("/custom/{list_id}")
async def delete_custom_wordlist(list_id: str, request: Request):
    """Delete an operator wordlist."""
    repo = _get_payload_repo(request)
    deleted = await repo.delete_custom_wordlist(list_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Custom wordlist not found")
    return {"ok": True, "id": list_id}


@router.get("/{list_id}")
async def get_wordlist_detail(
    list_id: str,
    include_line_count: bool = Query(True),
):
    """Fetch metadata plus a small entry preview for one wordlist."""
    loader = get_wordlist_loader()
    entry = loader.get(list_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Wordlist not found")
    data = entry.model_dump()
    if include_line_count:
        data["line_count"] = loader.count_lines(list_id)
    data["preview"] = loader.preview(list_id, n=25)
    return data


@router.get("/{list_id}/entries")
async def get_wordlist_entries(
    list_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    """Stream a page of raw entries (comments/blank lines stripped)."""
    loader = get_wordlist_loader()
    if not loader.get(list_id):
        raise HTTPException(status_code=404, detail="Wordlist not found")
    page = loader.read_entries(list_id, offset=offset, limit=limit)
    return {"list_id": list_id, **page}
