"""Wordlist Arsenal REST routes: browse, search, preview, and stream offensive testing wordlists."""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException, Query

from flowforge.wordlists import get_wordlist_loader, reset_wordlist_loader

router = APIRouter(prefix="/api/v1/wordlists", tags=["Wordlist Arsenal"])


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
