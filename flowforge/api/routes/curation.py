"""
FlowForge Payload Curation, Grouping & Selective Pruning REST API routes.
Provides starring/pinning, named custom groups, selective filter-based pruning,
and JSON export/import.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel

from flowforge.models.curation import (
    BulkCreatePayloadRequest,
    CreateGroupRequest,
    CreatePayloadRequest,
    CurationExport,
    CurationImportRequest,
    CurationImportResponse,
    CuratedPayload,
    CuratedGroup,
    PayloadGroup,
    PruneFilterRequest,
    PruneResult,
    StarPayloadRequest,
    UpdateGroupRequest,
    UpdatePayloadRequest,
)

router = APIRouter(prefix="/api/v1/curation", tags=["Payload Curation"])

# In-memory storage for curation system
_groups_store: Dict[str, PayloadGroup] = {}
_payloads_store: Dict[str, CuratedPayload] = {}
_curation_lock = asyncio.Lock()


def _ensure_default_group() -> PayloadGroup:
    """Ensure the default collection group exists."""
    default_id = "default"
    if default_id not in _groups_store:
        now = time.time()
        _groups_store[default_id] = PayloadGroup(
            id=default_id,
            name="Default Collection",
            description="Default general storage for curated and starred mutation payloads.",
            color="#38bdf8",
            icon="star",
            payload_ids=[],
            item_count=0,
            items=[],
            created_at=now,
            updated_at=now,
        )
    return _groups_store[default_id]


def _sync_group_items(group_id: str) -> None:
    """Synchronize item list and counts for a group."""
    if group_id not in _groups_store:
        return
    group = _groups_store[group_id]
    items = [p for p in _payloads_store.values() if p.group_id == group_id]
    group.payload_ids = [p.id for p in items]
    group.item_count = len(items)
    group.items = items
    group.updated_at = time.time()


# Initialize default group on module load
_ensure_default_group()


@router.get("/groups", response_model=List[PayloadGroup])
async def list_payload_groups():
    """
    List all payload collections/groups with item counts and summary metadata.
    """
    async with _curation_lock:
        _ensure_default_group()
        for gid in list(_groups_store.keys()):
            _sync_group_items(gid)
        return list(_groups_store.values())


@router.post("/groups", response_model=PayloadGroup)
async def create_payload_group(payload: CreateGroupRequest):
    """
    Create a new custom named payload group.
    """
    async with _curation_lock:
        now = time.time()
        group_id = payload.id or f"group-{uuid.uuid4().hex[:8]}"
        if group_id in _groups_store:
            raise HTTPException(status_code=400, detail=f"Group with ID '{group_id}' already exists")

        new_group = PayloadGroup(
            id=group_id,
            name=payload.name,
            description=payload.description or "",
            color=payload.color or "#38bdf8",
            icon=payload.icon or "folder",
            payload_ids=[],
            item_count=0,
            items=[],
            created_at=now,
            updated_at=now,
        )
        _groups_store[group_id] = new_group
        return new_group


@router.get("/groups/{group_id}", response_model=PayloadGroup)
async def get_payload_group(group_id: str):
    """
    Retrieve a specific payload group including all its contained payload items.
    """
    async with _curation_lock:
        if group_id not in _groups_store:
            raise HTTPException(status_code=404, detail="Payload group not found")
        _sync_group_items(group_id)
        return _groups_store[group_id]


@router.put("/groups/{group_id}", response_model=PayloadGroup)
@router.patch("/groups/{group_id}", response_model=PayloadGroup)
async def update_payload_group(group_id: str, payload: UpdateGroupRequest):
    """
    Update payload group name, description, color, or icon.
    """
    async with _curation_lock:
        if group_id not in _groups_store:
            raise HTTPException(status_code=404, detail="Payload group not found")

        group = _groups_store[group_id]
        if payload.name is not None:
            group.name = payload.name
        if payload.description is not None:
            group.description = payload.description
        if payload.color is not None:
            group.color = payload.color
        if payload.icon is not None:
            group.icon = payload.icon
        group.updated_at = time.time()
        _sync_group_items(group_id)
        return group


@router.delete("/groups/{group_id}")
async def delete_payload_group(group_id: str):
    """
    Delete a payload group and all its curated payloads.
    """
    if group_id == "default":
        raise HTTPException(status_code=400, detail="Cannot delete default system group")

    async with _curation_lock:
        if group_id not in _groups_store:
            raise HTTPException(status_code=404, detail="Payload group not found")

        # Delete all member payloads
        payload_ids_to_del = [pid for pid, p in _payloads_store.items() if p.group_id == group_id]
        for pid in payload_ids_to_del:
            _payloads_store.pop(pid, None)

        del _groups_store[group_id]
        return {"status": "success", "message": f"Deleted group {group_id} and {len(payload_ids_to_del)} payloads"}


@router.get("/payloads", response_model=List[CuratedPayload])
async def list_curated_payloads(
    group_id: Optional[str] = None,
    starred: Optional[bool] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
):
    """
    List curated payload items with multi-field filtering.
    """
    async with _curation_lock:
        results = list(_payloads_store.values())

        if group_id is not None:
            results = [p for p in results if p.group_id == group_id]
        if starred is not None:
            results = [p for p in results if p.starred == starred]
        if category is not None:
            results = [p for p in results if p.category.lower() == category.lower()]
        if status is not None:
            results = [p for p in results if p.status.lower() == status.lower()]
        if search:
            s_lower = search.lower()
            results = [
                p for p in results
                if s_lower in p.name.lower()
                or s_lower in (p.notes or "").lower()
                or s_lower in p.target_param_name.lower()
                or s_lower in str(p.mutated_value or "").lower()
            ]

        results.sort(key=lambda p: (-p.starred, -p.created_at))
        return results


@router.post("/payloads", response_model=Union[CuratedPayload, List[CuratedPayload]])
async def create_curated_payload(payload: Union[BulkCreatePayloadRequest, CreatePayloadRequest, CuratedPayload, List[CreatePayloadRequest]]):
    """
    Create one or more curated payload items and add them to a group.
    """
    async with _curation_lock:
        _ensure_default_group()
        now = time.time()

        if isinstance(payload, BulkCreatePayloadRequest):
            created_items = []
            target_group = payload.group_id or "default"
            if target_group not in _groups_store:
                _ensure_default_group()
                target_group = "default"

            for item_req in payload.items:
                item = CuratedPayload(
                    id=f"payload-{uuid.uuid4().hex[:12]}",
                    group_id=target_group,
                    name=item_req.name,
                    category=item_req.category,
                    endpoint_path=item_req.endpoint_path,
                    method=item_req.method.upper(),
                    target_param_location=item_req.target_param_location,
                    target_param_name=item_req.target_param_name,
                    baseline_value=item_req.baseline_value,
                    mutated_value=item_req.mutated_value,
                    auth_override=item_req.auth_override,
                    status=item_req.status,
                    starred=item_req.starred,
                    notes=item_req.notes,
                    tags=item_req.tags,
                    result_summary=item_req.result_summary,
                    baseline_flow_id=item_req.baseline_flow_id,
                    created_at=now,
                    updated_at=now,
                )
                _payloads_store[item.id] = item
                created_items.append(item)
            _sync_group_items(target_group)
            return created_items

        elif isinstance(payload, list):
            created_items = []
            for item_req in payload:
                target_group = getattr(item_req, "group_id", "default") or "default"
                if target_group not in _groups_store:
                    target_group = "default"

                item = CuratedPayload(
                    id=f"payload-{uuid.uuid4().hex[:12]}",
                    group_id=target_group,
                    name=item_req.name,
                    category=item_req.category,
                    endpoint_path=item_req.endpoint_path,
                    method=item_req.method.upper(),
                    target_param_location=item_req.target_param_location,
                    target_param_name=item_req.target_param_name,
                    baseline_value=item_req.baseline_value,
                    mutated_value=item_req.mutated_value,
                    auth_override=item_req.auth_override,
                    status=item_req.status,
                    starred=item_req.starred,
                    notes=item_req.notes,
                    tags=item_req.tags,
                    result_summary=item_req.result_summary,
                    baseline_flow_id=item_req.baseline_flow_id,
                    created_at=now,
                    updated_at=now,
                )
                _payloads_store[item.id] = item
                created_items.append(item)
                _sync_group_items(target_group)
            return created_items

        elif isinstance(payload, CuratedPayload):
            target_group = payload.group_id or "default"
            if target_group not in _groups_store:
                _ensure_default_group()
                target_group = "default"
            payload.group_id = target_group
            _payloads_store[payload.id] = payload
            _sync_group_items(target_group)
            return payload

        else:
            target_group = payload.group_id or "default"
            if target_group not in _groups_store:
                _ensure_default_group()
                target_group = "default"

            item = CuratedPayload(
                id=f"payload-{uuid.uuid4().hex[:12]}",
                group_id=target_group,
                name=payload.name,
                category=payload.category,
                endpoint_path=payload.endpoint_path,
                method=payload.method.upper(),
                target_param_location=payload.target_param_location,
                target_param_name=payload.target_param_name,
                baseline_value=payload.baseline_value,
                mutated_value=payload.mutated_value,
                auth_override=payload.auth_override,
                status=payload.status,
                starred=payload.starred,
                notes=payload.notes,
                tags=payload.tags,
                result_summary=payload.result_summary,
                baseline_flow_id=payload.baseline_flow_id,
                created_at=now,
                updated_at=now,
            )
            _payloads_store[item.id] = item
            _sync_group_items(target_group)
            return item


@router.post("/payloads/star", response_model=CuratedPayload)
async def star_payload(req: StarPayloadRequest):
    """
    Toggle or set star/pinned status of a payload.
    """
    if not req.payload_id:
        raise HTTPException(status_code=400, detail="payload_id is required")

    async with _curation_lock:
        if req.payload_id not in _payloads_store:
            raise HTTPException(status_code=404, detail=f"Payload with ID '{req.payload_id}' not found")

        item = _payloads_store[req.payload_id]
        if req.starred is not None:
            item.starred = req.starred
        else:
            item.starred = not item.starred
        item.updated_at = time.time()
        _sync_group_items(item.group_id)
        return item


@router.post("/payloads/{payload_id}/star", response_model=CuratedPayload)
@router.patch("/payloads/{payload_id}/star", response_model=CuratedPayload)
async def star_payload_by_id(payload_id: str, starred: Optional[bool] = None):
    """
    Toggle or set star status by payload ID in route path.
    """
    async with _curation_lock:
        if payload_id not in _payloads_store:
            raise HTTPException(status_code=404, detail=f"Payload with ID '{payload_id}' not found")

        item = _payloads_store[payload_id]
        if starred is not None:
            item.starred = starred
        else:
            item.starred = not item.starred
        item.updated_at = time.time()
        _sync_group_items(item.group_id)
        return item


@router.get("/payloads/{payload_id}", response_model=CuratedPayload)
async def get_curated_payload(payload_id: str):
    """
    Retrieve single curated payload details.
    """
    async with _curation_lock:
        if payload_id not in _payloads_store:
            raise HTTPException(status_code=404, detail="Payload not found")
        return _payloads_store[payload_id]


@router.patch("/payloads/{payload_id}", response_model=CuratedPayload)
@router.put("/payloads/{payload_id}", response_model=CuratedPayload)
async def update_curated_payload(payload_id: str, payload: UpdatePayloadRequest):
    """
    Update notes, status, tags, group, or star status of a payload.
    """
    async with _curation_lock:
        if payload_id not in _payloads_store:
            raise HTTPException(status_code=404, detail="Payload not found")

        item = _payloads_store[payload_id]
        old_group = item.group_id

        if payload.name is not None:
            item.name = payload.name
        if payload.category is not None:
            item.category = payload.category
        if payload.starred is not None:
            item.starred = payload.starred
        if payload.status is not None:
            item.status = payload.status
        if payload.notes is not None:
            item.notes = payload.notes
        if payload.tags is not None:
            item.tags = payload.tags
        if payload.result_summary is not None:
            item.result_summary = payload.result_summary
        if payload.group_id is not None and payload.group_id in _groups_store:
            item.group_id = payload.group_id

        item.updated_at = time.time()
        _sync_group_items(old_group)
        if item.group_id != old_group:
            _sync_group_items(item.group_id)
        return item


@router.delete("/payloads/{payload_id}")
async def delete_curated_payload(payload_id: str):
    """
    Delete an individual curated payload item.
    """
    async with _curation_lock:
        if payload_id not in _payloads_store:
            raise HTTPException(status_code=404, detail="Payload not found")

        item = _payloads_store.pop(payload_id)
        _sync_group_items(item.group_id)
        return {"status": "success", "message": f"Deleted payload {payload_id}"}


def _execute_pruning_logic(filter_req: PruneFilterRequest) -> PruneResult:
    """Internal helper to execute selective pruning logic."""
    target_group_id = filter_req.group_id
    preserve_starred = filter_req.preserve_starred
    target_statuses = filter_req.statuses_to_delete or filter_req.status_filter
    if target_statuses:
        target_statuses = [s.lower() for s in target_statuses]

    target_categories = [c.lower() for c in filter_req.category_filter] if filter_req.category_filter else None

    regex_pattern = None
    if filter_req.regex_filter:
        try:
            regex_pattern = re.compile(filter_req.regex_filter, re.IGNORECASE)
        except re.error as e:
            raise HTTPException(status_code=400, detail=f"Invalid regex filter: {e}")

    deleted_ids = []
    preserved_count = 0

    all_payload_ids = list(_payloads_store.keys())

    for pid in all_payload_ids:
        item = _payloads_store.get(pid)
        if not item:
            continue

        # Check group scoping
        if target_group_id and item.group_id != target_group_id:
            continue

        # Check starred protection
        if preserve_starred and item.starred:
            preserved_count += 1
            continue

        # Check status filter
        if target_statuses and item.status.lower() not in target_statuses:
            continue

        # Check category filter
        if target_categories and item.category.lower() not in target_categories:
            continue

        # Check regex filter
        if regex_pattern:
            text_to_match = f"{item.name} {item.target_param_name} {item.mutated_value} {item.notes or ''}"
            if not regex_pattern.search(text_to_match):
                continue

        # Check length filter
        if filter_req.length_min is not None or filter_req.length_max is not None:
            mut_len = len(str(item.mutated_value or ""))
            resp_delta = 0
            if item.result_summary and "length_delta" in item.result_summary:
                try:
                    resp_delta = abs(int(item.result_summary["length_delta"]))
                except (ValueError, TypeError):
                    pass

            check_len = max(mut_len, resp_delta)
            if filter_req.length_min is not None and check_len < filter_req.length_min:
                continue
            if filter_req.length_max is not None and check_len > filter_req.length_max:
                continue

        # Condition met for pruning
        deleted_ids.append(pid)
        _payloads_store.pop(pid, None)

    # Sync all affected groups
    for gid in list(_groups_store.keys()):
        _sync_group_items(gid)

    remaining_count = len(_payloads_store)
    return PruneResult(
        deleted_count=len(deleted_ids),
        pruned_count=len(deleted_ids),
        preserved_count=preserved_count,
        remaining_count=remaining_count,
        deleted_payload_ids=deleted_ids,
    )


@router.post("/prune", response_model=PruneResult)
async def prune_curated_payloads(filter_req: PruneFilterRequest):
    """
    Selectively prune mutation payloads by status, length, category, or regex filter,
    while preserving starred and pinned items.
    """
    async with _curation_lock:
        return _execute_pruning_logic(filter_req)


@router.post("/groups/{group_id}/prune", response_model=PruneResult)
async def prune_group_payloads(group_id: str, filter_req: PruneFilterRequest):
    """
    Selectively prune payloads within a specific group.
    """
    async with _curation_lock:
        if group_id not in _groups_store:
            raise HTTPException(status_code=404, detail="Group not found")
        filter_req.group_id = group_id
        return _execute_pruning_logic(filter_req)


@router.get("/export", response_model=CurationExport)
@router.post("/export", response_model=CurationExport)
async def export_curation_data(group_id: Optional[str] = None):
    """
    Export all curated payload groups and items (or a specific group) as JSON.
    """
    async with _curation_lock:
        _ensure_default_group()
        for gid in list(_groups_store.keys()):
            _sync_group_items(gid)

        if group_id:
            if group_id not in _groups_store:
                raise HTTPException(status_code=404, detail="Payload group not found")
            groups = [_groups_store[group_id]]
            payloads = [p for p in _payloads_store.values() if p.group_id == group_id]
        else:
            groups = list(_groups_store.values())
            payloads = list(_payloads_store.values())

        return CurationExport(
            exported_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            version="1.0",
            groups=groups,
            payloads=payloads,
        )


@router.get("/groups/{group_id}/export", response_model=CurationExport)
async def export_single_group(group_id: str):
    """
    Export a single payload group and its curated items as JSON.
    """
    return await export_curation_data(group_id=group_id)


@router.post("/import", response_model=CurationImportResponse)
async def import_curation_data(req: CurationImportRequest):
    """
    Import payload groups and curated payloads from a JSON export payload.
    """
    async with _curation_lock:
        if req.overwrite:
            _groups_store.clear()
            _payloads_store.clear()
            _ensure_default_group()

        imported_groups = 0
        imported_payloads = 0

        if req.groups:
            for g in req.groups:
                _groups_store[g.id] = g
                imported_groups += 1

        if req.payloads:
            for p in req.payloads:
                if p.group_id not in _groups_store:
                    _ensure_default_group()
                    p.group_id = "default"
                _payloads_store[p.id] = p
                imported_payloads += 1

        for gid in list(_groups_store.keys()):
            _sync_group_items(gid)

        return CurationImportResponse(
            imported_groups_count=imported_groups,
            imported_payloads_count=imported_payloads,
            status="success",
        )
