"""
REST API endpoints for Nuclei Templates Discovery, Querying, Stats, and Dry-Run Testing.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import yaml
from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from flowforge.config import get_settings
from flowforge.db.repository import FlowRepository
from flowforge.heuristics.nuclei_loader import (
    NucleiTemplateLoader,
    PROJECT_ROOT,
    get_nuclei_loader,
)
from flowforge.heuristics.nuclei_matcher import (
    NucleiMatcherEngine,
    get_nuclei_matcher,
)
from flowforge.models.nuclei import (
    NucleiMatchResult,
    NucleiSeverity,
    NucleiTemplate,
)

logger = logging.getLogger("flowforge.api.routes.nuclei")

router = APIRouter(prefix="/api/v1/nuclei", tags=["Nuclei"])


class PaginatedNucleiTemplatesResponse(BaseModel):
    """Paginated list of discovered Nuclei templates."""
    items: List[NucleiTemplate]
    total: int
    limit: int
    offset: int


class NucleiStatsResponse(BaseModel):
    """Summary statistics of indexed Nuclei templates."""
    total_templates: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    passive_count: int
    active_count: int
    roots_scanned: List[str]
    overridden_count: int
    last_refresh_timestamp: float


class NucleiTestRequest(BaseModel):
    """Payload for dry-run testing a Nuclei template against a flow or raw response."""
    template_id: Optional[str] = None
    template_yaml: Optional[str] = None
    flow_id: Optional[str] = None
    status_code: Optional[int] = 200
    headers: Optional[Dict[str, str]] = Field(default_factory=dict)
    body: Optional[str] = None
    url: Optional[str] = ""
    method: Optional[str] = "GET"


def _get_flow_repo(request: Request) -> FlowRepository:
    """Retrieve FlowRepository from application state or create fallback instance."""
    repo = getattr(request.app.state, "repo", None)
    if repo is not None:
        return repo
    settings = get_settings()
    return FlowRepository(settings.db_path)


@router.get("/templates", response_model=PaginatedNucleiTemplatesResponse)
async def list_templates(
    category: Optional[str] = Query(None, description="Filter by category (e.g. CVE, EXPOSURE, MISCONFIG)"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
    tag: Optional[str] = Query(None, description="Filter by tag keyword"),
    query: Optional[str] = Query(None, description="Search across template ID, name, description, tags"),
    is_passive: Optional[bool] = Query(None, description="Filter by passive match compatibility"),
    is_active: Optional[bool] = Query(None, description="Filter by active execution compatibility"),
    limit: int = Query(50, ge=1, le=500, description="Page size limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
) -> PaginatedNucleiTemplatesResponse:
    """
    Search and filter indexed Nuclei vulnerability, exposure, and misconfiguration templates.
    """
    loader = get_nuclei_loader()
    items, total = loader.list_templates(
        category=category,
        severity=severity,
        tag=tag,
        query=query,
        is_passive=is_passive,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )
    return PaginatedNucleiTemplatesResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=NucleiStatsResponse)
async def get_stats() -> NucleiStatsResponse:
    """
    Get summary statistics and category/severity breakdown for all indexed templates.
    """
    loader = get_nuclei_loader()
    stats = loader.get_stats()
    return NucleiStatsResponse(**stats)


@router.post("/refresh", response_model=NucleiStatsResponse)
async def refresh_templates() -> NucleiStatsResponse:
    """
    Rescan all configured filesystem roots and refresh template index.
    """
    loader = get_nuclei_loader()
    loader.refresh()
    stats = loader.get_stats()
    return NucleiStatsResponse(**stats)


@router.get("/templates/{template_id}", response_model=NucleiTemplate)
async def get_template_by_id(template_id: str) -> NucleiTemplate:
    """
    Inspect a specific Nuclei template by ID.
    """
    loader = get_nuclei_loader()
    tmpl = loader.get_template(template_id)
    if tmpl is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Nuclei template '{template_id}' not found",
        )
    return tmpl


@router.post("/test", response_model=NucleiMatchResult)
async def test_template(
    payload: NucleiTestRequest,
    request: Request,
) -> NucleiMatchResult:
    """
    Test a Nuclei template against a historical flow record or raw HTTP response parameters.
    """
    loader = get_nuclei_loader()
    matcher = get_nuclei_matcher()

    # 1. Resolve template
    template: Optional[NucleiTemplate] = None
    if payload.template_yaml and payload.template_yaml.strip():
        try:
            raw_data = yaml.safe_load(payload.template_yaml)
            if not isinstance(raw_data, dict):
                raise ValueError("Parsed YAML must be a dictionary object")
            template = loader._build_template_model(
                data=raw_data,
                raw_yaml=payload.template_yaml,
                fpath_str="inline_test.yaml",
                root=loader._roots[0] if loader._roots else PROJECT_ROOT,
            )
            if template is None:
                raise ValueError("YAML does not define a valid Nuclei template with 'id'")
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid template YAML: {exc}",
            )
    elif payload.template_id and payload.template_id.strip():
        template = loader.get_template(payload.template_id)
        if template is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Nuclei template '{payload.template_id}' not found",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must specify either 'template_id' or 'template_yaml'",
        )

    # 2. Evaluate against flow or raw response
    if payload.flow_id and payload.flow_id.strip():
        repo = _get_flow_repo(request)
        try:
            flow_rec = await repo.get_flow_by_id(payload.flow_id.strip())
        except Exception as exc:
            logger.debug("Error fetching flow '%s': %s", payload.flow_id, exc)
            flow_rec = None
        if flow_rec is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Flow with ID '{payload.flow_id}' not found",
            )
        result = matcher.evaluate_flow(template, flow_rec)
    else:
        # Evaluate against direct parameters
        status_code = payload.status_code if payload.status_code is not None else 200
        headers = payload.headers or {}
        body = payload.body or ""
        url = payload.url or ""
        result = matcher.evaluate_response(
            template=template,
            status_code=status_code,
            headers=headers,
            body=body,
            url=url,
        )

    return result
