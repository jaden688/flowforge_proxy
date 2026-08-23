"""
REST API endpoints for Custom Heuristic Match Rules (Requirement R5).

Provides CRUD operations, toggling, dry-run testing, and import/export capabilities.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel

from flowforge.db.repository import FlowRepository
from flowforge.heuristics.rule_engine import (
    FlowInspectionContext,
    RuleEngine,
    get_rule_engine,
)
from flowforge.models.rules import (
    MatchRule,
    RuleExportResponse,
    RuleImportRequest,
    RuleImportResult,
    RuleSeverity,
    RuleTestRequest,
    RuleTestResponse,
)

logger = logging.getLogger("flowforge.api.routes.rules")

router = APIRouter(prefix="/api/v1/rules", tags=["Custom Rules"])


def get_engine() -> RuleEngine:
    """Dependency provider for RuleEngine singleton."""
    return get_rule_engine()


def get_repository() -> FlowRepository:
    """Dependency provider for FlowRepository."""
    return FlowRepository()


class RuleListResponse(BaseModel):
    rules: List[MatchRule]
    total: int


class RuleSingleResponse(BaseModel):
    rule: MatchRule


class RuleActionResponse(BaseModel):
    status: str
    rule: Optional[MatchRule] = None
    rule_id: Optional[str] = None


class ToggleRequest(BaseModel):
    enabled: Optional[bool] = None


# -------------------------------------------------------------------------
# CRUD Endpoints
# -------------------------------------------------------------------------


@router.get("", response_model=RuleListResponse)
async def list_rules(
    enabled: Optional[bool] = Query(None, description="Filter by active enabled state"),
    severity: Optional[str] = Query(None, description="Filter by severity level (LOW, MEDIUM, HIGH, CRITICAL)"),
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search name, description, tags, or ID"),
    engine: RuleEngine = Depends(get_engine),
) -> RuleListResponse:
    """List all registered custom and built-in heuristic rules with filtering."""
    sev_enum = None
    if severity:
        for s in RuleSeverity:
            if s.value == severity.upper():
                sev_enum = s
                break

    rules = engine.list_rules(
        enabled_only=enabled is True,
        category=category,
        severity=sev_enum,
        search=search,
    )
    if enabled is False:
        rules = [r for r in rules if not r.enabled]

    return RuleListResponse(rules=rules, total=len(rules))


@router.post("", response_model=RuleActionResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: Dict[str, Any] = Body(...),
    engine: RuleEngine = Depends(get_engine),
) -> RuleActionResponse:
    """Create and register a new heuristic rule from JSON or YAML dictionary."""
    try:
        rule = engine.parse_rule_from_dict(payload)
        engine.register_rule(rule)
        return RuleActionResponse(status="created", rule=rule, rule_id=rule.id)
    except Exception as exc:
        logger.error("Failed to create rule: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid rule specification: {exc}",
        ) from exc


@router.get("/export")
async def export_rules(
    format: str = Query("yaml", description="Export format: 'yaml' or 'json'"),
    enabled_only: bool = Query(False, description="Export only enabled rules"),
    raw: bool = Query(False, description="Return raw YAML/JSON content instead of wrapper"),
    engine: RuleEngine = Depends(get_engine),
) -> Any:
    """Export active rules to YAML or JSON."""
    rules = engine.list_rules(enabled_only=enabled_only)
    fmt = format.lower().strip()

    if fmt in ("json",):
        content = engine.export_rules_to_json(rules)
        if raw:
            return Response(
                content=content,
                media_type="application/json",
                headers={"Content-Disposition": "attachment; filename=flowforge_rules.json"},
            )
        return RuleExportResponse(format="json", content=content, count=len(rules))
    else:
        content = engine.export_rules_to_yaml(rules)
        if raw:
            return Response(
                content=content,
                media_type="application/x-yaml",
                headers={"Content-Disposition": "attachment; filename=flowforge_rules.yaml"},
            )
        return RuleExportResponse(format="yaml", content=content, count=len(rules))


@router.post("/import", response_model=RuleImportResult)
async def import_rules(
    req: RuleImportRequest,
    engine: RuleEngine = Depends(get_engine),
) -> RuleImportResult:
    """Import and register rules from a YAML or JSON payload."""
    fmt = req.format.lower().strip()
    if fmt == "json":
        imported, updated, errors, rules = engine.import_from_json(req.content, overwrite=req.overwrite)
    else:
        imported, updated, errors, rules = engine.import_from_yaml(req.content, overwrite=req.overwrite)

    return RuleImportResult(
        imported_count=imported,
        updated_count=updated,
        failed_count=len(errors),
        errors=errors,
        rules=rules,
    )


@router.post("/test", response_model=RuleTestResponse)
async def test_rule(
    req: RuleTestRequest,
    engine: RuleEngine = Depends(get_engine),
    repo: FlowRepository = Depends(get_repository),
) -> RuleTestResponse:
    """
    Test/dry-run rule evaluation against sample flow payload or existing flow record.
    """
    flow_obj = None

    if req.flow_id:
        flow_record = await repo.get_flow_by_id(req.flow_id)
        if not flow_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Flow with ID '{req.flow_id}' not found",
            )
        flow_obj = flow_record
    elif req.sample_flow:
        flow_obj = req.sample_flow
    else:
        # Default empty/synthetic sample flow
        flow_obj = {
            "method": "GET",
            "url": "http://localhost:8080/api/v1/test",
            "path": "/api/v1/test",
            "response_status": 200,
            "response_body": "OK",
            "response_headers": {"content-type": "text/plain"},
        }

    target_rules: List[MatchRule] = []

    if req.rule_id:
        existing = engine.get_rule(req.rule_id)
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule with ID '{req.rule_id}' not found",
            )
        target_rules.append(existing)

    elif req.rule:
        if isinstance(req.rule, MatchRule):
            target_rules.append(req.rule)
        elif isinstance(req.rule, dict):
            target_rules.append(engine.parse_rule_from_dict(req.rule))
        elif isinstance(req.rule, str):
            # Try parsing as YAML or JSON
            content = req.rule.strip()
            if content.startswith("{") or content.startswith("["):
                target_rules.extend(engine.parse_rules_from_json(content))
            else:
                target_rules.extend(engine.parse_rules_from_yaml(content))
    else:
        # Evaluate all active rules
        target_rules = engine.list_rules(enabled_only=True)

    results = []
    any_matched = False
    for r in target_rules:
        # Force evaluation even if rule was disabled, because user is explicitly testing it
        saved_enabled = r.enabled
        r.enabled = True
        try:
            res = engine.evaluate_rule(r, flow_obj)
            results.append(res)
            if res.matched:
                any_matched = True
        finally:
            r.enabled = saved_enabled

    ctx = FlowInspectionContext.from_flow(flow_obj)
    flow_summary = {
        "method": ctx.method,
        "url": ctx.url,
        "path": ctx.path,
        "status_code": ctx.status_code,
        "duration_ms": ctx.duration_ms,
        "content_length": ctx.content_length,
    }

    return RuleTestResponse(
        matched=any_matched,
        results=results,
        flow_summary=flow_summary,
    )


@router.get("/{rule_id}", response_model=RuleSingleResponse)
async def get_rule(
    rule_id: str,
    engine: RuleEngine = Depends(get_engine),
) -> RuleSingleResponse:
    """Retrieve single rule by ID."""
    rule = engine.get_rule(rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule with ID '{rule_id}' not found",
        )
    return RuleSingleResponse(rule=rule)


@router.put("/{rule_id}", response_model=RuleActionResponse)
async def update_rule(
    rule_id: str,
    payload: Dict[str, Any] = Body(...),
    engine: RuleEngine = Depends(get_engine),
) -> RuleActionResponse:
    """Update an existing rule definition."""
    existing = engine.get_rule(rule_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule with ID '{rule_id}' not found",
        )

    payload["id"] = rule_id
    updated_rule = engine.parse_rule_from_dict(payload)
    engine.update_rule(rule_id, updated_rule)
    return RuleActionResponse(status="updated", rule=updated_rule, rule_id=rule_id)


@router.delete("/{rule_id}", response_model=RuleActionResponse)
async def delete_rule(
    rule_id: str,
    engine: RuleEngine = Depends(get_engine),
) -> RuleActionResponse:
    """Delete a rule from the active registry."""
    success = engine.unregister_rule(rule_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule with ID '{rule_id}' not found",
        )
    return RuleActionResponse(status="deleted", rule_id=rule_id)


@router.patch("/{rule_id}/toggle", response_model=RuleActionResponse)
@router.put("/{rule_id}/toggle", response_model=RuleActionResponse)
@router.post("/{rule_id}/toggle", response_model=RuleActionResponse)
async def toggle_rule(
    rule_id: str,
    body: Optional[ToggleRequest] = None,
    engine: RuleEngine = Depends(get_engine),
) -> RuleActionResponse:
    """Toggle or explicitly set active enabled state of a rule."""
    explicit_state = body.enabled if body else None
    rule = engine.toggle_rule(rule_id, enabled=explicit_state)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule with ID '{rule_id}' not found",
        )
    return RuleActionResponse(status="toggled", rule=rule, rule_id=rule_id)
