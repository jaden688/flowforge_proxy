"""
REST API endpoints for Custom Heuristic Match Rules (Requirement R5).

Provides CRUD operations, toggling, dry-run testing, and import/export capabilities.
Rules are persisted to SQLite and loaded into the in-memory RuleEngine on startup.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, Request, status
from pydantic import BaseModel, Field

from flowforge.config import get_settings
from flowforge.db.repository import FlowRepository
from flowforge.db.rules_repository import RulesRepository
from flowforge.heuristics.rule_engine import (
    FlowInspectionContext,
    RuleEngine,
    get_rule_engine,
)
from flowforge.models.rules import (
    MatchRule,
    RuleCondition,
    RuleOperator,
    RuleExportResponse,
    RuleImportRequest,
    RuleImportResult,
    RuleSeverity,
    RuleTestRequest,
    RuleTestResponse,
)

logger = logging.getLogger("flowforge.api.routes.rules")

router = APIRouter(prefix="/api/v1/rules", tags=["Custom Rules"])


_rules_repo_checked = False
_rules_repo_available = False


def _rules_repo(request: Request) -> Optional[RulesRepository]:
    """Get or create the RulesRepository from app state. Returns None if DB table missing."""
    global _rules_repo_checked, _rules_repo_available
    repo = getattr(request.app.state, "rules_repo", None)
    if repo is not None:
        return repo
    if _rules_repo_checked:
        return None if not _rules_repo_available else repo
    try:
        settings = get_settings()
        repo = RulesRepository(settings.db_path)
        request.app.state.rules_repo = repo
        _rules_repo_checked = True
        _rules_repo_available = True
        return repo
    except Exception:
        _rules_repo_checked = True
        _rules_repo_available = False
        return None


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
# CRUD Endpoints — persist to DB + update in-memory engine
# -------------------------------------------------------------------------


@router.get("", response_model=RuleListResponse)
async def list_rules(
    request: Request,
    enabled: Optional[bool] = Query(None, description="Filter by active enabled state"),
    severity: Optional[str] = Query(None, description="Filter by severity level (LOW, MEDIUM, HIGH, CRITICAL)"),
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search name, description, tags, or ID"),
    engine: RuleEngine = Depends(get_engine),
) -> RuleListResponse:
    """List all registered custom and built-in heuristic rules with filtering."""
    repo = _rules_repo(request)
    if repo:
        try:
            rules = await repo.list_rules(
                enabled_only=enabled is True,
                category=category,
                severity=severity,
                search=search,
            )
        except Exception:
            rules = []
    else:
        rules = []

    # Also include in-memory-only rules (built-ins not yet in DB)
    engine_rules = engine.list_rules(
        enabled_only=enabled is True,
        category=category,
        severity=None,
        search=search,
    )
    engine_rule_ids = {r.id for r in rules}
    for er in engine_rules:
        if er.id not in engine_rule_ids:
            rules.append(er)

    if enabled is False:
        rules = [r for r in rules if not r.enabled]

    return RuleListResponse(rules=rules, total=len(rules))


@router.post("", response_model=RuleActionResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    request: Request,
    payload: Dict[str, Any] = Body(...),
    engine: RuleEngine = Depends(get_engine),
) -> RuleActionResponse:
    """Create and register a new heuristic rule. Persists to DB and loads into engine."""
    try:
        rule = engine.parse_rule_from_dict(payload)
        # Persist to DB (graceful if table missing)
        repo = _rules_repo(request)
        if repo:
            try:
                await repo.upsert_rule(rule)
            except Exception:
                logger.debug("DB persistence skipped for rule %s", rule.id)
        # Also register in-memory
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
    request: Request,
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
    request: Request,
    req: RuleImportRequest,
    engine: RuleEngine = Depends(get_engine),
) -> RuleImportResult:
    """Import and register rules from a YAML or JSON payload. Persists to DB."""
    fmt = req.format.lower().strip()
    if fmt == "json":
        imported, updated, errors, rules = engine.import_from_json(req.content, overwrite=req.overwrite)
    else:
        imported, updated, errors, rules = engine.import_from_yaml(req.content, overwrite=req.overwrite)

    # Persist imported rules to DB (graceful if table missing)
    repo = _rules_repo(request)
    if repo:
        for rule in rules:
            try:
                await repo.upsert_rule(rule)
            except Exception:
                logger.debug("DB persistence skipped for imported rule %s", rule.id)

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
    request: Request,
    payload: Dict[str, Any] = Body(...),
    engine: RuleEngine = Depends(get_engine),
) -> RuleActionResponse:
    """Update an existing rule definition. Persists to DB."""
    existing = engine.get_rule(rule_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule with ID '{rule_id}' not found",
        )

    payload["id"] = rule_id
    updated_rule = engine.parse_rule_from_dict(payload)
    # Persist to DB (graceful if table missing)
    repo = _rules_repo(request)
    if repo:
        try:
            await repo.upsert_rule(updated_rule)
        except Exception:
            logger.debug("DB persistence skipped for rule %s", rule_id)
    # Update in-memory
    engine.update_rule(rule_id, updated_rule)
    return RuleActionResponse(status="updated", rule=updated_rule, rule_id=rule_id)


@router.delete("/{rule_id}", response_model=RuleActionResponse)
async def delete_rule(
    rule_id: str,
    request: Request,
    engine: RuleEngine = Depends(get_engine),
) -> RuleActionResponse:
    """Delete a rule from the active registry and DB."""
    # Delete from DB (graceful if table missing)
    repo = _rules_repo(request)
    if repo:
        try:
            await repo.delete_rule(rule_id)
        except Exception:
            logger.debug("DB delete skipped for rule %s", rule_id)
    # Delete from in-memory engine
    engine.unregister_rule(rule_id)
    return RuleActionResponse(status="deleted", rule_id=rule_id)


@router.patch("/{rule_id}/toggle", response_model=RuleActionResponse)
@router.put("/{rule_id}/toggle", response_model=RuleActionResponse)
@router.post("/{rule_id}/toggle", response_model=RuleActionResponse)
async def toggle_rule(
    rule_id: str,
    request: Request,
    body: Optional[ToggleRequest] = None,
    engine: RuleEngine = Depends(get_engine),
) -> RuleActionResponse:
    """Toggle or explicitly set active enabled state of a rule. Persists to DB."""
    explicit_state = body.enabled if body else None
    # Toggle in DB (graceful if table missing)
    repo = _rules_repo(request)
    if repo:
        try:
            await repo.toggle_rule(rule_id, enabled=explicit_state)
        except Exception:
            logger.debug("DB toggle skipped for rule %s", rule_id)
    # Toggle in-memory
    rule = engine.toggle_rule(rule_id, enabled=explicit_state)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule with ID '{rule_id}' not found",
        )
    return RuleActionResponse(status="toggled", rule=rule, rule_id=rule_id)


class ScopeImportRequest(BaseModel):
    program_name: Optional[str] = "Imported Target Scope"
    in_scope_patterns: List[str]
    out_of_scope_patterns: Optional[List[str]] = Field(default_factory=list)


@router.post("/import-scope", response_model=RuleImportResult)
async def import_scope_as_rules(
    request: Request,
    payload: ScopeImportRequest = Body(...),
    engine: RuleEngine = Depends(get_engine),
) -> RuleImportResult:
    """
    Import a target scope list (in-scope & out-of-scope patterns) as active scope-filter rules.
    Creates rule definitions for matching in-scope host/path targets and tagging them in telemetry.
    """
    imported_count = 0
    errors: List[str] = []
    repo = _rules_repo(request)

    # 1. Create In-Scope Rule
    if payload.in_scope_patterns:
        conditions = []
        for pat in payload.in_scope_patterns:
            clean_pat = pat.replace("*.", "").replace("https://", "").replace("http://", "").strip()
            if not clean_pat:
                continue
            conditions.append(
                RuleCondition(
                    field="url",
                    operator=RuleOperator.CONTAINS,
                    value=clean_pat,
                    case_sensitive=False,
                )
            )

        if conditions:
            in_scope_rule = MatchRule(
                id=f"scope-in-{uuid.uuid4().hex[:6]}",
                name=f"In-Scope Match: {payload.program_name}",
                description=f"Auto-generated scope rule for in-scope assets: {', '.join(payload.in_scope_patterns[:5])}",
                severity=RuleSeverity.INFO,
                category="SCOPE_IN",
                tags=["scope", "in_scope", payload.program_name.lower().replace(" ", "_")],
                condition_combinator="any",
                conditions=conditions,
                enabled=True,
            )
            engine.register_rule(in_scope_rule)
            if repo:
                try:
                    await repo.upsert_rule(in_scope_rule)
                except Exception as ex:
                    logger.warning("Failed to persist in-scope rule to DB: %s", ex)
            imported_count += 1

    # 2. Create Out-of-Scope Rule
    if payload.out_of_scope_patterns:
        out_conditions = []
        for pat in payload.out_of_scope_patterns:
            clean_pat = pat.replace("*.", "").replace("https://", "").replace("http://", "").strip()
            if not clean_pat:
                continue
            out_conditions.append(
                RuleCondition(
                    field="url",
                    operator=RuleOperator.CONTAINS,
                    value=clean_pat,
                    case_sensitive=False,
                )
            )

        if out_conditions:
            out_scope_rule = MatchRule(
                id=f"scope-out-{uuid.uuid4().hex[:6]}",
                name=f"Out-of-Scope Match: {payload.program_name}",
                description=f"Auto-generated scope rule for out-of-scope assets: {', '.join(payload.out_of_scope_patterns[:5])}",
                severity=RuleSeverity.HIGH,
                category="SCOPE_OUT",
                tags=["scope", "out_of_scope", payload.program_name.lower().replace(" ", "_")],
                condition_combinator="any",
                conditions=out_conditions,
                enabled=True,
            )
            engine.register_rule(out_scope_rule)
            if repo:
                try:
                    await repo.upsert_rule(out_scope_rule)
                except Exception as ex:
                    logger.warning("Failed to persist out-of-scope rule to DB: %s", ex)
            imported_count += 1

    return RuleImportResult(
        status="imported",
        imported_count=imported_count,
        errors=errors,
    )

