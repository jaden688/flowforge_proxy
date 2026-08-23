"""Confirmed vulnerability findings API.

Surfaces executed test proposals whose replay produced an anomalous verdict
(CRITICAL_IDOR, AUTH_BYPASS, HIGH_REFLECTION, ...) so operators can analyze
confirmed vulnerabilities instead of raw candidate noise.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query, Request

from flowforge.db.repository import FlowRepository

router = APIRouter(prefix="/api/v1/findings", tags=["Findings"])

_BENIGN_VERDICTS = {"IDENTICAL", "INFO_DIFF"}

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_VERDICT_RANK = {
    "CRITICAL_IDOR": 5,
    "AUTH_BYPASS": 5,
    "HIGH_REFLECTION": 4,
    "SQLI_INDICATOR": 4,
    "ANOMALY_DETECTED": 3,
}

_SCAN_LIMIT = 2000


def _get_repo(request: Request) -> FlowRepository:
    repo = getattr(request.app.state, "repo", None)
    if repo is None:
        raise RuntimeError("FlowRepository not initialized on app state")
    return repo


def _finding_from_proposal(p: Any) -> Optional[Dict[str, Any]]:
    er = p.execution_result
    if er is None:
        return None
    verdict_level = (er.verdict_level or "").upper()
    if not verdict_level or verdict_level in _BENIGN_VERDICTS:
        return None
    anomaly_type = p.anomaly_type.value if hasattr(p.anomaly_type, "value") else str(p.anomaly_type)
    severity = p.severity.value if hasattr(p.severity, "value") else str(p.severity)
    return {
        "finding_id": p.id,
        "proposal_id": p.id,
        "flow_id": p.flow_id,
        "executed_flow_id": er.executed_flow_id or p.executed_flow_id,
        "endpoint_hash": p.endpoint_hash,
        "endpoint_path": p.endpoint_path,
        "method": p.method,
        "anomaly_type": anomaly_type,
        "title": p.title,
        "description": p.description,
        "severity": severity,
        "confidence_score": p.confidence_score,
        "target_param_name": p.target_param_name,
        "target_param_location": p.target_param_location,
        "baseline_value": p.baseline_value,
        "mutated_value": p.mutated_value,
        "tags": p.tags,
        "verdict_level": verdict_level,
        "verdict_description": er.verdict_description,
        "status_delta": er.status_delta,
        "length_delta_bytes": er.length_delta_bytes,
        "latency_delta_ms": er.latency_delta_ms,
        "reflected": er.reflected,
        "response_body_preview": er.response_body_preview,
        "executed_at": er.executed_at,
    }


@router.get("")
async def list_findings(
    request: Request,
    verdict: Optional[str] = Query(None, description="Filter by verdict level"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    search: Optional[str] = Query(None, description="Substring filter on title/path"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    """List confirmed vulnerability findings from executed test proposals."""
    repo = _get_repo(request)
    proposals, _total = await repo.list_proposals(state="COMPLETED", page=1, page_size=_SCAN_LIMIT)

    findings: List[Dict[str, Any]] = []
    for p in proposals:
        f = _finding_from_proposal(p)
        if f is None:
            continue
        if verdict and f["verdict_level"] != verdict.upper():
            continue
        if severity and f["severity"] != severity.upper():
            continue
        if search:
            q = search.lower()
            if not (q in (f["title"] or "").lower() or q in (f["endpoint_path"] or "").lower()):
                continue
        findings.append(f)

    findings.sort(
        key=lambda f: (
            -_VERDICT_RANK.get(f["verdict_level"], 2),
            -_SEVERITY_RANK.get(f["severity"], 0),
            -(f["executed_at"] or 0),
        )
    )

    total = len(findings)
    offset = (page - 1) * page_size
    window = findings[offset : offset + page_size]
    return {"items": window, "total": total, "page": page, "page_size": page_size}


@router.get("/stats")
async def findings_stats(request: Request) -> Dict[str, Any]:
    """Aggregate confirmed finding counts by verdict level and severity."""
    repo = _get_repo(request)
    proposals, _total = await repo.list_proposals(state="COMPLETED", page=1, page_size=_SCAN_LIMIT)

    by_verdict: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    latest: List[Dict[str, Any]] = []
    for p in proposals:
        f = _finding_from_proposal(p)
        if f is None:
            continue
        by_verdict[f["verdict_level"]] = by_verdict.get(f["verdict_level"], 0) + 1
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        latest.append(f)

    latest.sort(key=lambda f: -(f["executed_at"] or 0))
    return {
        "total_findings": len(latest),
        "by_verdict": dict(sorted(by_verdict.items(), key=lambda kv: -kv[1])),
        "by_severity": dict(sorted(by_severity.items(), key=lambda kv: -_SEVERITY_RANK.get(kv[0], 0))),
        "latest": latest[:10],
    }
