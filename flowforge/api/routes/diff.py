"""
FlowForge Request/Response Diff Engine & Delta Computation Route
Provides structural and token-level delta analysis between baseline and mutated flows.
"""

from __future__ import annotations

import difflib
import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/diff", tags=["Diff Viewer"])


class DiffSegment(BaseModel):
    type: str  # 'added', 'removed', 'unchanged'
    value: str
    line_number: Optional[int] = None


class HeaderDiff(BaseModel):
    key: str
    val_a: Optional[str] = None
    val_b: Optional[str] = None
    status: str  # 'added', 'removed', 'modified', 'identical'


class AnomalyVerdict(BaseModel):
    level: str  # 'CRITICAL_IDOR', 'HIGH_REFLECTION', 'AUTH_BYPASS', 'INFO_DIFF', 'IDENTICAL'
    description: str


class DiffRequest(BaseModel):
    flow_id_a: Optional[str] = None
    flow_id_b: Optional[str] = None
    flow_a: Optional[Dict[str, Any]] = None
    flow_b: Optional[Dict[str, Any]] = None


class FlowComparisonResult(BaseModel):
    flow_a: Dict[str, Any]
    flow_b: Dict[str, Any]
    status_match: bool
    status_delta: str
    length_delta_bytes: int
    length_delta_percent: float
    latency_delta_ms: float
    header_diffs: List[HeaderDiff]
    body_diff_segments: List[DiffSegment]
    anomaly_verdict: AnomalyVerdict


def _compute_header_diffs(headers_a: Dict[str, Any], headers_b: Dict[str, Any]) -> List[HeaderDiff]:
    diffs: List[HeaderDiff] = []
    # Normalize headers to lowercase for comparison
    map_a = {str(k).lower(): (k, str(v)) for k, v in headers_a.items()}
    map_b = {str(k).lower(): (k, str(v)) for k, v in headers_b.items()}
    
    all_keys = set(map_a.keys()) | set(map_b.keys())
    for key_lower in sorted(all_keys):
        in_a = key_lower in map_a
        in_b = key_lower in map_b
        
        if in_a and in_b:
            orig_k, val_a = map_a[key_lower]
            _, val_b = map_b[key_lower]
            if val_a == val_b:
                diffs.append(HeaderDiff(key=orig_k, val_a=val_a, val_b=val_b, status="identical"))
            else:
                diffs.append(HeaderDiff(key=orig_k, val_a=val_a, val_b=val_b, status="modified"))
        elif in_a:
            orig_k, val_a = map_a[key_lower]
            diffs.append(HeaderDiff(key=orig_k, val_a=val_a, val_b=None, status="removed"))
        else:
            orig_k, val_b = map_b[key_lower]
            diffs.append(HeaderDiff(key=orig_k, val_a=None, val_b=val_b, status="added"))
            
    return diffs


def _compute_body_diffs(body_a: Optional[str], body_b: Optional[str]) -> List[DiffSegment]:
    str_a = body_a or ""
    str_b = body_b or ""
    
    # Try formatting as JSON if valid
    try:
        json_a = json.loads(str_a)
        str_a = json.dumps(json_a, indent=2)
    except Exception:
        pass
        
    try:
        json_b = json.loads(str_b)
        str_b = json.dumps(json_b, indent=2)
    except Exception:
        pass

    lines_a = str_a.splitlines(keepends=True)
    lines_b = str_b.splitlines(keepends=True)
    
    matcher = difflib.SequenceMatcher(None, lines_a, lines_b)
    segments: List[DiffSegment] = []
    line_num = 1
    
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for line in lines_a[i1:i2]:
                segments.append(DiffSegment(type="unchanged", value=line.rstrip("\r\n"), line_number=line_num))
                line_num += 1
        elif tag == "replace":
            for line in lines_a[i1:i2]:
                segments.append(DiffSegment(type="removed", value=line.rstrip("\r\n"), line_number=line_num))
            for line in lines_b[j1:j2]:
                segments.append(DiffSegment(type="added", value=line.rstrip("\r\n"), line_number=line_num))
                line_num += 1
        elif tag == "delete":
            for line in lines_a[i1:i2]:
                segments.append(DiffSegment(type="removed", value=line.rstrip("\r\n"), line_number=line_num))
        elif tag == "insert":
            for line in lines_b[j1:j2]:
                segments.append(DiffSegment(type="added", value=line.rstrip("\r\n"), line_number=line_num))
                line_num += 1
                
    return segments


def _evaluate_anomaly_verdict(
    flow_a: Dict[str, Any],
    flow_b: Dict[str, Any],
    status_match: bool,
    len_delta: int,
    body_b: str
) -> AnomalyVerdict:
    status_a = flow_a.get("response_status") or flow_a.get("response_status_code") or 200
    status_b = flow_b.get("response_status") or flow_b.get("response_status_code") or 200
    
    # 1. Critical IDOR Check: Both 200 OK, but significant body change or different user ID
    if status_a == 200 and status_b == 200:
        if abs(len_delta) > 200 or ("leak" in body_b.lower() or "victim" in body_b.lower() or "address" in body_b.lower()):
            return AnomalyVerdict(
                level="CRITICAL_IDOR",
                description=f"Status identical (200 OK) with significant body delta (Δ {len_delta:+d} bytes) — Strong IDOR Data Leak Indication"
            )
            
    # 2. Auth Bypass Check: Flow B has no auth or swapped auth but returns 200 OK
    auth_a = str(flow_a.get("request_headers", {})).lower()
    auth_b = str(flow_b.get("request_headers", {})).lower()
    if ("authorization" in auth_a or "bearer" in auth_a) and ("authorization" not in auth_b or "none" in auth_b) and status_b == 200:
        return AnomalyVerdict(
            level="AUTH_BYPASS",
            description="Unauthenticated request succeeded with HTTP 200 OK — Sensitive Endpoint Auth Bypass"
        )
        
    # 3. Reflected Payload Check
    req_body_b = flow_b.get("request_body") or ""
    req_path_b = flow_b.get("path") or ""
    if ("<svg" in req_body_b or "<svg" in req_path_b or "alert(" in req_body_b) and ("<svg" in body_b or "alert(" in body_b):
        return AnomalyVerdict(
            level="HIGH_REFLECTION",
            description="Injected XSS / dangerous probe reflected verbatim in mutated response body"
        )
        
    if status_match and len_delta == 0:
        return AnomalyVerdict(
            level="IDENTICAL",
            description="Baseline and comparison flows produced identical responses"
        )
        
    return AnomalyVerdict(
        level="INFO_DIFF",
        description=f"Responses differ in status ({status_a} -> {status_b}) or length (Δ {len_delta:+d} bytes)"
    )


@router.post("", response_model=FlowComparisonResult)
async def compute_flow_diff(payload: DiffRequest, request: Request):
    """
    Compute structural and token-level diff between two flows.
    """
    flow_a = payload.flow_a
    flow_b = payload.flow_b
    
    # Attempt to fetch from repository if flow IDs are supplied
    if (payload.flow_id_a or payload.flow_id_b) and hasattr(request.app.state, "repo"):
        repo = request.app.state.repo
        if payload.flow_id_a and not flow_a:
            rec_a = await repo.get_flow_by_id(payload.flow_id_a)
            if rec_a:
                flow_a = rec_a.dict() if hasattr(rec_a, "dict") else dict(rec_a)
        if payload.flow_id_b and not flow_b:
            rec_b = await repo.get_flow_by_id(payload.flow_id_b)
            if rec_b:
                flow_b = rec_b.dict() if hasattr(rec_b, "dict") else dict(rec_b)

    if not flow_a:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Flow A (or a valid flow_id_a) must be provided for comparison.",
        )
    if not flow_b:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Flow B (or a valid flow_id_b) must be provided for comparison.",
        )


    status_a = flow_a.get("response_status") or flow_a.get("response_status_code") or 200
    status_b = flow_b.get("response_status") or flow_b.get("response_status_code") or 200
    status_match = (status_a == status_b)
    status_delta = f"{status_a} == {status_b}" if status_match else f"{status_a} -> {status_b}"
    
    body_a = flow_a.get("response_body") or ""
    body_b = flow_b.get("response_body") or ""
    len_a = flow_a.get("response_size") or len(body_a.encode("utf-8"))
    len_b = flow_b.get("response_size") or len(body_b.encode("utf-8"))
    len_delta_bytes = len_b - len_a
    len_delta_percent = round((len_delta_bytes / max(1, len_a)) * 100, 1)
    
    lat_a = flow_a.get("latency_ms") or 0.0
    lat_b = flow_b.get("latency_ms") or 0.0
    lat_delta = round(lat_b - lat_a, 2)
    
    headers_a = flow_a.get("response_headers") or {}
    headers_b = flow_b.get("response_headers") or {}
    header_diffs = _compute_header_diffs(headers_a, headers_b)
    body_segments = _compute_body_diffs(body_a, body_b)
    verdict = _evaluate_anomaly_verdict(flow_a, flow_b, status_match, len_delta_bytes, body_b)
    
    return FlowComparisonResult(
        flow_a=flow_a,
        flow_b=flow_b,
        status_match=status_match,
        status_delta=status_delta,
        length_delta_bytes=len_delta_bytes,
        length_delta_percent=len_delta_percent,
        latency_delta_ms=lat_delta,
        header_diffs=header_diffs,
        body_diff_segments=body_segments,
        anomaly_verdict=verdict
    )
