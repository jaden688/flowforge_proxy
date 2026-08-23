"""
REST API endpoints for Automated Test Proposals, 1-Click Execution, Replay Diffing, and Curation Bridges.
"""

from __future__ import annotations

import asyncio
import copy
import json
import math
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from flowforge.core.broadcaster import EventBroadcaster, get_broadcaster
from flowforge.db.repository import FlowRepository
from flowforge.heuristics.pipeline import TriagePipeline, default_pipeline
from flowforge.heuristics.proposal_synthesizer import ProposalSynthesizer
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.proposal import (
    AnomalyType,
    ApproveProposalRequest,
    BatchProposalActionRequest,
    BatchProposalActionResponse,
    DismissProposalRequest,
    ExecuteProposalResponse,
    GenerateProposalsRequest,
    PaginatedProposalsResponse,
    ProposalExecutionResult,
    ProposalSeverity,
    ProposalState,
    ProposalStatsResponse,
    TestProposal,
    ToCuratedRequest,
    ToMatrixRequest,
)
from flowforge.utils.serializers import json_dumps, json_loads

router = APIRouter(prefix="/api/v1/proposals", tags=["Test Proposals"])


def get_repository(request: Request) -> FlowRepository:
    """Dependency provider for FlowRepository."""
    if hasattr(request.app.state, "repo") and request.app.state.repo:
        return request.app.state.repo
    return FlowRepository()


def get_broadcaster_dep(request: Request) -> EventBroadcaster:
    """Dependency provider for EventBroadcaster."""
    if hasattr(request.app.state, "broadcaster") and request.app.state.broadcaster:
        return request.app.state.broadcaster
    return get_broadcaster()


@router.get("", response_model=PaginatedProposalsResponse)
async def list_proposals(
    flow_id: Optional[str] = Query(None, description="Filter by source flow ID"),
    state: Optional[str] = Query(None, description="Filter by proposal state (PENDING, APPROVED, EXECUTING, COMPLETED, DISMISSED)"),
    anomaly_type: Optional[str] = Query(None, description="Filter by anomaly type"),
    severity: Optional[str] = Query(None, description="Filter by proposal severity"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=100.0, description="Minimum confidence score"),
    search: Optional[str] = Query(None, description="Search across title, description, param name, path"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
    repo: FlowRepository = Depends(get_repository),
):
    """
    List and filter automated test proposals with pagination.
    """
    items, total = await repo.list_proposals(
        flow_id=flow_id,
        state=state,
        anomaly_type=anomaly_type,
        severity=severity,
        min_confidence=min_confidence,
        search=search,
        page=page,
        page_size=page_size,
    )
    total_pages = math.ceil(total / page_size) if total > 0 else 0
    return PaginatedProposalsResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/stats", response_model=ProposalStatsResponse)
async def get_proposal_stats(
    repo: FlowRepository = Depends(get_repository),
):
    """
    Get aggregated counts of proposals across all lifecycle states.
    """
    stats_dict = await repo.get_proposal_stats()
    return ProposalStatsResponse(
        total=stats_dict.get("total", 0),
        pending=stats_dict.get("pending", 0),
        approved=stats_dict.get("approved", 0),
        executing=stats_dict.get("executing", 0),
        completed=stats_dict.get("completed", 0),
        dismissed=stats_dict.get("dismissed", 0),
    )


@router.get("/{proposal_id}", response_model=TestProposal)
async def get_proposal(
    proposal_id: str,
    repo: FlowRepository = Depends(get_repository),
):
    """
    Fetch a single proposal by ID.
    """
    proposal = await repo.get_proposal_by_id(proposal_id)
    if not proposal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proposal with ID '{proposal_id}' not found.",
        )
    return proposal


@router.post("/{proposal_id}/approve", response_model=TestProposal)
async def approve_proposal(
    proposal_id: str,
    payload: Optional[ApproveProposalRequest] = None,
    repo: FlowRepository = Depends(get_repository),
    broadcaster: EventBroadcaster = Depends(get_broadcaster_dep),
):
    """
    Approve a staged proposal for execution.
    """
    proposal = await repo.get_proposal_by_id(proposal_id)
    if not proposal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proposal with ID '{proposal_id}' not found.",
        )

    proposal.state = ProposalState.APPROVED
    proposal.updated_at = time.time()
    await repo.update_proposal_state(proposal_id, ProposalState.APPROVED)

    broadcaster.broadcast_proposal_updated(
        proposal.flow_id,
        proposal_id,
        {"state": ProposalState.APPROVED.value, "updated_at": proposal.updated_at},
    )
    return proposal


@router.post("/{proposal_id}/dismiss", response_model=TestProposal)
async def dismiss_proposal(
    proposal_id: str,
    payload: Optional[DismissProposalRequest] = None,
    repo: FlowRepository = Depends(get_repository),
    broadcaster: EventBroadcaster = Depends(get_broadcaster_dep),
):
    """
    Dismiss and ignore a staged proposal.
    """
    proposal = await repo.get_proposal_by_id(proposal_id)
    if not proposal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proposal with ID '{proposal_id}' not found.",
        )

    proposal.state = ProposalState.DISMISSED
    proposal.updated_at = time.time()
    await repo.update_proposal_state(proposal_id, ProposalState.DISMISSED)

    broadcaster.broadcast_proposal_dismissed(proposal.flow_id, proposal_id)
    return proposal


@router.delete("/{proposal_id}")
async def delete_proposal(
    proposal_id: str,
    repo: FlowRepository = Depends(get_repository),
):
    """
    Permanently delete a proposal record.
    """
    deleted = await repo.delete_proposal(proposal_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proposal with ID '{proposal_id}' not found.",
        )
    return {"ok": True, "id": proposal_id}


@router.post("/batch", response_model=BatchProposalActionResponse)
async def batch_proposal_action(
    payload: BatchProposalActionRequest,
    repo: FlowRepository = Depends(get_repository),
    broadcaster: EventBroadcaster = Depends(get_broadcaster_dep),
):
    """
    Execute batch operations across multiple proposals (approve, dismiss, delete).
    """
    action = payload.action.lower().strip()
    proposal_ids = payload.proposal_ids
    if not proposal_ids:
        return BatchProposalActionResponse(success_count=0, failure_count=0, updated_ids=[])

    updated_ids: List[str] = []
    errors: List[str] = []

    if action == "approve":
        for pid in proposal_ids:
            p = await repo.get_proposal_by_id(pid)
            if p:
                await repo.update_proposal_state(pid, ProposalState.APPROVED)
                broadcaster.broadcast_proposal_updated(p.flow_id, pid, {"state": ProposalState.APPROVED.value})
                updated_ids.append(pid)
            else:
                errors.append(f"Proposal {pid} not found")
    elif action == "dismiss":
        for pid in proposal_ids:
            p = await repo.get_proposal_by_id(pid)
            if p:
                await repo.update_proposal_state(pid, ProposalState.DISMISSED)
                broadcaster.broadcast_proposal_dismissed(p.flow_id, pid)
                updated_ids.append(pid)
            else:
                errors.append(f"Proposal {pid} not found")
    elif action == "delete":
        for pid in proposal_ids:
            del_ok = await repo.delete_proposal(pid)
            if del_ok:
                updated_ids.append(pid)
            else:
                errors.append(f"Proposal {pid} not found")
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported batch action '{payload.action}'. Supported: 'approve', 'dismiss', 'delete'.",
        )

    return BatchProposalActionResponse(
        success_count=len(updated_ids),
        failure_count=len(errors),
        updated_ids=updated_ids,
        errors=errors if errors else None,
    )


@router.post("/generate/{flow_id}", response_model=List[TestProposal])
async def generate_proposals_for_flow(
    flow_id: str,
    payload: Optional[GenerateProposalsRequest] = None,
    request: Request = None,
    repo: FlowRepository = Depends(get_repository),
    broadcaster: EventBroadcaster = Depends(get_broadcaster_dep),
):
    """
    On-demand trigger to synthesize test proposals for a specific intercepted flow.
    """
    flow_record = await repo.get_flow_by_id(flow_id)
    if not flow_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flow with ID '{flow_id}' not found.",
        )

    # If triage data is missing or incomplete, process flow through triage pipeline
    triage_summary = None
    if flow_record.triage_data:
        try:
            from flowforge.heuristics.models import TriageSummary
            triage_summary = TriageSummary.model_validate(flow_record.triage_data)
        except Exception:
            triage_summary = None

    if not triage_summary:
        triage_summary = await default_pipeline.process_flow(flow_record)

    synthesizer = ProposalSynthesizer()
    proposals = synthesizer.synthesize(flow_record, triage_summary)

    # Filter anomaly types if requested
    if payload and payload.anomaly_types:
        allowed_types = {t.upper() for t in payload.anomaly_types}
        proposals = [
            p for p in proposals
            if (p.anomaly_type.value if hasattr(p.anomaly_type, "value") else str(p.anomaly_type)).upper() in allowed_types
        ]

    # Persist generated proposals
    if proposals:
        db_writer = getattr(request.app.state, "db_writer", None) if request else None
        if db_writer:
            await db_writer.enqueue_proposals_batch(proposals)
        else:
            for p in proposals:
                await repo.update_proposal_state(p.id, p.state)

        broadcaster.broadcast_proposal_created(flow_id, proposals)

    return proposals


@router.post("/{proposal_id}/execute", response_model=ExecuteProposalResponse)
async def execute_proposal(
    proposal_id: str,
    request: Request,
    repo: FlowRepository = Depends(get_repository),
    broadcaster: EventBroadcaster = Depends(get_broadcaster_dep),
):
    """
    1-Click Operator Replay Execution:
    Rebuilds mutated request, replays it through HTTP engine, computes delta diff, attaches verdict,
    and returns proposal along with baseline-vs-mutation comparison.
    """
    from flowforge.api.routes.diff import (
        _compute_body_diffs,
        _compute_header_diffs,
        _evaluate_anomaly_verdict,
    )

    proposal = await repo.get_proposal_by_id(proposal_id)
    if not proposal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proposal with ID '{proposal_id}' not found.",
        )

    baseline_flow = await repo.get_flow_by_id(proposal.flow_id)
    if not baseline_flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline flow '{proposal.flow_id}' not found for proposal '{proposal_id}'.",
        )

    proposal.state = ProposalState.EXECUTING
    await repo.update_proposal_state(proposal_id, ProposalState.EXECUTING)

    # Reconstruct request
    req = baseline_flow.request
    method = proposal.method or req.method
    url = req.url
    path = proposal.endpoint_path or req.path
    headers = dict(req.headers)
    query_params = dict(req.query_params)
    body = req.body

    # Apply parameter mutation based on location
    if proposal.target_param_location == "query" and proposal.target_param_name:
        query_params[proposal.target_param_name] = proposal.mutated_value
    elif proposal.target_param_location == "path":
        # Mutate path segment if baseline value found
        if proposal.baseline_value and str(proposal.baseline_value) in path:
            path = path.replace(str(proposal.baseline_value), str(proposal.mutated_value or ""), 1)
        elif proposal.mutated_value is not None:
            path = f"{path.rstrip('/')}/{proposal.mutated_value}"
        parsed_url = urllib.parse.urlparse(url)
        url = urllib.parse.urlunparse(parsed_url._replace(path=path))
    elif proposal.target_param_location in ("body", "body_json", "json_body"):
        if isinstance(proposal.mutated_value, (dict, list)):
            body = json_dumps(proposal.mutated_value)
        elif proposal.mutated_value is not None:
            body = str(proposal.mutated_value)
    elif proposal.target_param_location == "header" and proposal.target_param_name:
        if proposal.mutated_value is None:
            headers.pop(proposal.target_param_name, None)
            headers.pop(proposal.target_param_name.lower(), None)
        else:
            headers[proposal.target_param_name] = str(proposal.mutated_value)

    # Apply auth overrides
    if proposal.auth_override == "DROP":
        for k in list(headers.keys()):
            if k.lower() in ("authorization", "cookie", "x-api-key", "apikey", "x-auth-token"):
                del headers[k]
    elif proposal.auth_override == "USER_B":
        headers["Authorization"] = "Bearer simulated-user-b-token-12345"
        headers["Cookie"] = "session_id=user_b_session_token_67890"
    elif proposal.auth_override == "EXPIRED":
        headers["Authorization"] = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJleHBpcmVkIiwiaWF0IjoxNTAwMDAwMDAwLCJleHAiOjE1MDAwMDAwMDB9.invalidsig"
    elif proposal.auth_override == "ALG_NONE":
        headers["Authorization"] = "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlzX2FkbWluIjp0cnVlfQ."

    # Replay execution
    start_time = time.perf_counter()
    resp_status = 200
    resp_headers: Dict[str, str] = {}
    resp_body = ""
    error_msg: Optional[str] = None

    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
            http_resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                params=query_params if query_params else None,
                content=body.encode("utf-8") if isinstance(body, str) else body,
            )
            resp_status = http_resp.status_code
            resp_headers = {k: v for k, v in http_resp.headers.items()}
            resp_body = http_resp.text
    except Exception as http_err:
        error_msg = f"Network connection error: {str(http_err)}"
        resp_status = 502
        resp_body = f"Failed to execute replay request against {url}: {str(http_err)}"


    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    # Compare baseline vs replay
    baseline_resp = baseline_flow.response
    baseline_status = baseline_resp.status_code if baseline_resp and baseline_resp.status_code is not None else 200
    baseline_body = baseline_resp.body or "" if baseline_resp else ""
    baseline_len = baseline_resp.content_length if (baseline_resp and baseline_resp.content_length) else len(baseline_body.encode("utf-8"))

    replay_len = len(resp_body.encode("utf-8"))
    len_delta = replay_len - baseline_len
    len_delta_pct = round((len_delta / max(1, baseline_len)) * 100, 1)
    status_match = bool(resp_status == baseline_status)
    status_delta = f"{baseline_status} == {resp_status}" if status_match else f"{baseline_status} -> {resp_status}"

    # Check for reflection
    mut_val_str = str(proposal.mutated_value or "")
    reflected = bool(mut_val_str and (mut_val_str in resp_body or mut_val_str in str(resp_headers)))

    # Compute verdict
    flow_a_dict = {
        "response_status": baseline_status,
        "response_status_code": baseline_status,
        "response_body": baseline_body,
        "response_size": baseline_len,
        "request_headers": req.headers,
        "latency_ms": baseline_flow.duration_ms or 0.0,
    }
    flow_b_dict = {
        "response_status": resp_status,
        "response_status_code": resp_status,
        "response_body": resp_body,
        "response_size": replay_len,
        "request_headers": headers,
        "request_body": body,
        "path": path,
        "latency_ms": duration_ms,
    }

    verdict_obj = _evaluate_anomaly_verdict(flow_a_dict, flow_b_dict, status_match, len_delta, resp_body)
    header_diffs = _compute_header_diffs(req.headers, headers)
    body_diffs = _compute_body_diffs(baseline_body, resp_body)

    executed_flow_id = str(uuid.uuid4())
    exec_result = ProposalExecutionResult(
        executed_at=time.time(),
        duration_ms=duration_ms,
        status_code=resp_status,
        status_match=status_match,
        status_delta=status_delta,
        length_delta_bytes=len_delta,
        length_delta_percent=len_delta_pct,
        latency_delta_ms=round(duration_ms - (baseline_flow.duration_ms or 0.0), 2),
        reflected=reflected,
        anomaly_detected=verdict_obj.level not in ("IDENTICAL", "INFO_DIFF"),
        verdict_level=verdict_obj.level,
        verdict_description=verdict_obj.description,
        executed_flow_id=executed_flow_id,
        response_headers=resp_headers,
        response_body_preview=resp_body[:500] if resp_body else None,
    )

    proposal.state = ProposalState.COMPLETED
    proposal.execution_result = exec_result
    proposal.executed_flow_id = executed_flow_id
    proposal.updated_at = time.time()

    await repo.update_proposal_state(
        proposal.id,
        ProposalState.COMPLETED,
        execution_result=exec_result,
        executed_flow_id=executed_flow_id,
    )

    # Construct executed flow record and enqueue to DB
    executed_flow = FlowRecord(
        id=executed_flow_id,
        timestamp_start=time.time() - (duration_ms / 1000.0),
        timestamp_end=time.time(),
        duration_ms=duration_ms,
        client_ip=baseline_flow.client_ip,
        client_port=baseline_flow.client_port,
        server_host=baseline_flow.server_host,
        server_port=baseline_flow.server_port,
        scheme=baseline_flow.scheme,
        http_version=baseline_flow.http_version,
        request=RequestModel(
            method=method,
            url=url,
            path=path,
            query_string=baseline_flow.request.query_string,
            query_params=query_params,
            headers=headers,
            content_type=headers.get("content-type"),
            content_length=len(body.encode("utf-8")) if body else 0,
            body=body,
            cookies=baseline_flow.request.cookies,
        ),
        response=ResponseModel(
            status_code=resp_status,
            reason="OK" if resp_status == 200 else "Error",
            headers=resp_headers,
            content_type=resp_headers.get("content-type"),
            content_length=replay_len,
            body=resp_body,
            cookies={},
        ),
        tags=["proposal_replay", proposal.anomaly_type.value.lower()],
        notes=f"Replay execution of proposal '{proposal.id}': {verdict_obj.level}",
    )

    db_writer = getattr(request.app.state, "db_writer", None) if request else None
    if db_writer:
        await db_writer.enqueue_insert_flow(executed_flow)

    broadcaster.broadcast_proposal_executed(
        proposal.flow_id,
        proposal.id,
        {
            "proposal_id": proposal.id,
            "state": "COMPLETED",
            "verdict_level": exec_result.verdict_level,
            "verdict_description": exec_result.verdict_description,
            "length_delta_bytes": exec_result.length_delta_bytes,
            "status_delta": exec_result.status_delta,
            "latency_ms": duration_ms,
        },
    )

    diff_payload = {
        "flow_a": flow_a_dict,
        "flow_b": flow_b_dict,
        "status_match": status_match,
        "status_delta": status_delta,
        "length_delta_bytes": len_delta,
        "length_delta_percent": len_delta_pct,
        "latency_delta_ms": exec_result.latency_delta_ms,
        "header_diffs": [h.model_dump() for h in header_diffs],
        "body_diff_segments": [b.model_dump() for b in body_diffs],
        "anomaly_verdict": verdict_obj.model_dump(),
    }

    return ExecuteProposalResponse(
        proposal=proposal,
        executed_flow=executed_flow.model_dump(),
        diff=diff_payload,
    )


@router.post("/{proposal_id}/to-curated")
async def transfer_proposal_to_curated(
    proposal_id: str,
    payload: Optional[ToCuratedRequest] = None,
    repo: FlowRepository = Depends(get_repository),
):
    """
    Transfer a test proposal directly into the Curated Collections store.
    """
    from flowforge.api.routes.curation import _curation_lock, _groups_store, _payloads_store, _sync_group_items
    from flowforge.models.curation import CuratedPayload

    proposal = await repo.get_proposal_by_id(proposal_id)
    if not proposal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proposal with ID '{proposal_id}' not found.",
        )

    req_payload = payload or ToCuratedRequest()
    group_id = req_payload.group_id or "default"
    custom_name = req_payload.custom_name or proposal.title
    tags = req_payload.tags or proposal.tags

    cur_id = f"cur-{uuid.uuid4().hex[:8]}"
    curated_item = CuratedPayload(
        id=cur_id,
        group_id=group_id,
        name=custom_name,
        category=proposal.anomaly_type.value if hasattr(proposal.anomaly_type, "value") else str(proposal.anomaly_type),
        endpoint_path=proposal.endpoint_path,
        method=proposal.method,
        target_param_location=proposal.target_param_location,
        target_param_name=proposal.target_param_name,
        baseline_value=proposal.baseline_value,
        mutated_value=proposal.mutated_value,
        auth_override=proposal.auth_override,
        status="READY",
        starred=True,
        notes=f"Curated from proposal '{proposal.id}': {proposal.description}",
        tags=tags,
    )

    async with _curation_lock:
        _payloads_store[cur_id] = curated_item
        _sync_group_items(group_id)

    return {
        "ok": True,
        "curated_payload_id": cur_id,
        "group_id": group_id,
        "proposal_id": proposal.id,
        "name": custom_name,
    }


@router.post("/{proposal_id}/to-matrix")
async def transfer_proposal_to_matrix(
    proposal_id: str,
    payload: Optional[ToMatrixRequest] = None,
    repo: FlowRepository = Depends(get_repository),
):
    """
    Transfer a test proposal directly into the Test Matrix workbench.
    """
    from flowforge.api.routes.matrix import _matrix_jobs, TestMatrixCase, TestMatrixJob

    proposal = await repo.get_proposal_by_id(proposal_id)
    if not proposal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proposal with ID '{proposal_id}' not found.",
        )

    req_payload = payload or ToMatrixRequest()
    job_id = req_payload.job_id or f"job-{uuid.uuid4().hex[:8]}"
    custom_name = req_payload.custom_name or proposal.title

    case = TestMatrixCase(
        id=f"case-{uuid.uuid4().hex[:8]}",
        name=custom_name,
        endpoint_path=proposal.endpoint_path,
        method=proposal.method,
        category=proposal.anomaly_type.value if hasattr(proposal.anomaly_type, "value") else str(proposal.anomaly_type),
        target_param_location=proposal.target_param_location,
        target_param_name=proposal.target_param_name,
        baseline_value=proposal.baseline_value,
        mutated_value=proposal.mutated_value,
        auth_override=proposal.auth_override,
        selected=True,
        status="READY",
        baseline_flow_id=proposal.flow_id,
    )

    if job_id in _matrix_jobs:
        existing_job = _matrix_jobs[job_id]
        cases_list = existing_job.get("cases", [])
        cases_list.append(case.model_dump() if hasattr(case, "model_dump") else case.dict())
        existing_job["cases"] = cases_list
        existing_job["total_count"] = len(cases_list)
    else:
        new_job = TestMatrixJob(
            job_id=job_id,
            target_endpoint=f"{proposal.method} {proposal.endpoint_path}",
            cases=[case],
            total_count=1,
        )
        _matrix_jobs[job_id] = new_job.model_dump() if hasattr(new_job, "model_dump") else new_job.dict()

    return {
        "ok": True,
        "job_id": job_id,
        "case_id": case.id,
        "proposal_id": proposal.id,
        "name": custom_name,
    }
