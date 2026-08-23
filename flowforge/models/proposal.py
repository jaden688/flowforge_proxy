"""
Data models for Automated Test Proposals, Execution Results, and Operator Approval Workflows.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ProposalState(str, Enum):
    """Lifecycle states of a test proposal."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    DISMISSED = "DISMISSED"


class AnomalyType(str, Enum):
    """Vulnerability category or anomaly surface driving the proposal."""
    REFLECTION = "REFLECTION"
    IDOR_SEQUENTIAL = "IDOR_SEQUENTIAL"
    AUTH_DEVIATION = "AUTH_DEVIATION"
    JSON_SCHEMA = "JSON_SCHEMA"
    JWT_ANOMALY = "JWT_ANOMALY"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"
    CUSTOM_RULE = "CUSTOM_RULE"


class ProposalSeverity(str, Enum):
    """Risk severity classification for test proposals."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ProposalExecutionResult(BaseModel):
    """Execution telemetry and security delta analysis from replaying a proposal."""
    executed_at: float = Field(default_factory=time.time)
    duration_ms: float = 0.0
    status_code: int = 200
    status_match: bool = True
    status_delta: str = "200 == 200"
    length_delta_bytes: int = 0
    length_delta_percent: float = 0.0
    latency_delta_ms: float = 0.0
    reflected: bool = False
    anomaly_detected: bool = False
    verdict_level: str = "INFO_DIFF"  # 'CRITICAL_IDOR', 'HIGH_REFLECTION', 'AUTH_BYPASS', 'INFO_DIFF', 'IDENTICAL'
    verdict_description: str = ""
    executed_flow_id: Optional[str] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body_preview: Optional[str] = None


class TestProposal(BaseModel):
    """Structured test proposal generated automatically from passive anomaly triage."""
    __test__ = False
    id: str = Field(default_factory=lambda: f"prop-{uuid.uuid4().hex[:12]}")
    flow_id: str
    endpoint_hash: Optional[str] = None
    endpoint_path: str
    method: str = "GET"
    anomaly_type: AnomalyType
    title: str
    description: str
    severity: ProposalSeverity = ProposalSeverity.MEDIUM
    confidence_score: float = Field(ge=0.0, le=100.0, default=70.0)

    # Target Parameter & Mutation Definition
    target_param_name: str = ""
    target_param_location: str = "query"  # query, path, body, header, cookie
    baseline_value: Optional[Any] = None
    mutated_value: Optional[Any] = None
    auth_override: Optional[str] = None  # None, DROP, USER_B, EXPIRED, ALG_NONE, ADMIN

    # Lifecycle & Execution State
    state: ProposalState = ProposalState.PENDING
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)

    # Preset & Results
    tags: List[str] = Field(default_factory=list)
    execution_result: Optional[ProposalExecutionResult] = None
    executed_flow_id: Optional[str] = None


class PaginatedProposalsResponse(BaseModel):
    """Paginated list of test proposals."""
    items: List[TestProposal]
    total: int
    page: int
    page_size: int
    total_pages: int


class ProposalStatsResponse(BaseModel):
    """Aggregated proposal counts by state."""
    total: int = 0
    pending: int = 0
    approved: int = 0
    executing: int = 0
    completed: int = 0
    dismissed: int = 0


class BatchProposalActionRequest(BaseModel):
    """Request payload for batch updating proposal states."""
    proposal_ids: List[str]
    action: str  # "approve" | "execute" | "dismiss" | "delete"


class BatchProposalActionResponse(BaseModel):
    """Result summary of batch proposal operations."""
    success_count: int
    failure_count: int
    updated_ids: List[str]
    errors: Optional[List[str]] = None


class ExecuteProposalResponse(BaseModel):
    """Response returned when a proposal is executed and diffed."""
    proposal: TestProposal
    executed_flow: Optional[Dict[str, Any]] = None
    diff: Optional[Dict[str, Any]] = None


class GenerateProposalsRequest(BaseModel):
    """Optional configuration for on-demand proposal synthesis."""
    anomaly_types: Optional[List[str]] = None


class ApproveProposalRequest(BaseModel):
    """Optional notes when approving a proposal."""
    notes: Optional[str] = None


class DismissProposalRequest(BaseModel):
    """Optional reason when dismissing a proposal."""
    reason: Optional[str] = None


class ToCuratedRequest(BaseModel):
    """Request payload for transferring a proposal to Curated Collections."""
    group_id: Optional[str] = "default"
    custom_name: Optional[str] = None
    tags: Optional[List[str]] = None


class ToMatrixRequest(BaseModel):
    """Request payload for transferring a proposal to Test Matrix Builder."""
    job_id: Optional[str] = None
    custom_name: Optional[str] = None
