"""
Data models for Payload Curation, Selective Pruning, and Context-Aware Strategy Recommendations.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CuratedPayload(BaseModel):
    """Represents a curated, starred, or staged mutation payload item."""
    id: str = Field(default_factory=lambda: f"payload-{uuid.uuid4().hex[:12]}")
    group_id: str = "default"
    name: str
    category: str = "CUSTOM"  # IDOR_SEQUENTIAL, IDOR_ROLE_SWAP, AUTH_STRIPPING, TYPE_CONFUSION, BOUNDARY_OVERFLOW, MASS_ASSIGNMENT, REFLECTION_CONTEXT, NOSQL_INJECTION, PATH_TRAVERSAL, JWT_FORGERY_PROBES
    endpoint_path: str = "/"
    method: str = "GET"
    target_param_location: str = "query"  # query, path, body, header, cookie
    target_param_name: str = ""
    baseline_value: Optional[Any] = None
    mutated_value: Optional[Any] = None
    auth_override: Optional[str] = None  # None, DROP, USER_B, EXPIRED, ADMIN
    status: str = "READY"  # READY, QUEUED, RUNNING, PASSED, ANOMALY_DETECTED, FAILED
    starred: bool = False
    notes: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    result_summary: Optional[Dict[str, Any]] = None
    baseline_flow_id: Optional[str] = None
    executed_flow_id: Optional[str] = None
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


# Type alias for compatibility
CuratedPayloadItem = CuratedPayload


class PayloadGroup(BaseModel):
    """Represents a named collection/grouping of curated payloads."""
    id: str = Field(default_factory=lambda: f"group-{uuid.uuid4().hex[:8]}")
    name: str
    description: str = ""
    color: Optional[str] = "#38bdf8"
    icon: Optional[str] = "folder"
    payload_ids: List[str] = Field(default_factory=list)
    item_count: int = 0
    items: List[CuratedPayload] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


# Type alias for compatibility
CuratedGroup = PayloadGroup


class CreatePayloadRequest(BaseModel):
    """Request payload to create a new curated payload item."""
    group_id: Optional[str] = "default"
    name: str
    category: str = "CUSTOM"
    endpoint_path: str = "/"
    method: str = "GET"
    target_param_location: str = "query"
    target_param_name: str = ""
    baseline_value: Optional[Any] = None
    mutated_value: Optional[Any] = None
    auth_override: Optional[str] = None
    status: str = "READY"
    starred: bool = False
    notes: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    result_summary: Optional[Dict[str, Any]] = None
    baseline_flow_id: Optional[str] = None


class BulkCreatePayloadRequest(BaseModel):
    """Request payload to bulk create multiple curated payload items."""
    group_id: Optional[str] = "default"
    items: List[CreatePayloadRequest]


class StarPayloadRequest(BaseModel):
    """Request payload to star or unstar a curated payload."""
    payload_id: Optional[str] = None
    starred: Optional[bool] = None  # None indicates toggle


class UpdatePayloadRequest(BaseModel):
    """Request payload to update a curated payload."""
    name: Optional[str] = None
    group_id: Optional[str] = None
    category: Optional[str] = None
    starred: Optional[bool] = None
    status: Optional[str] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None
    result_summary: Optional[Dict[str, Any]] = None


class CreateGroupRequest(BaseModel):
    """Request payload to create a new payload group."""
    id: Optional[str] = None
    name: str
    description: Optional[str] = ""
    color: Optional[str] = "#38bdf8"
    icon: Optional[str] = "folder"


class UpdateGroupRequest(BaseModel):
    """Request payload to update an existing payload group."""
    name: Optional[str] = None
    description: Optional[str] = None
    color: Optional[str] = None
    icon: Optional[str] = None


class PruneFilterRequest(BaseModel):
    """Filter parameters for selective payload pruning."""
    group_id: Optional[str] = None
    preserve_starred: bool = True
    status_filter: Optional[List[str]] = None
    statuses_to_delete: Optional[List[str]] = None
    category_filter: Optional[List[str]] = None
    regex_filter: Optional[str] = None
    length_min: Optional[int] = None
    length_max: Optional[int] = None


class PruneResult(BaseModel):
    """Response returned after selective pruning execution."""
    deleted_count: int
    pruned_count: int = 0
    preserved_count: int
    remaining_count: int
    deleted_payload_ids: List[str] = Field(default_factory=list)


# Type alias for compatibility
PruneFilterResponse = PruneResult


class StrategyRecommendation(BaseModel):
    """Individual ranked strategy recommendation for an endpoint."""
    strategy_id: str
    label: str
    rank: int
    confidence_score: float
    is_recommended: bool
    badge: str  # e.g. "#1 (Recommended)", "#2 (Recommended)", "#3"
    reason: str
    category: str
    applicable_parameters: List[str] = Field(default_factory=list)


class RecommendStrategiesRequest(BaseModel):
    """Request payload to query context-aware strategy recommendations."""
    endpoint_hash: Optional[str] = None
    flow_id: Optional[str] = None
    method: Optional[str] = "GET"
    path: Optional[str] = None
    parameters: Optional[List[Dict[str, Any]]] = None
    triage_tags: Optional[List[str]] = None
    reflection_detected: Optional[bool] = None
    has_auth: Optional[bool] = None
    identifier_type: Optional[str] = None


class RankedStrategyResponse(BaseModel):
    """Response model containing ordered strategy recommendations."""
    endpoint_hash: Optional[str] = None
    target_endpoint: Optional[str] = None
    recommendations: List[StrategyRecommendation]
    top_recommended: Optional[StrategyRecommendation] = None
    total_strategies: int = 0


class CurationExport(BaseModel):
    """Full export representation of curated groups and payloads."""
    exported_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    version: str = "1.0"
    groups: List[PayloadGroup]
    payloads: List[CuratedPayload]


class CurationImportRequest(BaseModel):
    """Request payload to import groups and payloads from JSON."""
    groups: Optional[List[PayloadGroup]] = None
    payloads: Optional[List[CuratedPayload]] = None
    overwrite: bool = False


class CurationImportResponse(BaseModel):
    """Response returned after curation import."""
    imported_groups_count: int
    imported_payloads_count: int
    status: str = "success"
