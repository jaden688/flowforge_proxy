"""Target Dossier and Endpoint Parameter Catalog API routes (Requirement R2 & R3)."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from flowforge.heuristics.models import (
    EndpointCategory,
    ExtractedParameter,
    IdentifierType,
    ParameterLocation,
)

router = APIRouter(prefix="/api/v1", tags=["Target Dossier"])

# In-memory fallback registry for endpoints and parameters
_in_memory_endpoints: Dict[str, Dict[str, Any]] = {}
_in_memory_parameters: List[Dict[str, Any]] = []


class ParameterSummary(BaseModel):
    """Summarized parameter entry in the Target Dossier."""
    name: str
    location: str
    inferred_type: str = "string"
    inferred_format: Optional[str] = None
    identifier_type: Optional[str] = None
    idor_score: float = 0.0
    entropy: float = 0.0
    sample_values: List[Any] = Field(default_factory=list)
    observation_count: int = 1
    is_entropy_token: bool = False
    is_identifier: bool = False


class EndpointSummary(BaseModel):
    """Summarized canonical endpoint entry."""
    endpoint_hash: str
    method: str
    host: str
    path_pattern: str
    category: str = "DATA_READ"
    request_count: int = 1
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    parameters: List[ParameterSummary] = Field(default_factory=list)
    schema_summary: Dict[str, Any] = Field(default_factory=dict)
    has_critical_idor: bool = False


class HostDossier(BaseModel):
    """Host-level grouping in Target Dossier."""
    host: str
    endpoint_count: int = 0
    endpoints: List[EndpointSummary] = Field(default_factory=list)


class DossierResponse(BaseModel):
    """Full Target Dossier response hierarchy."""
    hosts: List[HostDossier] = Field(default_factory=list)
    total_endpoints: int = 0
    total_parameters: int = 0


class PaginatedEndpointsResponse(BaseModel):
    """Paginated list of discovered endpoints."""
    items: List[EndpointSummary]
    total: int
    page: int
    page_size: int


class ParameterRecordItem(BaseModel):
    """Individual parameter record for parameter search table."""
    id: Optional[int] = None
    flow_id: Optional[str] = None
    endpoint_hash: Optional[str] = None
    location: str
    name: str
    value: Optional[Any] = None
    data_type: Optional[str] = "string"
    is_entropy_token: bool = False
    is_identifier: bool = False
    idor_score: float = 0.0
    timestamp: float = Field(default_factory=time.time)


class PaginatedParametersResponse(BaseModel):
    """Paginated list of extracted parameters."""
    items: List[ParameterRecordItem]
    total: int
    page: int
    page_size: int


def compute_endpoint_hash(method: str, host: str, path_pattern: str) -> str:
    """Compute deterministic SHA256 endpoint hash."""
    key = f"{method.upper()}:{host.lower()}:{path_pattern}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def record_endpoint_observation(
    method: str,
    host: str,
    path_pattern: str,
    category: str = "DATA_READ",
    parameters: Optional[List[ExtractedParameter]] = None,
    schema: Optional[Dict[str, Any]] = None,
) -> str:
    """Record or update an endpoint observation in the in-memory registry."""
    ep_hash = compute_endpoint_hash(method, host, path_pattern)
    now = time.time()

    if ep_hash not in _in_memory_endpoints:
        _in_memory_endpoints[ep_hash] = {
            "endpoint_hash": ep_hash,
            "method": method.upper(),
            "host": host.lower(),
            "path_pattern": path_pattern,
            "category": category,
            "first_seen": now,
            "last_seen": now,
            "request_count": 1,
            "schema_summary": schema or {},
            "parameters": {},
        }
    else:
        ep = _in_memory_endpoints[ep_hash]
        ep["last_seen"] = now
        ep["request_count"] += 1
        if category and category != "DATA_READ":
            ep["category"] = category
        if schema:
            ep["schema_summary"] = schema

    # Merge parameters
    if parameters:
        ep_params = _in_memory_endpoints[ep_hash]["parameters"]
        for p in parameters:
            p_key = f"{p.location}:{p.name}"
            if p_key not in ep_params:
                ep_params[p_key] = {
                    "name": p.name,
                    "location": p.location.value if hasattr(p.location, "value") else str(p.location),
                    "inferred_type": p.inferred_type,
                    "inferred_format": p.inferred_format,
                    "identifier_type": p.identifier_type.value if hasattr(p.identifier_type, "value") and p.identifier_type else None,
                    "idor_score": p.idor_score,
                    "entropy": p.entropy,
                    "sample_values": [p.raw_value] if p.raw_value else [],
                    "observation_count": 1,
                    "is_entropy_token": p.entropy >= 4.2,
                    "is_identifier": bool(p.identifier_type and p.identifier_type != IdentifierType.UNKNOWN),
                }
            else:
                entry = ep_params[p_key]
                entry["observation_count"] += 1
                if p.raw_value and p.raw_value not in entry["sample_values"] and len(entry["sample_values"]) < 10:
                    entry["sample_values"].append(p.raw_value)
                if p.idor_score > entry["idor_score"]:
                    entry["idor_score"] = p.idor_score

            # Add to flat parameter records list
            _in_memory_parameters.append({
                "id": len(_in_memory_parameters) + 1,
                "endpoint_hash": ep_hash,
                "location": p.location.value if hasattr(p.location, "value") else str(p.location),
                "name": p.name,
                "value": p.raw_value,
                "data_type": p.inferred_type,
                "is_entropy_token": p.entropy >= 4.2,
                "is_identifier": bool(p.identifier_type and p.identifier_type != IdentifierType.UNKNOWN),
                "idor_score": p.idor_score,
                "timestamp": now,
            })

    return ep_hash


@router.get("/dossier", response_model=DossierResponse)
@router.get("/dossiers", response_model=DossierResponse)
async def get_target_dossier(
    request: Request,
    host: Optional[str] = Query(None, description="Filter by host name"),
):
    """
    Get aggregated Target Dossier hierarchy containing all hosts, discovered endpoints,
    parameter catalogs, and inferred schemas.
    """
    endpoints_map: Dict[str, Dict[str, Any]] = {}
    host_filter = host if isinstance(host, str) else None

    # Check if database repository has endpoints
    if hasattr(request.app.state, "repo"):
        try:
            repo_endpoints, _ = await request.app.state.repo.list_endpoints(host=host_filter)
            if repo_endpoints:
                for ep in repo_endpoints:
                    ep_dict = ep if isinstance(ep, dict) else (ep.model_dump() if hasattr(ep, "model_dump") else (ep.dict() if hasattr(ep, "dict") else ep.__dict__))
                    h = ep_dict.get("endpoint_hash") or compute_endpoint_hash(
                        ep_dict.get("method", "GET"),
                        ep_dict.get("host", "localhost"),
                        ep_dict.get("path_pattern", "/"),
                    )
                    # Query parameters for this endpoint if repo has parameters
                    try:
                        ep_params_db, _ = await request.app.state.repo.list_parameters(endpoint_hash=h)
                        if ep_params_db:
                            ep_dict["parameters"] = [
                                p if isinstance(p, dict) else (p.model_dump() if hasattr(p, "model_dump") else p.__dict__)
                                for p in ep_params_db
                            ]
                    except Exception:
                        pass
                    endpoints_map[h] = ep_dict
        except Exception:
            pass

    # Merge with in-memory registry
    for h, ep in _in_memory_endpoints.items():
        if h not in endpoints_map:
            endpoints_map[h] = ep

    # Group by host
    hosts_dict: Dict[str, List[EndpointSummary]] = {}
    total_params = 0

    for ep_hash, ep_data in endpoints_map.items():
        ep_host = ep_data.get("host", "localhost")
        if host_filter and host_filter.lower() not in ep_host.lower():
            continue


        params_raw = ep_data.get("parameters", {})

        params_list: List[ParameterSummary] = []
        if isinstance(params_raw, dict):
            for p in params_raw.values():
                params_list.append(ParameterSummary(**p))
        elif isinstance(params_raw, list):
            for p in params_raw:
                if isinstance(p, dict):
                    params_list.append(ParameterSummary(
                        name=p.get("name", ""),
                        location=p.get("location", "query"),
                        inferred_type=p.get("data_type") or p.get("inferred_type") or "string",
                        inferred_format=p.get("inferred_format"),
                        identifier_type=p.get("identifier_type"),
                        idor_score=float(p.get("idor_score") or 0.0),
                        entropy=float(p.get("entropy") or 0.0),
                        sample_values=[p.get("value")] if p.get("value") is not None else [],
                        observation_count=int(p.get("observation_count", 1)),
                        is_entropy_token=bool(p.get("is_entropy_token")),
                        is_identifier=bool(p.get("is_identifier")),
                    ))

        total_params += len(params_list)
        has_critical_idor = any(p.idor_score >= 0.70 or p.is_identifier for p in params_list)

        schema = ep_data.get("schema_summary", {})
        if isinstance(schema, str):
            try:
                schema = json.loads(schema)
            except Exception:
                schema = {}

        ep_summary = EndpointSummary(
            endpoint_hash=ep_hash,
            method=ep_data.get("method", "GET"),
            host=ep_host,
            path_pattern=ep_data.get("path_pattern", "/"),
            category=ep_data.get("category", "DATA_READ"),
            request_count=int(ep_data.get("request_count", 1)),
            first_seen=float(ep_data.get("first_seen", time.time())),
            last_seen=float(ep_data.get("last_seen", time.time())),
            parameters=params_list,
            schema_summary=schema,
            has_critical_idor=has_critical_idor,
        )

        if ep_host not in hosts_dict:
            hosts_dict[ep_host] = []
        hosts_dict[ep_host].append(ep_summary)

    hosts_list: List[HostDossier] = []
    for host_name, eps in hosts_dict.items():
        hosts_list.append(
            HostDossier(
                host=host_name,
                endpoint_count=len(eps),
                endpoints=sorted(eps, key=lambda e: (e.path_pattern, e.method)),
            )
        )

    hosts_list.sort(key=lambda h: h.host)

    return DossierResponse(
        hosts=hosts_list,
        total_endpoints=sum(len(h.endpoints) for h in hosts_list),
        total_parameters=total_params,
    )


@router.get("/endpoints", response_model=PaginatedEndpointsResponse)
async def list_endpoints(
    request: Request,
    host: Optional[str] = Query(None, description="Filter by host name"),
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search path pattern"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=200, description="Items per page"),
):
    """
    List discovered endpoints with optional filtering and pagination.
    """
    dossier = await get_target_dossier(request, host=host)
    all_endpoints: List[EndpointSummary] = []
    for h in dossier.hosts:
        all_endpoints.extend(h.endpoints)

    # Apply filters
    filtered = all_endpoints
    if host:
        filtered = [e for e in filtered if host.lower() in e.host.lower()]
    if category:
        filtered = [e for e in filtered if e.category.upper() == category.upper()]
    if search:
        search_lower = search.lower()
        filtered = [
            e
            for e in filtered
            if search_lower in e.path_pattern.lower() or search_lower in e.method.lower()
        ]

    total = len(filtered)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_items = filtered[start_idx:end_idx]

    return PaginatedEndpointsResponse(
        items=paginated_items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/dossier/{endpoint_hash}", response_model=EndpointSummary)
@router.get("/dossiers/{endpoint_hash}", response_model=EndpointSummary)
@router.get("/endpoints/{endpoint_hash}", response_model=EndpointSummary)
async def get_endpoint_detail(endpoint_hash: str, request: Request):
    """
    Get detailed information for a specific canonical endpoint by hash.
    """
    # 1. Direct DB lookup
    if hasattr(request.app.state, "repo"):
        try:
            ep = await request.app.state.repo.get_endpoint_by_hash(endpoint_hash)
            if ep:
                params_list: List[ParameterSummary] = []
                for p in ep.parameters:
                    params_list.append(ParameterSummary(
                        name=p.name,
                        location=p.location,
                        inferred_type=p.data_type or "string",
                        sample_values=[p.value] if p.value is not None else [],
                        observation_count=1,
                        is_entropy_token=p.is_entropy_token,
                        is_identifier=p.is_identifier,
                    ))
                return EndpointSummary(
                    endpoint_hash=ep.endpoint_hash,
                    method=ep.method,
                    host=ep.host,
                    path_pattern=ep.path_pattern,
                    category=ep.category or "DATA_READ",
                    request_count=ep.request_count,
                    first_seen=ep.first_seen,
                    last_seen=ep.last_seen,
                    parameters=params_list,
                    schema_summary=ep.schema_summary,
                    has_critical_idor=any(p.is_identifier for p in ep.parameters),
                )
        except Exception:
            pass

    # 2. Check in-memory dossier
    dossier = await get_target_dossier(request)
    for h in dossier.hosts:
        for ep in h.endpoints:
            if ep.endpoint_hash == endpoint_hash:
                return ep

    raise HTTPException(status_code=404, detail=f"Endpoint with hash '{endpoint_hash}' not found")


@router.get("/parameters", response_model=PaginatedParametersResponse)
async def list_parameters(
    request: Request,
    endpoint_hash: Optional[str] = Query(None, description="Filter by endpoint hash"),
    name: Optional[str] = Query(None, description="Filter by parameter name"),
    location: Optional[str] = Query(None, description="Filter by parameter location"),
    data_type: Optional[str] = Query(None, description="Filter by data type"),
    is_identifier: Optional[bool] = Query(None, description="Filter by identifier status"),
    is_entropy_token: Optional[bool] = Query(None, description="Filter by high-entropy token status"),
    search: Optional[str] = Query(None, description="Search parameter name or value"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=200, description="Items per page"),
):
    """
    Query extracted parameters across all captured traffic with filtering and pagination.
    """
    all_params: List[Dict[str, Any]] = []

    # Check database repository
    if hasattr(request.app.state, "repo"):
        try:
            repo_params, _ = await request.app.state.repo.list_parameters(
                endpoint_hash=endpoint_hash,
                name=name,
                location=location,
                limit=1000,
            )
            if repo_params:
                for p in repo_params:
                    p_dict = p if isinstance(p, dict) else (p.model_dump() if hasattr(p, "model_dump") else (p.dict() if hasattr(p, "dict") else p.__dict__))
                    all_params.append(p_dict)
        except Exception:
            pass

    # Merge with in-memory parameters
    for p in _in_memory_parameters:
        all_params.append(p)

    # Filter
    filtered = all_params
    if endpoint_hash:
        filtered = [p for p in filtered if p.get("endpoint_hash") == endpoint_hash]
    if name:
        filtered = [p for p in filtered if name.lower() in p.get("name", "").lower()]
    if location:
        filtered = [p for p in filtered if p.get("location", "").lower() == location.lower()]
    if data_type:
        filtered = [p for p in filtered if (p.get("data_type") or "").lower() == data_type.lower()]
    if is_identifier is not None:
        filtered = [p for p in filtered if bool(p.get("is_identifier")) == is_identifier]
    if is_entropy_token is not None:
        filtered = [p for p in filtered if bool(p.get("is_entropy_token")) == is_entropy_token]
    if search:
        s_lower = search.lower()
        filtered = [
            p
            for p in filtered
            if s_lower in p.get("name", "").lower() or s_lower in str(p.get("value", "")).lower()
        ]

    total = len(filtered)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated = filtered[start_idx:end_idx]

    items = [
        ParameterRecordItem(
            id=p.get("id"),
            flow_id=p.get("flow_id"),
            endpoint_hash=p.get("endpoint_hash"),
            location=p.get("location", "query"),
            name=p.get("name", ""),
            value=p.get("value"),
            data_type=p.get("data_type") or "string",
            is_entropy_token=bool(p.get("is_entropy_token")),
            is_identifier=bool(p.get("is_identifier")),
            idor_score=float(p.get("idor_score") or 0.0),
            timestamp=float(p.get("timestamp") or time.time()),
        )
        for p in paginated
    ]

    return PaginatedParametersResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )
