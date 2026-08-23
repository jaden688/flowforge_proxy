"""
Pydantic data models for extracted parameters and discovered endpoints.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExtractedParameterModel(BaseModel):
    """Represents a single discovered parameter across any request/response carrier."""
    id: Optional[int] = None
    flow_id: str
    endpoint_hash: str
    location: str  # 'query', 'header', 'json_body', 'form_body', 'cookie', 'path_param'
    name: str
    value: Optional[str] = None
    data_type: Optional[str] = "string"  # 'string', 'integer', 'float', 'boolean', 'uuid', 'jwt', 'array', 'object'
    is_entropy_token: bool = False
    is_identifier: bool = False
    timestamp: float = Field(default_factory=time.time)


class DiscoveredEndpointModel(BaseModel):
    """Represents a discovered canonical endpoint in the Target Dossier."""
    endpoint_hash: str
    method: str
    host: str
    path_pattern: str
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    request_count: int = 1
    category: Optional[str] = "DATA_READ"  # 'Auth', 'Data Read', 'Mutation/Action', 'Admin'
    schema_summary: Dict[str, Any] = Field(default_factory=dict)
    parameters: List[ExtractedParameterModel] = Field(default_factory=list)
