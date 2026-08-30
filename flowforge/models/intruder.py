"""
Pydantic models for payload management (custom wordlists) and the active
Intruder replay engine (injection points, job configs, live results).
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Custom Wordlists (operator-uploaded payload sets)
# ---------------------------------------------------------------------------

class CustomWordlist(BaseModel):
    """A persisted, operator-authored wordlist stored in SQLite."""

    id: str
    name: str
    description: str = ""
    category: str = "attack_payloads"
    tags: List[str] = Field(default_factory=list)
    line_count: int = 0
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


class CustomWordlistUpload(BaseModel):
    """Payload for creating/updating a custom wordlist."""

    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    category: str = "attack_payloads"
    tags: List[str] = Field(default_factory=list)
    content: str = Field(min_length=1, max_length=8_000_000)


class CustomWordlistUpdate(BaseModel):
    """Partial update for a custom wordlist."""

    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    content: Optional[str] = None


class CustomWordlistDetail(CustomWordlist):
    """Custom wordlist including its full content and a preview."""

    content: str = ""
    preview: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Injection Points & Job Configuration
# ---------------------------------------------------------------------------

class InjectionPosition(str, Enum):
    """Where a payload is injected into the replayed request."""

    HEADER = "header"
    QUERY = "query"
    BODY = "body"


class InjectionPoint(BaseModel):
    """A single injection marker on the replay template.

    - header/query: `key` selects the target header or query parameter name.
      The original value is replaced with prefix + payload + suffix.
    - body: the entire request body is replaced with prefix + payload + suffix.
    """

    position: InjectionPosition
    key: Optional[str] = None
    prefix: str = ""
    suffix: str = ""

    @field_validator("prefix", "suffix", mode="before")
    @classmethod
    def _coerce_empty(cls, v: Any) -> str:
        """Never let None/undefined leak onto the wire as the literal string 'None'."""
        if v is None:
            return ""
        return str(v)

    def label(self) -> str:
        if self.position == InjectionPosition.HEADER:
            return f"header:{self.key or '*'}"
        if self.position == InjectionPosition.QUERY:
            return f"query:{self.key or '*'}"
        return "body"


class IntruderJobConfig(BaseModel):
    """Full configuration of an active intruder campaign."""

    flow_id: Optional[str] = None
    method: str = "GET"
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None

    injection_points: List[InjectionPoint] = Field(default_factory=list)

    # Payload sources (merged, deduplicated in order)
    custom_wordlist_ids: List[str] = Field(default_factory=list)
    arsenal_wordlist_ids: List[str] = Field(default_factory=list)
    inline_payloads: List[str] = Field(default_factory=list)

    # Execution controls
    concurrency: int = Field(default=4, ge=1, le=64)
    rate_limit_rps: Optional[float] = Field(default=None, gt=0, le=10000)
    timeout_seconds: float = Field(default=10.0, ge=0.5, le=120)
    follow_redirects: bool = False


class IntruderJobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    ABORTED = "ABORTED"
    FAILED = "FAILED"


class IntruderJob(BaseModel):
    """State record for an intruder campaign."""

    id: str
    flow_id: Optional[str] = None
    status: IntruderJobStatus = IntruderJobStatus.PENDING
    config: IntruderJobConfig
    payload_count: int = 0
    total_requests: int = 0
    sent_requests: int = 0
    completed_requests: int = 0
    anomaly_count: int = 0
    created_at: float = Field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

class IntruderResult(BaseModel):
    """Outcome of one replayed (payload, injection point) pair."""

    request_index: int
    position_label: str
    payload: str
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    response_size_bytes: Optional[int] = None
    reflected: bool = False
    anomaly_reasons: List[str] = Field(default_factory=list)
    error: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)


class ResultFilterParams(BaseModel):
    """Filters applied when querying stored intruder results."""

    offset: int = 0
    limit: int = 200
    anomalies_only: bool = False
    reflected_only: bool = False
    status_code: Optional[int] = None
    min_size: Optional[int] = None
    max_size: Optional[int] = None
    min_time_ms: Optional[float] = None
    max_time_ms: Optional[float] = None
    payload_search: Optional[str] = None
