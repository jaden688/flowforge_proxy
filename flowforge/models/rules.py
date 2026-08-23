"""Data models for Custom YAML/JSON Heuristic Match Rule Engine (Requirement R5)."""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class RuleSeverity(str, Enum):
    """Severity ratings for rule match triggers."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RuleOperator(str, Enum):
    """Comparison and matching operators supported by the rule engine."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    NOT_REGEX = "not_regex"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    IN_LIST = "in_list"
    NOT_IN_LIST = "not_in_list"
    ENTROPY_GT = "entropy_gt"
    ENTROPY_LT = "entropy_lt"


class RuleFieldTarget(str, Enum):
    """Normalized targets for flow inspection."""
    METHOD = "method"
    URL = "url"
    PATH = "path"
    SCHEME = "scheme"
    HTTP_VERSION = "http_version"
    STATUS = "status"
    STATUS_CODE = "status_code"
    HEADER = "header"
    REQUEST_HEADER = "request_header"
    RESPONSE_HEADER = "response_header"
    BODY = "body"
    REQUEST_BODY = "request_body"
    RESPONSE_BODY = "response_body"
    QUERY = "query"
    QUERY_PARAM = "query_param"
    QUERY_STRING = "query_string"
    COOKIE = "cookie"
    REQUEST_COOKIE = "request_cookie"
    RESPONSE_COOKIE = "response_cookie"
    CONTENT_TYPE = "content_type"
    REQUEST_CONTENT_TYPE = "request_content_type"
    RESPONSE_CONTENT_TYPE = "response_content_type"
    DURATION_MS = "duration_ms"
    TTFB_MS = "ttfb_ms"
    CONTENT_LENGTH = "content_length"
    ENTROPY = "entropy"
    TAGS = "tags"


class RuleCondition(BaseModel):
    """Single matching condition within a heuristic rule."""
    field: str
    operator: Union[RuleOperator, str] = RuleOperator.EQUALS
    value: Optional[Any] = None
    target: Optional[str] = None  # e.g., header name "x-debug" or query param "id"
    case_sensitive: bool = False
    invert: bool = False

    def normalized_operator(self) -> RuleOperator:
        """Convert operator to strongly-typed enum."""
        if isinstance(self.operator, RuleOperator):
            return self.operator
        val = str(self.operator).lower().strip()
        for op in RuleOperator:
            if op.value == val:
                return op
        return RuleOperator.EQUALS


class MatchRule(BaseModel):
    """User-defined or built-in YAML/JSON heuristic matching rule."""
    id: str = Field(default_factory=lambda: f"rule-{uuid.uuid4().hex[:8]}")
    name: str
    description: str = ""
    severity: RuleSeverity = RuleSeverity.MEDIUM
    category: str = "CUSTOM"
    tags: List[str] = Field(default_factory=list)
    tag: Optional[str] = None  # Single tag alias for simple rules
    enabled: bool = True
    condition_combinator: str = "all"  # "all" (AND), "any" (OR), "not" (NOR)
    conditions: List[RuleCondition] = Field(default_factory=list)
    nested_conditions: Optional[Dict[str, List[RuleCondition]]] = None
    raw_yaml: Optional[str] = None
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)

    def all_tags(self) -> List[str]:
        """Return combined unique list of tags."""
        result = list(self.tags)
        if self.tag and self.tag not in result:
            result.append(self.tag)
        return sorted(list(set(result)))


# Aliases for compatibility
CustomRule = MatchRule
RuleField = RuleFieldTarget
RuleAction = Any


class RuleEvaluationResult(BaseModel):
    """Result of evaluating a single rule against an intercepted flow."""
    rule_id: str
    rule_name: str
    matched: bool
    severity: RuleSeverity
    tags: List[str] = Field(default_factory=list)
    category: str = "CUSTOM"
    matched_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    execution_time_ms: float = 0.0


class RuleTestRequest(BaseModel):
    """Payload for testing rules against real or sample flows."""
    rule: Optional[Union[MatchRule, Dict[str, Any], str]] = None
    rule_id: Optional[str] = None
    flow_id: Optional[str] = None
    sample_flow: Optional[Dict[str, Any]] = None


class RuleTestResponse(BaseModel):
    """Response returned when executing rule dry-run testing."""
    matched: bool
    results: List[RuleEvaluationResult] = Field(default_factory=list)
    flow_summary: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class RuleImportRequest(BaseModel):
    """Payload for batch rule imports."""
    content: str
    format: str = "yaml"  # "yaml" or "json"
    overwrite: bool = False


class RuleImportResult(BaseModel):
    """Summary of batch rule import operation."""
    status: str = "success"
    imported_count: int = 0
    updated_count: int = 0
    failed_count: int = 0
    errors: List[str] = Field(default_factory=list)
    rules: List[MatchRule] = Field(default_factory=list)


class RuleExportResponse(BaseModel):
    """Response containing exported rules."""
    format: str
    content: str
    count: int
