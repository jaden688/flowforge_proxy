"""
Pydantic v2 data models for Nuclei templates, matchers, HTTP blocks, and match results.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator


class NucleiSeverity(str, Enum):
    """Normalized severity ratings for Nuclei templates."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, val: Any) -> "NucleiSeverity":
        if isinstance(val, cls):
            return val
        if not val:
            return cls.INFO
        s = str(val).strip().lower()
        for member in cls:
            if member.value == s:
                return member
        if s in ("none", "informational", "log", "notice"):
            return cls.INFO
        return cls.INFO


class NucleiMatcherType(str, Enum):
    """Matcher types supported by the Nuclei engine."""
    WORD = "word"
    WORDS = "word"
    REGEX = "regex"
    STATUS = "status"
    BINARY = "binary"
    SIZE = "size"
    DSL = "dsl"
    XPATH = "xpath"

    @classmethod
    def from_str(cls, val: Any) -> "NucleiMatcherType":
        if isinstance(val, cls):
            return val
        if not val:
            return cls.WORD
        s = str(val).strip().lower()
        if s == "words":
            return cls.WORD
        for member in cls:
            if member.value == s:
                return member
        return cls.WORD


class NucleiMatcher(BaseModel):
    """Condition matcher defined within a Nuclei HTTP request/response block."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    type: Union[NucleiMatcherType, str] = Field(default=NucleiMatcherType.WORD)
    part: str = Field(default="body")
    words: List[str] = Field(default_factory=list)
    regex: List[str] = Field(default_factory=list)
    status: List[int] = Field(default_factory=list)
    condition: str = Field(default="or")
    case_insensitive: bool = Field(default=False, alias="case-insensitive")
    negative: bool = Field(default=False)
    dsl: List[str] = Field(default_factory=list)
    name: Optional[str] = Field(default=None)
    internal: bool = Field(default=False)
    encoding: Optional[str] = Field(default=None)

    @field_validator("type", mode="before")
    @classmethod
    def _validate_type(cls, v: Any) -> NucleiMatcherType:
        if isinstance(v, NucleiMatcherType):
            return v
        return NucleiMatcherType.from_str(v)

    @field_validator("words", mode="before")
    @classmethod
    def _validate_words(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v if x is not None]
        return [str(v)]

    @field_validator("regex", mode="before")
    @classmethod
    def _validate_regex(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v if x is not None]
        return [str(v)]

    @field_validator("status", mode="before")
    @classmethod
    def _validate_status(cls, v: Any) -> List[int]:
        if v is None:
            return []
        if isinstance(v, (int, float)):
            return [int(v)]
        if isinstance(v, str):
            try:
                return [int(v.strip())]
            except ValueError:
                return []
        if isinstance(v, (list, tuple)):
            res: List[int] = []
            for item in v:
                try:
                    res.append(int(item))
                except (ValueError, TypeError):
                    pass
            return res
        return []

    @field_validator("dsl", mode="before")
    @classmethod
    def _validate_dsl(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v if x is not None]
        return [str(v)]

    @field_validator("condition", mode="before")
    @classmethod
    def _validate_condition(cls, v: Any) -> str:
        if not v:
            return "or"
        s = str(v).strip().lower()
        return "and" if s == "and" else "or"


class NucleiHttpBlock(BaseModel):
    """HTTP request and assertion block in a Nuclei template."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    method: str = Field(default="GET")
    path: List[str] = Field(default_factory=list)
    raw: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = Field(default=None)
    matchers_condition: str = Field(default="or", alias="matchers-condition")
    matchers: List[NucleiMatcher] = Field(default_factory=list)
    extractors: List[Dict[str, Any]] = Field(default_factory=list)
    stop_at_first_match: bool = Field(default=False, alias="stop-at-first-match")
    payloads: Dict[str, Any] = Field(default_factory=dict)
    cookie_reuse: bool = Field(default=False, alias="cookie-reuse")
    redirects: bool = Field(default=False)
    max_redirects: int = Field(default=10, alias="max-redirects")

    @field_validator("path", mode="before")
    @classmethod
    def _validate_path(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v if x is not None]
        return []

    @field_validator("raw", mode="before")
    @classmethod
    def _validate_raw(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v if x is not None]
        return []

    @field_validator("method", mode="before")
    @classmethod
    def _validate_method(cls, v: Any) -> str:
        if not v:
            return "GET"
        return str(v).strip().upper()

    @field_validator("headers", mode="before")
    @classmethod
    def _validate_headers(cls, v: Any) -> Dict[str, str]:
        if not isinstance(v, dict):
            return {}
        return {str(k): str(val) for k, val in v.items()}

    @field_validator("matchers_condition", mode="before")
    @classmethod
    def _validate_matchers_condition(cls, v: Any) -> str:
        if not v:
            return "or"
        s = str(v).strip().lower()
        return "and" if s == "and" else "or"


class NucleiTemplate(BaseModel):
    """Structured representation of a parsed Nuclei vulnerability/exposure template."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str
    name: str
    author: Union[str, List[str]] = Field(default="flowforge")
    severity: NucleiSeverity = Field(default=NucleiSeverity.INFO)
    description: str = Field(default="")
    reference: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    category: str = Field(default="MISC")
    source_path: str = Field(default="")
    http_blocks: List[NucleiHttpBlock] = Field(default_factory=list)
    raw_yaml: str = Field(default="")
    is_passive: bool = Field(default=False)
    is_active: bool = Field(default=True)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    variables: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity", mode="before")
    @classmethod
    def _validate_severity(cls, v: Any) -> NucleiSeverity:
        return NucleiSeverity.from_str(v)

    @field_validator("reference", mode="before")
    @classmethod
    def _validate_reference(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v.strip()]
        if isinstance(v, (list, tuple)):
            return [str(x).strip() for x in v if x is not None]
        return [str(v)]

    @field_validator("tags", mode="before")
    @classmethod
    def _validate_tags(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [t.strip().lower() for t in v.split(",") if t.strip()]
        if isinstance(v, (list, tuple)):
            res: List[str] = []
            for item in v:
                if isinstance(item, str):
                    for sub in item.split(","):
                        if sub.strip():
                            res.append(sub.strip().lower())
                elif item is not None:
                    res.append(str(item).lower())
            return res
        return []

    @property
    def author_str(self) -> str:
        """Formatted string of template authors."""
        if isinstance(self.author, list):
            return ", ".join(self.author)
        return str(self.author)

    @property
    def cve_id(self) -> Optional[str]:
        """Extract CVE identifier from ID or tags if present."""
        tid = self.id.upper()
        if tid.startswith("CVE-"):
            return tid
        for tag in self.tags:
            if tag.upper().startswith("CVE-"):
                return tag.upper()
        return None


class NucleiMatchResult(BaseModel):
    """Result of evaluating a Nuclei template against a flow or HTTP response."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    template_id: str
    template_name: str
    severity: NucleiSeverity = Field(default=NucleiSeverity.INFO)
    category: str = Field(default="MISC")
    tags: List[str] = Field(default_factory=list)
    matched: bool = Field(default=False)
    matched_conditions: List[str] = Field(default_factory=list)
    extracted_data: Dict[str, Any] = Field(default_factory=dict)
    matched_at: str = Field(default="")
    execution_time_ms: float = Field(default=0.0)

    @field_validator("severity", mode="before")
    @classmethod
    def _validate_severity(cls, v: Any) -> NucleiSeverity:
        return NucleiSeverity.from_str(v)
