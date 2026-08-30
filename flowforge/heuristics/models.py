"""Data models for Passive Heuristic Triage Engine (Requirement R2)."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ParameterLocation(str, Enum):
    """Location where a parameter was observed."""
    QUERY = "query"
    PATH = "path"
    PATH_PARAM = "path"
    BODY_JSON = "body_json"
    JSON_BODY = "body_json"
    BODY_FORM = "body_form"
    BODY_MULTIPART = "body_multipart"
    BODY_XML = "body_xml"
    BODY_GRAPHQL = "body_graphql"
    HEADER = "header"
    COOKIE = "cookie"


class IdentifierType(str, Enum):
    """Classification of dynamic identifier predictability."""
    SEQUENTIAL_INTEGER = "sequential_integer"
    MONOTONIC_TIMESTAMP = "monotonic_timestamp"
    MONGO_OBJECT_ID = "mongo_object_id"
    UUID_V1 = "uuid_v1"
    UUID_V4 = "uuid_v4"
    UUID_V7 = "uuid_v7"
    ULID = "ulid"
    SHORT_OPAQUE_SLUG = "short_opaque_slug"
    HASH_DIGEST = "hash_digest"
    UNKNOWN = "unknown"


class ReflectionContext(str, Enum):
    """HTML/DOM/JSON context where input was reflected."""
    HTML_SCRIPT_BLOCK = "html_script_block"
    HTML_ATTR_EVENT = "html_attr_event"
    HTML_ATTR_UNQUOTED = "html_attr_unquoted"
    HTML_ATTR_URI = "html_attr_uri"
    HTML_ATTR_QUOTED = "html_attr_quoted"
    HTML_BODY_TEXT = "html_body_text"
    RESPONSE_HEADER = "response_header"
    JSON_VALUE = "json_value"
    JSON_KEY = "json_key"
    HTML_COMMENT = "html_comment"
    PLAIN_TEXT = "plain_text"


class EncodingStatus(str, Enum):
    """Encoding state of the reflected input."""
    UNENCODED_RAW = "unencoded_raw"
    HTML_ENCODED = "html_encoded"
    URL_ENCODED = "url_encoded"
    JSON_ESCAPED = "json_escaped"
    BASE64_ENCODED = "base64_encoded"
    PARTIALLY_ENCODED = "partially_encoded"


class FindingSeverity(str, Enum):
    """Severity ratings for security triage findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EndpointCategory(str, Enum):
    """Functional categorization of an endpoint."""
    AUTH_SESSION = "AUTH_SESSION"
    DATA_READ = "DATA_READ"
    MUTATION_ACTION = "MUTATION_ACTION"
    ADMIN_MANAGEMENT = "ADMIN_MANAGEMENT"
    FILE_TRANSFER = "FILE_TRANSFER"
    TELEMETRY_HEALTH = "TELEMETRY_HEALTH"


class ExtractedParameter(BaseModel):
    """Extracted request/response parameter."""
    name: str
    location: ParameterLocation
    value: Any = None
    raw_value: str = ""
    inferred_type: str = "string"
    inferred_format: Optional[str] = None
    identifier_type: Optional[IdentifierType] = None
    idor_score: float = 0.0
    entropy: float = 0.0
    is_array: bool = False
    nested_path: Optional[str] = None


class ReflectionFinding(BaseModel):
    """Input reflection finding."""
    parameter_name: str
    source_location: ParameterLocation
    reflected_value: str
    context: ReflectionContext
    encoding_status: EncodingStatus = EncodingStatus.UNENCODED_RAW
    start_offset: int = 0
    end_offset: int = 0
    matched_in: str = "body"  # "body" or header name e.g. "Location"
    severity: FindingSeverity = FindingSeverity.MEDIUM
    snippet: str = ""  # Surrounding text snippet for UI inspection


class AuthFinding(BaseModel):
    """Authentication or session consistency finding."""
    rule_code: str
    finding_type: str
    severity: FindingSeverity = FindingSeverity.MEDIUM
    message: str = ""
    token_type: Optional[str] = None
    token_masked: Optional[str] = None
    jwt_claims: Optional[Dict[str, Any]] = None
    jwt_security_flags: List[str] = Field(default_factory=list)


class SecretFinding(BaseModel):
    """High-entropy secret or cloud token finding."""
    secret_type: str
    severity: FindingSeverity = FindingSeverity.HIGH
    matched_pattern: str = ""
    masked_value: str = ""
    location: ParameterLocation = ParameterLocation.HEADER
    entropy: float = 0.0


class IdentifierFinding(BaseModel):
    """Identifier and IDOR risk finding."""
    parameter_name: str
    location: ParameterLocation
    raw_value: str
    id_type: IdentifierType
    idor_risk_score: float = 0.5
    is_mutation: bool = False
    canonical_pattern: str = ""


class TriageSummary(BaseModel):
    """Aggregated triage analysis for a single HTTP/WebSocket flow."""
    flow_id: str
    canonical_endpoint: str
    endpoint_category: EndpointCategory
    parameters: List[ExtractedParameter] = Field(default_factory=list)
    reflections: List[ReflectionFinding] = Field(default_factory=list)
    auth_findings: List[AuthFinding] = Field(default_factory=list)
    secret_findings: List[SecretFinding] = Field(default_factory=list)
    identifier_findings: List[IdentifierFinding] = Field(default_factory=list)
    schema_inferred: Dict[str, Any] = Field(default_factory=dict)
    rule_matches: List[Any] = Field(default_factory=list)
    nuclei_matches: List[Any] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    has_high_priority_anomalies: bool = False
    analysis_duration_ms: float = 0.0

