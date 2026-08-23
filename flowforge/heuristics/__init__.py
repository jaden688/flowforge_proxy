"""Passive Heuristic Triage Engine for FlowForge Proxy (Requirement R2)."""

from flowforge.heuristics.auth_tracker import AuthTracker
from flowforge.heuristics.clustering import EndpointClassifier, RouteNormalizer
from flowforge.heuristics.entropy_scanner import EntropyScanner
from flowforge.heuristics.identifiers import IdentifierClassifier
from flowforge.heuristics.models import (
    AuthFinding,
    EncodingStatus,
    EndpointCategory,
    ExtractedParameter,
    FindingSeverity,
    IdentifierFinding,
    IdentifierType,
    ParameterLocation,
    ReflectionContext,
    ReflectionFinding,
    SecretFinding,
    TriageSummary,
)
from flowforge.heuristics.parameters import ParameterExtractor
from flowforge.heuristics.pipeline import (
    TriagePipeline,
    default_pipeline,
    process_flow,
)
from flowforge.heuristics.recommendations import (
    StrategyRecommendationEngine,
    recommendation_engine,
)
from flowforge.heuristics.reflection import ReflectionDetector
from flowforge.heuristics.rule_engine import (
    FlowInspectionContext,
    RuleEngine,
    calculate_shannon_entropy,
    default_rule_engine,
    get_rule_engine,
)
from flowforge.heuristics.schema_inferrer import SchemaInferrer

__all__ = [
    "ParameterLocation",
    "IdentifierType",
    "ReflectionContext",
    "EncodingStatus",
    "FindingSeverity",
    "EndpointCategory",
    "ExtractedParameter",
    "ReflectionFinding",
    "AuthFinding",
    "SecretFinding",
    "IdentifierFinding",
    "TriageSummary",
    "ParameterExtractor",
    "SchemaInferrer",
    "ReflectionDetector",
    "AuthTracker",
    "EntropyScanner",
    "IdentifierClassifier",
    "EndpointClassifier",
    "RouteNormalizer",
    "TriagePipeline",
    "process_flow",
    "default_pipeline",
    "StrategyRecommendationEngine",
    "recommendation_engine",
    "RuleEngine",
    "get_rule_engine",
    "default_rule_engine",
    "FlowInspectionContext",
    "calculate_shannon_entropy",
]
