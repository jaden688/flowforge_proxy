"""Unified passive heuristic triage pipeline coordinator (Requirement R2)."""

import time
from typing import Any, Dict, List, Optional, Union

from flowforge.heuristics.auth_tracker import AuthTracker
from flowforge.heuristics.clustering import EndpointClassifier, RouteNormalizer
from flowforge.heuristics.entropy_scanner import EntropyScanner
from flowforge.heuristics.identifiers import IdentifierClassifier
from flowforge.heuristics.models import (
    EndpointCategory,
    FindingSeverity,
    TriageSummary,
)
from flowforge.heuristics.nuclei_loader import (
    NucleiTemplateLoader,
    get_nuclei_loader,
)
from flowforge.heuristics.nuclei_matcher import (
    NucleiMatcherEngine,
    get_nuclei_matcher,
)
from flowforge.heuristics.parameters import ParameterExtractor
from flowforge.heuristics.reflection import ReflectionDetector
from flowforge.heuristics.rule_engine import RuleEngine, get_rule_engine
from flowforge.heuristics.schema_inferrer import SchemaInferrer
from flowforge.models.nuclei import NucleiSeverity
from flowforge.models.rules import RuleSeverity


class TriagePipeline:
    """Orchestrates passive heuristic analyzers on intercepted HTTP and WebSocket flows."""

    def __init__(
        self,
        rule_engine: Optional[RuleEngine] = None,
        nuclei_loader: Optional[NucleiTemplateLoader] = None,
        nuclei_matcher: Optional[NucleiMatcherEngine] = None,
    ):
        self.param_extractor = ParameterExtractor()
        self.schema_inferrer = SchemaInferrer()
        self.reflection_detector = ReflectionDetector()
        self.auth_tracker = AuthTracker()
        self.entropy_scanner = EntropyScanner()
        self.id_classifier = IdentifierClassifier()
        self.endpoint_classifier = EndpointClassifier()
        self.route_normalizer = RouteNormalizer()
        self.rule_engine = rule_engine or get_rule_engine()
        self.nuclei_loader = nuclei_loader or get_nuclei_loader()
        self.nuclei_matcher = nuclei_matcher or get_nuclei_matcher()


    async def process_flow(self, flow: Any) -> TriageSummary:
        """Asynchronously process an intercepted flow record through all heuristic stages."""
        return self.process_flow_sync(flow)

    def process_flow_sync(self, flow: Any) -> TriageSummary:
        """Synchronously execute the full heuristic triage pipeline."""
        start_time = time.perf_counter()

        flow_id = str(getattr(flow, "id", "") or "flow-unknown")
        req = getattr(flow, "request", None)
        resp = getattr(flow, "response", None)

        method = getattr(flow, "method", "") or (getattr(req, "method", "") if req else "") or "GET"
        method = method.upper()
        url = getattr(flow, "url", "") or (getattr(req, "url", "") if req else "") or ""
        path = getattr(flow, "path", "") or (getattr(req, "path", "") if req else "") or "/"
        req_body = getattr(flow, "request_body", None)
        if req_body is None:
            req_body = getattr(req, "body", "") if req else ""
        resp_body = getattr(flow, "response_body", None)
        if resp_body is None:
            resp_body = getattr(resp, "body", "") if resp else ""
        req_headers = getattr(flow, "request_headers", None)
        if req_headers is None:
            req_headers = getattr(req, "headers", {}) if req else {}
        resp_headers = getattr(flow, "response_headers", None)
        if resp_headers is None:
            resp_headers = getattr(resp, "headers", {}) if resp else {}
        resp_status = getattr(flow, "response_status_code", None)
        if resp_status is None and resp:
            resp_status = getattr(resp, "status_code", None)
        if resp_status is None:
            resp_status = getattr(flow, "response_status", 200)
        req_content_type = getattr(flow, "request_content_type", None)
        if req_content_type is None:
            req_content_type = getattr(req, "content_type", "") if req else ""
        resp_content_type = getattr(flow, "response_content_type", None)
        if resp_content_type is None:
            resp_content_type = getattr(resp, "content_type", "") if resp else ""

        # 1. Canonical Route & Endpoint Categorization
        canonical_endpoint = self.route_normalizer.canonical_endpoint(method, path)
        endpoint_category = self.endpoint_classifier.classify(
            method=method,
            path=path,
            status_code=resp_status,
            content_type=req_content_type or resp_content_type,
            request_body=req_body,
        )

        # 2. Parameter Extraction
        parameters = self.param_extractor.extract_all(flow)

        # 3. Dynamic JSON Schema Inference
        schema_inferred: Dict[str, Any] = {}
        if req_body:
            req_schema = self.schema_inferrer.infer_payload_schema(req_body)
            if req_schema:
                schema_inferred["request"] = req_schema
        if resp_body:
            resp_schema = self.schema_inferrer.infer_payload_schema(resp_body)
            if resp_schema:
                schema_inferred["response"] = resp_schema

        # 4. Input Reflection Detection
        reflections = self.reflection_detector.detect_reflections(
            parameters=parameters,
            response_body=resp_body,
            response_headers=resp_headers,
            response_content_type=resp_content_type,
        )

        # 5. Auth & Session Consistency Tracking
        auth_findings = self.auth_tracker.analyze_flow(
            flow=flow,
            parameters=parameters,
            canonical_endpoint=canonical_endpoint,
        )
        is_authenticated = not any(
            f.rule_code == "AUTH_ANOMALY_UNAUTH_SENSITIVE" for f in auth_findings
        )

        # 6. High-Entropy Tokens & Secret Signatures
        secret_findings = self.entropy_scanner.scan_secrets(
            parameters=parameters,
            flow=flow,
        )

        # 7. Identifier Classification & IDOR Risk Scoring
        identifier_findings = self.id_classifier.analyze_parameters(
            parameters=parameters,
            method=method,
            is_authenticated=is_authenticated,
            canonical_pattern=canonical_endpoint,
        )

        # 8. Custom Heuristic Rule Engine Evaluation
        rule_matches = self.rule_engine.evaluate_flow(flow=flow, parameters=parameters)

        # 8b. Passive Nuclei Template Evaluation
        nuclei_matches: List[Any] = []
        try:
            passive_templates = self.nuclei_loader.get_passive_templates()
            if passive_templates:
                nuclei_matches = self.nuclei_matcher.evaluate_flow_all(passive_templates, flow)
        except Exception as exc:
            logger.debug("Error during passive Nuclei evaluation: %s", exc)

        # 9. Tag Generation & High-Priority Anomaly Flagging
        tags: List[str] = []
        has_high_priority = False

        req_headers = flow.request.headers if getattr(flow, "request", None) and getattr(flow.request, "headers", None) else {}
        has_auth_header = any(k.lower() in ("authorization", "x-api-key", "x-auth-token") for k in req_headers) or any(p.name.lower() in ("authorization", "x-api-key", "x-auth-token") for p in parameters)

        if endpoint_category == EndpointCategory.AUTH_SESSION or has_auth_header:
            tags.append("auth")
        elif endpoint_category == EndpointCategory.ADMIN_MANAGEMENT:
            tags.append("admin")
        elif endpoint_category == EndpointCategory.MUTATION_ACTION:
            tags.append("state_mutation")
        elif endpoint_category == EndpointCategory.FILE_TRANSFER:
            tags.append("file_transfer")
        elif endpoint_category == EndpointCategory.TELEMETRY_HEALTH:
            tags.append("telemetry")

        if reflections:
            tags.append("reflection")
            if any(r.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) for r in reflections):
                has_high_priority = True

        if auth_findings:
            tags.append("auth_anomaly")
            if any(a.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) for a in auth_findings):
                has_high_priority = True

        if secret_findings:
            tags.append("secrets")
            if any(s.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) for s in secret_findings):
                has_high_priority = True

        if identifier_findings:
            if any(i.idor_risk_score >= 0.45 for i in identifier_findings):
                tags.append("idor_candidate")
            if any(i.idor_risk_score >= 0.70 for i in identifier_findings):
                has_high_priority = True

        if any(p.inferred_format == "jwt" or (p.raw_value.startswith("ey") and p.raw_value.count(".") == 2) for p in parameters):
            tags.append("jwt")

        # Add rule match tags and check high-priority rule triggers
        for rm in rule_matches:
            tags.extend(rm.tags)
            if rm.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH, RuleSeverity.CRITICAL, RuleSeverity.HIGH):
                has_high_priority = True

        # Add Nuclei template tags and check high-priority triggers
        for nm in nuclei_matches:
            tags.append("nuclei")
            if getattr(nm, "template_id", None):
                tags.append(str(nm.template_id).lower())
            if getattr(nm, "category", None):
                tags.append(str(nm.category).lower())
            if getattr(nm, "tags", None):
                tags.extend([str(t).lower() for t in nm.tags])
            nm_sev = getattr(nm, "severity", None)
            if isinstance(nm_sev, NucleiSeverity):
                if nm_sev in (NucleiSeverity.CRITICAL, NucleiSeverity.HIGH):
                    has_high_priority = True
            elif str(nm_sev).lower() in ("critical", "high"):
                has_high_priority = True

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return TriageSummary(
            flow_id=flow_id,
            canonical_endpoint=canonical_endpoint,
            endpoint_category=endpoint_category,
            parameters=parameters,
            reflections=reflections,
            auth_findings=auth_findings,
            secret_findings=secret_findings,
            identifier_findings=identifier_findings,
            schema_inferred=schema_inferred,
            rule_matches=rule_matches,
            nuclei_matches=nuclei_matches,
            tags=sorted(list(set(tags))),
            has_high_priority_anomalies=has_high_priority,
            analysis_duration_ms=duration_ms,
        )


# Global singleton instance
default_pipeline = TriagePipeline()


async def process_flow(flow: Any) -> TriageSummary:
    """Global convenience hook for processing flow through default triage pipeline."""
    return await default_pipeline.process_flow(flow)
