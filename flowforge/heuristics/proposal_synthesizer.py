"""
Automated Proposal Synthesizer Engine (Requirement R1 / Milestone M1).
Transforms passive heuristic triage findings into structured, ready-to-execute test proposals.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from flowforge.heuristics.models import (
    EncodingStatus,
    EndpointCategory,
    ExtractedParameter,
    FindingSeverity,
    IdentifierFinding,
    IdentifierType,
    ParameterLocation,
    ReflectionContext,
    ReflectionFinding,
    TriageSummary,
)
from flowforge.models.flow import FlowRecord
from flowforge.models.proposal import (
    AnomalyType,
    ProposalSeverity,
    ProposalState,
    TestProposal,
)

logger = logging.getLogger("flowforge.heuristics.proposal_synthesizer")


class ProposalSynthesizer:
    """
    Synthesizes actionable, contextual test candidates from intercepted traffic anomalies:
    1. Reflection breakouts across DOM / HTML / Header contexts.
    2. Sequential integer IDOR / BOLA parameter boundary sweeps.
    3. Authentication header dropping, role swaps, and JWT anomalies.
    4. JSON Schema mass assignment, type confusion, and NoSQL injection.
    5. High-entropy secrets and custom heuristic rule action triggers.
    """

    def __init__(self) -> None:
        pass

    def synthesize(self, flow: FlowRecord, triage: TriageSummary) -> List[TestProposal]:
        """
        Main entrypoint: evaluate all anomaly surfaces and generate deduplicated proposals.
        """
        proposals: List[TestProposal] = []
        seen_keys: Set[Tuple[str, str, str, str, str]] = set()

        def _add(p: TestProposal) -> None:
            # Deduplicate by (flow_id, target_param_name, target_param_location, str(mutated_value), str(auth_override))
            key = (
                p.flow_id,
                p.target_param_name,
                p.target_param_location,
                str(p.mutated_value),
                str(p.auth_override),
            )
            if key not in seen_keys:
                seen_keys.add(key)
                proposals.append(p)

        # 1. Synthesize Reflection Context Probes
        for p in self.synthesize_reflections(flow, triage):
            _add(p)

        # 2. Synthesize Sequential Integer IDOR / BOLA Probes
        for p in self.synthesize_idor(flow, triage):
            _add(p)

        # 3. Synthesize Authentication Enforcement & JWT Probes
        for p in self.synthesize_auth(flow, triage):
            _add(p)

        # 4. Synthesize JSON Schema & Mass Assignment Probes
        for p in self.synthesize_schema(flow, triage):
            _add(p)

        # 5. Synthesize Secret Exposure Probes
        for p in self.synthesize_secrets(flow, triage):
            _add(p)

        # 6. Synthesize Custom Rule Match Probes
        for p in self.synthesize_custom_rules(flow, triage):
            _add(p)

        return proposals

    def _compute_endpoint_hash(self, method: str, host: str, path: str) -> str:
        """Generate consistent 16-character endpoint hash."""
        raw = f"{method.upper()}:{host.lower()}:{path}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _get_path_and_host(self, flow: FlowRecord) -> Tuple[str, str, str]:
        """Extract method, host, and path from flow."""
        method = flow.request.method.upper() if flow.request else "GET"
        host = flow.server_host or "localhost"
        path = flow.request.path if flow.request else "/"
        return method, host, path

    def _map_finding_severity(self, sev: Any) -> ProposalSeverity:
        """Map triage severity enum or string to ProposalSeverity."""
        s = str(getattr(sev, "value", sev)).upper()
        if s == "CRITICAL":
            return ProposalSeverity.CRITICAL
        elif s == "HIGH":
            return ProposalSeverity.HIGH
        elif s == "LOW":
            return ProposalSeverity.LOW
        elif s == "INFO":
            return ProposalSeverity.INFO
        return ProposalSeverity.MEDIUM

    # -------------------------------------------------------------------------
    # 1. Reflection Context Probes
    # -------------------------------------------------------------------------
    def synthesize_reflections(self, flow: FlowRecord, triage: TriageSummary) -> List[TestProposal]:
        """Synthesize DOM-context breakout payloads for reflected inputs."""
        proposals: List[TestProposal] = []
        if not triage.reflections:
            return proposals

        method, host, path = self._get_path_and_host(flow)
        ep_hash = self._compute_endpoint_hash(method, host, path)

        for r in triage.reflections:
            ctx = r.context.value if hasattr(r.context, "value") else str(r.context)
            param_name = r.parameter_name or "q"
            param_loc = r.source_location.value if hasattr(r.source_location, "value") else str(r.source_location)
            base_val = r.reflected_value
            sev = self._map_finding_severity(r.severity)

            # Select context-specific mutation payloads
            payloads: List[Tuple[str, str, float]] = []

            if ctx == ReflectionContext.HTML_SCRIPT_BLOCK.value:
                payloads.append(("</script><script>alert(1)</script>", "Script Block Close & Re-open", 95.0))
                payloads.append(("'-alert(1)-'", "JavaScript String Concatenation Breakout", 92.0))
                payloads.append(("';alert(1)//", "JavaScript Statement Terminator Breakout", 90.0))
            elif ctx in (ReflectionContext.HTML_ATTR_EVENT.value, ReflectionContext.HTML_ATTR_QUOTED.value):
                payloads.append(('"><script>alert(1)</script>', "Quoted Attribute Tag Breakout", 95.0))
                payloads.append(('" onfocus="alert(1)" autofocus="', "Inline Event Handler Injection", 93.0))
            elif ctx == ReflectionContext.HTML_ATTR_UNQUOTED.value:
                payloads.append((' x onfocus=alert(1) autofocus', "Unquoted Attribute Space Event Injection", 94.0))
            elif ctx == ReflectionContext.HTML_ATTR_URI.value:
                payloads.append(('javascript:alert(1)', "JavaScript Pseudo-Protocol URI Injection", 94.0))
                payloads.append(('data:text/html,<script>alert(1)</script>', "Data URI HTML Execution", 90.0))
            elif ctx == ReflectionContext.RESPONSE_HEADER.value:
                payloads.append(('\r\nInjected-Header: test\r\n\r\n<script>alert(1)</script>', "CRLF Response Header Injection", 91.0))
            elif ctx == ReflectionContext.JSON_VALUE.value:
                payloads.append(('", "injected": "test"', "JSON String Property Breakout", 88.0))
                payloads.append(('\\u0022', "Unicode Escaped Quote Injection", 85.0))
            else:  # HTML_BODY_TEXT, PLAIN_TEXT, HTML_COMMENT, etc.
                payloads.append(('<svg onload=alert(1)>', "SVG Onload Autonomous Execution", 93.0))
                payloads.append(('<img src=x onerror=alert(1)>', "IMG Onerror DOM Execution", 90.0))

            for mut_val, desc_suffix, conf in payloads:
                title = f"XSS / Reflection Breakout ({param_name} in {ctx})"
                desc = (
                    f"Parameter '{param_name}' reflects in response {r.matched_in} within {ctx} context. "
                    f"Candidate mutation tests unencoded character boundary breakout: {desc_suffix}."
                )
                prop = TestProposal(
                    flow_id=flow.id,
                    endpoint_hash=ep_hash,
                    endpoint_path=path,
                    method=method,
                    anomaly_type=AnomalyType.REFLECTION,
                    title=title,
                    description=desc,
                    severity=sev,
                    confidence_score=conf,
                    target_param_name=param_name,
                    target_param_location=param_loc,
                    baseline_value=base_val,
                    mutated_value=mut_val,
                    state=ProposalState.PENDING,
                    tags=["reflection", "xss", "dom_breakout", ctx.lower()],
                )
                proposals.append(prop)

        return proposals

    # -------------------------------------------------------------------------
    # 2. Sequential Integer IDOR / BOLA Probes
    # -------------------------------------------------------------------------
    def synthesize_idor(self, flow: FlowRecord, triage: TriageSummary) -> List[TestProposal]:
        """Synthesize IDOR / BOLA boundary and sequential parameter mutation probes."""
        proposals: List[TestProposal] = []
        method, host, path = self._get_path_and_host(flow)
        ep_hash = self._compute_endpoint_hash(method, host, path)

        is_mutating_method = method in ("POST", "PUT", "PATCH", "DELETE")
        is_auth = "auth" in triage.tags or any(
            k.lower() in ("authorization", "cookie") for k in (flow.request.headers if flow.request else {})
        )

        default_sev = ProposalSeverity.HIGH if (is_mutating_method or is_auth) else ProposalSeverity.MEDIUM

        # Collect identifier candidates from identifier_findings and parameters
        id_candidates: List[Tuple[str, str, Any, float, str]] = []  # (name, loc, val, score, id_type)

        for finding in triage.identifier_findings:
            loc = finding.location.value if hasattr(finding.location, "value") else str(finding.location)
            id_type_str = finding.id_type.value if hasattr(finding.id_type, "value") else str(finding.id_type)
            id_candidates.append((
                finding.parameter_name,
                loc,
                finding.raw_value,
                finding.idor_risk_score,
                id_type_str,
            ))

        for param in triage.parameters:
            loc = param.location.value if hasattr(param.location, "value") else str(param.location)
            val_str = str(param.value) if param.value is not None else param.raw_value
            if param.is_array:
                continue

            # Check if integer or high IDOR score
            is_digit = val_str.isdigit() or isinstance(param.value, int)
            if (is_digit or param.idor_score >= 0.45) and not any(c[0] == param.name and c[1] == loc for c in id_candidates):
                id_candidates.append((
                    param.name,
                    loc,
                    param.value if param.value is not None else val_str,
                    param.idor_score if param.idor_score > 0 else 0.65,
                    "sequential_integer" if is_digit else "unknown",
                ))

        # Check URL path for sequential integer segments
        path_segments = [s for s in path.strip("/").split("/") if s]
        for idx, seg in enumerate(path_segments):
            if seg.isdigit() and len(seg) <= 10:
                parent_name = path_segments[idx - 1] if idx > 0 else "id"
                param_name = f"{parent_name}_id" if not parent_name.endswith("_id") and parent_name != "id" else parent_name
                loc = "path"
                if not any(c[1] == "path" and str(c[2]) == seg for c in id_candidates):
                    id_candidates.append((
                        param_name,
                        loc,
                        int(seg),
                        0.85,
                        "sequential_integer",
                    ))

        for param_name, param_loc, raw_val, score, id_type_str in id_candidates:
            # Check integer conversion
            int_val: Optional[int] = None
            try:
                if isinstance(raw_val, int):
                    int_val = raw_val
                elif isinstance(raw_val, str) and raw_val.strip().isdigit():
                    int_val = int(raw_val.strip())
            except Exception:
                int_val = None

            conf = min(98.0, max(55.0, 70.0 + (score * 25.0)))

            if int_val is not None:
                # 1. Increment N + 1
                proposals.append(TestProposal(
                    flow_id=flow.id,
                    endpoint_hash=ep_hash,
                    endpoint_path=path,
                    method=method,
                    anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
                    title=f"IDOR / BOLA Probe ({param_name} +1)",
                    description=(
                        f"Predictable sequential integer observed in {param_loc} for parameter '{param_name}' ({int_val}). "
                        f"Tests cross-tenant object access by incrementing ID to {int_val + 1}."
                    ),
                    severity=default_sev,
                    confidence_score=conf,
                    target_param_name=param_name,
                    target_param_location=param_loc,
                    baseline_value=int_val,
                    mutated_value=int_val + 1,
                    state=ProposalState.PENDING,
                    tags=["idor", "bola", "access_control", "sequential_int"],
                ))

                # 2. Decrement N - 1
                proposals.append(TestProposal(
                    flow_id=flow.id,
                    endpoint_hash=ep_hash,
                    endpoint_path=path,
                    method=method,
                    anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
                    title=f"IDOR / BOLA Probe ({param_name} -1)",
                    description=(
                        f"Predictable sequential integer observed in {param_loc} for parameter '{param_name}' ({int_val}). "
                        f"Tests cross-tenant object access by decrementing ID to {max(0, int_val - 1)}."
                    ),
                    severity=default_sev,
                    confidence_score=conf,
                    target_param_name=param_name,
                    target_param_location=param_loc,
                    baseline_value=int_val,
                    mutated_value=max(0, int_val - 1),
                    state=ProposalState.PENDING,
                    tags=["idor", "bola", "access_control", "sequential_int"],
                ))

                # 3. Zero boundary
                proposals.append(TestProposal(
                    flow_id=flow.id,
                    endpoint_hash=ep_hash,
                    endpoint_path=path,
                    method=method,
                    anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
                    title=f"IDOR Boundary Probe ({param_name} = 0)",
                    description=f"Tests zero boundary integer access control handling on '{param_name}'.",
                    severity=ProposalSeverity.MEDIUM,
                    confidence_score=max(60.0, conf - 10.0),
                    target_param_name=param_name,
                    target_param_location=param_loc,
                    baseline_value=int_val,
                    mutated_value=0,
                    state=ProposalState.PENDING,
                    tags=["idor", "boundary", "zero_id"],
                ))

                # 4. Extreme High ID
                proposals.append(TestProposal(
                    flow_id=flow.id,
                    endpoint_hash=ep_hash,
                    endpoint_path=path,
                    method=method,
                    anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
                    title=f"IDOR Non-Existent Probe ({param_name} = 999999999)",
                    description=f"Tests unhandled 404 / 500 error boundary handling for non-existent ID on '{param_name}'.",
                    severity=ProposalSeverity.LOW,
                    confidence_score=max(55.0, conf - 15.0),
                    target_param_name=param_name,
                    target_param_location=param_loc,
                    baseline_value=int_val,
                    mutated_value=999999999,
                    state=ProposalState.PENDING,
                    tags=["idor", "boundary", "non_existent"],
                ))

                # 5. Negative ID
                proposals.append(TestProposal(
                    flow_id=flow.id,
                    endpoint_hash=ep_hash,
                    endpoint_path=path,
                    method=method,
                    anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
                    title=f"IDOR Negative Boundary Probe ({param_name} = -1)",
                    description=f"Tests signed integer boundary condition and underflow handling for '{param_name}'.",
                    severity=ProposalSeverity.LOW,
                    confidence_score=max(55.0, conf - 15.0),
                    target_param_name=param_name,
                    target_param_location=param_loc,
                    baseline_value=int_val,
                    mutated_value=-1,
                    state=ProposalState.PENDING,
                    tags=["idor", "boundary", "negative_id"],
                ))
            elif "uuid" in id_type_str or "uuid" in param_name.lower():
                # UUID candidate
                proposals.append(TestProposal(
                    flow_id=flow.id,
                    endpoint_hash=ep_hash,
                    endpoint_path=path,
                    method=method,
                    anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
                    title=f"IDOR / BOLA Probe (UUID Swap on {param_name})",
                    description=f"Tests object authorization against UUID substitution on '{param_name}'.",
                    severity=default_sev,
                    confidence_score=conf,
                    target_param_name=param_name,
                    target_param_location=param_loc,
                    baseline_value=str(raw_val),
                    mutated_value="00000000-0000-0000-0000-000000000000",
                    state=ProposalState.PENDING,
                    tags=["idor", "bola", "uuid_swap"],
                ))

        return proposals

    # -------------------------------------------------------------------------
    # 3. Authentication Enforcement & JWT Probes
    # -------------------------------------------------------------------------
    def synthesize_auth(self, flow: FlowRecord, triage: TriageSummary) -> List[TestProposal]:
        """Synthesize auth header dropping, role swaps, and JWT anomaly probes."""
        proposals: List[TestProposal] = []
        method, host, path = self._get_path_and_host(flow)
        ep_hash = self._compute_endpoint_hash(method, host, path)

        headers = flow.request.headers if (flow.request and flow.request.headers) else {}
        auth_hdr = headers.get("authorization") or headers.get("Authorization") or ""
        api_key_hdr = headers.get("x-api-key") or headers.get("apikey") or headers.get("x-auth-token") or ""
        cookies = flow.request.cookies if (flow.request and flow.request.cookies) else {}
        has_auth_carrier = bool(auth_hdr or api_key_hdr or cookies) or "auth" in triage.tags

        # Detect JWT presence
        has_jwt = (
            auth_hdr.lower().startswith("bearer ey")
            or "jwt" in triage.tags
            or any("jwt" in str(getattr(p, "inferred_format", "")) for p in triage.parameters)
            or any("eyJ" in str(v) for v in headers.values())
        )

        if has_auth_carrier or triage.auth_findings:
            # 1. Drop Auth
            proposals.append(TestProposal(
                flow_id=flow.id,
                endpoint_hash=ep_hash,
                endpoint_path=path,
                method=method,
                anomaly_type=AnomalyType.AUTH_DEVIATION,
                title="Auth Enforcement Probe (Drop Auth Header)",
                description=(
                    "Strips Authorization headers and session cookies to test if sensitive endpoint enforces "
                    "mandatory authentication controls."
                ),
                severity=ProposalSeverity.HIGH,
                confidence_score=85.0,
                target_param_name="Authorization",
                target_param_location="header",
                baseline_value="[AUTHENTICATED_SESSION]",
                mutated_value=None,
                auth_override="DROP",
                state=ProposalState.PENDING,
                tags=["auth", "access_control", "auth_omission"],
            ))

            # 2. User B Role Swap
            proposals.append(TestProposal(
                flow_id=flow.id,
                endpoint_hash=ep_hash,
                endpoint_path=path,
                method=method,
                anomaly_type=AnomalyType.AUTH_DEVIATION,
                title="Auth Enforcement Probe (User B Role Swap)",
                description=(
                    "Substitutes authenticated caller token with simulated secondary user (User B) token "
                    "to verify tenant/role isolation."
                ),
                severity=ProposalSeverity.HIGH,
                confidence_score=80.0,
                target_param_name="Authorization",
                target_param_location="header",
                baseline_value="[USER_A_TOKEN]",
                mutated_value="[USER_B_TOKEN]",
                auth_override="USER_B",
                state=ProposalState.PENDING,
                tags=["auth", "rbac", "role_swap", "tenant_isolation"],
            ))

            # 3. Expired Token Replay
            proposals.append(TestProposal(
                flow_id=flow.id,
                endpoint_hash=ep_hash,
                endpoint_path=path,
                method=method,
                anomaly_type=AnomalyType.AUTH_DEVIATION,
                title="Auth Enforcement Probe (Expired JWT Replay)",
                description="Substitutes active token with pre-expired JWT signature to test token lifetime enforcement.",
                severity=ProposalSeverity.MEDIUM,
                confidence_score=75.0,
                target_param_name="Authorization",
                target_param_location="header",
                baseline_value="[ACTIVE_TOKEN]",
                mutated_value="[EXPIRED_TOKEN]",
                auth_override="EXPIRED",
                state=ProposalState.PENDING,
                tags=["auth", "jwt", "token_expiry"],
            ))

        # 4. JWT alg: none Forgery
        if has_jwt:
            proposals.append(TestProposal(
                flow_id=flow.id,
                endpoint_hash=ep_hash,
                endpoint_path=path,
                method=method,
                anomaly_type=AnomalyType.JWT_ANOMALY,
                title="JWT Security Probe (alg: none Forgery)",
                description=(
                    "Strips cryptographic signature and sets header {'alg': 'none'} to test insecure "
                    "JWT signature verification."
                ),
                severity=ProposalSeverity.CRITICAL,
                confidence_score=92.0,
                target_param_name="Authorization",
                target_param_location="header",
                baseline_value="Bearer eyJhbGciOiJSUzI1NiIs...",
                mutated_value="Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
                auth_override="ALG_NONE",
                state=ProposalState.PENDING,
                tags=["auth", "jwt", "crypto", "alg_none"],
            ))

        # 5. Targeted proposals from specific AuthFindings
        for f in triage.auth_findings:
            if f.rule_code == "AUTH_ANOMALY_UNAUTH_SENSITIVE":
                proposals.append(TestProposal(
                    flow_id=flow.id,
                    endpoint_hash=ep_hash,
                    endpoint_path=path,
                    method=method,
                    anomaly_type=AnomalyType.AUTH_DEVIATION,
                    title="Unauthenticated Sensitive Endpoint Probe",
                    description=f.message or "Sensitive route responded with 200 OK without authentication.",
                    severity=ProposalSeverity.CRITICAL,
                    confidence_score=90.0,
                    target_param_name="",
                    target_param_location="header",
                    auth_override="DROP",
                    state=ProposalState.PENDING,
                    tags=["auth", "sensitive_endpoint", "unauth_access"],
                ))

        return proposals

    # -------------------------------------------------------------------------
    # 4. JSON Schema Mass Assignment & Type Confusion
    # -------------------------------------------------------------------------
    def synthesize_schema(self, flow: FlowRecord, triage: TriageSummary) -> List[TestProposal]:
        """Synthesize mass assignment, type confusion, and NoSQL injection proposals."""
        proposals: List[TestProposal] = []
        method, host, path = self._get_path_and_host(flow)
        ep_hash = self._compute_endpoint_hash(method, host, path)

        req_body = flow.request.body if flow.request else ""
        content_type = (flow.request.content_type if flow.request else "") or ""
        is_json = "json" in content_type.lower() or (isinstance(req_body, str) and req_body.strip().startswith("{"))

        # Parse JSON body if present
        parsed_body: Optional[Dict[str, Any]] = None
        if is_json and req_body:
            try:
                data = json.loads(req_body)
                if isinstance(data, dict):
                    parsed_body = data
            except Exception:
                parsed_body = None

        if parsed_body is not None or (method in ("POST", "PUT", "PATCH") and is_json):
            # 1. Mass Assignment (role: admin)
            mutated_dict = dict(parsed_body or {})
            mutated_dict["role"] = "admin"
            mutated_dict["is_admin"] = True
            mutated_dict["permissions"] = ["*"]

            proposals.append(TestProposal(
                flow_id=flow.id,
                endpoint_hash=ep_hash,
                endpoint_path=path,
                method=method,
                anomaly_type=AnomalyType.JSON_SCHEMA,
                title="Schema Mass Assignment (Inject role: 'admin')",
                description=(
                    "Injects privileged administrative attributes ('role': 'admin', 'is_admin': true, 'permissions': ['*']) "
                    "into JSON request payload body to test unauthorized privilege elevation."
                ),
                severity=ProposalSeverity.HIGH,
                confidence_score=78.0,
                target_param_name="role",
                target_param_location="body",
                baseline_value=parsed_body,
                mutated_value=mutated_dict,
                state=ProposalState.PENDING,
                tags=["schema", "mass_assignment", "privilege_escalation"],
            ))

            # 2. Type Confusion & Array Wrapping on discovered parameters
            for k, v in list((parsed_body or {}).items())[:3]:
                # Array wrapping
                arr_mutated = dict(parsed_body)
                arr_mutated[k] = [v]
                proposals.append(TestProposal(
                    flow_id=flow.id,
                    endpoint_hash=ep_hash,
                    endpoint_path=path,
                    method=method,
                    anomaly_type=AnomalyType.JSON_SCHEMA,
                    title=f"JSON Type Confusion (Array Wrapping '{k}')",
                    description=f"Replaces scalar value of '{k}' with an array wrapper [{v}] to test type handling resilience.",
                    severity=ProposalSeverity.MEDIUM,
                    confidence_score=70.0,
                    target_param_name=k,
                    target_param_location="body",
                    baseline_value=v,
                    mutated_value=arr_mutated,
                    state=ProposalState.PENDING,
                    tags=["schema", "type_confusion", "input_validation"],
                ))

                # Null substitution
                null_mutated = dict(parsed_body)
                null_mutated[k] = None
                proposals.append(TestProposal(
                    flow_id=flow.id,
                    endpoint_hash=ep_hash,
                    endpoint_path=path,
                    method=method,
                    anomaly_type=AnomalyType.JSON_SCHEMA,
                    title=f"JSON Type Confusion (Null Substitution '{k}')",
                    description=f"Substitutes null for property '{k}' to test null-dereference and validation error handling.",
                    severity=ProposalSeverity.LOW,
                    confidence_score=65.0,
                    target_param_name=k,
                    target_param_location="body",
                    baseline_value=v,
                    mutated_value=null_mutated,
                    state=ProposalState.PENDING,
                    tags=["schema", "type_confusion", "null_handling"],
                ))

        # 3. NoSQL Operator Injection
        for param in triage.parameters:
            loc = param.location.value if hasattr(param.location, "value") else str(param.location)
            p_name = param.name.lower()
            if any(k in p_name for k in ("user", "id", "email", "name", "status", "query", "filter")):
                nosql_payload = {"$ne": None}
                proposals.append(TestProposal(
                    flow_id=flow.id,
                    endpoint_hash=ep_hash,
                    endpoint_path=path,
                    method=method,
                    anomaly_type=AnomalyType.JSON_SCHEMA,
                    title=f"NoSQL Operator Injection ({param.name})",
                    description=f"Mutates '{param.name}' in {loc} to MongoDB query operator {{'$ne': null}} to test auth/filter bypass.",
                    severity=ProposalSeverity.HIGH,
                    confidence_score=75.0,
                    target_param_name=param.name,
                    target_param_location=loc,
                    baseline_value=param.value or param.raw_value,
                    mutated_value=nosql_payload,
                    state=ProposalState.PENDING,
                    tags=["schema", "nosql_injection", "database"],
                ))
                break

        return proposals

    # -------------------------------------------------------------------------
    # 5. High-Entropy Secret Exposure Probes
    # -------------------------------------------------------------------------
    def synthesize_secrets(self, flow: FlowRecord, triage: TriageSummary) -> List[TestProposal]:
        """Synthesize secret exposure verification probes."""
        proposals: List[TestProposal] = []
        if not triage.secret_findings:
            return proposals

        method, host, path = self._get_path_and_host(flow)
        ep_hash = self._compute_endpoint_hash(method, host, path)

        for s in triage.secret_findings:
            loc = s.location.value if hasattr(s.location, "value") else str(s.location)
            sev = self._map_finding_severity(s.severity)
            title = f"Secret Exposure Verification ({s.secret_type})"
            desc = (
                f"High-entropy secret or API token signature '{s.secret_type}' ({s.masked_value}) observed in {loc}. "
                f"Tests credential reachability and public exposure."
            )
            proposals.append(TestProposal(
                flow_id=flow.id,
                endpoint_hash=ep_hash,
                endpoint_path=path,
                method=method,
                anomaly_type=AnomalyType.SECRET_EXPOSURE,
                title=title,
                description=desc,
                severity=sev,
                confidence_score=88.0,
                target_param_name=s.secret_type,
                target_param_location=loc,
                baseline_value=s.masked_value,
                mutated_value=None,
                state=ProposalState.PENDING,
                tags=["secrets", "credential_leak", s.secret_type.lower()],
            ))

        return proposals

    # -------------------------------------------------------------------------
    # 6. Custom Heuristic Rule Triggers
    # -------------------------------------------------------------------------
    def synthesize_custom_rules(self, flow: FlowRecord, triage: TriageSummary) -> List[TestProposal]:
        """Synthesize test proposals from custom heuristic rule match findings."""
        proposals: List[TestProposal] = []
        if not triage.rule_matches:
            return proposals

        method, host, path = self._get_path_and_host(flow)
        ep_hash = self._compute_endpoint_hash(method, host, path)

        for rm in triage.rule_matches:
            rule_name = getattr(rm, "rule_name", getattr(rm, "name", "Custom Rule Match"))
            rule_desc = getattr(rm, "description", "Custom rule condition matched on intercepted flow.")
            rule_sev = self._map_finding_severity(getattr(rm, "severity", "HIGH"))
            rule_tags = list(getattr(rm, "tags", []))

            proposals.append(TestProposal(
                flow_id=flow.id,
                endpoint_hash=ep_hash,
                endpoint_path=path,
                method=method,
                anomaly_type=AnomalyType.CUSTOM_RULE,
                title=f"Custom Rule Trigger ({rule_name})",
                description=rule_desc,
                severity=rule_sev,
                confidence_score=85.0,
                target_param_name="",
                target_param_location="request",
                state=ProposalState.PENDING,
                tags=["custom_rule"] + rule_tags,
            ))

        return proposals
