"""
Proposal → Intruder Bridge.

Converts heuristic-generated TestProposals into actionable IntruderJobConfigs
by selecting the right injection points, wordlists, and payload vectors
for each vulnerability class.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from flowforge.db.repository import FlowRepository
from flowforge.models.intruder import InjectionPoint, InjectionPosition, IntruderJobConfig
from flowforge.models.proposal import (
    AnomalyType,
    ProposalSeverity,
    ProposalState,
    TestProposal,
)

logger = logging.getLogger("flowforge.core.bridge")

# Maps each proposal anomaly type to its payload wordlist categories.
# The intruder merges these with any inline payloads.
_PAYLOAD_MAP: Dict[AnomalyType, List[str]] = {
    AnomalyType.REFLECTION: ["xss", "html_injection"],
    AnomalyType.IDOR_SEQUENTIAL: ["idor", "integer_sequential", "path_traversal"],
    AnomalyType.AUTH_DEVIATION: ["auth_bypass", "jwt_attacks", "privilege_escalation"],
    AnomalyType.JSON_SCHEMA: ["mass_assignment", "type_confusion", "injection"],
    AnomalyType.JWT_ANOMALY: ["jwt_attacks"],
    AnomalyType.SECRET_EXPOSURE: ["secret_discovery", "info_disclosure"],
    AnomalyType.CUSTOM_RULE: ["injection", "generic_fuzz"],
    AnomalyType.NUCLEI_TEMPLATE: ["nuclei", "cve", "exposure", "misconfig", "generic_fuzz"],
    AnomalyType.CVE: ["cve", "exploit", "nuclei"],
    AnomalyType.EXPOSURE: ["exposure", "sensitive_files", "nuclei"],
    AnomalyType.MISCONFIG: ["misconfig", "headers", "nuclei"],
}

# Inline payload seeds per anomaly type — used when no wordlist files exist.
_INLINE_SEEDS: Dict[AnomalyType, List[str]] = {
    AnomalyType.REFLECTION: [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        '"><svg/onload=alert(1)>',
        "{{7*7}}",
        "${7*7}",
        "';alert(1)//",
    ],
    AnomalyType.IDOR_SEQUENTIAL: [
        "0", "1", "2", "-1", "99999",
        "admin", "test", "100", "101",
    ],
    AnomalyType.AUTH_DEVIATION: [
        "true", "false", "1", "0", "admin", "null",
    ],
    AnomalyType.JSON_SCHEMA: [
        '{"admin":true}',
        '{"role":"admin"}',
        '{"is_admin":true}',
        '{"__proto__":{"admin":true}}',
    ],
    AnomalyType.JWT_ANOMALY: [
        "none", "null", "HS256", "HS384", "HS512",
    ],
    AnomalyType.SECRET_EXPOSURE: [
        "/etc/passwd",
        "{{config}}",
        "{{env}}",
        "../../etc/passwd",
        "${env.HOME}",
    ],
    AnomalyType.CUSTOM_RULE: [
        "{{7*7}}",
        "true",
        "null",
    ],
    AnomalyType.NUCLEI_TEMPLATE: [
        "/admin",
        "/.env",
        "/actuator/health",
        "/api/v1/debug",
    ],
    AnomalyType.CVE: [
        "/vulnerable-endpoint",
        "/api/v1/exploit",
    ],
    AnomalyType.EXPOSURE: [
        "/.git/config",
        "/.env",
        "/backup.sql",
        "/server-status",
    ],
    AnomalyType.MISCONFIG: [
        "/debug",
        "/trace",
        "/elmah.axd",
        "/phpinfo.php",
    ],
}


def build_injection_points(
    proposal: TestProposal,
    flow: Optional[Dict[str, Any]] = None,
) -> List[InjectionPoint]:
    """Convert a proposal's target parameter into injection point(s).

    For IDOR/secrets: inject at the target param location.
    For reflection/schema: inject at body (or the target param if known).
    For auth: inject at headers.
    """
    points: List[InjectionPoint] = []

    if proposal.anomaly_type == AnomalyType.AUTH_DEVIATION:
        loc = proposal.target_param_location or "header"
        if loc == "header":
            points.append(InjectionPoint(
                position=InjectionPosition.HEADER,
                key=proposal.target_param_name or "Authorization",
            ))
        else:
            points.append(InjectionPoint(
                position=InjectionPosition.QUERY,
                key=proposal.target_param_name or "token",
            ))
        return points

    if proposal.anomaly_type in (AnomalyType.REFLECTION, AnomalyType.JSON_SCHEMA):
        if proposal.target_param_name:
            points.append(InjectionPoint(
                position=InjectionPosition.QUERY,
                key=proposal.target_param_name,
            ))
            points.append(InjectionPoint(
                position=InjectionPosition.BODY,
            ))
        else:
            points.append(InjectionPoint(
                position=InjectionPosition.BODY,
            ))
        return points

    loc = proposal.target_param_location or "query"
    if loc == "path" and proposal.endpoint_path:
        # For path-based injection, we replace the last path segment.
        path = proposal.endpoint_path.rstrip("/")
        parts = path.split("/")
        if len(parts) >= 2:
            key = f"{parts[-1]}"
            points.append(InjectionPoint(
                position=InjectionPosition.QUERY,
                key=key,
            ))
            return points

    if loc == "header":
        points.append(InjectionPoint(
            position=InjectionPosition.HEADER,
            key=proposal.target_param_name,
        ))
    elif loc == "body":
        points.append(InjectionPoint(
            position=InjectionPosition.BODY,
        ))
    else:
        points.append(InjectionPoint(
            position=InjectionPosition.QUERY,
            key=proposal.target_param_name,
        ))

    return points


def select_auth_override(proposal: TestProposal) -> Optional[str]:
    """Map proposal's auth_override hint to intruder config."""
    if proposal.auth_override:
        return proposal.auth_override
    if proposal.anomaly_type == AnomalyType.AUTH_DEVIATION:
        return "DROP"
    return None


def build_intruder_config(
    proposal: TestProposal,
    flow: Optional[Dict[str, Any]] = None,
    *,
    concurrency: int = 4,
    rate_limit_rps: Optional[float] = None,
) -> IntruderJobConfig:
    """Convert a TestProposal into an IntruderJobConfig ready for execution.

    Parameters
    ----------
    proposal : TestProposal
        The proposal to convert.
    flow : dict, optional
        The original intercepted flow dict (keys: method, url, headers, body).
    concurrency : int
        Max parallel requests for the intruder.
    rate_limit_rps : float, optional
        Requests-per-second cap.
    """
    method = proposal.method
    url = _build_target_url(proposal, flow)
    headers = _build_headers(proposal, flow)
    body = _build_body(proposal, flow)
    auth_override = select_auth_override(proposal)

    # If auth override requested, strip/modify auth headers
    if auth_override == "DROP":
        headers.pop("Authorization", None)
        headers.pop("X-Auth-Token", None)
        headers.pop("Cookie", None)

    injection_points = build_injection_points(proposal, flow)

    # Build payload sources
    wordlist_categories = _PAYLOAD_MAP.get(proposal.anomaly_type, ["generic_fuzz"])
    inline = _INLINE_SEEDS.get(proposal.anomaly_type, ["true"])

    # Add mutation-specific payloads
    if proposal.mutated_value is not None:
        inline.insert(0, str(proposal.mutated_value))
    if proposal.baseline_value is not None:
        inline.insert(0, str(proposal.baseline_value))

    config = IntruderJobConfig(
        flow_id=proposal.flow_id,
        method=method,
        url=url,
        headers=headers,
        body=body,
        injection_points=injection_points,
        arsenal_wordlist_ids=wordlist_categories,
        inline_payloads=inline,
        concurrency=concurrency,
        rate_limit_rps=rate_limit_rps,
        timeout_seconds=10.0,
        follow_redirects=False,
    )

    logger.info(
        "Built intruder config from proposal %s (%s) → %d injection points, "
        "%d inline payloads, categories=%s",
        proposal.id,
        proposal.anomaly_type.value,
        len(injection_points),
        len(inline),
        wordlist_categories,
    )

    return config


def _build_target_url(
    proposal: TestProposal,
    flow: Optional[Dict[str, Any]] = None,
) -> str:
    """Reconstruct the target URL dynamically from proposal + flow."""
    if flow and flow.get("url"):
        url = flow["url"]
        if url.startswith("/"):
            scheme = flow.get("scheme") or "http"
            host = flow.get("server_host") or flow.get("host") or "127.0.0.1"
            port = flow.get("server_port")
            port_str = f":{port}" if (port and port not in (80, 443)) else ""
            url = f"{scheme}://{host}{port_str}{url}"
        return url

    # Fallback: construct from flow metadata or proposal path
    scheme = (flow and (flow.get("scheme") or "http")) or "http"
    host = (flow and (flow.get("server_host") or flow.get("host"))) or "127.0.0.1"
    port = flow and flow.get("server_port")
    port_str = f":{port}" if (port and port not in (80, 443)) else (":8000" if (not flow or (not flow.get("server_host") and not flow.get("host"))) else "")
    base = f"{scheme}://{host}{port_str}"

    path = proposal.endpoint_path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if proposal.target_param_name and proposal.target_param_location == "query":
        sep = "&" if "?" in path else "?"
        path = f"{path}{sep}{proposal.target_param_name}={proposal.baseline_value or 1}"
    return f"{base}{path}"


def _build_headers(
    proposal: TestProposal,
    flow: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Extract headers from the flow or set sensible defaults."""
    if flow and flow.get("headers"):
        return dict(flow["headers"])
    return {"Content-Type": "application/json", "Accept": "application/json"}


def _build_body(
    proposal: TestProposal,
    flow: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Extract the request body from the flow."""
    if flow and flow.get("body"):
        return flow["body"]
    if proposal.baseline_value is not None and proposal.target_param_location == "body":
        import json
        return json.dumps({proposal.target_param_name: proposal.baseline_value})
    return None


# ---------------------------------------------------------------------------
# Batch proposal → intruder conversion
# ---------------------------------------------------------------------------

def proposals_to_intruder_configs(
    proposals: List[TestProposal],
    flows: Optional[Dict[str, Dict[str, Any]]] = None,
    *,
    concurrency: int = 4,
    max_proposals: int = 20,
) -> List[IntruderJobConfig]:
    """Convert a batch of proposals into intruder configs.

    Parameters
    ----------
    proposals : list
        Proposals to convert, sorted by priority.
    flows : dict, optional
        Map of flow_id → flow dict for URL/header/body resolution.
    concurrency : int
        Shared concurrency cap per job.
    max_proposals : int
        Hard limit on how many proposals to convert in one batch.
    """
    configs: List[IntruderJobConfig] = []

    # Sort by severity then confidence descending
    severity_order = {
        ProposalSeverity.CRITICAL: 0,
        ProposalSeverity.HIGH: 1,
        ProposalSeverity.MEDIUM: 2,
        ProposalSeverity.LOW: 3,
        ProposalSeverity.INFO: 4,
    }
    sorted_props = sorted(
        proposals,
        key=lambda p: (severity_order.get(p.severity, 9), -p.confidence_score),
    )

    for proposal in sorted_props[:max_proposals]:
        if proposal.state != ProposalState.PENDING:
            continue

        flow = flows.get(proposal.flow_id) if flows else None
        config = build_intruder_config(proposal, flow, concurrency=concurrency)
        configs.append(config)

    logger.info(
        "Converted %d proposals to intruder configs (of %d eligible)",
        len(configs),
        min(len(proposals), max_proposals),
    )

    return configs
