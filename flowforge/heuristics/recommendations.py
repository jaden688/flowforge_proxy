"""
Context-Aware Strategy Recommendation Engine.
Analyzes endpoint parameters, triage tags, reflection status, identifier classification,
and auth state to rank mutation strategies with '#1 Recommended' badges and explanations.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Union
from flowforge.models.curation import (
    RankedStrategyResponse,
    RecommendStrategiesRequest,
    StrategyRecommendation,
)


class StrategyDefinition:
    """Static metadata and baseline scoring for a mutation strategy."""

    def __init__(
        self,
        strategy_id: str,
        label: str,
        category: str,
        base_score: float,
        default_reason: str,
    ):
        self.strategy_id = strategy_id
        self.label = label
        self.category = category
        self.base_score = base_score
        self.default_reason = default_reason


STRATEGY_CATALOG: List[StrategyDefinition] = [
    StrategyDefinition(
        strategy_id="REFLECTION_CONTEXT",
        label="Reflection Context Breaking",
        category="REFLECTION",
        base_score=30.0,
        default_reason="Fuzzes parameters for dynamic reflection and context escaping in responses.",
    ),
    StrategyDefinition(
        strategy_id="IDOR_SEQUENTIAL",
        label="Sequential Integer IDOR Probes",
        category="IDOR_SEQUENTIAL",
        base_score=30.0,
        default_reason="Tests predictable object identifiers for horizontal authorization boundary bypass.",
    ),
    StrategyDefinition(
        strategy_id="IDOR_ROLE_SWAP",
        label="Authorization Role Swap & Privilege Escalation",
        category="IDOR_ROLE_SWAP",
        base_score=25.0,
        default_reason="Evaluates horizontal and vertical privilege boundaries by swapping authorization tokens.",
    ),
    StrategyDefinition(
        strategy_id="AUTH_STRIPPING",
        label="Unauthenticated Access & Auth Header Stripping",
        category="AUTH_STRIPPING",
        base_score=25.0,
        default_reason="Verifies access control enforcement by stripping or corrupting authentication carriers.",
    ),
    StrategyDefinition(
        strategy_id="TYPE_CONFUSION",
        label="Type Confusion & Array Wrapping",
        category="TYPE_CONFUSION",
        base_score=25.0,
        default_reason="Injects unexpected data types, array brackets, nulls, and booleans to uncover parser flaws.",
    ),
    StrategyDefinition(
        strategy_id="BOUNDARY_OVERFLOW",
        label="Boundary Fuzzing & Special Character Escapes",
        category="BOUNDARY_OVERFLOW",
        base_score=30.0,
        default_reason="Fuzzes input boundaries with quotes, delimiters, format strings, and extreme lengths.",
    ),
    StrategyDefinition(
        strategy_id="MASS_ASSIGNMENT",
        label="Schema Mass Assignment & Role Injection",
        category="MASS_ASSIGNMENT",
        base_score=20.0,
        default_reason="Probes state-changing mutation endpoints for unvalidated administrative property injection.",
    ),
    StrategyDefinition(
        strategy_id="NOSQL_INJECTION",
        label="NoSQL & JSON Operator Injection",
        category="TYPE_CONFUSION",
        base_score=20.0,
        default_reason="Fuzzes JSON request parameters with NoSQL operators ($ne, $gt, $where, $regex).",
    ),
    StrategyDefinition(
        strategy_id="PATH_TRAVERSAL",
        label="Directory & Path Traversal Probes",
        category="BOUNDARY_OVERFLOW",
        base_score=20.0,
        default_reason="Tests file and path-referencing parameters for directory traversal escape sequences.",
    ),
    StrategyDefinition(
        strategy_id="JWT_FORGERY_PROBES",
        label="JWT Signature Stripping & Key Confusion",
        category="AUTH_STRIPPING",
        base_score=20.0,
        default_reason="Tests JSON Web Token authentication for alg: none signature stripping and token forgery.",
    ),
]


class StrategyRecommendationEngine:
    """
    Intelligent context-aware engine that analyzes endpoint characteristics,
    triage findings, parameters, reflection flags, and auth state to produce
    dynamically ranked mutation strategy recommendations.
    """

    def __init__(self, catalog: Optional[List[StrategyDefinition]] = None):
        self.catalog = catalog or STRATEGY_CATALOG

    def recommend(
        self,
        endpoint_hash: Optional[str] = None,
        method: str = "GET",
        path: str = "/",
        parameters: Optional[List[Dict[str, Any]]] = None,
        triage_tags: Optional[List[str]] = None,
        reflections: Optional[List[Any]] = None,
        auth_findings: Optional[List[Any]] = None,
        identifier_findings: Optional[List[Any]] = None,
        has_auth_carrier: bool = False,
        category: Optional[str] = None,
        schema_summary: Optional[Dict[str, Any]] = None,
    ) -> RankedStrategyResponse:
        """
        Compute confidence scores and rank all available strategies for the given endpoint context.
        """
        method_upper = (method or "GET").upper()
        path_str = path or "/"
        params = parameters or []
        tags = [t.lower() for t in (triage_tags or [])]
        has_reflection = bool(reflections) or ("reflection" in tags)
        has_auth = has_auth_carrier or bool(auth_findings) or ("auth" in tags) or ("auth_anomaly" in tags)

        # Parameter metadata extraction
        param_names = set()
        param_types = set()
        param_id_types = set()
        has_sequential_id = False
        has_file_param = False
        has_jwt_token = "jwt" in tags
        has_role_param = False
        max_idor_score = 0.0

        for p in params:
            p_dict = p if isinstance(p, dict) else (p.dict() if hasattr(p, "dict") else p.__dict__)
            name = str(p_dict.get("name", "")).lower()
            val = str(p_dict.get("value", "") or p_dict.get("sample_value", "") or "")
            dtype = str(p_dict.get("data_type", "") or p_dict.get("inferred_type", "")).lower()
            id_type = str(p_dict.get("id_type", "") or p_dict.get("identifier_type", "")).lower()
            idor_score = float(p_dict.get("idor_score") or p_dict.get("idor_risk_score") or 0.0)

            param_names.add(name)
            if dtype:
                param_types.add(dtype)
            if id_type:
                param_id_types.add(id_type)
            if idor_score > max_idor_score:
                max_idor_score = idor_score

            if id_type in ("sequential_integer", "monotonic_timestamp", "sequential_int") or idor_score >= 0.45:
                has_sequential_id = True
            elif (isinstance(val, int) or val.isdigit()) and any(k in name for k in ("id", "user", "acc", "num", "no")):
                has_sequential_id = True

            if any(k in name for k in ("file", "path", "doc", "dir", "download", "template", "image", "avatar", "attachment", "url", "view")):
                has_file_param = True

            if any(k in name for k in ("role", "admin", "is_admin", "group", "permission", "status", "level", "verified", "org_id", "tier")):
                has_role_param = True

            if p_dict.get("inferred_format") == "jwt" or (val.startswith("ey") and val.count(".") == 2):
                has_jwt_token = True

        # Path heuristics
        path_segments = [s for s in path_str.split("/") if s]
        for seg in path_segments:
            if seg.isdigit() or ("{" in seg and "id" in seg.lower()):
                has_sequential_id = True
            if any(k in seg.lower() for k in ("download", "file", "export", "document", "view", "avatar", "static")):
                has_file_param = True
            if any(k in seg.lower() for k in ("admin", "role", "manage", "tenant", "org", "account", "user", "profile")):
                has_role_param = True

        if identifier_findings:
            for id_f in identifier_findings:
                id_type_val = str(getattr(id_f, "id_type", "")).lower()
                if "sequential" in id_type_val or "monotonic" in id_type_val:
                    has_sequential_id = True
                score = float(getattr(id_f, "idor_risk_score", 0.0))
                if score > max_idor_score:
                    max_idor_score = score
                    if score >= 0.45:
                        has_sequential_id = True

        scored_recommendations: List[StrategyRecommendation] = []

        for defn in self.catalog:
            score = defn.base_score
            reasons: List[str] = []
            applicable_params: List[str] = []

            if defn.strategy_id == "REFLECTION_CONTEXT":
                if has_reflection:
                    score += 65.0
                    reasons.append("Input reflection confirmed in response body/headers with potential XSS / injection context.")
                    applicable_params.extend([p for p in param_names if any(k in p for k in ("q", "search", "name", "redirect", "url", "msg", "input", "query", "text", "callback", "err"))])
                elif "reflection" in tags:
                    score += 55.0
                    reasons.append("Reflection tags observed on endpoint traffic.")
                elif any(k in p for p in param_names for k in ("q", "search", "name", "redirect", "url", "msg", "input", "query", "text", "callback", "err")):
                    score += 35.0
                    reasons.append("Candidate reflection parameters (e.g. search, query, redirect, message) discovered.")
                    applicable_params.extend([p for p in param_names if any(k in p for k in ("q", "search", "name", "redirect", "url", "msg", "input", "query", "text", "callback", "err"))])

            elif defn.strategy_id == "IDOR_SEQUENTIAL":
                if has_sequential_id or max_idor_score >= 0.70:
                    score += 65.0
                    reasons.append("Predictable sequential integer identifier discovered in request target (high IDOR susceptibility).")
                    applicable_params.extend([p for p in param_names if any(k in p for k in ("id", "user", "acc", "num", "no", "item", "order"))])
                elif max_idor_score >= 0.45 or "idor_candidate" in tags:
                    score += 50.0
                    reasons.append("Potential sequential ID or IDOR candidate parameter detected.")
                    applicable_params.extend([p for p in param_names if "id" in p])
                elif any("id" in p for p in param_names):
                    score += 25.0
                    reasons.append("Identifier parameter present in request.")
                    applicable_params.extend([p for p in param_names if "id" in p])

            elif defn.strategy_id == "IDOR_ROLE_SWAP":
                if has_auth and (has_role_param or category in ("DATA_READ", "MUTATION_ACTION", "ADMIN_MANAGEMENT", "Admin")):
                    score += 60.0
                    reasons.append("Authenticated sensitive endpoint susceptible to cross-tenant or role-swap authorization bypass.")
                elif has_auth:
                    score += 45.0
                    reasons.append("Authenticated resource; role swap testing verifies multi-tenant isolation.")
                elif "auth" in tags or "auth_anomaly" in tags:
                    score += 40.0
                    reasons.append("Authentication tags present; role swap probes recommended.")

            elif defn.strategy_id == "AUTH_STRIPPING":
                if has_auth and (category in ("ADMIN_MANAGEMENT", "Admin") or has_role_param):
                    score += 58.0
                    reasons.append("Sensitive authenticated resource must be tested for unauthenticated access enforcement.")
                elif has_auth or "auth_anomaly" in tags:
                    score += 50.0
                    reasons.append("Authenticated endpoint carrier detected; stripping tests access control enforcement.")
                elif "auth" in tags:
                    score += 35.0
                    reasons.append("Auth carrier observed in flow; auth dropping probe recommended.")

            elif defn.strategy_id == "TYPE_CONFUSION":
                if method_upper in ("POST", "PUT", "PATCH") and (schema_summary or "body" in [p.get("location", "") for p in params]):
                    score += 52.0
                    reasons.append("Structured JSON request body suitable for type confusion, array wrapping, and null injection.")
                    applicable_params.extend(list(param_names)[:3])
                elif any(t in param_types for t in ("integer", "boolean", "array", "object")):
                    score += 40.0
                    reasons.append("Typed parameters (integer/boolean/array) detected for type juggling probes.")
                    applicable_params.extend(list(param_names)[:3])
                elif len(params) > 2:
                    score += 25.0
                    reasons.append("Multiple parameters available for type confusion fuzzing.")

            elif defn.strategy_id == "BOUNDARY_OVERFLOW":
                if any(t in param_types for t in ("string", "text", "str")) or len(params) > 0:
                    score += 45.0
                    reasons.append("String/text input parameters accept variable lengths and delimiter escapes.")
                    applicable_params.extend([p for p in param_names if not p.endswith("_id")][:3])
                else:
                    score += 20.0
                    reasons.append("Standard boundary breakout and format string testing.")

            elif defn.strategy_id == "MASS_ASSIGNMENT":
                if method_upper in ("POST", "PUT", "PATCH") and (has_role_param or category in ("MUTATION_ACTION", "ADMIN_MANAGEMENT", "Mutation/Action", "Admin")):
                    score += 65.0
                    reasons.append("State-mutating endpoint containing role/permission fields vulnerable to mass assignment.")
                    applicable_params.extend([p for p in param_names if any(k in p for k in ("role", "admin", "is_admin", "group", "permission", "status", "org_id"))])
                elif method_upper in ("POST", "PUT", "PATCH"):
                    score += 48.0
                    reasons.append("State-changing request method (POST/PUT/PATCH); probe for unvalidated object property injection.")
                elif has_role_param:
                    score += 40.0
                    reasons.append("Privilege-related parameter attributes detected in endpoint.")

            elif defn.strategy_id == "NOSQL_INJECTION":
                if "mongo_object_id" in param_id_types or any("mongo" in str(f).lower() for f in (identifier_findings or [])):
                    score += 65.0
                    reasons.append("MongoDB ObjectId detected; high susceptibility to NoSQL operator injection ($ne, $gt, $where).")
                    applicable_params.extend([p for p in param_names if "id" in p])
                elif method_upper in ("POST", "PUT", "PATCH") and any(k in p for p in param_names for k in ("filter", "query", "where", "find", "search", "user", "username", "email", "lookup")):
                    score += 55.0
                    reasons.append("JSON query/filter parameters detected, vulnerable to NoSQL operator injection ($ne: null, $gt).")
                    applicable_params.extend([p for p in param_names if any(k in p for k in ("filter", "query", "where", "find", "search", "user", "username", "email"))])
                elif method_upper in ("POST", "PUT", "PATCH"):
                    score += 25.0
                    reasons.append("JSON request body can be tested with nested NoSQL operator payloads.")

            elif defn.strategy_id == "PATH_TRAVERSAL":
                if has_file_param or category in ("FILE_TRANSFER", "File Transfer") or "file_transfer" in tags:
                    score += 70.0
                    reasons.append("File transfer or path-referencing parameter detected, susceptible to directory traversal probes (../../../../etc/passwd).")
                    applicable_params.extend([p for p in param_names if any(k in p for k in ("file", "path", "doc", "dir", "download", "template", "image", "avatar", "attachment", "url", "view"))])
                elif any("path" in p or "file" in p for p in param_names):
                    score += 45.0
                    reasons.append("File or path parameter detected for directory traversal testing.")
                    applicable_params.extend([p for p in param_names if "path" in p or "file" in p])

            elif defn.strategy_id == "JWT_FORGERY_PROBES":
                if has_jwt_token or "jwt" in tags or any("jwt" in str(f).lower() for f in (auth_findings or [])):
                    score += 68.0
                    reasons.append("JSON Web Token (JWT) detected in authentication flow; probe for alg: none signature stripping and key confusion.")
                    applicable_params.extend([p for p in param_names if "token" in p or "auth" in p or "jwt" in p])
                elif has_auth:
                    score += 25.0
                    reasons.append("Authenticated endpoint; check if bearer token is a malleable JWT.")

            # Bounded score
            final_score = min(99.0, max(10.0, round(score, 1)))
            explanation = " ".join(reasons) if reasons else defn.default_reason

            scored_recommendations.append(
                StrategyRecommendation(
                    strategy_id=defn.strategy_id,
                    label=defn.label,
                    rank=0,  # will be assigned after sorting
                    confidence_score=final_score,
                    is_recommended=False,  # will be assigned after sorting
                    badge="",
                    reason=explanation,
                    category=defn.category,
                    applicable_parameters=sorted(list(set(applicable_params))),
                )
            )

        # Sort descending by confidence score, tie-break by strategy_id
        scored_recommendations.sort(key=lambda s: (-s.confidence_score, s.strategy_id))

        # Assign ranks and badges
        for idx, item in enumerate(scored_recommendations, start=1):
            item.rank = idx
            if idx == 1:
                item.is_recommended = True
                item.badge = "#1 (Recommended)"
            elif idx == 2 and item.confidence_score >= 60.0:
                item.is_recommended = True
                item.badge = "#2 (Recommended)"
            else:
                item.is_recommended = False
                item.badge = f"#{idx}"

        top_recommended = scored_recommendations[0] if scored_recommendations else None
        target_endpoint_str = f"{method_upper} {path_str}"

        return RankedStrategyResponse(
            endpoint_hash=endpoint_hash,
            target_endpoint=target_endpoint_str,
            recommendations=scored_recommendations,
            top_recommended=top_recommended,
            total_strategies=len(scored_recommendations),
        )

    def recommend_from_request(self, req: RecommendStrategiesRequest) -> RankedStrategyResponse:
        """Helper to compute recommendations from a RecommendStrategiesRequest."""
        return self.recommend(
            endpoint_hash=req.endpoint_hash,
            method=req.method or "GET",
            path=req.path or "/",
            parameters=req.parameters or [],
            triage_tags=req.triage_tags or [],
            reflections=[{"dummy": True}] if req.reflection_detected else None,
            has_auth_carrier=bool(req.has_auth),
        )


# Global singleton recommendation engine instance
recommendation_engine = StrategyRecommendationEngine()
