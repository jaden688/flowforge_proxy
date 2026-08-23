"""
Custom YAML/JSON Heuristic Match Rule Engine (Requirement R5).

Provides rule parsing (YAML/JSON), condition evaluation (headers, status, method, url,
regex body, entropy thresholds, etc.), flow evaluation, and rule registry management.
"""

from __future__ import annotations

import collections
import json
import logging
import math
import re
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import yaml

from flowforge.models.rules import (
    MatchRule,
    RuleCondition,
    RuleEvaluationResult,
    RuleOperator,
    RuleSeverity,
)

logger = logging.getLogger("flowforge.heuristics.rule_engine")


def calculate_shannon_entropy(data: Union[str, bytes, None]) -> float:
    """
    Calculate Shannon entropy H(S) = -sum(p * log2(p)) for input data.
    Returns a float between 0.0 and 8.0.
    """
    if not data:
        return 0.0
    if isinstance(data, str):
        data_bytes = data.encode("utf-8", errors="replace")
    elif isinstance(data, (bytes, bytearray)):
        data_bytes = bytes(data)
    else:
        data_bytes = str(data).encode("utf-8", errors="replace")

    length = len(data_bytes)
    if length == 0:
        return 0.0

    counts = collections.Counter(data_bytes)
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)


class FlowInspectionContext:
    """Normalized representation of flow attributes for fast rule condition evaluation."""

    def __init__(
        self,
        method: str = "GET",
        url: str = "",
        path: str = "/",
        scheme: str = "http",
        http_version: str = "HTTP/1.1",
        status_code: Optional[int] = None,
        request_headers: Optional[Dict[str, str]] = None,
        response_headers: Optional[Dict[str, str]] = None,
        request_body: str = "",
        response_body: str = "",
        request_content_type: str = "",
        response_content_type: str = "",
        query_params: Optional[Dict[str, Any]] = None,
        query_string: str = "",
        request_cookies: Optional[Dict[str, str]] = None,
        response_cookies: Optional[Dict[str, str]] = None,
        duration_ms: float = 0.0,
        ttfb_ms: float = 0.0,
        content_length: int = 0,
        tags: Optional[List[str]] = None,
        parameters: Optional[List[Any]] = None,
    ):
        self.method = method.upper()
        self.url = url
        self.path = path
        self.scheme = scheme.lower()
        self.http_version = http_version
        self.status_code = status_code
        self.request_headers_raw = request_headers or {}
        self.response_headers_raw = response_headers or {}
        # Pre-normalize lowercase headers
        self.request_headers = {k.lower(): str(v) for k, v in self.request_headers_raw.items()}
        self.response_headers = {k.lower(): str(v) for k, v in self.response_headers_raw.items()}
        self.request_body = request_body or ""
        self.response_body = response_body or ""
        self.request_content_type = request_content_type or self.request_headers.get("content-type", "")
        self.response_content_type = response_content_type or self.response_headers.get("content-type", "")
        self.query_params = query_params or {}
        self.query_string = query_string
        self.request_cookies = request_cookies or {}
        self.response_cookies = response_cookies or {}
        self.duration_ms = duration_ms
        self.ttfb_ms = ttfb_ms
        self.content_length = content_length or len(self.response_body.encode("utf-8", errors="replace"))
        self.tags = tags or []
        self.parameters = parameters or []

    @classmethod
    def from_flow(cls, flow: Any, parameters: Optional[List[Any]] = None) -> FlowInspectionContext:
        """Construct normalized inspection context from FlowRecord, dict, or object."""
        if isinstance(flow, dict):
            return cls._from_dict(flow, parameters)

        req = getattr(flow, "request", None)
        resp = getattr(flow, "response", None)

        method = getattr(flow, "method", None) or (getattr(req, "method", None) if req else None) or "GET"
        url = getattr(flow, "url", None) or (getattr(req, "url", None) if req else None) or ""
        path = getattr(flow, "path", None) or (getattr(req, "path", None) if req else None) or "/"
        scheme = getattr(flow, "scheme", None) or (getattr(req, "scheme", None) if req else None) or "http"
        http_version = getattr(flow, "http_version", None) or (getattr(req, "http_version", None) if req else None) or "HTTP/1.1"

        status_code = getattr(flow, "response_status_code", None)
        if status_code is None and resp:
            status_code = getattr(resp, "status_code", None)
        if status_code is None:
            status_code = getattr(flow, "response_status", None)

        req_headers = getattr(flow, "request_headers", None)
        if req_headers is None and req:
            req_headers = getattr(req, "headers", {})
        resp_headers = getattr(flow, "response_headers", None)
        if resp_headers is None and resp:
            resp_headers = getattr(resp, "headers", {})

        req_body = getattr(flow, "request_body", None)
        if req_body is None and req:
            req_body = getattr(req, "body", "")
        resp_body = getattr(flow, "response_body", None)
        if resp_body is None and resp:
            resp_body = getattr(resp, "body", "")

        req_ct = getattr(flow, "request_content_type", None)
        if req_ct is None and req:
            req_ct = getattr(req, "content_type", "")
        resp_ct = getattr(flow, "response_content_type", None)
        if resp_ct is None and resp:
            resp_ct = getattr(resp, "content_type", "")

        q_params = getattr(flow, "query_params", None)
        if q_params is None and req:
            q_params = getattr(req, "query_params", {})
        if not q_params and url:
            try:
                parsed = urllib.parse.urlparse(url)
                parsed_qs = urllib.parse.parse_qs(parsed.query)
                q_params = {k: v[0] if len(v) == 1 else v for k, v in parsed_qs.items()}
            except Exception:
                q_params = {}

        q_string = getattr(flow, "query_string", None)
        if q_string is None and url:
            try:
                q_string = urllib.parse.urlparse(url).query
            except Exception:
                q_string = ""

        req_cookies = getattr(flow, "request_cookies", None)
        if req_cookies is None and req:
            req_cookies = getattr(req, "cookies", {})
        resp_cookies = getattr(flow, "response_cookies", None)
        if resp_cookies is None and resp:
            resp_cookies = getattr(resp, "cookies", {})

        duration_ms = float(getattr(flow, "duration_ms", 0.0) or 0.0)
        ttfb_ms = 0.0
        telemetry = getattr(flow, "telemetry", None)
        if telemetry:
            if isinstance(telemetry, dict):
                timings = telemetry.get("timings", {})
                ttfb_ms = float(timings.get("ttfb_ms", 0.0) or 0.0)
            else:
                timings = getattr(telemetry, "timings", None)
                if timings:
                    ttfb_ms = float(getattr(timings, "ttfb_ms", 0.0) or 0.0)

        content_length = int(getattr(flow, "response_content_length", 0) or 0)
        tags = getattr(flow, "tags", None) or []

        return cls(
            method=str(method),
            url=str(url),
            path=str(path),
            scheme=str(scheme),
            http_version=str(http_version),
            status_code=status_code,
            request_headers=req_headers if isinstance(req_headers, dict) else {},
            response_headers=resp_headers if isinstance(resp_headers, dict) else {},
            request_body=str(req_body or ""),
            response_body=str(resp_body or ""),
            request_content_type=str(req_ct or ""),
            response_content_type=str(resp_ct or ""),
            query_params=q_params if isinstance(q_params, dict) else {},
            query_string=str(q_string or ""),
            request_cookies=req_cookies if isinstance(req_cookies, dict) else {},
            response_cookies=resp_cookies if isinstance(resp_cookies, dict) else {},
            duration_ms=duration_ms,
            ttfb_ms=ttfb_ms,
            content_length=content_length,
            tags=list(tags),
            parameters=parameters or getattr(flow, "parameters", []) or [],
        )

    @classmethod
    def _from_dict(cls, data: Dict[str, Any], parameters: Optional[List[Any]] = None) -> FlowInspectionContext:
        req = data.get("request", {}) if isinstance(data.get("request"), dict) else {}
        resp = data.get("response", {}) if isinstance(data.get("response"), dict) else {}

        method = data.get("method") or req.get("method") or "GET"
        url = data.get("url") or req.get("url") or ""
        path = data.get("path") or req.get("path") or "/"
        scheme = data.get("scheme") or req.get("scheme") or "http"
        http_version = data.get("http_version") or req.get("http_version") or "HTTP/1.1"

        status_code = data.get("response_status_code") or data.get("response_status") or resp.get("status_code") or data.get("status_code") or data.get("status")

        req_headers = data.get("request_headers") or req.get("headers") or {}
        resp_headers = data.get("response_headers") or resp.get("headers") or {}

        req_body = data.get("request_body") or req.get("body") or ""
        resp_body = data.get("response_body") or resp.get("body") or ""

        req_ct = data.get("request_content_type") or req.get("content_type") or ""
        resp_ct = data.get("response_content_type") or resp.get("content_type") or ""

        q_params = data.get("query_params") or req.get("query_params") or {}
        if not q_params and url:
            try:
                parsed = urllib.parse.urlparse(url)
                parsed_qs = urllib.parse.parse_qs(parsed.query)
                q_params = {k: v[0] if len(v) == 1 else v for k, v in parsed_qs.items()}
            except Exception:
                q_params = {}

        q_string = data.get("query_string") or req.get("query_string") or ""
        if not q_string and url:
            try:
                q_string = urllib.parse.urlparse(url).query
            except Exception:
                q_string = ""

        req_cookies = data.get("request_cookies") or req.get("cookies") or {}
        resp_cookies = data.get("response_cookies") or resp.get("cookies") or {}

        duration_ms = float(data.get("duration_ms", 0.0) or 0.0)
        ttfb_ms = float(data.get("ttfb_ms", 0.0) or 0.0)
        content_length = int(data.get("response_content_length", 0) or data.get("content_length", 0) or 0)
        tags = data.get("tags") or []

        return cls(
            method=str(method),
            url=str(url),
            path=str(path),
            scheme=str(scheme),
            http_version=str(http_version),
            status_code=int(status_code) if status_code is not None else None,
            request_headers=req_headers if isinstance(req_headers, dict) else {},
            response_headers=resp_headers if isinstance(resp_headers, dict) else {},
            request_body=str(req_body or ""),
            response_body=str(resp_body or ""),
            request_content_type=str(req_ct or ""),
            response_content_type=str(resp_ct or ""),
            query_params=q_params if isinstance(q_params, dict) else {},
            query_string=str(q_string or ""),
            request_cookies=req_cookies if isinstance(req_cookies, dict) else {},
            response_cookies=resp_cookies if isinstance(resp_cookies, dict) else {},
            duration_ms=duration_ms,
            ttfb_ms=ttfb_ms,
            content_length=content_length,
            tags=list(tags),
            parameters=parameters or data.get("parameters", []),
        )


class ConditionEvaluator:
    """Evaluates individual RuleCondition against FlowInspectionContext."""

    def __init__(self, max_regex_length: int = 1_000_000):
        self.max_regex_length = max_regex_length
        self._regex_cache: Dict[Tuple[str, bool], Optional[re.Pattern]] = {}
        self._cache_lock = threading.Lock()

    def get_compiled_regex(self, pattern_str: str, case_sensitive: bool = False) -> Optional[re.Pattern]:
        """Get or compile cached regular expression with safety bounds."""
        key = (pattern_str, case_sensitive)
        with self._cache_lock:
            if key in self._regex_cache:
                return self._regex_cache[key]

        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            compiled = re.compile(pattern_str, flags)
            with self._cache_lock:
                self._regex_cache[key] = compiled
            return compiled
        except re.error as err:
            logger.warning("Invalid regex pattern '%s': %s", pattern_str, err)
            with self._cache_lock:
                self._regex_cache[key] = None
            return None

    def evaluate(self, condition: RuleCondition, ctx: FlowInspectionContext) -> Tuple[bool, Dict[str, Any]]:
        """
        Evaluate condition against context. Returns (is_matched, match_details).
        """
        field_raw = condition.field.lower().strip()
        target = condition.target

        # Handle dot-notation in field (e.g. "request_header.x-admin" -> field="request_header", target="x-admin")
        if "." in field_raw and not target:
            parts = field_raw.split(".", 1)
            field_raw = parts[0].strip()
            target = parts[1].strip()

        op = condition.normalized_operator()
        case_sensitive = condition.case_sensitive
        expected = condition.value

        actual_val, exists = self._extract_field_value(field_raw, target, ctx)

        matched = self._apply_operator(
            op=op,
            actual=actual_val,
            expected=expected,
            exists=exists,
            case_sensitive=case_sensitive,
        )

        if condition.invert:
            matched = not matched

        details = {
            "field": condition.field,
            "target": target,
            "operator": op.value,
            "expected": expected,
            "actual": str(actual_val)[:200] if actual_val is not None else None,
            "matched": matched,
        }
        return matched, details

    def _extract_field_value(
        self, field: str, target: Optional[str], ctx: FlowInspectionContext
    ) -> Tuple[Any, bool]:
        """Extract value and existence flag for target field."""
        if field in ("method",):
            return ctx.method, bool(ctx.method)

        elif field in ("url",):
            return ctx.url, bool(ctx.url)

        elif field in ("path",):
            return ctx.path, bool(ctx.path)

        elif field in ("scheme",):
            return ctx.scheme, bool(ctx.scheme)

        elif field in ("http_version",):
            return ctx.http_version, bool(ctx.http_version)

        elif field in ("status", "status_code", "response_status", "response_status_code"):
            return ctx.status_code, ctx.status_code is not None

        elif field in ("header", "request_header"):
            if target:
                t_lower = target.lower()
                val = ctx.request_headers.get(t_lower)
                return val, (t_lower in ctx.request_headers)
            # Full header string or dict
            headers_str = "\n".join(f"{k}: {v}" for k, v in ctx.request_headers_raw.items())
            return headers_str, bool(ctx.request_headers)

        elif field in ("response_header",):
            if target:
                t_lower = target.lower()
                val = ctx.response_headers.get(t_lower)
                return val, (t_lower in ctx.response_headers)
            headers_str = "\n".join(f"{k}: {v}" for k, v in ctx.response_headers_raw.items())
            return headers_str, bool(ctx.response_headers)

        elif field in ("body", "response_body"):
            return ctx.response_body, bool(ctx.response_body)

        elif field in ("request_body",):
            return ctx.request_body, bool(ctx.request_body)

        elif field in ("query", "query_param", "param"):
            if target:
                t_lower = target.lower()
                # Check case-insensitive query params dict
                for k, v in ctx.query_params.items():
                    if k.lower() == t_lower:
                        return v, True
                return None, False
            return ctx.query_string or str(ctx.query_params), bool(ctx.query_params or ctx.query_string)

        elif field in ("query_string",):
            return ctx.query_string, bool(ctx.query_string)

        elif field in ("cookie", "request_cookie"):
            if target:
                t_lower = target.lower()
                for k, v in ctx.request_cookies.items():
                    if k.lower() == t_lower:
                        return v, True
                return None, False
            return str(ctx.request_cookies), bool(ctx.request_cookies)

        elif field in ("response_cookie",):
            if target:
                t_lower = target.lower()
                for k, v in ctx.response_cookies.items():
                    if k.lower() == t_lower:
                        return v, True
                return None, False
            return str(ctx.response_cookies), bool(ctx.response_cookies)

        elif field in ("content_type", "response_content_type"):
            return ctx.response_content_type, bool(ctx.response_content_type)

        elif field in ("request_content_type",):
            return ctx.request_content_type, bool(ctx.request_content_type)

        elif field in ("duration_ms", "duration", "latency_ms"):
            return ctx.duration_ms, True

        elif field in ("ttfb_ms", "ttfb"):
            return ctx.ttfb_ms, True

        elif field in ("content_length", "response_content_length"):
            return ctx.content_length, True

        elif field in ("entropy",):
            # Evaluate entropy on specified target or response body
            data_to_measure = ctx.response_body
            if target:
                t_lower = target.lower()
                if t_lower == "request_body":
                    data_to_measure = ctx.request_body
                elif t_lower in ctx.response_headers:
                    data_to_measure = ctx.response_headers[t_lower]
                elif t_lower in ctx.request_headers:
                    data_to_measure = ctx.request_headers[t_lower]
                elif t_lower in ctx.query_params:
                    data_to_measure = str(ctx.query_params[t_lower])
            ent = calculate_shannon_entropy(data_to_measure)
            return ent, True

        elif field in ("tags", "tag"):
            return ctx.tags, bool(ctx.tags)

        # Fallback inspection on parameters
        if target:
            for p in ctx.parameters:
                p_name = getattr(p, "name", "") if not isinstance(p, dict) else p.get("name", "")
                if p_name.lower() == target.lower():
                    p_val = getattr(p, "value", None) if not isinstance(p, dict) else p.get("value")
                    return p_val, True

        return None, False

    def _apply_operator(
        self,
        op: RuleOperator,
        actual: Any,
        expected: Any,
        exists: bool,
        case_sensitive: bool,
    ) -> bool:
        """Execute atomic comparison logic."""
        if op == RuleOperator.EXISTS:
            return exists and actual is not None and actual != ""

        if op == RuleOperator.NOT_EXISTS:
            return not exists or actual is None or actual == ""

        if not exists or actual is None:
            return False

        # Numeric comparisons
        if op in (RuleOperator.GT, RuleOperator.GTE, RuleOperator.LT, RuleOperator.LTE, RuleOperator.ENTROPY_GT, RuleOperator.ENTROPY_LT):
            try:
                num_actual = float(actual)
                num_expected = float(expected)
            except (ValueError, TypeError):
                return False

            if op == RuleOperator.GT or op == RuleOperator.ENTROPY_GT:
                return num_actual > num_expected
            elif op == RuleOperator.GTE:
                return num_actual >= num_expected
            elif op == RuleOperator.LT or op == RuleOperator.ENTROPY_LT:
                return num_actual < num_expected
            elif op == RuleOperator.LTE:
                return num_actual <= num_expected

        # List membership
        if op == RuleOperator.IN_LIST:
            if isinstance(expected, list):
                if case_sensitive:
                    return actual in expected or str(actual) in [str(x) for x in expected]
                else:
                    act_str = str(actual).lower()
                    return act_str in [str(x).lower() for x in expected]
            return False

        if op == RuleOperator.NOT_IN_LIST:
            if isinstance(expected, list):
                if case_sensitive:
                    return actual not in expected and str(actual) not in [str(x) for x in expected]
                else:
                    act_str = str(actual).lower()
                    return act_str not in [str(x).lower() for x in expected]
            return True

        # String / Regex comparisons
        str_actual = str(actual)
        str_expected = str(expected) if expected is not None else ""

        # Safe length bound for regex
        if len(str_actual) > self.max_regex_length:
            str_actual_bounded = str_actual[: self.max_regex_length]
        else:
            str_actual_bounded = str_actual

        if op == RuleOperator.EQUALS:
            # Handle numeric equality if both look like numbers
            try:
                if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
                    return float(actual) == float(expected)
            except Exception:
                pass
            if case_sensitive:
                return str_actual == str_expected
            return str_actual.lower() == str_expected.lower()

        elif op == RuleOperator.NOT_EQUALS:
            try:
                if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
                    return float(actual) != float(expected)
            except Exception:
                pass
            if case_sensitive:
                return str_actual != str_expected
            return str_actual.lower() != str_expected.lower()

        elif op == RuleOperator.CONTAINS:
            if case_sensitive:
                return str_expected in str_actual
            return str_expected.lower() in str_actual.lower()

        elif op == RuleOperator.NOT_CONTAINS:
            if case_sensitive:
                return str_expected not in str_actual
            return str_expected.lower() not in str_actual.lower()

        elif op == RuleOperator.STARTS_WITH:
            if case_sensitive:
                return str_actual.startswith(str_expected)
            return str_actual.lower().startswith(str_expected.lower())

        elif op == RuleOperator.ENDS_WITH:
            if case_sensitive:
                return str_actual.endswith(str_expected)
            return str_actual.lower().endswith(str_expected.lower())

        elif op == RuleOperator.REGEX:
            compiled = self.get_compiled_regex(str_expected, case_sensitive=case_sensitive)
            if not compiled:
                return False
            if len(str_actual) > self.max_regex_length and (str_expected.endswith("$") or str_expected.endswith(r"\Z")):
                return False
            return bool(compiled.search(str_actual_bounded))

        elif op == RuleOperator.NOT_REGEX:
            compiled = self.get_compiled_regex(str_expected, case_sensitive=case_sensitive)
            if not compiled:
                return True
            if len(str_actual) > self.max_regex_length and (str_expected.endswith("$") or str_expected.endswith(r"\Z")):
                return True
            return not bool(compiled.search(str_actual_bounded))

        return False


class RuleEngine:
    """
    Central heuristic rule execution engine and registry.
    Evaluates YAML/JSON rules in real time across incoming flows.
    """

    def __init__(self, load_defaults: bool = True):
        self._rules: Dict[str, MatchRule] = {}
        self._lock = threading.RLock()
        self.evaluator = ConditionEvaluator()
        if load_defaults:
            self.load_builtin_rules()

    # -------------------------------------------------------------------------
    # Rule Registry Management
    # -------------------------------------------------------------------------

    def register_rule(self, rule: MatchRule) -> MatchRule:
        """Register or update a rule in the active registry."""
        with self._lock:
            rule.updated_at = time.time()
            self._rules[rule.id] = rule
            logger.info("Registered heuristic rule: %s (%s)", rule.name, rule.id)
            return rule

    def unregister_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID."""
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                logger.info("Unregistered heuristic rule: %s", rule_id)
                return True
            return False

    def get_rule(self, rule_id: str) -> Optional[MatchRule]:
        """Retrieve a registered rule by ID."""
        with self._lock:
            return self._rules.get(rule_id)

    def list_rules(
        self,
        enabled_only: bool = False,
        category: Optional[str] = None,
        severity: Optional[RuleSeverity] = None,
        search: Optional[str] = None,
    ) -> List[MatchRule]:
        """List registered rules with optional filtering."""
        with self._lock:
            rules = list(self._rules.values())

        filtered: List[MatchRule] = []
        for r in rules:
            if enabled_only and not r.enabled:
                continue
            if category and r.category.upper() != category.upper():
                continue
            if severity and r.severity != severity:
                continue
            if search:
                query = search.lower()
                in_name = query in r.name.lower()
                in_desc = query in r.description.lower()
                in_id = query in r.id.lower()
                in_tags = any(query in t.lower() for t in r.all_tags())
                if not (in_name or in_desc or in_id or in_tags):
                    continue
            filtered.append(r)

        # Sort by updated_at descending
        filtered.sort(key=lambda r: r.updated_at, reverse=True)
        return filtered

    def update_rule(self, rule_id: str, updated: MatchRule) -> Optional[MatchRule]:
        """Update existing rule."""
        with self._lock:
            if rule_id not in self._rules:
                return None
            updated.id = rule_id
            updated.updated_at = time.time()
            self._rules[rule_id] = updated
            return updated

    def toggle_rule(self, rule_id: str, enabled: Optional[bool] = None) -> Optional[MatchRule]:
        """Toggle or explicitly set enabled status for a rule."""
        with self._lock:
            rule = self._rules.get(rule_id)
            if not rule:
                return None
            if enabled is None:
                rule.enabled = not rule.enabled
            else:
                rule.enabled = enabled
            rule.updated_at = time.time()
            return rule

    def clear_rules(self) -> None:
        """Clear all registered rules."""
        with self._lock:
            self._rules.clear()

    def reset_to_defaults(self) -> None:
        """Clear all rules and reload built-in defaults."""
        with self._lock:
            self.clear_rules()
            self.load_builtin_rules()

    # -------------------------------------------------------------------------
    # Parsing & Serialization (YAML & JSON)
    # -------------------------------------------------------------------------

    @staticmethod
    def parse_rule_from_dict(data: Dict[str, Any]) -> MatchRule:
        """Parse MatchRule from a raw dictionary with flexible condition structures."""
        # Normalize fields
        rule_id = str(data.get("id") or f"rule-{int(time.time()*1000)%1000000:06d}")
        name = str(data.get("name") or "Unnamed Rule")
        description = str(data.get("description") or "")

        severity_raw = str(data.get("severity", "MEDIUM")).upper()
        severity = RuleSeverity.MEDIUM
        for s in RuleSeverity:
            if s.value == severity_raw:
                severity = s
                break

        category = str(data.get("category") or "CUSTOM")
        tags_raw = data.get("tags") or []
        if isinstance(tags_raw, str):
            tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        else:
            tags = [str(t) for t in tags_raw]
        tag = data.get("tag")
        if tag and tag not in tags:
            tags.append(str(tag))

        enabled = bool(data.get("enabled", True))
        combinator = str(data.get("condition_combinator") or "all").lower()

        # Parse conditions
        conditions: List[RuleCondition] = []
        nested_conditions: Optional[Dict[str, List[RuleCondition]]] = None

        cond_raw = data.get("conditions")
        if isinstance(cond_raw, list):
            for c in cond_raw:
                if isinstance(c, dict):
                    conditions.append(RuleCondition(**c))
                elif isinstance(c, RuleCondition):
                    conditions.append(c)
        elif isinstance(cond_raw, dict):
            # Nested conditions: e.g. {"any": [...], "all": [...], "not": [...]}
            nested_conditions = {}
            for block_key, block_items in cond_raw.items():
                if isinstance(block_items, list):
                    parsed_block: List[RuleCondition] = []
                    for c in block_items:
                        if isinstance(c, dict):
                            parsed_block.append(RuleCondition(**c))
                        elif isinstance(c, RuleCondition):
                            parsed_block.append(c)
                    nested_conditions[block_key.lower()] = parsed_block
                    # Also flatten for default listing
                    conditions.extend(parsed_block)

        # Check for top-level any/all/not blocks if conditions was missing
        if not conditions and not nested_conditions:
            for comb_key in ("all", "any", "not"):
                if comb_key in data and isinstance(data[comb_key], list):
                    if nested_conditions is None:
                        nested_conditions = {}
                    parsed_block = []
                    for c in data[comb_key]:
                        if isinstance(c, dict):
                            parsed_block.append(RuleCondition(**c))
                    nested_conditions[comb_key] = parsed_block
                    conditions.extend(parsed_block)

        return MatchRule(
            id=rule_id,
            name=name,
            description=description,
            severity=severity,
            category=category,
            tags=sorted(list(set(tags))),
            tag=str(tag) if tag else None,
            enabled=enabled,
            condition_combinator=combinator,
            conditions=conditions,
            nested_conditions=nested_conditions,
            created_at=float(data.get("created_at") or time.time()),
            updated_at=float(data.get("updated_at") or time.time()),
            raw_yaml=data.get("raw_yaml"),
        )

    @classmethod
    def parse_rule_from_yaml(cls, yaml_str: str) -> MatchRule:
        """Parse a single MatchRule from a YAML string."""
        data = yaml.safe_load(yaml_str)
        if not isinstance(data, dict):
            raise ValueError(f"Expected YAML dictionary, got {type(data).__name__}")
        rule = cls.parse_rule_from_dict(data)
        rule.raw_yaml = yaml_str
        return rule

    @classmethod
    def parse_rules_from_yaml(cls, yaml_str: str) -> List[MatchRule]:
        """Parse one or multiple MatchRules from YAML (handles docs or lists)."""
        rules: List[MatchRule] = []
        try:
            docs = list(yaml.safe_load_all(yaml_str))
        except Exception as exc:
            raise ValueError(f"YAML parsing failed: {exc}") from exc

        for doc in docs:
            if not doc:
                continue
            if isinstance(doc, list):
                for item in doc:
                    if isinstance(item, dict):
                        rules.append(cls.parse_rule_from_dict(item))
            elif isinstance(doc, dict):
                # Check if it has a 'rules' list wrapper
                if "rules" in doc and isinstance(doc["rules"], list):
                    for item in doc["rules"]:
                        if isinstance(item, dict):
                            rules.append(cls.parse_rule_from_dict(item))
                else:
                    rules.append(cls.parse_rule_from_dict(doc))
        return rules

    @classmethod
    def parse_rule_from_json(cls, json_str: str) -> MatchRule:
        """Parse a single MatchRule from a JSON string."""
        data = json.loads(json_str)
        if not isinstance(data, dict):
            raise ValueError(f"Expected JSON dictionary, got {type(data).__name__}")
        return cls.parse_rule_from_dict(data)

    @classmethod
    def parse_rules_from_json(cls, json_str: str) -> List[MatchRule]:
        """Parse one or multiple MatchRules from a JSON string."""
        data = json.loads(json_str)
        rules: List[MatchRule] = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    rules.append(cls.parse_rule_from_dict(item))
        elif isinstance(data, dict):
            if "rules" in data and isinstance(data["rules"], list):
                for item in data["rules"]:
                    if isinstance(item, dict):
                        rules.append(cls.parse_rule_from_dict(item))
            else:
                rules.append(cls.parse_rule_from_dict(data))
        return rules

    @staticmethod
    def export_rule_to_dict(rule: MatchRule) -> Dict[str, Any]:
        """Export MatchRule to clean dictionary for YAML/JSON serialization."""
        d: Dict[str, Any] = {
            "id": rule.id,
            "name": rule.name,
            "description": rule.description,
            "severity": rule.severity.value,
            "category": rule.category,
            "tags": rule.all_tags(),
            "enabled": rule.enabled,
        }
        if rule.nested_conditions:
            nested_dict: Dict[str, Any] = {}
            for block_k, block_conds in rule.nested_conditions.items():
                nested_dict[block_k] = [
                    {
                        "field": c.field,
                        "operator": c.normalized_operator().value,
                        "value": c.value,
                        **({"target": c.target} if c.target else {}),
                        **({"case_sensitive": True} if c.case_sensitive else {}),
                        **({"invert": True} if c.invert else {}),
                    }
                    for c in block_conds
                ]
            d["conditions"] = nested_dict
        else:
            d["condition_combinator"] = rule.condition_combinator
            d["conditions"] = [
                {
                    "field": c.field,
                    "operator": c.normalized_operator().value,
                    "value": c.value,
                    **({"target": c.target} if c.target else {}),
                    **({"case_sensitive": True} if c.case_sensitive else {}),
                    **({"invert": True} if c.invert else {}),
                }
                for c in rule.conditions
            ]
        return d

    @classmethod
    def export_rule_to_yaml(cls, rule: MatchRule) -> str:
        """Serialize a single rule to YAML string."""
        return yaml.dump(cls.export_rule_to_dict(rule), sort_keys=False)

    @classmethod
    def export_rules_to_yaml(cls, rules: List[MatchRule]) -> str:
        """Serialize a list of rules to multi-document YAML."""
        dicts = [cls.export_rule_to_dict(r) for r in rules]
        return yaml.dump(dicts, sort_keys=False)

    @classmethod
    def export_rule_to_json(cls, rule: MatchRule, indent: int = 2) -> str:
        """Serialize a single rule to JSON string."""
        return json.dumps(cls.export_rule_to_dict(rule), indent=indent)

    @classmethod
    def export_rules_to_json(cls, rules: List[MatchRule], indent: int = 2) -> str:
        """Serialize a list of rules to JSON string."""
        dicts = [cls.export_rule_to_dict(r) for r in rules]
        return json.dumps({"rules": dicts, "total": len(dicts)}, indent=indent)

    def import_from_yaml(self, yaml_str: str, overwrite: bool = False) -> Tuple[int, int, List[str], List[MatchRule]]:
        """Import rules from YAML. Returns (imported_count, updated_count, errors, imported_rules)."""
        errors: List[str] = []
        imported = 0
        updated = 0
        imported_rules: List[MatchRule] = []

        try:
            parsed = self.parse_rules_from_yaml(yaml_str)
        except Exception as exc:
            return 0, 0, [f"YAML syntax error: {exc}"], []

        for rule in parsed:
            try:
                with self._lock:
                    if rule.id in self._rules:
                        if overwrite:
                            self.update_rule(rule.id, rule)
                            updated += 1
                            imported_rules.append(rule)
                        else:
                            # Generate unique ID
                            rule.id = f"{rule.id}-{int(time.time()*1000)%10000}"
                            self.register_rule(rule)
                            imported += 1
                            imported_rules.append(rule)
                    else:
                        self.register_rule(rule)
                        imported += 1
                        imported_rules.append(rule)
            except Exception as e:
                errors.append(f"Failed to register rule {rule.name}: {e}")

        return imported, updated, errors, imported_rules

    def import_from_json(self, json_str: str, overwrite: bool = False) -> Tuple[int, int, List[str], List[MatchRule]]:
        """Import rules from JSON. Returns (imported_count, updated_count, errors, imported_rules)."""
        errors: List[str] = []
        imported = 0
        updated = 0
        imported_rules: List[MatchRule] = []

        try:
            parsed = self.parse_rules_from_json(json_str)
        except Exception as exc:
            return 0, 0, [f"JSON syntax error: {exc}"], []

        for rule in parsed:
            try:
                with self._lock:
                    if rule.id in self._rules:
                        if overwrite:
                            self.update_rule(rule.id, rule)
                            updated += 1
                            imported_rules.append(rule)
                        else:
                            rule.id = f"{rule.id}-{int(time.time()*1000)%10000}"
                            self.register_rule(rule)
                            imported += 1
                            imported_rules.append(rule)
                    else:
                        self.register_rule(rule)
                        imported += 1
                        imported_rules.append(rule)
            except Exception as e:
                errors.append(f"Failed to register rule {rule.name}: {e}")

        return imported, updated, errors, imported_rules

    # -------------------------------------------------------------------------
    # Flow Evaluation
    # -------------------------------------------------------------------------

    def evaluate_rule(
        self,
        rule: MatchRule,
        flow: Any,
        parameters: Optional[List[Any]] = None,
    ) -> RuleEvaluationResult:
        """
        Evaluate a single MatchRule against an intercepted flow context.
        """
        start_t = time.perf_counter()
        ctx = flow if isinstance(flow, FlowInspectionContext) else FlowInspectionContext.from_flow(flow, parameters)

        if not rule.enabled:
            return RuleEvaluationResult(
                rule_id=rule.id,
                rule_name=rule.name,
                matched=False,
                severity=rule.severity,
                tags=rule.all_tags(),
                category=rule.category,
                details={"reason": "rule_disabled"},
                execution_time_ms=round((time.perf_counter() - start_t) * 1000, 3),
            )

        matched_conditions: List[Dict[str, Any]] = []
        all_eval_details: List[Dict[str, Any]] = []

        is_overall_match = False

        if rule.nested_conditions:
            # Evaluate block by block
            block_results: Dict[str, bool] = {}
            for block_name, conds in rule.nested_conditions.items():
                if not conds:
                    continue
                cond_results: List[bool] = []
                for c in conds:
                    m, det = self.evaluator.evaluate(c, ctx)
                    all_eval_details.append(det)
                    cond_results.append(m)
                    if m:
                        matched_conditions.append(det)

                if block_name in ("any", "or"):
                    block_results[block_name] = any(cond_results)
                elif block_name in ("not", "nor"):
                    block_results[block_name] = not any(cond_results)
                else:  # "all", "and"
                    block_results[block_name] = all(cond_results) if cond_results else True

            # Combine all blocks with logical AND
            is_overall_match = all(block_results.values()) if block_results else False

        else:
            # Evaluate flat conditions list using condition_combinator
            if not rule.conditions:
                is_overall_match = True
            else:
                cond_results = []
                for c in rule.conditions:
                    m, det = self.evaluator.evaluate(c, ctx)
                    all_eval_details.append(det)
                    cond_results.append(m)
                    if m:
                        matched_conditions.append(det)

                comb = rule.condition_combinator.lower()
                if comb in ("any", "or"):
                    is_overall_match = any(cond_results)
                elif comb in ("not", "nor"):
                    is_overall_match = not any(cond_results)
                else:  # "all", "and"
                    is_overall_match = all(cond_results)

        duration_ms = round((time.perf_counter() - start_t) * 1000, 3)

        return RuleEvaluationResult(
            rule_id=rule.id,
            rule_name=rule.name,
            matched=is_overall_match,
            severity=rule.severity,
            tags=rule.all_tags() if is_overall_match else [],
            category=rule.category,
            matched_conditions=matched_conditions if is_overall_match else [],
            details={
                "evaluated_conditions_count": len(all_eval_details),
                "matched_conditions_count": len(matched_conditions),
                "evaluations": all_eval_details,
            },
            execution_time_ms=duration_ms,
        )

    def evaluate_flow(
        self,
        flow: Any,
        parameters: Optional[List[Any]] = None,
    ) -> List[RuleEvaluationResult]:
        """
        Evaluate all active rules in the registry against an intercepted flow.
        Returns list of positive evaluation matches.
        """
        ctx = flow if isinstance(flow, FlowInspectionContext) else FlowInspectionContext.from_flow(flow, parameters)
        matches: List[RuleEvaluationResult] = []

        with self._lock:
            active_rules = [r for r in self._rules.values() if r.enabled]

        for rule in active_rules:
            try:
                res = self.evaluate_rule(rule, ctx)
                if res.matched:
                    matches.append(res)
            except Exception as exc:
                logger.error("Error evaluating rule %s (%s): %s", rule.name, rule.id, exc)

        return matches

    # -------------------------------------------------------------------------
    # Built-in Default Rules
    # -------------------------------------------------------------------------

    def load_builtin_rules(self) -> None:
        """Load comprehensive set of production-grade default security heuristic rules."""
        builtin_rules = [
            MatchRule(
                id="rule-debug-mode-leak",
                name="Debug Mode / Stack Trace Leak",
                description="Matches responses containing verbose framework tracebacks, debug output, or exception dumps",
                severity=RuleSeverity.HIGH,
                category="LEAK",
                tags=["debug_leak", "stack_trace"],
                condition_combinator="any",
                conditions=[
                    RuleCondition(
                        field="response_body",
                        operator=RuleOperator.REGEX,
                        value=r"(?i)(Traceback \(most recent call last\)|Django Version:|Exception Value:|DEBUG = True|Fatal error: Uncaught|Whoops! There was an error|Laravel\\Framework|org\.springframework\.|java\.lang\.NullPointerException)",
                    ),
                    RuleCondition(
                        field="response_header",
                        target="x-debug-token",
                        operator=RuleOperator.EXISTS,
                    ),
                    RuleCondition(
                        field="query_param",
                        target="debug",
                        operator=RuleOperator.EQUALS,
                        value="true",
                    ),
                ],
            ),
            MatchRule(
                id="rule-graphql-introspection",
                name="GraphQL Introspection Enabled",
                description="Detects active GraphQL schema introspection responses leaking internal types",
                severity=RuleSeverity.MEDIUM,
                category="INFO_DISCLOSURE",
                tags=["graphql", "introspection"],
                condition_combinator="all",
                conditions=[
                    RuleCondition(
                        field="response_body",
                        operator=RuleOperator.CONTAINS,
                        value="__schema",
                    ),
                    RuleCondition(
                        field="response_body",
                        operator=RuleOperator.CONTAINS,
                        value="__type",
                    ),
                    RuleCondition(
                        field="status_code",
                        operator=RuleOperator.EQUALS,
                        value=200,
                    ),
                ],
            ),
            MatchRule(
                id="rule-admin-unauthenticated",
                name="Admin Endpoint Missing Authentication",
                description="Flags successful 200 responses to /admin or /api/admin paths without standard authorization headers",
                severity=RuleSeverity.HIGH,
                category="AUTH_BYPASS",
                tags=["admin", "auth_anomaly"],
                condition_combinator="all",
                conditions=[
                    RuleCondition(
                        field="path",
                        operator=RuleOperator.REGEX,
                        value=r"(?i)^/(api/)?(admin|dashboard|management|internal)/",
                    ),
                    RuleCondition(
                        field="status_code",
                        operator=RuleOperator.EQUALS,
                        value=200,
                    ),
                    RuleCondition(
                        field="request_header",
                        target="authorization",
                        operator=RuleOperator.NOT_EXISTS,
                    ),
                ],
            ),
            MatchRule(
                id="rule-internal-ip-leak",
                name="Internal RFC1918 IP Address Disclosure",
                description="Detects private internal IP addresses leaked in response bodies or headers",
                severity=RuleSeverity.MEDIUM,
                category="LEAK",
                tags=["internal_ip_leak"],
                condition_combinator="any",
                conditions=[
                    RuleCondition(
                        field="response_body",
                        operator=RuleOperator.REGEX,
                        value=r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
                    ),
                    RuleCondition(
                        field="response_header",
                        target="x-forwarded-server",
                        operator=RuleOperator.REGEX,
                        value=r"\b(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01]))",
                    ),
                ],
            ),
            MatchRule(
                id="rule-cors-wildcard-creds",
                name="CORS Wildcard with Credentials Misconfiguration",
                description="Detects dangerous CORS configurations reflecting wildcard origins with credentials allowed",
                severity=RuleSeverity.HIGH,
                category="CORS",
                tags=["cors_misconfig"],
                condition_combinator="all",
                conditions=[
                    RuleCondition(
                        field="response_header",
                        target="access-control-allow-origin",
                        operator=RuleOperator.EQUALS,
                        value="*",
                    ),
                    RuleCondition(
                        field="response_header",
                        target="access-control-allow-credentials",
                        operator=RuleOperator.EQUALS,
                        value="true",
                    ),
                ],
            ),
            MatchRule(
                id="rule-sensitive-config-path",
                name="Sensitive File / Environment Path Access",
                description="Detects requests targeting sensitive configuration or credential files",
                severity=RuleSeverity.HIGH,
                category="INFO_DISCLOSURE",
                tags=["sensitive_path", "config_leak"],
                condition_combinator="all",
                conditions=[
                    RuleCondition(
                        field="path",
                        operator=RuleOperator.REGEX,
                        value=r"(?i)(\.env|\.git/config|actuator/(env|heapdump)|wp-config\.php|server-status|elmah\.axd)$",
                    ),
                    RuleCondition(
                        field="status_code",
                        operator=RuleOperator.IN_LIST,
                        value=[200, 206],
                    ),
                ],
            ),
            MatchRule(
                id="rule-high-entropy-response-token",
                name="High-Entropy Response Secret Indicator",
                description="Triggers on text responses exhibiting elevated Shannon entropy (> 5.8) indicative of cryptographic keys or token dumps",
                severity=RuleSeverity.MEDIUM,
                category="SECRETS",
                tags=["high_entropy_response"],
                condition_combinator="all",
                conditions=[
                    RuleCondition(
                        field="entropy",
                        operator=RuleOperator.GT,
                        value=5.8,
                    ),
                    RuleCondition(
                        field="response_content_type",
                        operator=RuleOperator.REGEX,
                        value=r"(?i)(text/|application/json|application/xml)",
                    ),
                    RuleCondition(
                        field="status_code",
                        operator=RuleOperator.EQUALS,
                        value=200,
                    ),
                ],
            ),
        ]

        with self._lock:
            for rule in builtin_rules:
                if rule.id not in self._rules:
                    self._rules[rule.id] = rule


# Global singleton instance for easy import and access
default_rule_engine = RuleEngine()


def get_rule_engine() -> RuleEngine:
    """Return default global RuleEngine instance."""
    return default_rule_engine
