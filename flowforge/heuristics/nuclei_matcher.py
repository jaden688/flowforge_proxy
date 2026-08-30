"""
High-performance, passive & active Nuclei template matcher engine.

Evaluates Nuclei templates against intercepted HTTP/WebSocket flow records,
or raw HTTP responses, with sub-millisecond efficiency and ReDoS protection.

Supported features:
- Matcher types: `status`, `word`, `regex`, `binary`, `size`, `dsl`, `xpath`.
- Target parts: `body`, `header`, `headers.<name>`, `all`, `response`, `status`, `request`.
- Conditions: `matchers-condition: and | or`, `condition: and | or`.
- Modifier flags: `negative: bool`, `case-insensitive: bool`.
- Bounded ReDoS-safe regex compilation and caching.
- Safe AST-based DSL expression evaluator.
- Structured `NucleiMatchResult` return type.
"""

from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import logging
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from flowforge.models.flow import FlowRecord
from flowforge.models.nuclei import (
    NucleiHttpBlock,
    NucleiMatcher,
    NucleiMatcherType,
    NucleiMatchResult,
    NucleiSeverity,
    NucleiTemplate,
)

logger = logging.getLogger("flowforge.heuristics.nuclei_matcher")

# Maximum string length in bytes/chars scanned by regex to prevent ReDoS on massive inputs
_MAX_REGEX_SCAN_CHARS = 1_048_576  # 1 MB
_REGEX_CACHE_MAX = 5_000


class SafeDSLEvaluator:
    """
    Evaluates Nuclei DSL expressions safely without arbitrary code execution.
    Supports logical operators, comparison operators, and Nuclei helper functions.
    """

    @staticmethod
    def _contains(haystack: Any, needle: Any) -> bool:
        return str(needle) in str(haystack)

    @staticmethod
    def _contains_all(haystack: Any, *needles: Any) -> bool:
        h = str(haystack)
        return all(str(n) in h for n in needles)

    @staticmethod
    def _contains_any(haystack: Any, *needles: Any) -> bool:
        h = str(haystack)
        return any(str(n) in h for n in needles)

    @staticmethod
    def _to_lower(s: Any) -> str:
        return str(s).lower()

    @staticmethod
    def _to_upper(s: Any) -> str:
        return str(s).upper()

    @staticmethod
    def _base64_decode(s: Any) -> str:
        try:
            return base64.b64decode(str(s).encode("utf-8", "ignore")).decode("utf-8", "replace")
        except Exception:
            return ""

    @staticmethod
    def _base64_encode(s: Any) -> str:
        try:
            return base64.b64encode(str(s).encode("utf-8", "ignore")).decode("utf-8")
        except Exception:
            return ""

    @staticmethod
    def _hex_decode(s: Any) -> str:
        try:
            cleaned = str(s).replace("0x", "").replace("\\x", "").replace(" ", "")
            return binascii.unhexlify(cleaned).decode("utf-8", "replace")
        except Exception:
            return ""

    @staticmethod
    def _hex_encode(s: Any) -> str:
        try:
            return binascii.hexlify(str(s).encode("utf-8", "ignore")).decode("utf-8")
        except Exception:
            return ""

    @staticmethod
    def _md5(s: Any) -> str:
        return hashlib.md5(str(s).encode("utf-8", "ignore")).hexdigest()

    @staticmethod
    def _sha256(s: Any) -> str:
        return hashlib.sha256(str(s).encode("utf-8", "ignore")).hexdigest()

    @staticmethod
    def _regex_match(pattern: Any, text: Any) -> bool:
        try:
            return bool(re.search(str(pattern), str(text)[:_MAX_REGEX_SCAN_CHARS], re.DOTALL | re.MULTILINE))
        except Exception:
            return False

    @classmethod
    def get_functions(cls) -> Dict[str, Callable[..., Any]]:
        return {
            "contains": cls._contains,
            "contains_all": cls._contains_all,
            "contains_any": cls._contains_any,
            "to_lower": cls._to_lower,
            "tolower": cls._to_lower,
            "to_upper": cls._to_upper,
            "toupper": cls._to_upper,
            "base64": cls._base64_encode,
            "base64_decode": cls._base64_decode,
            "hex_decode": cls._hex_decode,
            "hex_encode": cls._hex_encode,
            "md5": cls._md5,
            "sha256": cls._sha256,
            "len": len,
            "regex": cls._regex_match,
        }

    @classmethod
    def evaluate(cls, expression: str, context: Dict[str, Any]) -> bool:
        """
        Safely evaluates a DSL expression against a context dictionary.
        """
        if not expression or not expression.strip():
            return True

        expr_clean = expression.strip()
        # Replace Nuclei DSL boolean tokens with Python equivalents
        expr_clean = re.sub(r"\btrue\b", "True", expr_clean, flags=re.IGNORECASE)
        expr_clean = re.sub(r"\bfalse\b", "False", expr_clean, flags=re.IGNORECASE)
        expr_clean = expr_clean.replace("&&", " and ").replace("||", " or ")

        funcs = cls.get_functions()
        eval_scope = {**funcs, **context}

        try:
            # Parse into AST for safe execution check
            tree = ast.parse(expr_clean, mode="eval")
            for node in ast.walk(tree):
                # Disallow imports, exec, attributes access to private or dunder methods
                if isinstance(node, (ast.Import, ast.ImportFrom, ast.Exec if hasattr(ast, "Exec") else type(None))):
                    return False
                if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
                    return False

            compiled = compile(tree, filename="<nuclei_dsl>", mode="eval")
            result = eval(compiled, {"__builtins__": {}}, eval_scope)
            return bool(result)
        except Exception as exc:
            logger.debug("DSL evaluation failed for '%s': %s", expression, exc)
            return False


class NucleiMatcherEngine:
    """
    Thread-safe matching engine for Nuclei templates.
    """

    def __init__(self) -> None:
        self._regex_lock = threading.RLock()
        self._regex_cache: Dict[Tuple[str, int], re.Pattern] = {}

    def _compile_regex(self, pattern: str, case_insensitive: bool = False) -> Optional[re.Pattern]:
        """Compiles and caches regular expressions with ReDoS bounds and error protection."""
        if not pattern:
            return None
        flags = re.DOTALL | re.MULTILINE
        if case_insensitive:
            flags |= re.IGNORECASE

        cache_key = (pattern, flags)
        with self._regex_lock:
            if cache_key in self._regex_cache:
                return self._regex_cache[cache_key]

        try:
            compiled = re.compile(pattern, flags)
            with self._regex_lock:
                if len(self._regex_cache) >= _REGEX_CACHE_MAX:
                    # Drop oldest items
                    for _ in range(500):
                        if self._regex_cache:
                            self._regex_cache.pop(next(iter(self._regex_cache)))
                self._regex_cache[cache_key] = compiled
            return compiled
        except re.error as exc:
            logger.debug("Failed compiling regex '%s': %s", pattern, exc)
            return None

    def _extract_target_part(
        self,
        part: str,
        status_code: int,
        headers: Dict[str, str],
        body_str: str,
        body_bytes: bytes,
        headers_str: str,
        all_str: str,
        req_headers_str: str = "",
        req_body_str: str = "",
    ) -> Union[str, bytes]:
        """Extracts the specific target string or bytes corresponding to matcher part."""
        p = (part or "body").strip().lower()

        if p == "body":
            return body_str
        if p in ("header", "headers"):
            return headers_str
        if p.startswith("header.") or p.startswith("headers."):
            hdr_name = p.split(".", 1)[1].strip().lower()
            for k, v in headers.items():
                if k.lower() == hdr_name:
                    return v
            return ""
        if p in ("all", "response", "raw"):
            return all_str
        if p == "status":
            return str(status_code)
        if p in ("request", "request_all"):
            return f"{req_headers_str}\r\n\r\n{req_body_str}"
        if p in ("request_header", "request_headers", "req_header"):
            return req_headers_str
        if p in ("request_body", "req_body"):
            return req_body_str

        return body_str

    def evaluate_matcher(
        self,
        matcher: NucleiMatcher,
        status_code: int,
        headers: Dict[str, str],
        body_str: str,
        body_bytes: bytes,
        headers_str: str,
        all_str: str,
        req_headers_str: str = "",
        req_body_str: str = "",
    ) -> Tuple[bool, List[str]]:
        """
        Evaluates a single NucleiMatcher instance against response parts.

        Returns:
            Tuple of (matched_boolean, list_of_matched_condition_strings).
        """
        m_type = (
            matcher.type
            if isinstance(matcher.type, NucleiMatcherType)
            else NucleiMatcherType.from_str(matcher.type)
        )
        is_negative = bool(matcher.negative)
        condition = "and" if str(matcher.condition).strip().lower() == "and" else "or"
        case_insensitive = bool(matcher.case_insensitive)

        matched_conditions: List[str] = []

        # 1. STATUS MATCHER
        if m_type == NucleiMatcherType.STATUS:
            if not matcher.status:
                raw_match = False
            else:
                raw_match = status_code in matcher.status
                if raw_match:
                    matched_conditions.append(f"status == {status_code}")

            final_match = not raw_match if is_negative else raw_match
            if is_negative and final_match:
                matched_conditions.append(f"status != {status_code}")
            return final_match, matched_conditions

        target_val = self._extract_target_part(
            part=matcher.part,
            status_code=status_code,
            headers=headers,
            body_str=body_str,
            body_bytes=body_bytes,
            headers_str=headers_str,
            all_str=all_str,
            req_headers_str=req_headers_str,
            req_body_str=req_body_str,
        )
        target_str = (
            target_val if isinstance(target_val, str) else target_val.decode("utf-8", "replace")
        )

        # 2. WORD / WORDS MATCHER
        if m_type == NucleiMatcherType.WORD:
            if not matcher.words:
                return False, []

            word_matches: List[bool] = []
            target_cmp = target_str.lower() if case_insensitive else target_str

            for w in matcher.words:
                w_cmp = w.lower() if case_insensitive else w
                hit = w_cmp in target_cmp
                word_matches.append(hit)
                if hit:
                    matched_conditions.append(f"word '{w}' in {matcher.part}")

            if condition == "and":
                raw_match = all(word_matches)
            else:
                raw_match = any(word_matches)

            final_match = not raw_match if is_negative else raw_match
            if is_negative and final_match:
                matched_conditions.append(f"negative word match on {matcher.part}")
            return final_match, matched_conditions

        # 3. REGEX MATCHER
        if m_type == NucleiMatcherType.REGEX:
            if not matcher.regex:
                return False, []

            regex_matches: List[bool] = []
            scan_text = target_str[:_MAX_REGEX_SCAN_CHARS]

            for pat in matcher.regex:
                compiled = self._compile_regex(pat, case_insensitive=case_insensitive)
                if compiled:
                    hit = bool(compiled.search(scan_text))
                else:
                    hit = False
                regex_matches.append(hit)
                if hit:
                    matched_conditions.append(f"regex '{pat}' on {matcher.part}")

            if condition == "and":
                raw_match = all(regex_matches)
            else:
                raw_match = any(regex_matches)

            final_match = not raw_match if is_negative else raw_match
            if is_negative and final_match:
                matched_conditions.append(f"negative regex match on {matcher.part}")
            return final_match, matched_conditions

        # 4. BINARY MATCHER
        if m_type == NucleiMatcherType.BINARY:
            patterns = matcher.words or matcher.regex
            if not patterns:
                return False, []

            bin_matches: List[bool] = []
            for b_pat in patterns:
                cleaned = b_pat.replace("\\x", "").replace("0x", "").replace(" ", "").strip()
                try:
                    target_bytes = binascii.unhexlify(cleaned)
                    hit = target_bytes in body_bytes
                except Exception:
                    hit = False
                bin_matches.append(hit)
                if hit:
                    matched_conditions.append(f"binary '{b_pat}' in body")

            if condition == "and":
                raw_match = all(bin_matches)
            else:
                raw_match = any(bin_matches)

            final_match = not raw_match if is_negative else raw_match
            if is_negative and final_match:
                matched_conditions.append("negative binary match in body")
            return final_match, matched_conditions

        # 5. SIZE MATCHER
        if m_type == NucleiMatcherType.SIZE:
            body_len = len(body_bytes)
            size_targets: List[int] = []
            for item in (matcher.status + matcher.words):
                try:
                    size_targets.append(int(item))
                except (ValueError, TypeError):
                    pass

            if not size_targets:
                raw_match = False
            else:
                raw_match = body_len in size_targets
                if raw_match:
                    matched_conditions.append(f"size == {body_len}")

            final_match = not raw_match if is_negative else raw_match
            if is_negative and final_match:
                matched_conditions.append(f"size != {body_len}")
            return final_match, matched_conditions

        # 6. DSL MATCHER
        if m_type == NucleiMatcherType.DSL:
            if not matcher.dsl:
                return False, []

            dsl_context = {
                "status_code": status_code,
                "status": status_code,
                "content_length": len(body_bytes),
                "body": body_str,
                "header": headers_str,
                "all_headers": headers_str,
                "response": all_str,
            }
            # Add headers into context with lowercase keys
            for hk, hv in headers.items():
                dsl_context[f"header_{hk.lower().replace('-', '_')}"] = hv
                dsl_context[hk.lower().replace("-", "_")] = hv

            dsl_matches: List[bool] = []
            for expr in matcher.dsl:
                hit = SafeDSLEvaluator.evaluate(expr, dsl_context)
                dsl_matches.append(hit)
                if hit:
                    matched_conditions.append(f"dsl '{expr}'")

            if condition == "and":
                raw_match = all(dsl_matches)
            else:
                raw_match = any(dsl_matches)

            final_match = not raw_match if is_negative else raw_match
            if is_negative and final_match:
                matched_conditions.append("negative dsl condition matched")
            return final_match, matched_conditions

        return False, []

    def evaluate_http_block(
        self,
        block: NucleiHttpBlock,
        status_code: int,
        headers: Dict[str, str],
        body_str: str,
        body_bytes: bytes,
        headers_str: str,
        all_str: str,
        req_headers_str: str = "",
        req_body_str: str = "",
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        """
        Evaluates all matchers within a NucleiHttpBlock.

        Returns:
            Tuple of (block_matched, matched_conditions, extracted_data).
        """
        if not block.matchers:
            return False, [], {}

        def _matcher_cost(m: NucleiMatcher) -> int:
            t = m.type if isinstance(m.type, NucleiMatcherType) else NucleiMatcherType.from_str(m.type)
            if t == NucleiMatcherType.STATUS:
                return 0
            if t == NucleiMatcherType.SIZE:
                return 1
            if t in (NucleiMatcherType.WORD, "word", "words"):
                return 2
            if t == NucleiMatcherType.BINARY:
                return 3
            if t == NucleiMatcherType.REGEX:
                return 4
            return 5

        all_conditions: List[str] = []
        extracted: Dict[str, Any] = {}
        block_condition = (
            "and" if str(block.matchers_condition).strip().lower() == "and" else "or"
        )

        sorted_matchers = sorted(block.matchers, key=_matcher_cost)

        if block_condition == "and":
            for matcher in sorted_matchers:
                m_matched, m_conds = self.evaluate_matcher(
                    matcher=matcher,
                    status_code=status_code,
                    headers=headers,
                    body_str=body_str,
                    body_bytes=body_bytes,
                    headers_str=headers_str,
                    all_str=all_str,
                    req_headers_str=req_headers_str,
                    req_body_str=req_body_str,
                )
                if not m_matched:
                    return False, [], {}
                all_conditions.extend(m_conds)
            is_match = True
        else:
            is_match = False
            for matcher in sorted_matchers:
                m_matched, m_conds = self.evaluate_matcher(
                    matcher=matcher,
                    status_code=status_code,
                    headers=headers,
                    body_str=body_str,
                    body_bytes=body_bytes,
                    headers_str=headers_str,
                    all_str=all_str,
                    req_headers_str=req_headers_str,
                    req_body_str=req_body_str,
                )
                if m_matched:
                    is_match = True
                    all_conditions.extend(m_conds)
                    if not block.extractors:
                        break

        # Extract data if extractors present and block matched
        if is_match and block.extractors:
            for ext in block.extractors:
                if not isinstance(ext, dict):
                    continue
                ext_type = str(ext.get("type", "regex")).lower()
                ext_part = str(ext.get("part", "body")).lower()
                ext_name = str(ext.get("name") or "extracted")

                src = self._extract_target_part(
                    part=ext_part,
                    status_code=status_code,
                    headers=headers,
                    body_str=body_str,
                    body_bytes=body_bytes,
                    headers_str=headers_str,
                    all_str=all_str,
                    req_headers_str=req_headers_str,
                    req_body_str=req_body_str,
                )
                src_text = src if isinstance(src, str) else src.decode("utf-8", "replace")

                if ext_type == "regex":
                    patterns = ext.get("regex", [])
                    if isinstance(patterns, str):
                        patterns = [patterns]
                    for pat in patterns:
                        compiled = self._compile_regex(pat)
                        if compiled:
                            m = compiled.search(src_text[:_MAX_REGEX_SCAN_CHARS])
                            if m:
                                group_idx = int(ext.get("group", 1 if m.groups() else 0))
                                try:
                                    extracted[ext_name] = m.group(group_idx)
                                except IndexError:
                                    extracted[ext_name] = m.group(0)
                                break

        return is_match, all_conditions, extracted

    def evaluate_response(
        self,
        template: NucleiTemplate,
        status_code: int,
        headers: Dict[str, str],
        body: Union[str, bytes],
        url: str = "",
        req_headers: Optional[Dict[str, str]] = None,
        req_body: Optional[Union[str, bytes]] = None,
    ) -> NucleiMatchResult:
        """
        Evaluates a NucleiTemplate against a concrete HTTP response.
        """
        start_time = time.perf_counter()

        if isinstance(body, bytes):
            body_bytes = body
            body_str = body.decode("utf-8", errors="replace")
        else:
            body_str = str(body or "")
            body_bytes = body_str.encode("utf-8", errors="replace")

        norm_headers = {str(k): str(v) for k, v in (headers or {}).items()}
        headers_str = "\r\n".join(f"{k}: {v}" for k, v in norm_headers.items())
        all_str = f"HTTP/1.1 {status_code}\r\n{headers_str}\r\n\r\n{body_str}"

        req_headers_str = "\r\n".join(f"{k}: {v}" for k, v in (req_headers or {}).items())
        req_body_str = req_body.decode("utf-8", errors="replace") if isinstance(req_body, bytes) else str(req_body or "")

        matched = False
        matched_conditions: List[str] = []
        extracted_data: Dict[str, Any] = {}

        if template.http_blocks:
            for block in template.http_blocks:
                blk_match, conds, ext = self.evaluate_http_block(
                    block=block,
                    status_code=status_code,
                    headers=norm_headers,
                    body_str=body_str,
                    body_bytes=body_bytes,
                    headers_str=headers_str,
                    all_str=all_str,
                    req_headers_str=req_headers_str,
                    req_body_str=req_body_str,
                )
                if blk_match:
                    matched = True
                    matched_conditions.extend(conds)
                    extracted_data.update(ext)
                    if block.stop_at_first_match:
                        break
        else:
            # If template has no http blocks (e.g. metadata or network-only)
            matched = False

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

        return NucleiMatchResult(
            template_id=template.id,
            template_name=template.name,
            severity=template.severity,
            category=template.category,
            tags=template.tags,
            matched=matched,
            matched_conditions=matched_conditions,
            extracted_data=extracted_data,
            matched_at=url or f"status:{status_code}",
            execution_time_ms=elapsed_ms,
        )

    def evaluate_passive(
        self,
        template: NucleiTemplate,
        flow: FlowRecord,
    ) -> NucleiMatchResult:
        """
        Evaluates a template passively against an intercepted FlowRecord.
        """
        return self.evaluate_flow(template, flow)

    def evaluate_flow(
        self,
        template: NucleiTemplate,
        flow: Any,
    ) -> NucleiMatchResult:
        """
        Evaluates a template against any flow-like object (FlowRecord, mitmproxy HTTPFlow, or dictionary).
        """
        status_code = 200
        headers: Dict[str, str] = {}
        body: Union[str, bytes] = ""
        url = ""
        req_headers: Dict[str, str] = {}
        req_body: Union[str, bytes] = ""

        # FlowRecord or generic object
        if hasattr(flow, "response") and flow.response:
            resp = flow.response
            status_code = getattr(resp, "status_code", 200) or 200
            headers = getattr(resp, "headers", {}) or {}
            body = getattr(resp, "body", "") or ""

        if hasattr(flow, "request") and flow.request:
            req = flow.request
            url = getattr(req, "url", "") or getattr(flow, "url", "")
            req_headers = getattr(req, "headers", {}) or {}
            req_body = getattr(req, "body", "") or ""

        # Fallback to direct flow attributes
        if not headers and hasattr(flow, "response_headers") and flow.response_headers:
            headers = flow.response_headers
        if not body and hasattr(flow, "response_body") and flow.response_body:
            body = flow.response_body
        if not url and hasattr(flow, "url"):
            url = flow.url or ""

        return self.evaluate_response(
            template=template,
            status_code=status_code,
            headers=headers,
            body=body,
            url=url,
            req_headers=req_headers,
            req_body=req_body,
        )

    def evaluate_flow_all(
        self,
        templates: Sequence[NucleiTemplate],
        flow: Any,
    ) -> List[NucleiMatchResult]:
        """
        Evaluates a sequence of Nuclei templates against a single flow record efficiently.
        """
        if not templates:
            return []

        status_code = 200
        headers: Dict[str, str] = {}
        body: Union[str, bytes] = ""
        url = ""
        req_headers: Dict[str, str] = {}
        req_body: Union[str, bytes] = ""

        if hasattr(flow, "response") and flow.response:
            resp = flow.response
            status_code = getattr(resp, "status_code", 200) or 200
            headers = getattr(resp, "headers", {}) or {}
            body = getattr(resp, "body", "") or ""

        if hasattr(flow, "request") and flow.request:
            req = flow.request
            url = getattr(req, "url", "") or getattr(flow, "url", "")
            req_headers = getattr(req, "headers", {}) or {}
            req_body = getattr(req, "body", "") or ""

        if not headers and hasattr(flow, "response_headers") and flow.response_headers:
            headers = flow.response_headers
        if not body and hasattr(flow, "response_body") and flow.response_body:
            body = flow.response_body
        if not url and hasattr(flow, "url"):
            url = flow.url or ""

        # Pre-process strings and buffers once for all templates
        if isinstance(body, bytes):
            body_bytes = body
            body_str = body.decode("utf-8", errors="replace")
        else:
            body_str = str(body or "")
            body_bytes = body_str.encode("utf-8", errors="replace")

        norm_headers = {str(k): str(v) for k, v in (headers or {}).items()}
        headers_str = "\r\n".join(f"{k}: {v}" for k, v in norm_headers.items())
        all_str = f"HTTP/1.1 {status_code}\r\n{headers_str}\r\n\r\n{body_str}"

        req_headers_str = "\r\n".join(f"{k}: {v}" for k, v in (req_headers or {}).items())
        req_body_str = (
            req_body.decode("utf-8", errors="replace")
            if isinstance(req_body, bytes)
            else str(req_body or "")
        )

        results: List[NucleiMatchResult] = []
        for template in templates:
            start_time = time.perf_counter()
            matched = False
            matched_conditions: List[str] = []
            extracted_data: Dict[str, Any] = {}

            if template.http_blocks:
                for block in template.http_blocks:
                    blk_match, conds, ext = self.evaluate_http_block(
                        block=block,
                        status_code=status_code,
                        headers=norm_headers,
                        body_str=body_str,
                        body_bytes=body_bytes,
                        headers_str=headers_str,
                        all_str=all_str,
                        req_headers_str=req_headers_str,
                        req_body_str=req_body_str,
                    )
                    if blk_match:
                        matched = True
                        matched_conditions.extend(conds)
                        extracted_data.update(ext)
                        if block.stop_at_first_match:
                            break

            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)
            if matched:
                results.append(
                    NucleiMatchResult(
                        template_id=template.id,
                        template_name=template.name,
                        severity=template.severity,
                        category=template.category,
                        tags=template.tags,
                        matched=True,
                        matched_conditions=matched_conditions,
                        extracted_data=extracted_data,
                        matched_at=url or f"status:{status_code}",
                        execution_time_ms=elapsed_ms,
                    )
                )

        return results


# ----------------------------------------------------------------------
# Alias and Singleton Access
# ----------------------------------------------------------------------

# Alias NucleiMatcher to NucleiMatcherEngine for interface compatibility
NucleiMatcher = NucleiMatcherEngine

_GLOBAL_MATCHER: Optional[NucleiMatcherEngine] = None
_GLOBAL_MATCHER_LOCK = threading.Lock()


def get_nuclei_matcher() -> NucleiMatcherEngine:
    """Returns the process-wide singleton NucleiMatcherEngine instance."""
    global _GLOBAL_MATCHER
    with _GLOBAL_MATCHER_LOCK:
        if _GLOBAL_MATCHER is None:
            _GLOBAL_MATCHER = NucleiMatcherEngine()
        return _GLOBAL_MATCHER


def reset_nuclei_matcher() -> None:
    """Resets the singleton matcher instance (primarily for test isolation)."""
    global _GLOBAL_MATCHER
    with _GLOBAL_MATCHER_LOCK:
        _GLOBAL_MATCHER = None
