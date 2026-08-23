"""Input reflection detector and context classifier (Requirement R2)."""

import base64
import html
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from flowforge.heuristics.models import (
    EncodingStatus,
    ExtractedParameter,
    FindingSeverity,
    ParameterLocation,
    ReflectionContext,
    ReflectionFinding,
)


class ReflectionDetector:
    """Detects reflected parameters in response bodies and headers with context classification."""

    STOPWORDS = {
        "and",
        "the",
        "for",
        "with",
        "status",
        "type",
        "mode",
        "page",
        "limit",
        "offset",
        "true",
        "false",
        "null",
        "undefined",
        "none",
        "name",
        "value",
        "data",
        "user",
        "text",
        "view",
        "item",
        "list",
        "sort",
        "order",
    }

    TRIVIAL_VALUES = {
        "true",
        "false",
        "null",
        "undefined",
        "none",
        "nan",
        "0",
        "1",
        "-1",
        "",
        "{}",
        "[]",
        "nil",
    }

    DANGEROUS_CHARS = {"<", ">", '"', "'", "&", "/", "\\", "`"}

    def detect_reflections(
        self,
        parameters: List[ExtractedParameter],
        response_body: Union[str, bytes],
        response_headers: Union[Dict[str, Any], List[Tuple[str, str]], None] = None,
        response_content_type: str = "",
    ) -> List[ReflectionFinding]:
        """Scan response body and headers for reflected parameters."""
        findings: List[ReflectionFinding] = []
        if not parameters:
            return findings

        body_str = (
            response_body.decode("utf-8", errors="replace")
            if isinstance(response_body, (bytes, bytearray))
            else str(response_body or "")
        )

        headers_map: Dict[str, str] = {}
        if response_headers:
            if isinstance(response_headers, dict):
                headers_map = {str(k): str(v) for k, v in response_headers.items()}
            elif isinstance(response_headers, list):
                for item in response_headers:
                    if isinstance(item, (list, tuple)) and len(item) == 2:
                        headers_map[str(item[0])] = str(item[1])

        # Deduplicate candidate parameters
        seen_candidates: Set[Tuple[str, str, str]] = set()

        for param in parameters:
            # Skip parameters originating from response set-cookies or internal markers
            if param.location in (ParameterLocation.COOKIE,) and param.name.startswith("set_"):
                continue

            raw_val = param.raw_value or (str(param.value) if param.value is not None else "")
            if not self._is_valid_candidate(param.name, raw_val):
                continue

            transformations = self._generate_transformations(raw_val)

            # 1. Search in Response Body
            if body_str:
                for trans_val, encoding_status in transformations:
                    if not trans_val or len(trans_val) < 2:
                        continue

                    # Search all occurrences in body
                    start = 0
                    while True:
                        idx = body_str.find(trans_val, start)
                        if idx == -1:
                            break

                        end_idx = idx + len(trans_val)
                        cand_key = (param.name, "body", f"{idx}:{end_idx}")
                        if cand_key not in seen_candidates:
                            seen_candidates.add(cand_key)

                            context = self._classify_context(
                                body_str, idx, end_idx, response_content_type
                            )
                            verified_encoding = self._verify_encoding(
                                raw_val, trans_val, encoding_status, body_str, idx, end_idx
                            )
                            severity = self._score_severity(
                                context, verified_encoding, raw_val
                            )
                            snippet = self._extract_snippet(body_str, idx, end_idx)

                            findings.append(
                                ReflectionFinding(
                                    parameter_name=param.name,
                                    source_location=param.location,
                                    reflected_value=trans_val,
                                    context=context,
                                    encoding_status=verified_encoding,
                                    start_offset=idx,
                                    end_offset=end_idx,
                                    matched_in="body",
                                    severity=severity,
                                    snippet=snippet,
                                )
                            )

                        start = idx + 1
                        if len(findings) > 50:  # Bound findings to prevent CPU runaway
                            break

            # 2. Search in Response Headers
            for h_name, h_val in headers_map.items():
                for trans_val, encoding_status in transformations:
                    if not trans_val or len(trans_val) < 2:
                        continue

                    start = 0
                    while True:
                        idx = h_val.find(trans_val, start)
                        if idx == -1:
                            break

                        end_idx = idx + len(trans_val)
                        cand_key = (param.name, h_name, f"{idx}:{end_idx}")
                        if cand_key not in seen_candidates:
                            seen_candidates.add(cand_key)

                            snippet = self._extract_snippet(h_val, idx, end_idx)
                            severity = FindingSeverity.MEDIUM if h_name.lower() in ("location", "set-cookie", "refresh") else FindingSeverity.INFO

                            findings.append(
                                ReflectionFinding(
                                    parameter_name=param.name,
                                    source_location=param.location,
                                    reflected_value=trans_val,
                                    context=ReflectionContext.RESPONSE_HEADER,
                                    encoding_status=encoding_status,
                                    start_offset=idx,
                                    end_offset=end_idx,
                                    matched_in=h_name,
                                    severity=severity,
                                    snippet=f"{h_name}: {snippet}",
                                )
                            )

                        start = idx + 1

        return findings

    def _is_valid_candidate(self, param_name: str, value: str) -> bool:
        """Filter out trivial, boolean, short, or stopword parameters to prevent false positives."""
        if not value:
            return False

        clean_val = value.strip()
        if len(clean_val) < 3:
            # Allow short strings only if high-value identifier name
            lower_name = param_name.lower()
            if any(k in lower_name for k in ("id", "key", "token", "user", "account", "uuid")):
                return len(clean_val) >= 1
            return False

        lower_val = clean_val.lower()
        if lower_val in self.TRIVIAL_VALUES:
            return False

        if len(clean_val) <= 5 and lower_val in self.STOPWORDS:
            return False

        return True

    def _generate_transformations(
        self, raw_val: str
    ) -> List[Tuple[str, EncodingStatus]]:
        """Generate multi-pass transformations of the parameter value."""
        transformations: List[Tuple[str, EncodingStatus]] = []
        seen: Set[str] = set()

        def _add(val: str, status: EncodingStatus):
            if val and val not in seen:
                seen.add(val)
                transformations.append((val, status))

        # 1. Raw string
        _add(raw_val, EncodingStatus.UNENCODED_RAW)

        # 2. URL-decoded
        try:
            url_decoded = urllib.parse.unquote_plus(raw_val)
            if url_decoded != raw_val:
                _add(url_decoded, EncodingStatus.UNENCODED_RAW)
        except Exception:
            pass

        # 3. URL-encoded
        try:
            url_encoded = urllib.parse.quote_plus(raw_val)
            if url_encoded != raw_val:
                _add(url_encoded, EncodingStatus.URL_ENCODED)
        except Exception:
            pass

        # 4. HTML-entity-decoded
        try:
            html_decoded = html.unescape(raw_val)
            if html_decoded != raw_val:
                _add(html_decoded, EncodingStatus.UNENCODED_RAW)
        except Exception:
            pass

        # 5. HTML-entity-encoded
        try:
            html_encoded = html.escape(raw_val, quote=True)
            if html_encoded != raw_val:
                _add(html_encoded, EncodingStatus.HTML_ENCODED)
        except Exception:
            pass

        # 6. JSON-escaped
        try:
            json_esc = json.dumps(raw_val)[1:-1]
            if json_esc != raw_val:
                _add(json_esc, EncodingStatus.JSON_ESCAPED)
        except Exception:
            pass

        # 7. Base64-decoded (if raw_val is base64)
        if len(raw_val) >= 4 and len(raw_val) % 4 == 0:
            try:
                b64_dec = base64.b64decode(raw_val, validate=True).decode("utf-8")
                if b64_dec.isprintable() and len(b64_dec) >= 3:
                    _add(b64_dec, EncodingStatus.UNENCODED_RAW)
            except Exception:
                pass

        # 8. Base64-encoded (if response might contain base64 of raw_val)
        if len(raw_val) >= 4:
            try:
                b64_enc = base64.b64encode(raw_val.encode("utf-8")).decode("utf-8")
                _add(b64_enc, EncodingStatus.BASE64_ENCODED)
            except Exception:
                pass

        return transformations

    def _classify_context(
        self, body: str, start: int, end: int, content_type: str
    ) -> ReflectionContext:
        """Classify HTML/DOM/JSON state machine context around reflection offset."""
        ct = (content_type or "").lower()

        # Check JSON context first if content-type is JSON or body parses as JSON
        if "json" in ct or body.strip().startswith(("{", "[")):
            # Determine if reflected inside JSON string value or JSON key
            prefix_chunk = body[max(0, start - 50) : start]
            if re.search(r'"\s*:\s*"?$', prefix_chunk):
                return ReflectionContext.JSON_VALUE
            if re.search(r'[{\,]\s*"$', prefix_chunk):
                return ReflectionContext.JSON_KEY
            return ReflectionContext.JSON_VALUE

        # Check if matched value itself contains or starts with <script>
        matched_text = body[start:end].lower()
        if "<script" in matched_text:
            return ReflectionContext.HTML_SCRIPT_BLOCK

        if "<!--" in matched_text:
            return ReflectionContext.HTML_COMMENT

        # HTML / DOM state machine inspection
        # Look backwards to determine surrounding tags
        lookback = body[max(0, start - 500) : start]
        lookahead = body[end : min(len(body), end + 500)]

        # Check if inside <script> block
        last_script_open = lookback.rfind("<script")
        last_script_close = lookback.rfind("</script")
        if last_script_open > last_script_close:
            return ReflectionContext.HTML_SCRIPT_BLOCK

        # Check if inside HTML comment <!-- ... -->
        last_comment_open = lookback.rfind("<!--")
        last_comment_close = lookback.rfind("-->")
        if last_comment_open > last_comment_close:
            return ReflectionContext.HTML_COMMENT

        # Check if inside an HTML Tag (between < and >)
        last_tag_open = lookback.rfind("<")
        last_tag_close = lookback.rfind(">")

        if last_tag_open > last_tag_close:
            # Inside a tag definition: find the active tag attribute name
            tag_fragment = lookback[last_tag_open:]
            attr_match = re.search(
                r'\s+([a-zA-Z_:][-a-zA-Z0-9_.]*)\s*=\s*(?:"[^"]*|\'[^\']*|[^"\'\s>]*)$',
                tag_fragment,
                re.IGNORECASE,
            )
            if attr_match:
                attr_name = attr_match.group(1).lower()
                if attr_name.startswith("on"):
                    return ReflectionContext.HTML_ATTR_EVENT
                if attr_name in (
                    "href",
                    "src",
                    "action",
                    "formaction",
                    "data",
                    "codebase",
                ):
                    return ReflectionContext.HTML_ATTR_URI

            # Quoted vs Unquoted Attribute
            if tag_fragment.endswith(('="', "='")):
                return ReflectionContext.HTML_ATTR_QUOTED
            elif re.search(r'=\s*["\'][^"\']*$', tag_fragment):
                return ReflectionContext.HTML_ATTR_QUOTED
            elif re.search(r'=\s*[^"\'\s>]*$', tag_fragment):
                return ReflectionContext.HTML_ATTR_UNQUOTED
            else:
                return ReflectionContext.HTML_ATTR_QUOTED

        # Between tags: HTML Body Text
        if "<" in body and ">" in body:
            return ReflectionContext.HTML_BODY_TEXT

        return ReflectionContext.PLAIN_TEXT

    def _verify_encoding(
        self,
        raw_val: str,
        reflected_val: str,
        initial_status: EncodingStatus,
        body: str,
        start: int,
        end: int,
    ) -> EncodingStatus:
        """Verify character-level encoding state at match location."""
        if initial_status != EncodingStatus.UNENCODED_RAW:
            return initial_status

        # Check if dangerous characters in raw_val reflect unmodified
        has_dangerous_raw = any(c in raw_val for c in self.DANGEROUS_CHARS)
        if not has_dangerous_raw:
            return EncodingStatus.UNENCODED_RAW

        # Check if reflected value contains the dangerous characters unmodified
        matched_slice = body[start:end]
        if any(c in matched_slice for c in self.DANGEROUS_CHARS):
            return EncodingStatus.UNENCODED_RAW

        # Check if HTML entity encoded
        if any(ent in body[max(0, start - 10) : min(len(body), end + 10)] for ent in ("&lt;", "&gt;", "&quot;", "&#x27;", "&amp;")):
            return EncodingStatus.HTML_ENCODED

        # Check if URL encoded
        if any(enc in body[max(0, start - 10) : min(len(body), end + 10)] for enc in ("%3C", "%3E", "%22", "%27", "%26")):
            return EncodingStatus.URL_ENCODED

        return EncodingStatus.PARTIALLY_ENCODED

    def _score_severity(
        self,
        context: ReflectionContext,
        encoding: EncodingStatus,
        raw_val: str,
    ) -> FindingSeverity:
        """Calculate reflection severity based on context and encoding."""
        is_raw = encoding in (EncodingStatus.UNENCODED_RAW, EncodingStatus.PARTIALLY_ENCODED)
        contains_dangerous = any(c in raw_val for c in ("<", ">", '"', "'", ";", "(", ")"))

        if context == ReflectionContext.HTML_SCRIPT_BLOCK:
            return FindingSeverity.CRITICAL if is_raw else FindingSeverity.MEDIUM

        if context == ReflectionContext.HTML_ATTR_EVENT:
            return FindingSeverity.CRITICAL if is_raw else FindingSeverity.MEDIUM

        if context == ReflectionContext.HTML_ATTR_URI:
            if "javascript:" in raw_val.lower() or "data:" in raw_val.lower():
                return FindingSeverity.CRITICAL
            return FindingSeverity.HIGH if is_raw else FindingSeverity.LOW

        if context == ReflectionContext.HTML_ATTR_UNQUOTED:
            return FindingSeverity.HIGH if is_raw else FindingSeverity.LOW

        if context == ReflectionContext.HTML_ATTR_QUOTED:
            if is_raw and ('"' in raw_val or "'" in raw_val):
                return FindingSeverity.HIGH
            return FindingSeverity.MEDIUM if is_raw else FindingSeverity.LOW

        if context == ReflectionContext.HTML_BODY_TEXT:
            if is_raw and ("<" in raw_val or ">" in raw_val):
                return FindingSeverity.MEDIUM
            return FindingSeverity.LOW if is_raw else FindingSeverity.INFO

        if context == ReflectionContext.RESPONSE_HEADER:
            if "\r" in raw_val or "\n" in raw_val:
                return FindingSeverity.HIGH
            return FindingSeverity.MEDIUM

        if context in (ReflectionContext.JSON_VALUE, ReflectionContext.JSON_KEY):
            return FindingSeverity.LOW

        if context == ReflectionContext.HTML_COMMENT:
            if "-->" in raw_val:
                return FindingSeverity.MEDIUM
            return FindingSeverity.LOW

        return FindingSeverity.INFO

    def _extract_snippet(self, text: str, start: int, end: int, radius: int = 50) -> str:
        """Extract surrounding text snippet around the match offset."""
        snippet_start = max(0, start - radius)
        snippet_end = min(len(text), end + radius)
        prefix = "..." if snippet_start > 0 else ""
        suffix = "..." if snippet_end < len(text) else ""
        return f"{prefix}{text[snippet_start:snippet_end]}{suffix}"
