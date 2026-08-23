"""Multi-source parameter extraction engine (Requirement R2)."""

import hashlib
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple, Union

from flowforge.heuristics.models import ExtractedParameter, ParameterLocation


class ParameterExtractor:
    """Extracts and normalizes parameters from all request and response carriers."""

    MAX_RECURSION_DEPTH = 20
    TARGET_HEADERS = {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "apikey",
        "x-auth-token",
        "x-access-token",
        "x-user-id",
        "x-user",
        "x-tenant-id",
        "x-client-id",
        "x-forwarded-for",
        "x-original-url",
        "x-rewrite-url",
        "origin",
        "referer",
        "host",
        "content-type",
        "accept",
    }

    def __init__(self):
        self.uuid_regex = re.compile(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-7][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
        )
        self.hex_hash_regex = re.compile(r"^[0-9a-fA-F]{24,64}$")
        self.int_regex = re.compile(r"^\d+$")

    def extract_all(self, flow: Any) -> List[ExtractedParameter]:
        """Extract parameters from all available carriers in a flow record."""
        parameters: List[ExtractedParameter] = []

        req = getattr(flow, "request", None)
        resp = getattr(flow, "response", None)

        # 1. URL Query Parameters
        url = getattr(flow, "url", "") or (getattr(req, "url", "") if req else "") or ""
        query_string = (
            getattr(flow, "query_string", "")
            or (getattr(req, "query_string", "") if req else "")
            or ""
        )
        if not query_string and "?" in url:
            query_string = url.split("?", 1)[1]

        if query_string:
            parameters.extend(self.extract_query_params(query_string))

        # 2. Dynamic Path Parameters
        path = getattr(flow, "path", "") or (getattr(req, "path", "") if req else "") or ""
        if not path and url:
            parsed_url = urllib.parse.urlparse(url)
            path = parsed_url.path

        if path:
            parameters.extend(self.extract_path_params(path))

        # 3. Request Headers
        req_headers = getattr(flow, "request_headers", None)
        if req_headers is None:
            req_headers = getattr(req, "headers", {}) if req else {}
        if req_headers:
            parameters.extend(self.extract_headers(req_headers, ParameterLocation.HEADER))

        # 4. Request Cookies
        req_cookies = getattr(flow, "request_cookies", None)
        if req_cookies is None and req:
            req_cookies = getattr(req, "cookies", None)
        if req_cookies is None and isinstance(req_headers, dict):
            cookie_header = req_headers.get("cookie") or req_headers.get("Cookie") or ""
            if cookie_header:
                req_cookies = self._parse_cookie_header(cookie_header)

        if req_cookies:
            parameters.extend(self.extract_cookies(req_cookies))

        # 5. Request Body (JSON, Form, Multipart, XML, GraphQL)
        req_body = getattr(flow, "request_body", None)
        if req_body is None:
            req_body = getattr(req, "body", "") if req else ""
        req_content_type = getattr(flow, "request_content_type", None)
        if req_content_type is None:
            req_content_type = getattr(req, "content_type", "") if req else ""
        if not req_content_type and isinstance(req_headers, dict):
            req_content_type = (
                req_headers.get("content-type") or req_headers.get("Content-Type") or ""
            )

        if req_body:
            parameters.extend(self.extract_body_params(req_body, req_content_type))

        # 6. Response Cookies (Set-Cookie)
        resp_headers = getattr(flow, "response_headers", None)
        if resp_headers is None:
            resp_headers = getattr(resp, "headers", {}) if resp else {}
        if resp_headers:
            set_cookie_raw = None
            if isinstance(resp_headers, dict):
                set_cookie_raw = (
                    resp_headers.get("set-cookie") or resp_headers.get("Set-Cookie")
                )
            elif isinstance(resp_headers, list):
                for k, v in resp_headers:
                    if k.lower() == "set-cookie":
                        set_cookie_raw = v
                        break
            if set_cookie_raw:
                parameters.extend(self.extract_set_cookies(set_cookie_raw))

        return parameters

    def extract_query_params(self, query_string: str) -> List[ExtractedParameter]:
        """Parse query strings handling repeated keys, brackets, and nested objects."""
        params: List[ExtractedParameter] = []
        if not query_string:
            return params

        if query_string.startswith("?"):
            query_string = query_string[1:]

        # Raw query pairs
        pairs = urllib.parse.parse_qsl(query_string, keep_blank_values=True)
        aggregated: Dict[str, List[str]] = {}

        for key, val in pairs:
            if key not in aggregated:
                aggregated[key] = []
            aggregated[key].append(val)

        for raw_key, val_list in aggregated.items():
            norm_key, nested_path = self._normalize_bracket_key(raw_key)
            is_arr = len(val_list) > 1 or raw_key.endswith("[]") or bool(re.search(r"\[\d+\]$", raw_key))
            value = val_list if is_arr else val_list[0]
            raw_val_str = json.dumps(val_list) if is_arr else val_list[0]
            inferred_type = "array" if is_arr else self._infer_simple_type(val_list[0])

            params.append(
                ExtractedParameter(
                    name=norm_key,
                    location=ParameterLocation.QUERY,
                    value=value,
                    raw_value=raw_val_str,
                    inferred_type=inferred_type,
                    is_array=is_arr,
                    nested_path=nested_path,
                )
            )

        return params

    def extract_path_params(self, path: str) -> List[ExtractedParameter]:
        """Extract dynamic resource identifiers from path segments."""
        params: List[ExtractedParameter] = []
        clean_path = path.split("?")[0].strip("/")
        if not clean_path:
            return params

        segments = [s for s in clean_path.split("/") if s]
        for idx, seg in enumerate(segments):
            # Check if segment is dynamic (integer, uuid, mongo id, hash)
            is_dynamic = False
            inferred_type = "string"
            inferred_format = None

            if self.int_regex.match(seg):
                is_dynamic = True
                inferred_type = "integer"
            elif self.uuid_regex.match(seg):
                is_dynamic = True
                inferred_type = "string"
                inferred_format = "uuid"
            elif self.hex_hash_regex.match(seg):
                is_dynamic = True
                inferred_type = "string"
                inferred_format = "hash"

            if is_dynamic:
                # Infer dynamic name from preceding noun if available
                preceding = segments[idx - 1] if idx > 0 else f"segment_{idx}"
                param_name = f"{preceding}_id" if not preceding.endswith("_id") else preceding

                params.append(
                    ExtractedParameter(
                        name=param_name,
                        location=ParameterLocation.PATH,
                        value=int(seg) if inferred_type == "integer" else seg,
                        raw_value=seg,
                        inferred_type=inferred_type,
                        inferred_format=inferred_format,
                        nested_path=f"/{path.strip('/')}[{idx}]",
                    )
                )

        return params

    def extract_body_params(
        self, body: Union[str, bytes], content_type: str
    ) -> List[ExtractedParameter]:
        """Extract parameters from request body based on Content-Type."""
        params: List[ExtractedParameter] = []
        if not body:
            return params

        body_str = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
        ct = (content_type or "").lower()

        # GraphQL Detection
        if self._is_graphql(body_str, ct):
            return self.extract_graphql_params(body_str)

        # JSON Body
        if "application/json" in ct or (body_str.strip().startswith(("{", "[")) and "json" in ct):
            try:
                data = json.loads(body_str)
                return self.flatten_json(data, prefix="", location=ParameterLocation.BODY_JSON)
            except Exception:
                pass

        # Try JSON parsing even without explicit header if it looks like JSON
        if body_str.strip().startswith(("{", "[")):
            try:
                data = json.loads(body_str)
                return self.flatten_json(data, prefix="", location=ParameterLocation.BODY_JSON)
            except Exception:
                pass

        # Form URL-Encoded
        if "application/x-www-form-urlencoded" in ct:
            return self.extract_form_params(body_str)

        # Multipart Form-Data
        if "multipart/form-data" in ct:
            return self.extract_multipart_params(body_str, content_type)

        # XML / SOAP
        if "xml" in ct or body_str.strip().startswith("<"):
            try:
                return self.extract_xml_params(body_str)
            except Exception:
                pass

        return params

    def flatten_json(
        self,
        data: Any,
        prefix: str = "",
        location: ParameterLocation = ParameterLocation.BODY_JSON,
        depth: int = 0,
    ) -> List[ExtractedParameter]:
        """Depth-first recursive flattening for nested JSON objects and arrays."""
        params: List[ExtractedParameter] = []
        if depth > self.MAX_RECURSION_DEPTH:
            # Prevent stack overflow on deeply nested payloads
            raw_repr = json.dumps(data) if not isinstance(data, str) else data
            params.append(
                ExtractedParameter(
                    name=prefix or "root",
                    location=location,
                    value=data,
                    raw_value=raw_repr,
                    inferred_type="string",
                    nested_path=prefix,
                )
            )
            return params

        if isinstance(data, dict):
            if not data and prefix:
                params.append(
                    ExtractedParameter(
                        name=prefix,
                        location=location,
                        value={},
                        raw_value="{}",
                        inferred_type="object",
                        nested_path=prefix,
                    )
                )
            for k, v in data.items():
                key_path = f"{prefix}.{k}" if prefix else str(k)
                params.extend(self.flatten_json(v, key_path, location, depth + 1))

        elif isinstance(data, list):
            if not data and prefix:
                params.append(
                    ExtractedParameter(
                        name=prefix,
                        location=location,
                        value=[],
                        raw_value="[]",
                        inferred_type="array",
                        is_array=True,
                        nested_path=prefix,
                    )
                )
            for idx, item in enumerate(data):
                key_path = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
                params.extend(self.flatten_json(item, key_path, location, depth + 1))

        else:
            inferred_type = self._infer_simple_type(data)
            inferred_format = self._infer_format(str(data)) if isinstance(data, str) else None
            params.append(
                ExtractedParameter(
                    name=prefix or "value",
                    location=location,
                    value=data,
                    raw_value=str(data) if data is not None else "null",
                    inferred_type=inferred_type,
                    inferred_format=inferred_format,
                    nested_path=prefix,
                )
            )

        return params

    def extract_form_params(self, form_body: str) -> List[ExtractedParameter]:
        """Extract parameters from URL-encoded form body."""
        params: List[ExtractedParameter] = []
        pairs = urllib.parse.parse_qsl(form_body, keep_blank_values=True)
        aggregated: Dict[str, List[str]] = {}

        for key, val in pairs:
            if key not in aggregated:
                aggregated[key] = []
            aggregated[key].append(val)

        for raw_key, val_list in aggregated.items():
            norm_key, nested_path = self._normalize_bracket_key(raw_key)
            is_arr = len(val_list) > 1 or raw_key.endswith("[]")
            value = val_list if is_arr else val_list[0]
            raw_val_str = json.dumps(val_list) if is_arr else val_list[0]
            inferred_type = "array" if is_arr else self._infer_simple_type(val_list[0])

            params.append(
                ExtractedParameter(
                    name=norm_key,
                    location=ParameterLocation.BODY_FORM,
                    value=value,
                    raw_value=raw_val_str,
                    inferred_type=inferred_type,
                    is_array=is_arr,
                    nested_path=nested_path,
                )
            )

        return params

    def extract_multipart_params(
        self, body_str: str, content_type: str
    ) -> List[ExtractedParameter]:
        """Extract form fields and file metadata from multipart/form-data."""
        params: List[ExtractedParameter] = []
        # Extract boundary from Content-Type header
        boundary_match = re.search(r"boundary=([^;]+)", content_type, re.IGNORECASE)
        if not boundary_match:
            return params

        boundary = boundary_match.group(1).strip('"')
        delimiter = f"--{boundary}"
        parts = body_str.split(delimiter)

        for part in parts:
            part = part.strip()
            if not part or part == "--":
                continue

            if "\r\n\r\n" in part:
                headers_raw, content = part.split("\r\n\r\n", 1)
            elif "\n\n" in part:
                headers_raw, content = part.split("\n\n", 1)
            else:
                continue

            # Strip trailing CRLF
            content = content.rstrip("\r\n").rstrip("\n")

            disp_match = re.search(
                r'Content-Disposition:\s*form-data;\s*name="([^"]+)"(?:;\s*filename="([^"]+)")?',
                headers_raw,
                re.IGNORECASE,
            )
            if not disp_match:
                continue

            name = disp_match.group(1)
            filename = disp_match.group(2)

            if filename:
                # File field: extract metadata
                ct_match = re.search(
                    r"Content-Type:\s*([^\r\n]+)", headers_raw, re.IGNORECASE
                )
                part_ct = ct_match.group(1).strip() if ct_match else "application/octet-stream"
                size = len(content.encode("utf-8"))
                sha256_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

                file_meta = {
                    "filename": filename,
                    "content_type": part_ct,
                    "byte_size": size,
                    "sha256": sha256_hash,
                }
                params.append(
                    ExtractedParameter(
                        name=name,
                        location=ParameterLocation.BODY_MULTIPART,
                        value=file_meta,
                        raw_value=filename,
                        inferred_type="file",
                        nested_path=f"files.{name}",
                    )
                )
            else:
                # Text field
                params.append(
                    ExtractedParameter(
                        name=name,
                        location=ParameterLocation.BODY_MULTIPART,
                        value=content,
                        raw_value=content,
                        inferred_type=self._infer_simple_type(content),
                        nested_path=name,
                    )
                )

        return params

    def extract_xml_params(self, xml_str: str) -> List[ExtractedParameter]:
        """Extract XML element tag paths and attributes with robust namespace handling."""
        params: List[ExtractedParameter] = []
        if not xml_str:
            return params

        root = None
        try:
            root = ET.fromstring(xml_str)
        except Exception:
            try:
                # Strip XML namespace prefixes like <soap:Envelope> -> <Envelope>
                cleaned_xml = re.sub(r"<(/?)[\w-]+:", r"<\1", xml_str)
                # Remove xmlns attributes
                cleaned_xml = re.sub(r'\s+xmlns(?::[\w-]+)?="[^"]*"', "", cleaned_xml)
                root = ET.fromstring(cleaned_xml)
            except Exception:
                pass

        if root is not None:
            def _traverse(elem: ET.Element, current_path: str):
                # Clean tag namespace
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                path = f"{current_path}.{tag}" if current_path else tag

                # Element text
                if elem.text and elem.text.strip() and len(list(elem)) == 0:
                    text_val = elem.text.strip()
                    params.append(
                        ExtractedParameter(
                            name=path,
                            location=ParameterLocation.BODY_XML,
                            value=text_val,
                            raw_value=text_val,
                            inferred_type=self._infer_simple_type(text_val),
                            nested_path=path,
                        )
                    )

                # Element attributes
                for attr_name, attr_val in elem.attrib.items():
                    clean_attr = attr_name.split("}")[-1] if "}" in attr_name else attr_name
                    attr_path = f"{path}.@{clean_attr}"
                    params.append(
                        ExtractedParameter(
                            name=attr_path,
                            location=ParameterLocation.BODY_XML,
                            value=attr_val,
                            raw_value=attr_val,
                            inferred_type=self._infer_simple_type(attr_val),
                            nested_path=attr_path,
                        )
                    )

                for child in elem:
                    _traverse(child, path)

            _traverse(root, "")
            return params

        # Regex fallback for XML fragments
        tag_matches = re.finditer(r"<([\w:-]+)([^>]*)>([^<]+)</\1>", xml_str)
        for m in tag_matches:
            full_tag = m.group(1).split(":")[-1]
            content = m.group(3).strip()
            attrs_raw = m.group(2)
            if content:
                params.append(
                    ExtractedParameter(
                        name=full_tag,
                        location=ParameterLocation.BODY_XML,
                        value=content,
                        raw_value=content,
                        inferred_type=self._infer_simple_type(content),
                        nested_path=full_tag,
                    )
                )
            for attr_m in re.finditer(r'([\w:-]+)=["\']([^"\']+)["\']', attrs_raw):
                attr_name = attr_m.group(1).split(":")[-1]
                attr_val = attr_m.group(2)
                params.append(
                    ExtractedParameter(
                        name=f"{full_tag}.@{attr_name}",
                        location=ParameterLocation.BODY_XML,
                        value=attr_val,
                        raw_value=attr_val,
                        inferred_type=self._infer_simple_type(attr_val),
                        nested_path=f"{full_tag}.@{attr_name}",
                    )
                )

        return params

    def extract_graphql_params(self, body_str: str) -> List[ExtractedParameter]:
        """Extract GraphQL operation and variables."""
        params: List[ExtractedParameter] = []
        try:
            payload = json.loads(body_str) if isinstance(body_str, str) else {}
        except Exception:
            payload = {}

        if isinstance(payload, dict):
            query = payload.get("query") or ""
            op_name = payload.get("operationName")
            variables = payload.get("variables") or {}

            if query:
                params.append(
                    ExtractedParameter(
                        name="graphql.query",
                        location=ParameterLocation.BODY_GRAPHQL,
                        value=query,
                        raw_value=query,
                        inferred_type="string",
                        inferred_format="graphql",
                    )
                )

            if op_name:
                params.append(
                    ExtractedParameter(
                        name="graphql.operationName",
                        location=ParameterLocation.BODY_GRAPHQL,
                        value=op_name,
                        raw_value=str(op_name),
                        inferred_type="string",
                    )
                )

            if isinstance(variables, dict):
                params.extend(
                    self.flatten_json(
                        variables, prefix="graphql.variables", location=ParameterLocation.BODY_GRAPHQL
                    )
                )

        return params

    def extract_headers(
        self, headers: Union[Dict[str, Any], List[Tuple[str, str]]], location: ParameterLocation
    ) -> List[ExtractedParameter]:
        """Extract relevant custom, auth, and tenant headers."""
        params: List[ExtractedParameter] = []
        header_pairs = (
            headers.items() if isinstance(headers, dict) else (headers or [])
        )

        for k, v in header_pairs:
            k_str = str(k).strip()
            v_str = str(v).strip()
            k_lower = k_str.lower()

            if (
                k_lower in self.TARGET_HEADERS
                or k_lower.startswith(("x-", "sec-", "cf-", "app-"))
            ):
                params.append(
                    ExtractedParameter(
                        name=k_str,
                        location=location,
                        value=v_str,
                        raw_value=v_str,
                        inferred_type="string",
                        inferred_format="jwt" if v_str.startswith("Bearer ey") else None,
                        nested_path=f"headers.{k_str}",
                    )
                )

        return params

    def extract_cookies(self, cookies: Union[Dict[str, Any], List[Tuple[str, str]]]) -> List[ExtractedParameter]:
        """Extract named cookies."""
        params: List[ExtractedParameter] = []
        cookie_items = cookies.items() if isinstance(cookies, dict) else cookies

        for k, v in cookie_items:
            k_str = str(k).strip()
            v_str = str(v).strip()
            params.append(
                ExtractedParameter(
                    name=k_str,
                    location=ParameterLocation.COOKIE,
                    value=v_str,
                    raw_value=v_str,
                    inferred_type="string",
                    nested_path=f"cookies.{k_str}",
                )
            )

        return params

    def extract_set_cookies(self, set_cookie_header: str) -> List[ExtractedParameter]:
        """Extract Set-Cookie response directives."""
        params: List[ExtractedParameter] = []
        # Support comma-separated multiple Set-Cookies or single directive
        cookie_lines = set_cookie_header.split("\n") if "\n" in set_cookie_header else [set_cookie_header]

        for line in cookie_lines:
            parts = [p.strip() for p in line.split(";") if p.strip()]
            if not parts:
                continue

            # First part is name=value
            first_part = parts[0]
            if "=" in first_part:
                name, val = first_part.split("=", 1)
                attributes: Dict[str, Any] = {}
                for attr in parts[1:]:
                    if "=" in attr:
                        ak, av = attr.split("=", 1)
                        attributes[ak.strip().lower()] = av.strip()
                    else:
                        attributes[attr.strip().lower()] = True

                params.append(
                    ExtractedParameter(
                        name=name.strip(),
                        location=ParameterLocation.COOKIE,
                        value={"value": val.strip(), "attributes": attributes},
                        raw_value=val.strip(),
                        inferred_type="cookie_record",
                        nested_path=f"set_cookies.{name.strip()}",
                    )
                )

        return params

    # Helper methods
    def _normalize_bracket_key(self, key: str) -> Tuple[str, str]:
        """Convert bracket keys like 'user[profile][id]' to dot notation 'user.profile.id'."""
        if "[" in key and "]" in key:
            # Replace [x] with .x and strip trailing []
            norm = re.sub(r"\[([^\]]*)\]", r".\1", key).strip(".")
            norm = re.sub(r"\.+", ".", norm)
            return norm, key
        return key, key

    def _infer_simple_type(self, val: Any) -> str:
        """Infer basic primitive JSON data type."""
        if val is None:
            return "null"
        if isinstance(val, bool):
            return "boolean"
        if isinstance(val, int):
            return "integer"
        if isinstance(val, float):
            return "number"
        if isinstance(val, list):
            return "array"
        if isinstance(val, dict):
            return "object"

        str_val = str(val).strip()
        if str_val.lower() in ("true", "false"):
            return "boolean"
        if str_val.lower() in ("null", "none", "nil"):
            return "null"
        if self.int_regex.match(str_val):
            return "integer"
        try:
            float(str_val)
            return "number"
        except ValueError:
            pass

        return "string"

    def _infer_format(self, str_val: str) -> Optional[str]:
        """Infer string format (uuid, email, date-time, jwt, ip, etc.)."""
        if self.uuid_regex.match(str_val):
            return "uuid"
        if re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", str_val):
            return "email"
        if re.match(
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$", str_val
        ):
            return "date-time"
        if re.match(r"^\d{4}-\d{2}-\d{2}$", str_val):
            return "date"
        if re.match(r"^ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*$", str_val):
            return "jwt"
        if re.match(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$", str_val):
            return "ipv4"
        return None

    def _parse_cookie_header(self, cookie_str: str) -> Dict[str, str]:
        """Parse raw Cookie header string into key-value map."""
        cookies: Dict[str, str] = {}
        for item in cookie_str.split(";"):
            item = item.strip()
            if "=" in item:
                k, v = item.split("=", 1)
                cookies[k.strip()] = v.strip()
        return cookies

    def _is_graphql(self, body_str: str, content_type: str) -> bool:
        """Check if body payload represents a GraphQL operation."""
        if "graphql" in content_type:
            return True
        if '"query"' in body_str and ('"variables"' in body_str or '"operationName"' in body_str):
            return True
        stripped = body_str.strip()
        if stripped.startswith(("query ", "mutation ", "subscription ", "{")):
            if "query" in stripped or "mutation" in stripped:
                return True
        return False
