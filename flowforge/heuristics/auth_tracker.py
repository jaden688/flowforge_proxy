"""Authentication and session consistency tracker & anomaly detector (Requirement R2)."""

import base64
import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from flowforge.heuristics.models import (
    AuthFinding,
    ExtractedParameter,
    FindingSeverity,
    ParameterLocation,
)


class AuthTracker:
    """Tracks authentication credentials, session consistency, and security anomalies."""

    SENSITIVE_ROUTE_REGEX = re.compile(
        r"/(admin|internal|settings|billing|users?|account|export|finance|dashboard|config|api/v\d+/user|private|secret|manage)",
        re.IGNORECASE,
    )

    STATIC_EXTENSIONS = (
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".css",
        ".js",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".map",
    )

    SESSION_COOKIE_NAMES = {
        "session_id",
        "session",
        "phpsessid",
        "jsessionid",
        "connect.sid",
        "token",
        "auth",
        "auth_token",
        "access_token",
        "jwt",
        "sid",
        "s_id",
        "user_session",
        "id_token",
        "remember_token",
    }

    AUTH_HEADER_NAMES = {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "apikey",
        "x-auth-token",
        "x-access-token",
        "x-user-token",
        "x-session-token",
    }

    def __init__(self):
        # Historical endpoint state: endpoint_key -> {"auth_count": int, "anon_count": int}
        self._endpoint_history: Dict[str, Dict[str, int]] = {}

    def analyze_flow(
        self,
        flow: Any,
        parameters: Optional[List[ExtractedParameter]] = None,
        canonical_endpoint: str = "",
    ) -> List[AuthFinding]:
        """Analyze flow for authentication credentials, session anomalies, and cookie risks."""
        findings: List[AuthFinding] = []

        # Extract properties from FlowRecord or flat object
        req = getattr(flow, "request", None)
        resp = getattr(flow, "response", None)

        url = getattr(flow, "url", "") or (getattr(req, "url", "") if req else "") or ""
        path = getattr(flow, "path", "") or (getattr(req, "path", "") if req else "") or ""
        method = getattr(flow, "method", "") or (getattr(req, "method", "") if req else "") or "GET"
        method = method.upper()

        req_headers = getattr(flow, "request_headers", None)
        if req_headers is None:
            req_headers = getattr(req, "headers", {}) if req else {}

        resp_headers = getattr(flow, "response_headers", None)
        if resp_headers is None:
            resp_headers = getattr(resp, "headers", {}) if resp else {}

        status_code = getattr(flow, "response_status_code", None)
        if status_code is None and resp:
            status_code = getattr(resp, "status_code", None)
        if status_code is None:
            status_code = getattr(flow, "response_status", 200)

        scheme = getattr(flow, "scheme", "https") or "https"

        # 1. Extract Credentials & Session Identity
        credentials = self._extract_credentials(req_headers, flow)
        has_auth = len(credentials) > 0
        session_fp = self._compute_session_fingerprint(credentials)

        # 2. Check: Token in URL Query String
        self._check_token_in_url(flow, parameters, findings)

        # 3. Check: Sensitive Route vs Auth Presence
        is_static = any(path.lower().endswith(ext) for ext in self.STATIC_EXTENSIONS)
        if not is_static and status_code in (200, 201, 204):
            if not has_auth and self.SENSITIVE_ROUTE_REGEX.search(path):
                findings.append(
                    AuthFinding(
                        rule_code="AUTH_ANOMALY_UNAUTH_SENSITIVE",
                        finding_type="Unauthenticated Sensitive Endpoint Access",
                        severity=FindingSeverity.HIGH,
                        message=f"Sensitive endpoint '{path}' returned HTTP {status_code} without authentication credentials.",
                    )
                )

        # 4. Check: Endpoint Historical Auth Deviation
        endpoint_key = canonical_endpoint or f"{method} {path}"
        if not is_static:
            history = self._endpoint_history.setdefault(
                endpoint_key, {"auth_count": 0, "anon_count": 0}
            )
            if has_auth:
                history["auth_count"] += 1
            else:
                history["anon_count"] += 1

            if not has_auth and history["auth_count"] >= 3 and status_code in (200, 201, 204):
                findings.append(
                    AuthFinding(
                        rule_code="AUTH_ANOMALY_STATE_DEVIATION",
                        finding_type="Auth State Deviation",
                        severity=FindingSeverity.HIGH,
                        message=f"Endpoint '{endpoint_key}' historically requires authentication ({history['auth_count']} authenticated flows), but responded {status_code} anonymously.",
                    )
                )

        # 5. Check: Cookie Attribute Compliance (Response Set-Cookie)
        self._check_cookie_compliance(resp_headers, scheme, findings)

        # 6. Check: JWT Specific Findings
        for cred in credentials:
            if cred.get("type") == "bearer_jwt":
                self._inspect_jwt_token(cred.get("raw", ""), findings)

        # 7. Check: Dual Identity Collision
        identities = [c.get("identity") for c in credentials if c.get("identity")]
        if len(set(identities)) > 1:
            findings.append(
                AuthFinding(
                    rule_code="AUTH_ANOMALY_DUAL_IDENTITY",
                    finding_type="Conflicting Auth Identities",
                    severity=FindingSeverity.MEDIUM,
                    message=f"Multiple conflicting identities observed in same request: {list(set(identities))}",
                )
            )

        return findings

    def _extract_credentials(
        self, headers: Union[Dict[str, Any], List[Tuple[str, str]], Any], flow: Any
    ) -> List[Dict[str, Any]]:
        """Extract credentials across Bearer, Basic, API Keys, and Cookies."""
        creds: List[Dict[str, Any]] = []
        headers_map: Dict[str, str] = {}

        if isinstance(headers, dict):
            headers_map = {str(k).lower(): str(v) for k, v in headers.items()}
        elif isinstance(headers, list):
            for item in headers:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    headers_map[str(item[0]).lower()] = str(item[1])

        # 1. Authorization Header
        auth_hdr = headers_map.get("authorization")
        if auth_hdr:
            if auth_hdr.lower().startswith("bearer "):
                token = auth_hdr[7:].strip()
                if token.count(".") == 2 and token.startswith("ey"):
                    claims = self._decode_jwt_payload(token)
                    creds.append(
                        {
                            "type": "bearer_jwt",
                            "raw": token,
                            "identity": claims.get("sub") or claims.get("user_id") or "jwt_user",
                            "claims": claims,
                        }
                    )
                else:
                    creds.append(
                        {
                            "type": "bearer_token",
                            "raw": token,
                            "identity": token[:8] + "...",
                        }
                    )
            elif auth_hdr.lower().startswith("basic "):
                b64_val = auth_hdr[6:].strip()
                try:
                    decoded = base64.b64decode(b64_val).decode("utf-8")
                    user = decoded.split(":", 1)[0]
                    creds.append(
                        {
                            "type": "basic_auth",
                            "raw": auth_hdr,
                            "identity": user,
                        }
                    )
                except Exception:
                    creds.append({"type": "basic_auth", "raw": auth_hdr, "identity": "basic_user"})

        # 2. Custom API Keys
        for hk in ("x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token"):
            if hk in headers_map:
                key_val = headers_map[hk]
                creds.append(
                    {
                        "type": "api_key",
                        "name": hk,
                        "raw": key_val,
                        "identity": f"{hk}:{key_val[:6]}...",
                    }
                )

        # 3. Request Cookies
        cookies = getattr(flow, "request_cookies", None)
        if cookies is None and "cookie" in headers_map:
            cookie_hdr = headers_map["cookie"]
            cookies = {}
            for item in cookie_hdr.split(";"):
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()

        if isinstance(cookies, dict):
            for c_name, c_val in cookies.items():
                if c_name.lower() in self.SESSION_COOKIE_NAMES:
                    creds.append(
                        {
                            "type": "session_cookie",
                            "name": c_name,
                            "raw": c_val,
                            "identity": f"cookie_{c_name}:{c_val[:8]}...",
                        }
                    )

        return creds

    def _check_token_in_url(
        self,
        flow: Any,
        parameters: Optional[List[ExtractedParameter]],
        findings: List[AuthFinding],
    ):
        req = getattr(flow, "request", None)
        url = getattr(flow, "url", "") or (getattr(req, "url", "") if req else "") or ""
        query_string = getattr(flow, "query_string", "") or (getattr(req, "query_string", "") if req else "") or ""
        if not query_string and "?" in url:
            query_string = url.split("?", 1)[1]

        if not query_string:
            return

        sensitive_param_names = {
            "token",
            "access_token",
            "auth",
            "jwt",
            "api_key",
            "apikey",
            "secret",
            "session_id",
            "sid",
            "bearer",
        }

        # Check extracted parameters if available
        if parameters:
            for p in parameters:
                if p.location == ParameterLocation.QUERY:
                    p_name_lower = p.name.lower()
                    if p_name_lower in sensitive_param_names or (
                        p.raw_value.startswith("ey") and p.raw_value.count(".") == 2
                    ):
                        findings.append(
                            AuthFinding(
                                rule_code="AUTH_TOKEN_IN_URL",
                                finding_type="Insecure Auth Token in URL",
                                severity=FindingSeverity.MEDIUM,
                                message=f"Sensitive authentication token parameter '{p.name}' exposed in URL query string.",
                                token_type=p.name,
                                token_masked=self._mask_token(p.raw_value),
                            )
                        )
                        break

    def _check_cookie_compliance(
        self,
        resp_headers: Union[Dict[str, Any], List[Tuple[str, str]], Any],
        scheme: str,
        findings: List[AuthFinding],
    ):
        """Check Set-Cookie directives for Secure, HttpOnly, and SameSite flags."""
        set_cookie_raw = None
        if isinstance(resp_headers, dict):
            for k, v in resp_headers.items():
                if str(k).lower() == "set-cookie":
                    set_cookie_raw = v
                    break
        elif isinstance(resp_headers, list):
            for item in resp_headers:
                if isinstance(item, (list, tuple)) and len(item) == 2 and str(item[0]).lower() == "set-cookie":
                    set_cookie_raw = item[1]
                    break

        if not set_cookie_raw:
            return

        cookie_lines = set_cookie_raw.split("\n") if "\n" in set_cookie_raw else [set_cookie_raw]

        for line in cookie_lines:
            parts = [p.strip() for p in line.split(";") if p.strip()]
            if not parts:
                continue

            first_part = parts[0]
            if "=" not in first_part:
                continue

            cookie_name = first_part.split("=", 1)[0].strip().lower()
            if cookie_name not in self.SESSION_COOKIE_NAMES:
                # Still inspect if name contains session / auth
                if not any(k in cookie_name for k in ("sess", "auth", "token", "jwt")):
                    continue

            flags = {p.lower().split("=")[0].strip(): p.split("=")[1].strip() if "=" in p else True for p in parts[1:]}

            # 1. Missing HttpOnly
            if "httponly" not in flags:
                findings.append(
                    AuthFinding(
                        rule_code="AUTH_INSECURE_COOKIE",
                        finding_type="Missing HttpOnly Flag",
                        severity=FindingSeverity.MEDIUM,
                        message=f"Session cookie '{cookie_name}' missing HttpOnly flag, susceptible to XSS token theft.",
                    )
                )

            # 2. Missing Secure on HTTPS
            if "secure" not in flags and scheme.lower() == "https":
                findings.append(
                    AuthFinding(
                        rule_code="AUTH_INSECURE_COOKIE",
                        finding_type="Missing Secure Flag",
                        severity=FindingSeverity.MEDIUM,
                        message=f"Session cookie '{cookie_name}' missing Secure flag over HTTPS transport.",
                    )
                )

            # 3. Missing or Weak SameSite
            if "samesite" not in flags:
                findings.append(
                    AuthFinding(
                        rule_code="AUTH_SAMESITE_MISSING",
                        finding_type="Missing SameSite Cookie Flag",
                        severity=FindingSeverity.LOW,
                        message=f"Session cookie '{cookie_name}' missing SameSite directive.",
                    )
                )
            elif flags["samesite"].lower() == "none" and "secure" not in flags:
                findings.append(
                    AuthFinding(
                        rule_code="AUTH_SAMESITE_MISSING",
                        finding_type="Insecure SameSite=None Flag",
                        severity=FindingSeverity.MEDIUM,
                        message=f"Session cookie '{cookie_name}' has SameSite=None without Secure flag.",
                    )
                )

    def _inspect_jwt_token(self, jwt_str: str, findings: List[AuthFinding]):
        """Inspect JWT header and payload for alg:none and expiration."""
        parts = jwt_str.split(".")
        if len(parts) != 3:
            return

        header_b64, payload_b64, sig_b64 = parts
        header: Dict[str, Any] = {}
        payload: Dict[str, Any] = {}

        try:
            h_pad = header_b64 + "=" * (-len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(h_pad.encode("utf-8")).decode("utf-8"))
        except Exception:
            pass

        try:
            p_pad = payload_b64 + "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(p_pad.encode("utf-8")).decode("utf-8"))
        except Exception:
            pass

        sec_flags: List[str] = []

        # Check alg: none
        alg = header.get("alg", "").lower()
        if alg == "none" or not sig_b64:
            sec_flags.append("ALG_NONE")
            findings.append(
                AuthFinding(
                    rule_code="AUTH_JWT_NONE_ALG",
                    finding_type="JWT Signature Bypass (alg: none)",
                    severity=FindingSeverity.CRITICAL,
                    message=f"JWT token uses algorithm '{header.get('alg')}' allowing arbitrary token forgery.",
                    token_type="JWT",
                    token_masked=self._mask_token(jwt_str),
                    jwt_claims=payload,
                    jwt_security_flags=sec_flags,
                )
            )

        # Check expiration
        exp = payload.get("exp")
        if exp and isinstance(exp, (int, float)):
            now = time.time()
            if exp < now:
                sec_flags.append("EXPIRED")
                findings.append(
                    AuthFinding(
                        rule_code="AUTH_JWT_EXPIRED",
                        finding_type="Expired JWT Accepted",
                        severity=FindingSeverity.LOW,
                        message=f"JWT expired at epoch {exp} (elapsed: {int(now - exp)}s).",
                        token_type="JWT",
                        token_masked=self._mask_token(jwt_str),
                        jwt_claims=payload,
                        jwt_security_flags=sec_flags,
                    )
                )

    def _decode_jwt_payload(self, token: str) -> Dict[str, Any]:
        """Safely decode JWT payload claims without cryptographic verification."""
        parts = token.split(".")
        if len(parts) >= 2:
            try:
                p_pad = parts[1] + "=" * (-len(parts[1]) % 4)
                return json.loads(base64.urlsafe_b64decode(p_pad.encode("utf-8")).decode("utf-8"))
            except Exception:
                pass
        return {}

    def _compute_session_fingerprint(self, creds: List[Dict[str, Any]]) -> str:
        """Generate deterministic session fingerprint hash."""
        if not creds:
            return "anonymous"
        raw_signatures = "-".join(sorted(f"{c.get('type')}:{c.get('identity')}" for c in creds))
        return hashlib.sha256(raw_signatures.encode("utf-8")).hexdigest()[:16]

    def _mask_token(self, token: str) -> str:
        """Mask token for safe display."""
        if not token:
            return ""
        if len(token) <= 8:
            return "****"
        return f"{token[:4]}...{token[-4:]}"
