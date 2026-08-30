"""Token harvesting pipeline.

Extracts authentication tokens (JWTs, API keys, session tokens) from
intercepted HTTP responses and tracks their usage across endpoints.
Generates replay proposals to test token reuse across endpoints.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from flowforge.heuristics.models import TriageSummary
from flowforge.models.flow import FlowRecord
from flowforge.models.proposal import (
    AnomalyType,
    ProposalSeverity,
    ProposalState,
    TestProposal,
)

logger = logging.getLogger("flowforge.heuristics.token_harvester")

# Regex patterns for common token formats
_JWT_PATTERN = re.compile(
    r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
)
_API_KEY_PATTERNS = [
    re.compile(r"^(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}$"),           # GitHub
    re.compile(r"^(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}$"),           # Stripe
    re.compile(r"^xox[bpsa]-[a-zA-Z0-9-]+$"),                            # Slack
    re.compile(r"^(?:AKIA|ASIA)[A-Z0-9]{16}$"),                          # AWS
    re.compile(r"^AIza[a-zA-Z0-9_-]{35}$"),                              # Google API
    re.compile(r"^[a-f0-9]{32}$"),                                        # Generic 32-char hex (MD5-style keys)
    re.compile(r"^[a-zA-Z0-9]{40}$"),                                     # Generic 40-char (SHA1-style keys)
]
_SESSION_COOKIE_NAMES = {
    "session", "sessionid", "session_id", "sid", "jwt", "token",
    "auth", "auth_token", "access_token", "refresh_token",
    "phpsessid", "jsessionid", "connect.sid", "_rails_session",
}


@dataclass
class HarvestedToken:
    """A token extracted from intercepted traffic."""
    token_type: str           # "jwt", "api_key", "session_cookie", "bearer"
    token_preview: str        # First 20 chars + "..."
    token_hash: str           # SHA256 hash for dedup
    source_endpoint: str      # endpoint_hash where this token was seen
    source_host: str
    header_name: str          # Which header contained the token
    cookie_name: Optional[str] = None
    context: str = ""         # Additional context (e.g., user identifier)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_type": self.token_type,
            "token_preview": self.token_preview,
            "token_hash": self.token_hash,
            "source_endpoint": self.source_endpoint,
            "source_host": self.source_host,
            "header_name": self.header_name,
            "cookie_name": self.cookie_name,
            "context": self.context,
        }


class TokenHarvester:
    """Extracts and tracks authentication tokens across intercepted flows."""

    def __init__(self) -> None:
        self._tokens: Dict[str, HarvestedToken] = {}  # token_hash -> HarvestedToken
        self._endpoint_tokens: Dict[str, Set[str]] = defaultdict(set)  # endpoint_hash -> set of token_hashes
        self._host_tokens: Dict[str, Set[str]] = defaultdict(set)  # host -> set of token_hashes

    def extract_tokens(
        self,
        flow: FlowRecord,
        triage: TriageSummary,
    ) -> List[HarvestedToken]:
        """Extract tokens from a flow's request headers, cookies, and response body.

        Returns newly discovered tokens (not duplicates).
        """
        new_tokens: List[HarvestedToken] = []
        method, host, path = self._get_path_and_host(flow)
        ep_hash = self._compute_endpoint_hash(method, host, path)

        headers = flow.request.headers if (flow.request and flow.request.headers) else {}
        cookies = flow.request.cookies if (flow.request and flow.request.cookies) else {}

        # 1. Extract from Authorization header
        auth_header = headers.get("authorization") or headers.get("Authorization") or ""
        if auth_header:
            token = self._extract_from_auth_header(auth_header, ep_hash, host)
            if token and token.token_hash not in self._tokens:
                self._tokens[token.token_hash] = token
                self._endpoint_tokens[ep_hash].add(token.token_hash)
                self._host_tokens[host].add(token.token_hash)
                new_tokens.append(token)

        # 2. Extract from other common token headers
        for hdr_name in ("x-api-key", "apikey", "x-auth-token", "x-csrf-token", "x-xsrf-token"):
            val = headers.get(hdr_name) or headers.get(hdr_name.title()) or ""
            if val and len(val) >= 16:
                token = self._check_api_key(val, ep_hash, host, hdr_name)
                if token and token.token_hash not in self._tokens:
                    self._tokens[token.token_hash] = token
                    self._endpoint_tokens[ep_hash].add(token.token_hash)
                    self._host_tokens[host].add(token.token_hash)
                    new_tokens.append(token)

        # 3. Extract from cookies
        for cookie_name, cookie_val in cookies.items():
            if cookie_name.lower() in _SESSION_COOKIE_NAMES and cookie_val and len(cookie_val) >= 8:
                token = HarvestedToken(
                    token_type="session_cookie",
                    token_preview=cookie_val[:20] + "..." if len(cookie_val) > 20 else cookie_val,
                    token_hash=self._hash_token(cookie_val),
                    source_endpoint=ep_hash,
                    source_host=host,
                    header_name="Cookie",
                    cookie_name=cookie_name,
                    context=f"cookie:{cookie_name}",
                )
                if token.token_hash not in self._tokens:
                    self._tokens[token.token_hash] = token
                    self._endpoint_tokens[ep_hash].add(token.token_hash)
                    self._host_tokens[host].add(token.token_hash)
                    new_tokens.append(token)

        # 4. Extract from response body (JWTs embedded in JSON responses)
        resp_body = flow.response.body if (flow.response and flow.response.body) else ""
        if isinstance(resp_body, str) and resp_body:
            for match in _JWT_PATTERN.finditer(resp_body):
                jwt_val = match.group(0)
                token = HarvestedToken(
                    token_type="jwt",
                    token_preview=jwt_val[:20] + "...",
                    token_hash=self._hash_token(jwt_val),
                    source_endpoint=ep_hash,
                    source_host=host,
                    header_name="response_body",
                    context="embedded_in_response",
                )
                if token.token_hash not in self._tokens:
                    self._tokens[token.token_hash] = token
                    self._endpoint_tokens[ep_hash].add(token.token_hash)
                    self._host_tokens[host].add(token.token_hash)
                    new_tokens.append(token)

        # 5. Extract from response headers (Set-Cookie, Authorization)
        resp_headers = flow.response.headers if (flow.response and flow.response.headers) else {}
        for hdr in ("set-cookie", "x-auth-token", "x-csrf-token"):
            val = resp_headers.get(hdr) or resp_headers.get(hdr.title()) or ""
            if val and len(val) >= 16:
                token = self._check_api_key(val.split(";")[0].strip(), ep_hash, host, f"response:{hdr}")
                if token and token.token_hash not in self._tokens:
                    self._tokens[token.token_hash] = token
                    self._endpoint_tokens[ep_hash].add(token.token_hash)
                    self._host_tokens[host].add(token.token_hash)
                    new_tokens.append(token)

        return new_tokens

    def get_replay_candidates(self, target_endpoint_hash: str) -> List[HarvestedToken]:
        """Return tokens from other endpoints that could be replayed against the target.

        Returns tokens that were NOT seen at the target endpoint but were seen
        at other endpoints on the same host.
        """
        target_tokens = self._endpoint_tokens.get(target_endpoint_hash, set())
        # Find the host for this target endpoint
        target_host = ""
        for token_hash in target_tokens:
            t = self._tokens.get(token_hash)
            if t:
                target_host = t.source_host
                break

        if not target_host:
            # Try to find host from any token that references this endpoint
            for t in self._tokens.values():
                if t.source_endpoint == target_endpoint_hash:
                    target_host = t.source_host
                    break

        if not target_host:
            return []

        # Get all tokens from the same host
        host_tokens = self._host_tokens.get(target_host, set())
        # Filter out tokens already seen at the target
        candidate_hashes = host_tokens - target_tokens
        return [self._tokens[h] for h in candidate_hashes if h in self._tokens]

    def get_token_count(self) -> int:
        return len(self._tokens)

    def get_endpoint_token_count(self, endpoint_hash: str) -> int:
        return len(self._endpoint_tokens.get(endpoint_hash, set()))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_from_auth_header(
        self, auth_value: str, ep_hash: str, host: str,
    ) -> Optional[HarvestedToken]:
        """Extract a token from an Authorization header value."""
        val = auth_value.strip()
        if val.lower().startswith("bearer "):
            token_val = val[7:].strip()
            if _JWT_PATTERN.match(token_val):
                return HarvestedToken(
                    token_type="jwt",
                    token_preview=token_val[:20] + "...",
                    token_hash=self._hash_token(token_val),
                    source_endpoint=ep_hash,
                    source_host=host,
                    header_name="Authorization",
                    context="bearer_jwt",
                )
            elif len(token_val) >= 16:
                return HarvestedToken(
                    token_type="bearer",
                    token_preview=token_val[:20] + "...",
                    token_hash=self._hash_token(token_val),
                    source_endpoint=ep_hash,
                    source_host=host,
                    header_name="Authorization",
                    context="bearer_token",
                )
        elif val.lower().startswith("basic "):
            token_val = val[6:].strip()
            if len(token_val) >= 16:
                return HarvestedToken(
                    token_type="basic_auth",
                    token_preview=token_val[:20] + "...",
                    token_hash=self._hash_token(token_val),
                    source_endpoint=ep_hash,
                    source_host=host,
                    header_name="Authorization",
                    context="basic_auth",
                )
        return None

    def _check_api_key(
        self, value: str, ep_hash: str, host: str, header_name: str,
    ) -> Optional[HarvestedToken]:
        """Check if a value looks like an API key."""
        for pattern in _API_KEY_PATTERNS:
            if pattern.match(value):
                return HarvestedToken(
                    token_type="api_key",
                    token_preview=value[:20] + "..." if len(value) > 20 else value,
                    token_hash=self._hash_token(value),
                    source_endpoint=ep_hash,
                    source_host=host,
                    header_name=header_name,
                    context="api_key",
                )
        # Generic high-entropy token
        if len(value) >= 32 and self._entropy(value) > 3.5:
            return HarvestedToken(
                token_type="generic_token",
                token_preview=value[:20] + "...",
                token_hash=self._hash_token(value),
                source_endpoint=ep_hash,
                source_host=host,
                header_name=header_name,
                context="high_entropy",
            )
        return None

    @staticmethod
    def _hash_token(value: str) -> str:
        import hashlib
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _entropy(value: str) -> float:
        """Calculate Shannon entropy of a string."""
        import math
        if not value:
            return 0.0
        freq: Dict[str, int] = defaultdict(int)
        for c in value:
            freq[c] += 1
        length = len(value)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    @staticmethod
    def _get_path_and_host(flow: FlowRecord) -> tuple:
        method = flow.request.method.upper() if flow.request else "GET"
        host = flow.server_host or "localhost"
        path = flow.request.path if flow.request else "/"
        return method, host, path

    @staticmethod
    def _compute_endpoint_hash(method: str, host: str, path: str) -> str:
        import hashlib
        raw = f"{method.upper()}:{host.lower()}:{path}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
