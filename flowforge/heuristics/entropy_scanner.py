"""Shannon entropy token scanner, secret signature library & JWT security inspector (Requirement R2)."""

import base64
import json
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from flowforge.heuristics.models import (
    ExtractedParameter,
    FindingSeverity,
    ParameterLocation,
    SecretFinding,
)


class EntropyScanner:
    """Calculates Shannon entropy and matches deterministic secret patterns in flows."""

    SECRET_SIGNATURES: List[Tuple[str, re.Pattern, FindingSeverity]] = [
        (
            "AWS_ACCESS_KEY",
            re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
            FindingSeverity.CRITICAL,
        ),
        (
            "AWS_SECRET_KEY",
            re.compile(r"(?i)aws(.{0,20})?['\"]([0-9a-zA-Z/+]{40})['\"]"),
            FindingSeverity.CRITICAL,
        ),
        (
            "GITHUB_PAT_CLASSIC",
            re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"),
            FindingSeverity.CRITICAL,
        ),
        (
            "GITHUB_FINE_GRAINED",
            re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b"),
            FindingSeverity.CRITICAL,
        ),
        (
            "GITHUB_OAUTH",
            re.compile(r"\bgho_[0-9a-zA-Z]{36}\b"),
            FindingSeverity.CRITICAL,
        ),
        (
            "STRIPE_SECRET_KEY",
            re.compile(r"\b(sk|rk)_live_[0-9a-zA-Z]{24,99}\b"),
            FindingSeverity.CRITICAL,
        ),
        (
            "STRIPE_PUBLISHABLE",
            re.compile(r"\bpk_live_[0-9a-zA-Z]{24,99}\b"),
            FindingSeverity.LOW,
        ),
        (
            "SLACK_BOT_TOKEN",
            re.compile(r"\bxoxb-[0-9]{11,13}-[0-9]{11,13}-[0-9a-zA-Z]{24}\b"),
            FindingSeverity.HIGH,
        ),
        (
            "SLACK_USER_TOKEN",
            re.compile(r"\bxoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9a-zA-Z]{24}\b"),
            FindingSeverity.HIGH,
        ),
        (
            "GOOGLE_API_KEY",
            re.compile(r"\bAIza[0-9A-Za-z\-_]{35,45}\b"),
            FindingSeverity.HIGH,
        ),
        (
            "PRIVATE_KEY_PEM",
            re.compile(r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED)\s+)?(?:PRIVATE\s+)?KEY-----"),
            FindingSeverity.CRITICAL,
        ),
        (
            "GENERIC_API_KEY",
            re.compile(
                r'(?i)(?:api[_-]?key|secret|auth[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,128})["\']'
            ),
            FindingSeverity.HIGH,
        ),
        (
            "JWT_TOKEN",
            re.compile(
                r"\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*)\b"
            ),
            FindingSeverity.INFO,
        ),
    ]

    def __init__(self):
        self.hex_pattern = re.compile(r"^[0-9a-fA-F]+$")
        self.b64_pattern = re.compile(r"^[A-Za-z0-9+/=_-]+$")

    def shannon_entropy(self, text: str) -> float:
        """Compute standard Shannon entropy H(S) = -sum(p * log2(p))."""
        if not text:
            return 0.0

        length = len(text)
        freqs: Dict[str, int] = {}
        for char in text:
            freqs[char] = freqs.get(char, 0) + 1

        entropy = 0.0
        for count in freqs.values():
            p = count / length
            entropy -= p * math.log2(p)

        return round(entropy, 3)

    def is_high_entropy_token(self, text: str) -> Tuple[bool, float]:
        """Check if string exhibits high Shannon entropy normalized across alphabet."""
        if not text or len(text) < 16:
            return False, 0.0

        entropy = self.shannon_entropy(text)
        length = len(text)

        # Hexadecimal string
        if self.hex_pattern.match(text):
            if length >= 32 and entropy >= 3.0:
                return True, entropy
            return False, entropy

        # Base64 or URL-safe Base64
        if self.b64_pattern.match(text):
            if length >= 20 and entropy >= 4.5:
                return True, entropy
            if length >= 24 and entropy >= 4.2:
                return True, entropy

        # General alphanumeric
        if length >= 24 and entropy >= 4.3:
            return True, entropy

        return False, entropy

    def scan_secrets(
        self,
        parameters: List[ExtractedParameter],
        flow: Any = None,
    ) -> List[SecretFinding]:
        """Scan parameters and flow bodies for known secret signatures and high-entropy tokens."""
        findings: List[SecretFinding] = []
        seen_masked: Set[str] = set()

        # 1. Scan extracted parameters
        for param in parameters:
            raw_val = param.raw_value or (str(param.value) if param.value is not None else "")
            if not raw_val or len(raw_val) < 8:
                continue

            param.entropy = self.shannon_entropy(raw_val)

            # Check known signatures
            for sec_type, pattern, severity in self.SECRET_SIGNATURES:
                match = pattern.search(raw_val)
                if match:
                    matched_str = match.group(0)
                    masked = self.mask_secret(matched_str)
                    if masked not in seen_masked:
                        seen_masked.add(masked)
                        findings.append(
                            SecretFinding(
                                secret_type=sec_type,
                                severity=severity,
                                matched_pattern=pattern.pattern,
                                masked_value=masked,
                                location=param.location,
                                entropy=param.entropy,
                            )
                        )

            # Check high entropy token
            is_high, ent = self.is_high_entropy_token(raw_val)
            if is_high and not any(f.masked_value == self.mask_secret(raw_val) for f in findings):
                masked = self.mask_secret(raw_val)
                if masked not in seen_masked:
                    seen_masked.add(masked)
                    findings.append(
                        SecretFinding(
                            secret_type="HIGH_ENTROPY_TOKEN",
                            severity=FindingSeverity.LOW if param.location == ParameterLocation.HEADER else FindingSeverity.MEDIUM,
                            matched_pattern="Shannon Entropy >= 4.2",
                            masked_value=masked,
                            location=param.location,
                            entropy=ent,
                        )
                    )

        # 2. Scan flow bodies directly if provided
        if flow:
            req_body = getattr(flow, "request_body", "") or ""
            resp_body = getattr(flow, "response_body", "") or ""

            for body, loc in (
                (req_body, ParameterLocation.BODY_JSON),
                (resp_body, ParameterLocation.BODY_JSON),
            ):
                body_str = (
                    body.decode("utf-8", errors="replace")
                    if isinstance(body, (bytes, bytearray))
                    else str(body or "")
                )
                if not body_str:
                    continue

                for sec_type, pattern, severity in self.SECRET_SIGNATURES:
                    # Skip JWT in body unless secret
                    if sec_type == "JWT_TOKEN":
                        continue

                    for match in pattern.finditer(body_str):
                        matched_str = match.group(0)
                        masked = self.mask_secret(matched_str)
                        if masked not in seen_masked:
                            seen_masked.add(masked)
                            ent = self.shannon_entropy(matched_str)
                            findings.append(
                                SecretFinding(
                                    secret_type=sec_type,
                                    severity=severity,
                                    matched_pattern=pattern.pattern,
                                    masked_value=masked,
                                    location=loc,
                                    entropy=ent,
                                )
                            )

        return findings

    def inspect_jwt(self, jwt_str: str) -> Dict[str, Any]:
        """Decode and inspect JWT header, claims, and security flags."""
        parts = jwt_str.strip().split(".")
        if len(parts) != 3:
            return {"valid": False, "error": "Invalid JWT structure (must have 3 segments)"}

        header_b64, payload_b64, sig_b64 = parts
        header: Dict[str, Any] = {}
        payload: Dict[str, Any] = {}
        security_flags: List[str] = []

        try:
            h_pad = header_b64 + "=" * (-len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(h_pad.encode("utf-8")).decode("utf-8"))
        except Exception as e:
            return {"valid": False, "error": f"Header decode error: {e}"}

        try:
            p_pad = payload_b64 + "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(p_pad.encode("utf-8")).decode("utf-8"))
        except Exception as e:
            return {"valid": False, "error": f"Payload decode error: {e}"}

        # Check algorithm
        alg = header.get("alg", "").lower()
        if alg == "none" or not sig_b64:
            security_flags.append("ALG_NONE_FORGERY_RISK")

        # Check jku / x5u SSRF vectors
        if "jku" in header:
            security_flags.append("JKU_HEADER_INJECTION_RISK")
        if "x5u" in header:
            security_flags.append("X5U_HEADER_INJECTION_RISK")

        # Check kid traversal
        kid = header.get("kid", "")
        if isinstance(kid, str) and ("../" in kid or "'" in kid or '"' in kid):
            security_flags.append("KID_INJECTION_RISK")

        # Extract role claims
        roles: List[str] = []
        for rk in ("role", "roles", "groups", "scope", "permissions", "isAdmin", "is_admin", "admin"):
            if rk in payload:
                roles.append(f"{rk}={payload[rk]}")

        return {
            "valid": True,
            "header": header,
            "payload": payload,
            "security_flags": security_flags,
            "algorithm": header.get("alg"),
            "subject": payload.get("sub"),
            "issuer": payload.get("iss"),
            "audience": payload.get("aud"),
            "expiration": payload.get("exp"),
            "issued_at": payload.get("iat"),
            "roles": roles,
        }

    def mask_secret(self, secret: str) -> str:
        """Mask secret string showing only prefix and suffix."""
        if not secret:
            return ""
        if len(secret) <= 8:
            return "****"
        if len(secret) <= 16:
            return f"{secret[:3]}...{secret[-3:]}"
        return f"{secret[:4]}...{secret[-4:]}"
