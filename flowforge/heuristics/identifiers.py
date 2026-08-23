"""Identifier classification and IDOR risk scoring engine (Requirement R2)."""

import re
from typing import Any, Dict, List, Optional, Tuple

from flowforge.heuristics.models import (
    ExtractedParameter,
    IdentifierFinding,
    IdentifierType,
    ParameterLocation,
)


class IdentifierClassifier:
    """Classifies identifier predictability and calculates composite IDOR risk scores."""

    IDENTIFIER_REGEXES: List[Tuple[IdentifierType, re.Pattern, float]] = [
        # Sequential Integer (1 to 10 digits)
        (
            IdentifierType.SEQUENTIAL_INTEGER,
            re.compile(r"^\d{1,10}$"),
            1.00,
        ),
        # Monotonic Snowflake / Timestamp ID (15 to 20 digits)
        (
            IdentifierType.MONOTONIC_TIMESTAMP,
            re.compile(r"^\d{15,20}$"),
            0.85,
        ),
        # Mongo ObjectId (24 hex characters)
        (
            IdentifierType.MONGO_OBJECT_ID,
            re.compile(r"^[0-9a-fA-F]{24}$"),
            0.75,
        ),
        # UUID v1 (time-based)
        (
            IdentifierType.UUID_V1,
            re.compile(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-1[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
            ),
            0.65,
        ),
        # ULID (26 Crockford Base32 characters)
        (
            IdentifierType.ULID,
            re.compile(r"^[0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyz]{26}$"),
            0.55,
        ),
        # UUID v7 (time-ordered)
        (
            IdentifierType.UUID_V7,
            re.compile(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
            ),
            0.50,
        ),
        # UUID v4 (random)
        (
            IdentifierType.UUID_V4,
            re.compile(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
            ),
            0.15,
        ),
        # Hex Hash Digest (MD5=32, SHA1=40, SHA256=64)
        (
            IdentifierType.HASH_DIGEST,
            re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$"),
            0.10,
        ),
        # Short Opaque Slug (6-12 alphanumeric/dash/underscore)
        (
            IdentifierType.SHORT_OPAQUE_SLUG,
            re.compile(r"^[a-zA-Z0-9_-]{6,12}$"),
            0.40,
        ),
    ]

    LOCATION_WEIGHTS: Dict[ParameterLocation, float] = {
        ParameterLocation.PATH: 1.00,
        ParameterLocation.QUERY: 0.90,
        ParameterLocation.BODY_JSON: 0.80,
        ParameterLocation.BODY_FORM: 0.80,
        ParameterLocation.BODY_GRAPHQL: 0.80,
        ParameterLocation.BODY_MULTIPART: 0.70,
        ParameterLocation.BODY_XML: 0.70,
        ParameterLocation.HEADER: 0.70,
        ParameterLocation.COOKIE: 0.50,
    }

    METHOD_WEIGHTS: Dict[str, float] = {
        "DELETE": 1.00,
        "PUT": 1.00,
        "PATCH": 1.00,
        "POST": 0.85,
        "GET": 0.90,
        "HEAD": 0.10,
        "OPTIONS": 0.10,
    }

    IDENTIFIER_NAME_HINTS = {
        "id",
        "user_id",
        "account_id",
        "org_id",
        "team_id",
        "customer_id",
        "order_id",
        "file_id",
        "doc_id",
        "item_id",
        "record_id",
        "uuid",
        "guid",
        "uid",
        "pk",
        "key",
        "slug",
    }

    def classify_identifier(self, value: str, param_name: str = "") -> Tuple[IdentifierType, float]:
        """Classify value into identifier type and return type weight (W_type)."""
        if not value:
            return IdentifierType.UNKNOWN, 0.0

        val_str = str(value).strip()
        lower_name = param_name.lower().replace("-", "_").replace(".", "_")

        # Check regex rules in order
        for id_type, pattern, w_type in self.IDENTIFIER_REGEXES:
            if pattern.match(val_str):
                # If short slug, only classify as identifier if parameter name suggests an ID
                if id_type == IdentifierType.SHORT_OPAQUE_SLUG:
                    if any(hint in lower_name for hint in self.IDENTIFIER_NAME_HINTS):
                        return id_type, w_type
                    continue
                return id_type, w_type

        return IdentifierType.UNKNOWN, 0.0

    def compute_idor_score(
        self,
        id_type: IdentifierType,
        type_weight: float,
        location: ParameterLocation,
        method: str,
        is_authenticated: bool = True,
        param_name: str = "",
    ) -> float:
        """Calculate composite IDOR risk score: W_type * W_loc * W_method * W_auth."""
        if id_type == IdentifierType.UNKNOWN or type_weight <= 0.0:
            return 0.0

        w_loc = self.LOCATION_WEIGHTS.get(location, 0.70)
        w_method = self.METHOD_WEIGHTS.get(method.upper(), 0.80)
        w_auth = 1.00 if is_authenticated else 0.30

        score = type_weight * w_loc * w_method * w_auth

        # Name hint boost
        lower_name = param_name.lower().replace("-", "_").replace(".", "_")
        if any(hint in lower_name for hint in ("user_id", "account_id", "org_id", "id")):
            score = min(1.0, score * 1.1)

        return round(score, 3)

    def analyze_parameters(
        self,
        parameters: List[ExtractedParameter],
        method: str = "GET",
        is_authenticated: bool = True,
        canonical_pattern: str = "",
    ) -> List[IdentifierFinding]:
        """Classify identifiers in parameters and generate IDOR findings."""
        findings: List[IdentifierFinding] = []
        is_mutation = method.upper() in ("POST", "PUT", "PATCH", "DELETE")

        for param in parameters:
            raw_val = param.raw_value or (str(param.value) if param.value is not None else "")
            if not raw_val:
                continue

            id_type, w_type = self.classify_identifier(raw_val, param.name)
            if id_type != IdentifierType.UNKNOWN:
                param.identifier_type = id_type
                idor_score = self.compute_idor_score(
                    id_type,
                    w_type,
                    param.location,
                    method,
                    is_authenticated,
                    param.name,
                )
                param.idor_score = idor_score

                findings.append(
                    IdentifierFinding(
                        parameter_name=param.name,
                        location=param.location,
                        raw_value=raw_val,
                        id_type=id_type,
                        idor_risk_score=idor_score,
                        is_mutation=is_mutation,
                        canonical_pattern=canonical_pattern or param.name,
                    )
                )

        return findings
