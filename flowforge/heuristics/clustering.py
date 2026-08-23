"""State-mutation clustering and canonical route normalizer (Requirement R2)."""

import re
from typing import Any, List, Optional
from flowforge.heuristics.models import EndpointCategory


class EndpointClassifier:
    """Classifies endpoints into functional security categories based on method, path, and body."""

    AUTH_KEYWORDS = {
        "login",
        "logout",
        "auth",
        "oauth",
        "session",
        "token",
        "signup",
        "register",
        "password",
        "mfa",
        "2fa",
        "sso",
        "verify",
        "reset_password",
        "forgot_password",
    }

    ADMIN_KEYWORDS = {
        "admin",
        "manage",
        "superadmin",
        "settings",
        "system",
        "audit",
        "permissions",
        "roles",
        "config",
        "tenant_admin",
        "internal",
    }

    FILE_KEYWORDS = {
        "upload",
        "download",
        "export",
        "import",
        "attachment",
        "avatar",
        "file",
        "media",
        "document",
        "backup",
        "dump",
    }

    TELEMETRY_KEYWORDS = {
        "health",
        "healthz",
        "ping",
        "metrics",
        "ready",
        "status",
        "live",
        "info",
        "version",
        "heartbeat",
    }

    MUTATION_VERBS = {
        "create",
        "update",
        "delete",
        "toggle",
        "execute",
        "submit",
        "save",
        "edit",
        "remove",
        "add",
        "modify",
        "action",
        "cancel",
        "approve",
        "reject",
        "apply",
    }

    def classify(
        self,
        method: str,
        path: str,
        status_code: int = 200,
        content_type: str = "",
        request_body: Any = None,
    ) -> EndpointCategory:
        """Classify endpoint into one of the 6 security categories."""
        m = (method or "GET").upper()
        p = (path or "").lower().strip("/")
        ct = (content_type or "").lower()
        segments = [s for s in re.split(r"[/._-]", p) if s]

        # 1. Telemetry / Health Check
        if any(seg in self.TELEMETRY_KEYWORDS for seg in segments):
            return EndpointCategory.TELEMETRY_HEALTH

        # 2. Authentication & Session
        if any(seg in self.AUTH_KEYWORDS for seg in segments):
            return EndpointCategory.AUTH_SESSION

        # 3. Admin & Management
        if any(seg in self.ADMIN_KEYWORDS for seg in segments):
            return EndpointCategory.ADMIN_MANAGEMENT

        # 4. File Transfer
        if any(seg in self.FILE_KEYWORDS for seg in segments) or "multipart" in ct or "octet-stream" in ct:
            return EndpointCategory.FILE_TRANSFER

        # 5. Mutation Action (POST, PUT, PATCH, DELETE or action verbs in path)
        if m in ("POST", "PUT", "PATCH", "DELETE"):
            return EndpointCategory.MUTATION_ACTION

        if any(seg in self.MUTATION_VERBS for seg in segments):
            return EndpointCategory.MUTATION_ACTION

        # 6. Default: Data Read
        return EndpointCategory.DATA_READ


class RouteNormalizer:
    """Normalizes parameterized URLs into unified canonical route patterns."""

    def __init__(self):
        self.uuid_regex = re.compile(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-7][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
        )
        self.object_id_regex = re.compile(r"^[0-9a-fA-F]{24}$")
        self.hash_regex = re.compile(r"^[0-9a-fA-F]{32,64}$")
        self.int_regex = re.compile(r"^\d+$")
        self.slug_id_regex = re.compile(r"^[a-zA-Z]{1,8}[-_]\d+$", re.IGNORECASE)

    def normalize(self, path: str) -> str:
        """Convert variable slugs in path to parameterized canonical template."""
        if not path:
            return "/"

        # Strip query string and fragment
        clean_path = path.split("?")[0].split("#")[0].strip()
        if not clean_path.startswith("/"):
            clean_path = "/" + clean_path

        segments = [s for s in clean_path.split("/") if s]
        normalized_segments: List[str] = []

        for seg in segments:
            if self.int_regex.match(seg):
                normalized_segments.append("{integer_id}")
            elif self.slug_id_regex.match(seg):
                normalized_segments.append("{id}")
            elif self.uuid_regex.match(seg):
                normalized_segments.append("{uuid}")
            elif self.object_id_regex.match(seg):
                normalized_segments.append("{object_id}")
            elif self.hash_regex.match(seg):
                normalized_segments.append("{hash}")
            else:
                normalized_segments.append(seg)


        return "/" + "/".join(normalized_segments)

    def canonical_endpoint(self, method: str, path: str) -> str:
        """Produce full canonical endpoint string e.g. 'GET /api/v1/users/{integer_id}'."""
        norm_path = self.normalize(path)
        m = (method or "GET").upper()
        return f"{m} {norm_path}"
