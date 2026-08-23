"""
JSON serialization utilities and custom type encoders.
"""

from __future__ import annotations

import base64
import datetime
import json
import uuid
from typing import Any
from pydantic import BaseModel


class FlowForgeJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder handling bytes, UUIDs, dates, and Pydantic models."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, bytes):
            try:
                return obj.decode("utf-8")
            except UnicodeDecodeError:
                return base64.b64encode(obj).decode("ascii")
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        if isinstance(obj, uuid.UUID):
            return str(obj)
        if isinstance(obj, BaseModel):
            return obj.model_dump()
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        return super().default(obj)


def json_dumps(obj: Any, **kwargs: Any) -> str:
    """Serialize object to JSON string with custom encoder."""
    kwargs.setdefault("cls", FlowForgeJSONEncoder)
    return json.dumps(obj, **kwargs)


def json_loads(s: str | bytes, **kwargs: Any) -> Any:
    """Deserialize JSON string or bytes."""
    if isinstance(s, bytes):
        s = s.decode("utf-8", errors="replace")
    return json.loads(s, **kwargs)
