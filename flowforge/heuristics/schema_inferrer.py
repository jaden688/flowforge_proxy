"""Dynamic JSON Schema Inferrer & Multi-Flow Schema Synthesizer (Requirement R2)."""

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class SchemaInferrer:
    """Infers JSON schemas from observed payloads and merges schemas across multiple flows."""

    FORMAT_PATTERNS = {
        "date-time": re.compile(
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
        ),
        "date": re.compile(r"^\d{4}-\d{2}-\d{2}$"),
        "uuid": re.compile(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-7][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
        ),
        "email": re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"),
        "ipv4": re.compile(
            r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
        ),
        "ipv6": re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"),
        "uri": re.compile(r"^[a-zA-Z][a-zA-Z0-9+-.]*://[^\s/$.?#].[^\s]*$"),
        "jwt": re.compile(r"^ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*$"),
    }

    def infer_payload_schema(self, payload: Union[str, bytes, Dict, List, Any]) -> Dict[str, Any]:
        """Infer complete JSON schema for an arbitrary payload."""
        if isinstance(payload, (bytes, bytearray)):
            try:
                payload = payload.decode("utf-8")
            except Exception:
                return {"type": "string", "contentMediaType": "application/octet-stream"}

        if isinstance(payload, str):
            payload_str = payload.strip()
            if payload_str.startswith(("{", "[")):
                try:
                    data = json.loads(payload_str)
                    return self.infer_value_schema(data)
                except Exception:
                    pass
            return self.infer_value_schema(payload)

        return self.infer_value_schema(payload)

    def infer_value_schema(self, value: Any, depth: int = 0) -> Dict[str, Any]:
        """Recursively infer JSON Schema for a Python value."""
        if depth > 20:
            return {"type": "string", "description": "Max recursion depth exceeded"}

        if value is None:
            return {"type": "null"}

        if isinstance(value, bool):
            return {"type": "boolean", "examples": [value]}

        if isinstance(value, int):
            return {
                "type": "integer",
                "minimum": value,
                "maximum": value,
                "examples": [value],
            }

        if isinstance(value, float):
            return {
                "type": "number",
                "minimum": value,
                "maximum": value,
                "examples": [value],
            }

        if isinstance(value, str):
            schema: Dict[str, Any] = {
                "type": "string",
                "minLength": len(value),
                "maxLength": len(value),
                "examples": [value[:100]],
            }
            fmt = self.infer_string_format(value)
            if fmt:
                schema["format"] = fmt
            return schema

        if isinstance(value, list):
            if not value:
                return {"type": "array", "items": {}, "minItems": 0, "maxItems": 0}

            item_schemas = [self.infer_value_schema(item, depth + 1) for item in value]
            merged_item_schema = self._merge_item_schemas(item_schemas)

            return {
                "type": "array",
                "items": merged_item_schema,
                "minItems": len(value),
                "maxItems": len(value),
            }

        if isinstance(value, dict):
            properties: Dict[str, Any] = {}
            required: List[str] = []

            for k, v in value.items():
                k_str = str(k)
                prop_schema = self.infer_value_schema(v, depth + 1)
                prop_schema["x-flowforge-observed-count"] = 1
                prop_schema["x-flowforge-frequency"] = 1.0
                properties[k_str] = prop_schema
                required.append(k_str)

            return {
                "type": "object",
                "properties": properties,
                "required": sorted(required),
                "additionalProperties": True,
            }

        return {"type": "string", "examples": [str(value)[:100]]}

    def infer_string_format(self, text: str) -> Optional[str]:
        """Detect string format pattern."""
        if not text or len(text) > 1000:
            return None

        for fmt, pattern in self.FORMAT_PATTERNS.items():
            if pattern.match(text):
                return fmt
        return None

    def merge_schemas(
        self,
        existing_schema: Optional[Dict[str, Any]],
        new_schema: Optional[Dict[str, Any]],
        sample_count: int = 1,
    ) -> Dict[str, Any]:
        """Merge two JSON schemas into a unified representation."""
        if not existing_schema:
            if isinstance(new_schema, dict):
                merged_copy = json.loads(json.dumps(new_schema))
                if merged_copy.get("type") == "object" and "properties" in merged_copy:
                    eff_samples = max(1, sample_count)
                    for _, p in merged_copy["properties"].items():
                        if isinstance(p, dict):
                            p.setdefault("x-flowforge-observed-count", 1)
                            p["x-flowforge-frequency"] = round(p["x-flowforge-observed-count"] / eff_samples, 4)
                return merged_copy
            return new_schema or {}

        if not new_schema:
            return existing_schema

        # Dual schema handling (request / response sections)
        if (
            isinstance(existing_schema, dict)
            and isinstance(new_schema, dict)
            and ("request" in existing_schema or "response" in existing_schema or "request" in new_schema or "response" in new_schema)
            and existing_schema.get("type") not in ("object", "array", "string", "number", "integer", "boolean", "null")
            and new_schema.get("type") not in ("object", "array", "string", "number", "integer", "boolean", "null")
        ):
            merged_dual: Dict[str, Any] = {}
            if "request" in existing_schema or "request" in new_schema:
                merged_dual["request"] = self.merge_schemas(
                    existing_schema.get("request"), new_schema.get("request"), sample_count
                )
            if "response" in existing_schema or "response" in new_schema:
                merged_dual["response"] = self.merge_schemas(
                    existing_schema.get("response"), new_schema.get("response"), sample_count
                )
            return merged_dual

        # Unify types
        t1 = existing_schema.get("type")
        t2 = new_schema.get("type")
        merged_type = self._unify_types(t1, t2)

        merged: Dict[str, Any] = {"type": merged_type}

        # Merge formats
        f1 = existing_schema.get("format")
        f2 = new_schema.get("format")
        if f1 == f2 and f1:
            merged["format"] = f1

        # Numerical boundaries
        min_vals = [
            v
            for v in [existing_schema.get("minimum"), new_schema.get("minimum")]
            if v is not None
        ]
        max_vals = [
            v
            for v in [existing_schema.get("maximum"), new_schema.get("maximum")]
            if v is not None
        ]
        if min_vals:
            merged["minimum"] = min(min_vals)
        if max_vals:
            merged["maximum"] = max(max_vals)

        # String boundaries
        min_len = [
            v
            for v in [existing_schema.get("minLength"), new_schema.get("minLength")]
            if v is not None
        ]
        max_len = [
            v
            for v in [existing_schema.get("maxLength"), new_schema.get("maxLength")]
            if v is not None
        ]
        if min_len:
            merged["minLength"] = min(min_len)
        if max_len:
            merged["maxLength"] = max(max_len)

        # Array items
        if "items" in existing_schema or "items" in new_schema:
            merged["items"] = self.merge_schemas(
                existing_schema.get("items", {}),
                new_schema.get("items", {}),
                sample_count,
            )
            min_items = [
                v
                for v in [existing_schema.get("minItems"), new_schema.get("minItems")]
                if v is not None
            ]
            max_items = [
                v
                for v in [existing_schema.get("maxItems"), new_schema.get("maxItems")]
                if v is not None
            ]
            if min_items:
                merged["minItems"] = min(min_items)
            if max_items:
                merged["maxItems"] = max(max_items)

        # Object properties
        if "properties" in existing_schema or "properties" in new_schema:
            p1 = existing_schema.get("properties", {}) if isinstance(existing_schema, dict) else {}
            p2 = new_schema.get("properties", {}) if isinstance(new_schema, dict) else {}
            all_keys = set(p1.keys()) | set(p2.keys())
            merged_props: Dict[str, Any] = {}

            # Required fields: only properties present in both schemas
            r1 = set(existing_schema.get("required", p1.keys() if p1 else []))
            r2 = set(new_schema.get("required", p2.keys() if p2 else []))
            merged_required = sorted(list(r1 & r2 & all_keys))

            for k in all_keys:
                s1 = p1.get(k)
                s2 = p2.get(k)
                merged_prop = self.merge_schemas(s1, s2, sample_count)

                # Track observation count & frequency across flows
                c1 = s1.get("x-flowforge-observed-count", 1 if s1 is not None else 0) if isinstance(s1, dict) else 0
                c2 = s2.get("x-flowforge-observed-count", 1 if s2 is not None else 0) if isinstance(s2, dict) else 0
                obs_count = max(1, c1 + c2)
                merged_prop["x-flowforge-observed-count"] = obs_count
                eff_samples = max(sample_count, obs_count)
                merged_prop["x-flowforge-frequency"] = round(obs_count / eff_samples, 4)

                merged_props[k] = merged_prop

            merged["properties"] = merged_props
            if merged_required:
                merged["required"] = merged_required
            merged["additionalProperties"] = True

        # Examples and enums
        ex1 = existing_schema.get("examples", []) if isinstance(existing_schema, dict) else []
        ex2 = new_schema.get("examples", []) if isinstance(new_schema, dict) else []
        combined_examples = list(dict.fromkeys(ex1 + ex2))[:10]
        if combined_examples:
            merged["examples"] = combined_examples

        # Enum detection
        if (
            len(combined_examples) >= 2
            and len(combined_examples) <= 8
            and sample_count >= 3
            and all(isinstance(x, (str, int, bool)) for x in combined_examples)
        ):
            merged["enum"] = combined_examples

        return merged

    def synthesize_endpoint_schema(
        self, schemas: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Synthesize a single canonical schema from a collection of observed flow schemas."""
        if not schemas:
            return {}

        result = schemas[0]
        for idx, s in enumerate(schemas[1:], start=2):
            result = self.merge_schemas(result, s, sample_count=idx)

        return result

    def _unify_types(
        self, t1: Union[str, List[str], None], t2: Union[str, List[str], None]
    ) -> Union[str, List[str]]:
        """Combine two types into a single type or type union list."""
        if not t1 and not t2:
            return "string"
        if not t1:
            return t2  # type: ignore
        if not t2:
            return t1

        types_set: Set[str] = set()
        for t in [t1, t2]:
            if isinstance(t, list):
                types_set.update(t)
            elif isinstance(t, str):
                types_set.add(t)

        # Numeric unification: if both integer and number are present, number covers integer
        if "integer" in types_set and "number" in types_set:
            types_set.remove("integer")

        if len(types_set) == 1:
            return list(types_set)[0]

        return sorted(list(types_set))

    def _merge_item_schemas(self, item_schemas: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge schemas of list items."""
        if not item_schemas:
            return {}

        result = item_schemas[0]
        for idx, s in enumerate(item_schemas[1:], start=2):
            result = self.merge_schemas(result, s, sample_count=idx)
        return result
