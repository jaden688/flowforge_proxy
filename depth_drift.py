from __future__ import annotations

import json
from typing import Any, Dict, List, Set

from flowforge.heuristics.schema_inferrer import SchemaInferrer


class DepthDriftEngine:
    """Exploits depth-limit fallbacks + cumulative merge to corrupt canonical schemas.

    The engine alternates between two payload structural modes:
    - MODE_DEEP: Nested objects exceeding recursion depth 20, inducing
      "Max recursion depth exceeded" type fallbacks in inner levels.
    - MODE_SHALLOW: Same key paths with different required fields, causing
      the merge engine's intersection logic (r1 & r2 & all_keys) to erode
      required fields across flows.
    """

    # Indices into MODE_PAYLOADS
    MODE_DEEP = 0
    MODE_SHALLOW = 1

    # Alternating payload profiles: each is a dict constructor that produces
    # a nested structure with the same key paths but different required sets.
    MODE_PAYLOADS: List[Any] = []

    def __init__(self, max_depth: int = 20, n_levels: int = 25) -> None:
        self.inferrer = SchemaInferrer()
        self.max_depth = max_depth
        self.n_levels = n_levels
        self.canonical: Dict[str, Any] = {}
        self.flow_count = 0
        self.mode_idx = 0  # cycles MODE_DEEP, MODE_SHALLOW

    def _make_deep_payload(self, depth: int = None) -> Dict[str, Any]:
        """Generate a nested object that exceeds the inference depth limit.

        When depth > max_depth, the innermost level gets
        {"type": "string", "description": "Max recursion depth exceeded"}.
        """
        if depth is None:
            depth = self.n_levels
        if depth <= 0:
            return 42  # scalar, infers as integer
        key = f"level_{depth}"
        return {key: self._make_deep_payload(depth - 1)}

    def _make_shallow_payload(self) -> Dict[str, Any]:
        """Generate a 2-level deep payload with selective required fields.

        Structure: {"outer": {"inner": <value>}}
        The 'inner' key is required in some flows, optional in others,
        causing the merge engine's required-intersection to erode it.
        """
        inner_val = 99  # integer, infers as {"type": "integer", ...}
        return {"outer": {"inner": inner_val}}

    def inject_flow(self, payload: Any = None, mode: int = None) -> Dict[str, Any]:
        """Inject a flow payload and merge its inferred schema into the canonical schema.

        mode: 0 = MODE_DEEP (depth-exceeded fallbacks), 1 = MODE_SHALLOW
          (different required sets for erosion).
        """
        if mode is None:
            mode = self.mode_idx
        if payload is None:
            if mode == self.MODE_DEEP:
                payload = self._make_deep_payload()
            else:
                payload = self._make_shallow_payload()

        schema = self.inferrer.infer_value_schema(payload, depth=0)
        self.flow_count += 1
        self.mode_idx = 1 - self.mode_idx  # toggle for next flow
        sample_count = self.flow_count
        self.canonical = self.inferrer.merge_schemas(
            self.canonical, schema, sample_count=sample_count
        )
        return self.canonical

    @property
    def state(self) -> Dict[str, Any]:
        return {
            "flow_count": self.flow_count,
            "canonical": json.loads(json.dumps(self.canonical)),
            "type": self.canonical.get("type"),
            "required": self.canonical.get("required", []),
            "frequency": self.canonical.get("x-flowforge-frequency", 0),
            "observed_count": self.canonical.get("x-flowforge-observed-count", 0),
        }