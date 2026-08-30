"""
Learned IDOR Pattern Tracker.

Observes integer ID sequences across intercepted flows and generates
contextually smarter IDOR mutations based on observed patterns:
- Sequential increments → next-1, next+1, boundary probes
- Random integers → neighboring values, 0, negative, overflow
- UUID patterns → null UUID, zero UUID
- Step patterns (e.g., 5,10,15) → extrapolated next value
"""

from __future__ import annotations

import hashlib
import logging
import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from flowforge.heuristics.models import (
    EndpointCategory,
    ExtractedParameter,
    IdentifierType,
    ParameterLocation,
    TriageSummary,
)
from flowforge.models.flow import FlowRecord
from flowforge.models.proposal import (
    AnomalyType,
    ProposalSeverity,
    ProposalState,
    TestProposal,
)

logger = logging.getLogger("flowforge.heuristics.idor_patterns")

_MAX_HISTORY_PER_PARAM = 100
_MIN_SAMPLES_FOR_STEP = 3


class IDORPatternTracker:
    """Tracks integer ID sequences per endpoint-parameter and generates smarter IDOR probes."""

    def __init__(self) -> None:
        # endpoint_key → param_name → list of observed integer values (ordered by time)
        self._history: Dict[str, Dict[str, List[int]]] = defaultdict(lambda: defaultdict(list))
        self._seen_endpoints: Set[str] = set()
        # Track which endpoint+param+pattern combinations have already generated proposals
        self._generated: Set[str] = set()

    def _endpoint_key(self, flow: FlowRecord) -> str:
        method = flow.request.method.upper() if flow.request else "GET"
        host = flow.server_host or "localhost"
        path = flow.request.path if flow.request else "/"
        # Normalize: replace integer path segments with {id} placeholder
        normalized_segments = []
        for seg in path.strip("/").split("/"):
            if seg.isdigit():
                normalized_segments.append("{id}")
            else:
                normalized_segments.append(seg)
        normalized_path = "/" + "/".join(normalized_segments) if normalized_segments else "/"
        return f"{method}:{host}:{normalized_path}"

    def _param_key(self, param_name: str, location: str) -> str:
        return f"{location}:{param_name}"

    def observe_flow(self, flow: FlowRecord, triage: TriageSummary) -> None:
        """Record integer ID values observed in this flow for pattern learning."""
        ep_key = self._endpoint_key(flow)

        for param in triage.parameters:
            raw_val = param.value if param.value is not None else param.raw_value
            if isinstance(raw_val, int):
                pk = self._param_key(param.name, str(param.location.value if hasattr(param.location, "value") else param.location))
                hist = self._history[ep_key][pk]
                hist.append(raw_val)
                if len(hist) > _MAX_HISTORY_PER_PARAM:
                    hist.pop(0)

            # Also check path segments
        if flow.request and flow.request.path:
            segments = flow.request.path.strip("/").split("/")
            for idx, seg in enumerate(segments):
                if seg.isdigit():
                    parent = segments[idx - 1] if idx > 0 else "id"
                    pk = self._param_key(parent, "path")
                    hist = self._history[ep_key][pk]
                    hist.append(int(seg))
                    if len(hist) > _MAX_HISTORY_PER_PARAM:
                        hist.pop(0)

    def _detect_pattern(self, values: List[int]) -> str:
        """Detect the dominant pattern in a sequence of integer IDs.

        Returns: 'sequential', 'step', 'random', 'single'
        """
        if len(values) < 2:
            return "single"

        diffs = [values[i + 1] - values[i] for i in range(len(values) - 1)]

        if all(d == diffs[0] for d in diffs):
            if diffs[0] == 1:
                return "sequential"
            return "step"

        # Check if diffs are constant within tolerance (monotonically increasing)
        if len(set(diffs)) <= 3 and all(d > 0 for d in diffs):
            return "step"

        return "random"

    def _extrapolate_next(self, values: List[int], pattern: str) -> List[int]:
        """Generate the most likely next IDs based on the detected pattern."""
        if not values:
            return []

        candidates: List[int] = []

        if pattern == "sequential":
            last = values[-1]
            candidates = [last + 1, last + 2, last - 1, max(0, last - 1)]

        elif pattern == "step":
            if len(values) >= 2:
                avg_step = (values[-1] - values[0]) / (len(values) - 1)
                step = max(1, round(avg_step))
                next_val = values[-1] + step
                candidates = [next_val, next_val + step, values[-1] - step]
            else:
                candidates = [values[-1] + 1, values[-1] - 1]

        elif pattern == "random":
            last = values[-1]
            # Random IDs: test 0, -1, small, and nearby values
            nearby = set()
            for v in values[-5:]:
                nearby.add(v + 1)
                nearby.add(v - 1)
            candidates = [0, -1, 1] + sorted(nearby)[:3]

        else:
            candidates = [0, 1, values[-1] + 1]

        # Always include boundary probes
        candidates.extend([0, -1, 999999999])
        return list(dict.fromkeys(candidates))  # dedup preserving order

    def generate_learned_idor_proposals(
        self,
        flow: FlowRecord,
        triage: TriageSummary,
        ep_hash: str,
    ) -> List[TestProposal]:
        """Generate IDOR probes informed by learned patterns across flows."""
        proposals: List[TestProposal] = []
        ep_key = self._endpoint_key(flow)
        method = flow.request.method.upper() if flow.request else "GET"
        path = flow.request.path if flow.request else "/"

        is_auth = "auth" in triage.tags or any(
            k.lower() in ("authorization", "cookie")
            for k in (flow.request.headers if flow.request else {})
        )
        default_sev = ProposalSeverity.HIGH if is_auth else ProposalSeverity.MEDIUM

        param_history = self._history.get(ep_key, {})

        for pk, values in param_history.items():
            if len(values) < _MIN_SAMPLES_FOR_STEP:
                continue

            # Skip if all values are identical — no useful pattern to learn
            if len(set(values)) < 2:
                continue

            location_str, param_name = pk.split(":", 1)
            pattern = self._detect_pattern(values)

            # Only generate learned proposals once per endpoint+param+pattern
            gen_key = f"{ep_key}|{pk}|{pattern}"
            if gen_key in self._generated:
                continue
            self._generated.add(gen_key)

            candidates = self._extrapolate_next(values, pattern)

            # Get the representative baseline value
            baseline_val = values[-1]

            for idx, cand in enumerate(candidates[:5]):
                conf = 80.0 - (idx * 5)
                if pattern == "sequential":
                    conf += 5  # Higher confidence for sequential patterns

                desc_parts = [
                    f"Learned pattern analysis on '{param_name}': observed sequence {values[-5:]} "
                    f"detected as '{pattern}'.",
                    f"Extrapolated candidate value: {cand}.",
                ]

                proposals.append(TestProposal(
                    flow_id=flow.id,
                    endpoint_hash=ep_hash,
                    endpoint_path=path,
                    method=method,
                    anomaly_type=AnomalyType.IDOR_SEQUENTIAL,
                    title=f"Learned IDOR ({pattern.title()}) [{param_name}={cand}]",
                    description=" ".join(desc_parts),
                    severity=default_sev,
                    confidence_score=min(95.0, max(60.0, conf)),
                    target_param_name=param_name,
                    target_param_location=location_str,
                    baseline_value=baseline_val,
                    mutated_value=cand,
                    state=ProposalState.PENDING,
                    tags=["idor", "learned_pattern", pattern, f"observed_{len(values)}_flows"],
                ))

        return proposals
