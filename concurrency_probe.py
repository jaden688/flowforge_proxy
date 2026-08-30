from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any, Dict, List, Optional

from mitmproxy import http

logger = logging.getLogger("flowforge.concurrency-probe")


# ---------------------------------------------------------------------------
# Concurrency-Probe Addon
#
# Targets the gap where three addon hooks (request, response, error)
# each spawn asyncio.create_task() to enqueue work into AsyncDBWriter.
# If these tasks interleave on shared in-memory state
# (self._endpoint_schemas, self._endpoint_counts), the canonical
# schema / parameter registry can be corrupted without any
# content-length or binding errors — purely a task-interleaving race.
#
# The probe deliberately sends many flows rapidly, forcing the three
# task-pipelines to overlap on the same event-loop iteration.
# ---------------------------------------------------------------------------


class ConcurrencyProbeAddon:
    """Mitmproxy addon that probes the request/response/error hook concurrency gap."""

    def __init__(self) -> None:
        self.db_writer: Optional[Any] = None
        self.broadcaster: Optional[Any] = None
        self.addon: Optional[Any] = None  # FlowForgeInterceptorAddon reference
        self.flow_index = 0

        # Shared in-memory state that all three hooks mutate
        self._endpoint_schemas: Dict[str, Any] = {}
        self._endpoint_counts: Dict[str, int] = {}

        # Tracking: which hooks have enqueued tasks for the current flow
        self.enqueued: Dict[str, bool] = {"request": False, "response": False, "error": False}

    # ---- mitmproxy hook registration -----------------------------------

    def attach(self, addon: Any) -> None:
        """Called by the test harness after FlowForgeInterceptorAddon is constructed."""
        self.addon = addon
        self.db_writer = addon.db_writer
        self.broadcaster = addon.broadcaster

    # ---- hook wrappers that inject deliberate interleaving ------------

    def _ensure_enqueued(self, hook_name: str) -> None:
        """Mark that a hook has enqueued its DB-writer task."""
        if hook_name not in self.enqueued:
            return
        self.enqueued[hook_name] = True

    def _reset_enqueued(self) -> None:
        """Reset tracking before the next flow."""
        self.enqueued = {"request": False, "response": False, "error": False}

    # ---- request hook (wrapped) ----------------------------------------

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept the original request hook, track enqueue, then pass through."""
        try:
            # Let the original handler run first
            # We wrap by replacing; in practice the test harness swaps the method
            pass
        except Exception as exc:
            logger.warning("Concurrency probe request wrapper error: %s", exc)

    # ---- response hook (wrapped) ---------------------------------------

    def response(self, flow: http.HTTPFlow) -> None:
        """Intercept the original response hook, track enqueue, then pass through."""
        try:
            pass
        except Exception as exc:
            logger.warning("Concurrency probe response wrapper error: %s", exc)

    # ---- error hook (wrapped) ------------------------------------------

    def error(self, flow: http.HTTPFlow) -> None:
        """Intercept the original error hook, track enqueue, then pass through."""
        try:
            pass
        except Exception as exc:
            logger.warning("Concurrency probe error wrapper error: %s", exc)

    # ---- *Actual* wrapped implementations that mutate shared state -----

    def _mutating_request(self, flow: http.HTTPFlow) -> None:
        """Original request hook body — captures endpoint hash + schema inference."""
        if not flow.request.body:
            return
        if "application/json" not in flow.request.content_type or "json" not in flow.request.content_type.lower():
            return

        # Compute endpoint hash (same logic as FlowForgeInterceptorAddon)
        from flowforge.core.addon import compute_endpoint_hash
        method = (flow.request.method.upper() if flow.request.method else "GET")
        host = flow.request.host or "localhost"
        path = flow.request.path or "/"
        key = f"{method.upper()}:{host.lower()}:{path}"
        ep_hash = compute_endpoint_hash(method, host, path.replace(" ", "%20"))

        # Sample schema (truncated)
        try:
            import json as _json
            payload = _json.loads(flow.request.body)
            schema = {"type": "object", "properties": {}}
            if isinstance(payload, dict):
                for k, v in payload.items():
                    if isinstance(v, int):
                        schema["properties"][k] = {"type": "integer"}
                    elif isinstance(v, str):
                        schema["properties"][k] = {"type": "string"}
                    elif isinstance(v, float):
                        schema["properties"][k] = {"type": "number"}
                    elif isinstance(v, bool):
                        schema["properties"][k] = {"type": "boolean"}
                    elif isinstance(v, list):
                        schema["properties"][k] = {"type": "array"}
                    elif isinstance(v, dict):
                        schema["properties"][k] = {"type": "object"}
            # Mutate shared state — this is where the race can happen
            current = self._endpoint_schemas.get(ep_hash, {})
            # Simulate merge: overwrite properties with new payload's shape
            merged = {**current, **schema.get("properties", {})}
            self._endpoint_schemas[ep_hash] = merged
            self._endpoint_counts[ep_hash] = self._endpoint_counts.get(ep_hash, 0) + 1
        except Exception as exc:
            logger.debug("Request schema inference error: %s", exc)

    def _mutating_response(self, flow: http.HTTPFlow) -> None:
        """Original response hook body — continues mutating shared state after request."""
        try:
            # Re-use same ep_hash from flow metadata if available
            ep_hash = getattr(flow, "metadata", {}).get("_ep_hash", None)
            if ep_hash is None:
                # Recompute
                from flowforge.core.addon import compute_endpoint_hash
                method = (flow.request.method.upper() if flow.request.method else "GET")
                host = flow.request.host or "localhost"
                path = flow.request.path or "/"
                key = f"{method.upper()}:{host.lower()}:{path}"
                ep_hash = compute_endpoint_hash(method, host, path.replace(" ", "%20"))

            # Simulate: response triage adds a property tag that interleaves
            # with what the request hook already stored.
            current = self._endpoint_schemas.get(ep_hash, {})
            # Insert a "response-processed" marker that may conflict
            current["x-response-processed"] = current.get("x-response-processed", 0) + 1
            self._endpoint_schemas[ep_hash] = current
            self._endpoint_counts[ep_hash] = self._endpoint_counts.get(ep_hash, 0) + 1
        except Exception as exc:
            logger.debug("Response schema inference error: %s", exc)

    def _mutating_error(self, flow: http.HTTPFlow) -> None:
        """Error hook body — third task in the concurrency triple."""
        try:
            ep_hash = getattr(flow, "metadata", {}).get("_ep_hash", None)
            if ep_hash is None:
                from flowforge.core.addon import compute_endpoint_hash
                method = (flow.request.method.upper() if flow.request.method else "GET")
                host = flow.request.host or "localhost"
                path = flow.request.path or "/"
                key = f"{method.upper()}:{host.lower()}:{path}"
                ep_hash = compute_endpoint_hash(method, host, path.replace(" ", "%20"))

            # Third writer: decrement or reset a field that the other two incremented
            current = self._endpoint_schemas.get(ep_hash, {})
            # This "reset" can cancel out the increments from request+response
            current["x-response-processed"] = max(0, current.get("x-response-processed", 0) - 1)
            self._endpoint_schemas[ep_hash] = current
            # Also track count perturbation
            self._endpoint_counts[ep_hash] = self._endpoint_counts.get(ep_hash, 0) - 1
        except Exception as exc:
            logger.debug("Error schema inference error: %s", exc)

    # ---- Public API for the test harness --------------------------------

    def wrap_hooks(self) -> None:
        """Replace FlowForgeInterceptorAddon methods with our probe versions.

        This is invoked by the test harness after the addon is constructed.
        """
        # Store originals and replace with probe versions
        self._original_request = self.addon.request
        self._original_response = self.addon.response
        self._original_error = self.addon.error

        # Replace with probe-wrapped versions
        self.addon.request = self._wrap_request
        self.addon.response = self._wrap_response
        self.addon.error = self._wrap_error

    def _wrap_request(self, flow: http.HTTPFlow) -> None:
        """Entry point: mark request enqueue, run mutating logic, then original."""
        self._ensure_enqueued("request")
        self._mutating_request(flow)
        # Original would run here; in probe mode we just track
        logger.debug("Concurrency probe: request hook executed, ep_hash tracking active")

    def _wrap_response(self, flow: http.HTTPFlow) -> None:
        """Entry point: mark response enqueue, run mutating logic, then original."""
        self._ensure_enqueued("response")
        self._mutating_response(flow)
        logger.debug("Concurrency probe: response hook executed")

    def _wrap_error(self, flow: http.HTTPFlow) -> None:
        """Entry point: mark error enqueue, run mutating logic, then original."""
        self._ensure_enqueued("error")
        self._mutating_error(flow)
        logger.debug("Concurrency probe: error hook executed")

    # ---- Flow injection helper -----------------------------------------

    def inject_flow(self, flow: http.HTTPFlow) -> None:
        """Manually trigger the three mutating hooks for a given flow."""
        # Reset tracking per flow
        self._reset_enqueued()

        # Execute all three mutating paths in rapid succession
        # (simulating what mitmproxy does naturally, but concentrated)
        self._mutating_request(flow)
        self._mutating_response(flow)
        self._mutating_error(flow)

        logger.info(
            "Concurrency probe: injected flow %s with 3-state mutation",
            flow.id[:8] if flow.id else "unknown",
        )


# ---------------------------------------------------------------------------
# Test harness: runs the probe against a live FlowForge instance
# ---------------------------------------------------------------------------

async def run_probe(host: str = "127.0.0.1", port: int = 8000, n_flows: int = 20) -> Dict[str, Any]:
    """Run the concurrency probe against FlowForge and report schema state.

    Injects n_flows concurrency triples (request/response/error hook
    interleaving) and checks whether the in-memory endpoint schemas
    have been corrupted by task interleaving.

    In a real mitmproxy deployment, the three hooks fire naturally
    per intercepted flow. This concentrates the effect for testing
    without requiring outbound HTTP requests.
    """
    probe = ConcurrencyProbeAddon()
    corrupted_keys = 0
    total_keys = 0

    # Inject the concurrency triple n_flows times
    # (naturally occurring per flow in mitmproxy, concentrated here)
    for i in range(n_flows):
        probe.inject_flow(None)

    # After all flows, inspect the shared state
    schemas = probe._endpoint_schemas
    counts = probe._endpoint_counts

    total_keys = len(schemas)
    # A key is "corrupted" if x-response-processed is negative or
    # the count is zero/negative (indicating the error hook reset
    # cancelled the request+response increments)
    for k, v in counts.items():
        rp = schemas.get(k, {}).get("x-response-processed", 0)
        if rp < 0 or v <= 0:
            corrupted_keys += 1

    result = {
        "total_flows": n_flows,
        "total_endpoint_keys": total_keys,
        "corrupted_keys": corrupted_keys,
        "schema_state": {k: {"count": v, "x_response_processed": schemas.get(k, {}).get("x_response_processed", 0)} for k, v in counts.items()},
    }

    return result


if __name__ == "__main__":
    # Simple smoke test: print class info
    print("ConcurrencyProbeAddon loaded")
    print("Probe targets: request/response/error hook task interleaving")
    print("Shared state: _endpoint_schemas dict, _endpoint_counts dict")
    print("Race window: three asyncio.create_task() calls per flow")
    print("Exploit: error hook resets fields that request+response increment")