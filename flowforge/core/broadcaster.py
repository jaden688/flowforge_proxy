"""
Real-time Pub/Sub event broadcaster with backpressure protection for WebSocket & SSE clients.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional, Set

from flowforge.models.events import EventType, FlowEvent

logger = logging.getLogger("flowforge.core.broadcaster")


class EventBroadcaster:
    """Pub/Sub distribution hub streaming live proxy events to UI clients."""

    def __init__(self, max_queue_size: int = 500) -> None:
        self.max_queue_size = max_queue_size
        self._subscribers: Set[asyncio.Queue[FlowEvent]] = set()
        self._named_subscribers: Dict[str, asyncio.Queue[FlowEvent]] = {}
        self._lock = asyncio.Lock()

    @property
    def active_subscribers_count(self) -> int:
        return len(self._subscribers)

    async def subscribe(self, subscriber_id: Optional[str] = None) -> asyncio.Queue[FlowEvent]:
        """Register a new listener and return its event queue."""
        queue: asyncio.Queue[FlowEvent] = asyncio.Queue(maxsize=self.max_queue_size)
        async with self._lock:
            self._subscribers.add(queue)
            if subscriber_id:
                self._named_subscribers[subscriber_id] = queue
        logger.debug("Client %s subscribed to EventBroadcaster. Active: %d", subscriber_id or "anonymous", len(self._subscribers))
        return queue

    async def unsubscribe(self, queue_or_id: Union[asyncio.Queue[FlowEvent], str]) -> None:
        """Remove a listener queue upon client disconnect."""
        async with self._lock:
            if isinstance(queue_or_id, str):
                target_q = self._named_subscribers.pop(queue_or_id, None)
                if target_q:
                    self._subscribers.discard(target_q)
            else:
                self._subscribers.discard(queue_or_id)
                # Remove from named subscribers if present
                for name, q in list(self._named_subscribers.items()):
                    if q == queue_or_id:
                        del self._named_subscribers[name]
        logger.debug("Client unsubscribed from EventBroadcaster. Active: %d", len(self._subscribers))

    def publish(self, event: FlowEvent | Dict[str, Any]) -> None:
        """
        Non-blocking dispatch of event to all active subscriber queues.
        Guarantees that slow clients do not impede proxy throughput.
        """
        if not self._subscribers:
            return

        if isinstance(event, dict):
            ev_name = event.get("event") or event.get("type") or "unknown"
            event_obj = FlowEvent(
                event=ev_name,
                type=ev_name,
                event_type=ev_name,
                flow_id=event.get("flow_id") or (event.get("data", {}).get("flow_id") if isinstance(event.get("data"), dict) else None),
                timestamp=event.get("timestamp", time.time()),
                data=event.get("data", event),
            )
        else:
            event_obj = event

        dead_queues = set()
        for q in list(self._subscribers):
            try:
                # If queue is full, drop the oldest item to preserve real-time recency
                if q.full():
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                q.put_nowait(event_obj)
            except Exception as exc:
                logger.warning("Failed to put event into subscriber queue: %s", exc)
                dead_queues.add(q)

        if dead_queues:
            for dq in dead_queues:
                self._subscribers.discard(dq)

    def broadcast_flow_created(self, data: Any) -> None:
        """Emit flow_created event when request headers are captured."""
        payload = data.model_dump() if hasattr(data, "model_dump") else data
        flow_id = payload.get("id") if isinstance(payload, dict) else getattr(data, "id", None)
        self.publish(FlowEvent(event=EventType.FLOW_CREATED.value, event_type=EventType.FLOW_CREATED.value, flow_id=flow_id, data=payload))

    def broadcast_flow_completed(self, data: Any) -> None:
        """Emit flow_completed event when full response is received."""
        payload = data.model_dump() if hasattr(data, "model_dump") else data
        flow_id = payload.get("id") if isinstance(payload, dict) else getattr(data, "id", None)
        self.publish(FlowEvent(event=EventType.FLOW_COMPLETED.value, event_type=EventType.FLOW_COMPLETED.value, flow_id=flow_id, data=payload))

    def broadcast_triage_annotated(self, flow_id: str, triage_data: Any) -> None:
        """Emit triage_annotated event when R2 engine finishes deep analysis."""
        payload = triage_data.model_dump() if hasattr(triage_data, "model_dump") else triage_data
        data_dict: Dict[str, Any] = {"flow_id": flow_id, "triage": payload}
        if isinstance(payload, dict) and "tags" in payload:
            data_dict["tags"] = payload["tags"]
        elif hasattr(triage_data, "tags"):
            data_dict["tags"] = getattr(triage_data, "tags")
        self.publish(FlowEvent(
            event=EventType.TRIAGE_ANNOTATED.value,
            event_type=EventType.TRIAGE_ANNOTATED.value,
            flow_id=flow_id,
            data=data_dict,
        ))

    def broadcast_ws_frame(self, frame: Any) -> None:
        """Emit ws_frame event when a WebSocket frame is intercepted."""
        payload = frame.model_dump() if hasattr(frame, "model_dump") else frame
        self.publish(FlowEvent(event=EventType.WS_FRAME.value, data=payload))

    def broadcast_stats(self, stats: Dict[str, Any]) -> None:
        """Emit periodic proxy_stats telemetry heartbeat."""
        self.publish(FlowEvent(event=EventType.PROXY_STATS.value, data=stats))

    def broadcast_matrix_progress(self, matrix_data: Any) -> None:
        """Emit test matrix execution progress."""
        payload = matrix_data.model_dump() if hasattr(matrix_data, "model_dump") else matrix_data
        self.publish(FlowEvent(event=EventType.MATRIX_PROGRESS.value, data=payload))

    def broadcast_proposal_created(self, flow_id: str, proposals: List[Any], top_severity: Optional[str] = None) -> None:
        """Emit proposal_created event when proposals are synthesized for an intercepted flow."""
        proposals_payload = [p.model_dump() if hasattr(p, "model_dump") else p for p in proposals]
        top_sev = top_severity
        if not top_sev and proposals:
            # Determine top severity
            severities = [p.get("severity") if isinstance(p, dict) else getattr(p, "severity", "MEDIUM") for p in proposals_payload]
            for candidate in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                if any(str(getattr(s, "value", s)).upper() == candidate for s in severities):
                    top_sev = candidate
                    break
        data = {
            "flow_id": flow_id,
            "proposal_count": len(proposals_payload),
            "top_severity": top_sev or "MEDIUM",
            "proposals": proposals_payload,
        }
        self.publish(FlowEvent(
            event=EventType.PROPOSAL_CREATED.value,
            event_type=EventType.PROPOSAL_CREATED.value,
            flow_id=flow_id,
            data=data,
        ))

    def broadcast_proposal_updated(self, flow_id: str, proposal_id: str, updates: Dict[str, Any]) -> None:
        """Emit proposal_updated event when operator or system modifies a proposal."""
        data = {
            "flow_id": flow_id,
            "id": proposal_id,
            "proposal_id": proposal_id,
            "updates": updates,
        }
        self.publish(FlowEvent(
            event=EventType.PROPOSAL_UPDATED.value,
            event_type=EventType.PROPOSAL_UPDATED.value,
            flow_id=flow_id,
            data=data,
        ))

    def broadcast_proposal_executed(self, flow_id: str, proposal_id: str, result_data: Dict[str, Any]) -> None:
        """Emit proposal_executed event when proposal replay execution completes."""
        data = {
            "flow_id": flow_id,
            "proposal_id": proposal_id,
            "state": "COMPLETED",
            **result_data,
        }
        self.publish(FlowEvent(
            event=EventType.PROPOSAL_EXECUTED.value,
            event_type=EventType.PROPOSAL_EXECUTED.value,
            flow_id=flow_id,
            data=data,
        ))

    def broadcast_proposal_dismissed(self, flow_id: str, proposal_id: str) -> None:
        """Emit proposal_dismissed event when operator dismisses a proposal."""
        data = {
            "flow_id": flow_id,
            "proposal_id": proposal_id,
            "state": "DISMISSED",
        }
        self.publish(FlowEvent(
            event=EventType.PROPOSAL_DISMISSED.value,
            event_type=EventType.PROPOSAL_DISMISSED.value,
            flow_id=flow_id,
            data=data,
        ))

    def broadcast_proposal_stats(self, stats: Dict[str, int]) -> None:
        """Emit proposal_stats event with updated proposal counters."""
        self.publish(FlowEvent(
            event=EventType.PROPOSAL_STATS.value,
            event_type=EventType.PROPOSAL_STATS.value,
            data=stats,
        ))

    def broadcast_schema_updated(
        self,
        endpoint_hash: str,
        host: str,
        path_pattern: str,
        method: str,
        schema_summary: Dict[str, Any],
        parameters: Optional[List[Any]] = None,
        category: Optional[str] = "DATA_READ",
        request_count: int = 1,
    ) -> None:
        """Emit schema_updated event when cumulative schema evolves for an endpoint."""
        params_payload = []
        if parameters:
            for p in parameters:
                if hasattr(p, "model_dump"):
                    params_payload.append(p.model_dump())
                elif isinstance(p, dict):
                    params_payload.append(p)
                else:
                    params_payload.append(p.__dict__ if hasattr(p, "__dict__") else str(p))
        data = {
            "endpoint_hash": endpoint_hash,
            "host": host,
            "path_pattern": path_pattern,
            "method": method,
            "schema_summary": schema_summary,
            "parameters": params_payload,
            "category": category,
            "request_count": request_count,
        }
        self.publish(FlowEvent(
            event=EventType.SCHEMA_UPDATED.value,
            type=EventType.SCHEMA_UPDATED.value,
            event_type=EventType.SCHEMA_UPDATED.value,
            data=data,
        ))

    def broadcast(self, event_name: str, data: Dict[str, Any], flow_id: Optional[str] = None) -> None:
        """Generic event broadcast convenience method."""
        self.publish(FlowEvent(event=event_name, event_type=event_name, flow_id=flow_id, data=data))


_global_broadcaster: Optional[EventBroadcaster] = None


def get_broadcaster() -> EventBroadcaster:
    """Get or create singleton EventBroadcaster instance."""
    global _global_broadcaster
    if _global_broadcaster is None:
        _global_broadcaster = EventBroadcaster()
    return _global_broadcaster
