"""
Active Intruder replay engine.

Takes an intercepted flow (or an arbitrary request template), applies operator
defined injection points, and iterates a merged payload set with configurable
concurrency and rate limiting. Results stream live over the WebSocket hub and
persist to SQLite with automatic anomaly flagging:

- reflection matching (payload echoed in response body)
- response size deviation vs running baseline median
- response timing deviation vs running baseline median
"""

from __future__ import annotations

import asyncio
import logging
import statistics
import time
import uuid
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from flowforge.config import get_settings
from flowforge.core.broadcaster import EventBroadcaster, get_broadcaster
from flowforge.db.payload_repository import PayloadRepository, parse_entries
from flowforge.db.repository import FlowRepository
from flowforge.models.intruder import (
    InjectionPoint,
    IntruderJob,
    IntruderJobConfig,
    IntruderJobStatus,
    IntruderResult,
)
from flowforge.wordlists.loader import WordlistCategory, get_wordlist_loader

logger = logging.getLogger("flowforge.core.intruder")

_BASELINE_WINDOW = 25          # rolling sample window for medians
_MIN_BASELINE_SAMPLES = 5      # samples before anomaly detection arms
_SIZE_DEVIATION_RATIO = 0.4    # ±40% from median size flags an anomaly
_TIME_DEVIATION_FACTOR = 3.0   # >3x median time flags a timing anomaly
_TIME_ABSOLUTE_FLOOR_MS = 250  # ignore sub-250ms deviations (noise)
_RESULT_FLUSH_BATCH = 20       # results buffered before DB flush


def apply_payload(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    point: InjectionPoint,
    payload: str,
) -> Tuple[str, Dict[str, str], Optional[str]]:
    """Return (url, headers, body) with `payload` injected at `point`."""
    value = f"{point.prefix}{payload}{point.suffix}"

    if point.position.value == "header":
        new_headers = dict(headers)
        key = point.key or "X-Injected"
        new_headers[key] = value
        return url, new_headers, body

    if point.position.value == "query":
        parts = urlsplit(url)
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        key = point.key or "q"
        replaced = False
        new_pairs: List[Tuple[str, str]] = []
        for name, existing in query_pairs:
            if name == key:
                new_pairs.append((name, value))
                replaced = True
            else:
                new_pairs.append((name, existing))
        if not replaced:
            new_pairs.append((key, value))
        new_query = urlencode(new_pairs)
        new_url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
        return new_url, dict(headers), body

    # body position: replace the whole body (prefix/suffix wrap the payload)
    return url, dict(headers), value


class IntruderEngine:
    """Orchestrates concurrent, rate-limited payload replay campaigns."""

    def __init__(
        self,
        payload_repo: PayloadRepository,
        flow_repo: Optional[FlowRepository] = None,
        broadcaster: Optional[EventBroadcaster] = None,
    ) -> None:
        self.payload_repo = payload_repo
        self.flow_repo = flow_repo or FlowRepository()
        self.broadcaster = broadcaster or get_broadcaster()
        self._tasks: Dict[str, asyncio.Task] = {}
        self._abort_flags: Dict[str, asyncio.Event] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def resolve_payloads(self, config: IntruderJobConfig) -> List[str]:
        """Merge payloads from custom DB lists, filesystem arsenal lists, and inline entries."""
        collected: List[str] = []

        for wl_id in config.custom_wordlist_ids:
            detail = await self.payload_repo.get_custom_wordlist(wl_id, include_content=True)
            if detail:
                collected.extend(parse_entries(detail.content))

        loader = get_wordlist_loader()
        for wl_id in config.arsenal_wordlist_ids:
            entry = loader.get(wl_id)
            if not entry:
                continue
            for value in loader.iter_entries(wl_id):
                collected.append(value)

        collected.extend(config.inline_payloads)

        # Deduplicate preserving order; drop None but keep intentional
        # empty-string payloads (they must still hit the wire).
        deduped = list(dict.fromkeys(p for p in collected if p is not None))[:20000]
        return deduped

    async def start_job(self, config: IntruderJobConfig) -> IntruderJob:
        """Create, persist, and launch an intruder campaign. Returns immediately."""
        payloads = await self.resolve_payloads(config)
        points = config.injection_points or [
            InjectionPoint(position="query", key="id"),
        ]
        total = len(payloads) * len(points)

        job = IntruderJob(
            id=f"intr-{uuid.uuid4().hex[:12]}",
            flow_id=config.flow_id,
            status=IntruderJobStatus.PENDING,
            config=config,
            payload_count=len(payloads),
            total_requests=total,
        )
        await self.payload_repo.create_intruder_job(job)

        abort_event = asyncio.Event()
        self._abort_flags[job.id] = abort_event
        task = asyncio.create_task(self._run_job(job.id, config, points, payloads, abort_event))
        self._tasks[job.id] = task
        task.add_done_callback(lambda _t: self._tasks.pop(job.id, None))
        return job

    async def abort_job(self, job_id: str) -> bool:
        event = self._abort_flags.get(job_id)
        if event:
            event.set()
            return True
        # Job may exist but its task already finished; mark aborted in DB.
        job = await self.payload_repo.get_intruder_job(job_id)
        if job and job.status == IntruderJobStatus.RUNNING:
            await self.payload_repo.update_intruder_job(
                job_id, status=IntruderJobStatus.ABORTED, finished_at=time.time()
            )
            return True
        return False

    async def wait_for_job(self, job_id: str, timeout: Optional[float] = None) -> None:
        """Test/ops helper: block until a campaign's runner task completes."""
        task = self._tasks.get(job_id)
        if task:
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

    # ------------------------------------------------------------------
    # Runner
    # ------------------------------------------------------------------

    async def _run_job(
        self,
        job_id: str,
        config: IntruderJobConfig,
        points: List[InjectionPoint],
        payloads: List[str],
        abort_event: asyncio.Event,
    ) -> None:
        settings = get_settings()
        proxy_url = (
            f"http://{settings.proxy_host}:{settings.proxy_port}"
            if settings.auto_start_proxy and config.flow_id
            else None
        )

        started = time.time()
        await self.payload_repo.update_intruder_job(
            job_id, status=IntruderJobStatus.RUNNING, started_at=started
        )
        self._broadcast_status(job_id, config.flow_id, "RUNNING", 0, len(payloads) * len(points))

        work: List[Tuple[InjectionPoint, str]] = []
        for point in points:
            for payload in payloads:
                work.append((point, payload))

        semaphore = asyncio.Semaphore(max(1, config.concurrency))
        rate_interval = 1.0 / config.rate_limit_rps if config.rate_limit_rps else None
        next_slot_lock = asyncio.Lock()
        next_slot_time = 0.0

        pending_results: List[Tuple[str, IntruderResult]] = []
        sent_counter = {"sent": 0}
        completed_counter = {"completed": 0}
        anomaly_counter = {"anomalies": 0}

        sizes: Deque[int] = deque(maxlen=_BASELINE_WINDOW)
        times: Deque[float] = deque(maxlen=_BASELINE_WINDOW)
        index_counter = {"i": 0}

        async def _acquire_rate_slot() -> None:
            nonlocal next_slot_time
            if rate_interval is None:
                return
            async with next_slot_lock:
                now = time.monotonic()
                slot = max(now, next_slot_time)
                next_slot_time = slot + rate_interval
            delay = slot - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)

        async def _dispatch(request_index: int, point: InjectionPoint, payload: str) -> None:
            nonlocal pending_results
            if abort_event.is_set():
                return
            async with semaphore:
                if abort_event.is_set():
                    return
                await _acquire_rate_slot()

                url, headers, body = apply_payload(
                    config.method, config.url, config.headers, config.body, point, payload
                )
                send_headers = {k: v for k, v in headers.items() if k.lower() not in ("host", "content-length")}
                start = time.time()
                status_code: Optional[int] = None
                resp_size: Optional[int] = None
                error: Optional[str] = None
                text_head = ""
                try:
                    async with httpx.AsyncClient(
                        proxy=proxy_url,
                        verify=False,
                        timeout=config.timeout_seconds,
                        follow_redirects=config.follow_redirects,
                    ) as client:
                        resp = await client.request(
                            method=config.method.upper(),
                            url=url,
                            headers=send_headers,
                            content=body.encode("utf-8") if body is not None else None,
                        )
                        duration_ms = (time.time() - start) * 1000.0
                        status_code = resp.status_code
                        resp_size = len(resp.content)
                        try:
                            text_head = resp.text[:65536]
                        except Exception:
                            text_head = ""

                        sizes.append(resp_size)
                        times.append(duration_ms)
                except Exception as exc:
                    duration_ms = (time.time() - start) * 1000.0
                    error = str(exc)[:500]

                reflected = bool(payload and text_head and payload in text_head)
                reasons = self._detect_anomalies(payload, reflected, status_code, resp_size, duration_ms, sizes, times)

                sent_counter["sent"] += 1
                completed_counter["completed"] += 1
                if reasons:
                    anomaly_counter["anomalies"] += 1
                    try:
                        from urllib.parse import urlsplit
                        from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
                        parsed_url = urlsplit(url)
                        executed_flow = FlowRecord(
                            id=f"flow-intruder-{uuid.uuid4().hex[:8]}",
                            timestamp_start=start,
                            timestamp_end=time.time(),
                            duration_ms=round(duration_ms, 2),
                            scheme=parsed_url.scheme or "http",
                            server_host=parsed_url.netloc.split(":")[0] if parsed_url.netloc else "localhost",
                            server_port=int(parsed_url.netloc.split(":")[1]) if ":" in parsed_url.netloc else (443 if parsed_url.scheme == "https" else 80),
                            method=config.method.upper(),
                            url=url,
                            request=RequestModel(
                                method=config.method.upper(),
                                url=url,
                                path=parsed_url.path or "/",
                                query_string=parsed_url.query or "",
                                query_params={},
                                headers=send_headers,
                                body=body or "",
                            ),
                            response=ResponseModel(
                                status_code=status_code if (status_code and status_code > 0) else 500,
                                reason="OK" if status_code == 200 else ("Error" if status_code else "Failed"),
                                headers={},
                                body=text_head,
                            ) if status_code else None,
                            error_message=error,
                            tags=["intruder_execution", "anomaly"] + [r.lower().replace(" ", "_") for r in reasons],
                            triage_data={
                                "is_anomaly": True,
                                "vulnerability_class": reasons[0],
                                "confidence_score": 0.85,
                                "findings": reasons,
                            },
                            notes=f"Intruder anomaly detected for payload '{payload}' at {point.label()}: {', '.join(reasons)}",
                        )
                        asyncio.create_task(self.flow_repo.insert_flow(executed_flow))
                    except Exception as f_exc:
                        logger.warning("Failed saving intruder anomalous FlowRecord: %s", f_exc)

                result = IntruderResult(
                    request_index=request_index,
                    position_label=point.label(),
                    payload=payload,
                    status_code=status_code,
                    response_time_ms=round(duration_ms, 2),
                    response_size_bytes=resp_size,
                    reflected=reflected,
                    anomaly_reasons=reasons,
                    error=error,
                )
                pending_results.append((job_id, result))

                self.broadcaster.broadcast("intruder_result", {
                    "job_id": job_id,
                    "flow_id": config.flow_id,
                    **result.model_dump(),
                })

                if len(pending_results) >= _RESULT_FLUSH_BATCH:
                    batch = pending_results
                    pending_results = []
                    try:
                        await self.payload_repo.insert_results_batch(batch)
                        await self.payload_repo.increment_job_counters(
                            job_id,
                            sent=len(batch),
                            completed=len(batch),
                            anomalies=sum(1 for _, r in batch if r.anomaly_reasons),
                        )
                    except Exception as exc:
                        logger.warning("Failed flushing intruder results: %s", exc)

        try:
            index_counter["i"] = 0
            tasks: List[asyncio.Task] = []
            for point, payload in work:
                if abort_event.is_set():
                    break
                index_counter["i"] += 1
                tasks.append(asyncio.create_task(_dispatch(index_counter["i"], point, payload)))

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            # Flush remainder
            if pending_results:
                try:
                    await self.payload_repo.insert_results_batch(pending_results)
                    await self.payload_repo.increment_job_counters(
                        job_id,
                        sent=len(pending_results),
                        completed=len(pending_results),
                        anomalies=sum(1 for _, r in pending_results if r.anomaly_reasons),
                    )
                except Exception as exc:
                    logger.warning("Failed final intruder result flush: %s", exc)

            final_status = (
                IntruderJobStatus.ABORTED if abort_event.is_set() else IntruderJobStatus.COMPLETED
            )
            await self.payload_repo.update_intruder_job(job_id, status=final_status, finished_at=time.time())
            self._broadcast_status(
                job_id,
                config.flow_id,
                final_status.value,
                completed_counter["completed"],
                len(work),
            )
        except asyncio.CancelledError:
            await self.payload_repo.update_intruder_job(
                job_id, status=IntruderJobStatus.ABORTED, finished_at=time.time()
            )
            raise
        except Exception as exc:
            logger.error("Intruder job %s failed: %s", job_id, exc, exc_info=True)
            await self.payload_repo.update_intruder_job(
                job_id, status=IntruderJobStatus.FAILED, finished_at=time.time()
            )
            self._broadcast_status(job_id, config.flow_id, "FAILED", completed_counter["completed"], len(work))

    @staticmethod
    def _detect_anomalies(
        payload: str,
        reflected: bool,
        status_code: Optional[int],
        size: Optional[int],
        duration_ms: float,
        sizes: Deque[int],
        times: Deque[float],
    ) -> List[str]:
        reasons: List[str] = []
        if reflected:
            reasons.append("REFLECTION")
        if status_code is None:
            reasons.append("REQUEST_ERROR")
            return reasons

        if len(sizes) >= _MIN_BASELINE_SAMPLES and size is not None:
            median_size = statistics.median(sizes)
            if median_size > 0 and abs(size - median_size) / max(median_size, 1) >= _SIZE_DEVIATION_RATIO:
                reasons.append("SIZE_ANOMALY")

        if (
            len(times) >= _MIN_BASELINE_SAMPLES
            and duration_ms >= _TIME_ABSOLUTE_FLOOR_MS
            and statistics.median(times) > 0
            and duration_ms >= statistics.median(times) * _TIME_DEVIATION_FACTOR
        ):
            reasons.append("TIMING_ANOMALY")

        if status_code >= 500:
            reasons.append("SERVER_ERROR")
        return reasons

    def _broadcast_status(
        self, job_id: str, flow_id: Optional[str], status: str, completed: int, total: int
    ) -> None:
        self.broadcaster.broadcast("intruder_status", {
            "job_id": job_id,
            "flow_id": flow_id,
            "status": status,
            "completed_requests": completed,
            "total_requests": total,
            "timestamp": time.time(),
        })
