"""SQLite repository for custom wordlists and intruder jobs/results."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from flowforge.db.connection import get_connection
from flowforge.models.intruder import (
    CustomWordlist,
    CustomWordlistDetail,
    IntruderJob,
    IntruderJobConfig,
    IntruderJobStatus,
    IntruderResult,
)

MAX_CONTENT_BYTES = 8_000_000


def _parse_tags(raw: Any) -> List[str]:
    if isinstance(raw, list):
        return [str(t) for t in raw]
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(t) for t in parsed]
        except (json.JSONDecodeError, TypeError):
            pass
    return []


def count_usable_lines(content: str) -> int:
    """Count non-blank, non-comment entries in raw wordlist content."""
    return sum(
        1
        for line in content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def parse_entries(content: str) -> List[str]:
    """Extract usable entries from raw wordlist content."""
    return [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


class PayloadRepository:
    """Database repository for payload sets and intruder campaigns."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path

    # ------------------------------------------------------------------
    # Custom wordlists CRUD
    # ------------------------------------------------------------------

    async def create_custom_wordlist(
        self,
        name: str,
        content: str,
        description: str = "",
        category: str = "attack_payloads",
        tags: Optional[List[str]] = None,
    ) -> CustomWordlist:
        now = time.time()
        wl_id = f"wl-{uuid.uuid4().hex[:12]}"
        sql = """
        INSERT INTO custom_wordlists (id, name, description, category, tags, content, line_count, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        async with get_connection(self.db_path) as conn:
            await conn.execute(
                sql,
                (
                    wl_id,
                    name,
                    description,
                    category,
                    json.dumps(tags or []),
                    content,
                    count_usable_lines(content),
                    now,
                    now,
                ),
            )
            await conn.commit()
        return CustomWordlist(
            id=wl_id,
            name=name,
            description=description,
            category=category,
            tags=tags or [],
            line_count=count_usable_lines(content),
            created_at=now,
            updated_at=now,
        )

    async def get_custom_wordlist(self, wl_id: str, include_content: bool = False) -> Optional[CustomWordlistDetail]:
        sql = "SELECT * FROM custom_wordlists WHERE id = ?;"
        async with get_connection(self.db_path) as conn:
            async with conn.execute(sql, (wl_id,)) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                content = row["content"]
                detail = CustomWordlistDetail(
                    id=row["id"],
                    name=row["name"],
                    description=row["description"] or "",
                    category=row["category"] or "attack_payloads",
                    tags=_parse_tags(row["tags"]),
                    line_count=row["line_count"] or 0,
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    content=content if include_content else "",
                    preview=parse_entries(content)[:25],
                )
                return detail

    async def list_custom_wordlists(
        self,
        tag: Optional[str] = None,
        search: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[CustomWordlist]:
        conditions: List[str] = []
        params: List[Any] = []
        if tag:
            conditions.append("tags LIKE ?")
            params.append(f'%"{tag}"%')
        if search:
            conditions.append("(name LIKE ? OR description LIKE ?)")
            term = f"%{search}%"
            params.extend([term, term])
        if category:
            conditions.append("category = ?")
            params.append(category)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"""
        SELECT id, name, description, category, tags, line_count, created_at, updated_at
        FROM custom_wordlists {where} ORDER BY created_at DESC;
        """
        async with get_connection(self.db_path) as conn:
            async with conn.execute(sql, params) as cursor:
                rows = await cursor.fetchall()
                return [
                    CustomWordlist(
                        id=r["id"],
                        name=r["name"],
                        description=r["description"] or "",
                        category=r["category"] or "attack_payloads",
                        tags=_parse_tags(r["tags"]),
                        line_count=r["line_count"] or 0,
                        created_at=r["created_at"],
                        updated_at=r["updated_at"],
                    )
                    for r in rows
                ]

    async def update_custom_wordlist(self, wl_id: str, updates: Dict[str, Any]) -> bool:
        """Apply a partial update. Returns False when the list does not exist."""
        existing = await self.get_custom_wordlist(wl_id)
        if not existing:
            return False

        sets: List[str] = []
        params: List[Any] = []
        field_map = {
            "name": "name",
            "description": "description",
            "category": "category",
        }
        for key, column in field_map.items():
            if key in updates and updates[key] is not None:
                sets.append(f"{column} = ?")
                params.append(updates[key])
        if "tags" in updates and updates["tags"] is not None:
            sets.append("tags = ?")
            params.append(json.dumps(list(updates["tags"])))
        if "content" in updates and updates["content"] is not None:
            content = str(updates["content"])[:MAX_CONTENT_BYTES]
            sets.append("content = ?")
            sets.append("line_count = ?")
            params.extend([content, count_usable_lines(content)])

        if not sets:
            return True
        sets.append("updated_at = ?")
        params.append(time.time())
        params.append(wl_id)
        sql = f"UPDATE custom_wordlists SET {', '.join(sets)} WHERE id = ?;"
        async with get_connection(self.db_path) as conn:
            await conn.execute(sql, params)
            await conn.commit()
        return True

    async def delete_custom_wordlist(self, wl_id: str) -> bool:
        async with get_connection(self.db_path) as conn:
            cursor = await conn.execute("DELETE FROM custom_wordlists WHERE id = ?;", (wl_id,))
            await conn.commit()
            return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Intruder jobs
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_job(row: Any) -> IntruderJob:
        try:
            config = IntruderJobConfig.model_validate_json(row["config"])
        except Exception:
            config = IntruderJobConfig(url="")
        return IntruderJob(
            id=row["id"],
            flow_id=row["flow_id"],
            status=IntruderJobStatus(row["status"]),
            config=config,
            payload_count=row["payload_count"] or 0,
            total_requests=row["total_requests"] or 0,
            sent_requests=row["sent_requests"] or 0,
            completed_requests=row["completed_requests"] or 0,
            anomaly_count=row["anomaly_count"] or 0,
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
        )

    async def create_intruder_job(self, job: IntruderJob) -> IntruderJob:
        sql = """
        INSERT INTO intruder_jobs (
            id, flow_id, status, config, payload_count, total_requests,
            sent_requests, completed_requests, anomaly_count,
            created_at, started_at, finished_at
        ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?, NULL);
        """
        async with get_connection(self.db_path) as conn:
            await conn.execute(
                sql,
                (
                    job.id,
                    job.flow_id,
                    job.status.value,
                    job.config.model_dump_json(),
                    job.payload_count,
                    job.total_requests,
                    job.created_at,
                    job.started_at,
                ),
            )
            await conn.commit()
        return job

    async def get_intruder_job(self, job_id: str) -> Optional[IntruderJob]:
        async with get_connection(self.db_path) as conn:
            async with conn.execute("SELECT * FROM intruder_jobs WHERE id = ?;", (job_id,)) as cursor:
                row = await cursor.fetchone()
                return self._row_to_job(row) if row else None

    async def list_intruder_jobs(self, limit: int = 100) -> List[IntruderJob]:
        async with get_connection(self.db_path) as conn:
            async with conn.execute(
                "SELECT * FROM intruder_jobs ORDER BY created_at DESC LIMIT ?;", (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
                return [self._row_to_job(r) for r in rows]

    async def update_intruder_job(self, job_id: str, **fields: Any) -> None:
        """Update arbitrary scalar columns on an intruder job."""
        allowed = {
            "status", "payload_count", "total_requests", "sent_requests",
            "completed_requests", "anomaly_count", "started_at", "finished_at",
        }
        sets: List[str] = []
        params: List[Any] = []
        for key, value in fields.items():
            if key not in allowed:
                continue
            if key == "status" and hasattr(value, "value"):
                value = value.value
            sets.append(f"{key} = ?")
            params.append(value)
        if not sets:
            return
        params.append(job_id)
        async with get_connection(self.db_path) as conn:
            await conn.execute(f"UPDATE intruder_jobs SET {', '.join(sets)} WHERE id = ?;", params)
            await conn.commit()

    async def increment_job_counters(self, job_id: str, sent: int = 0, completed: int = 0, anomalies: int = 0) -> None:
        sql = """
        UPDATE intruder_jobs SET
            sent_requests = sent_requests + ?,
            completed_requests = completed_requests + ?,
            anomaly_count = anomaly_count + ?
        WHERE id = ?;
        """
        async with get_connection(self.db_path) as conn:
            await conn.execute(sql, (sent, completed, anomalies, job_id))
            await conn.commit()

    # ------------------------------------------------------------------
    # Intruder results
    # ------------------------------------------------------------------

    async def insert_results_batch(self, results: List[Tuple[str, IntruderResult]]) -> None:
        """Insert a batch of (job_id, result) pairs in one transaction."""
        if not results:
            return
        sql = """
        INSERT INTO intruder_results (
            job_id, request_index, position, payload, status_code,
            response_time_ms, response_size_bytes, reflected, anomaly_reasons, error, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        rows = [
            (
                job_id,
                res.request_index,
                res.position_label,
                res.payload[:2000],
                res.status_code,
                res.response_time_ms,
                res.response_size_bytes,
                1 if res.reflected else 0,
                json.dumps(res.anomaly_reasons),
                res.error,
                res.timestamp,
            )
            for job_id, res in results
        ]
        async with get_connection(self.db_path) as conn:
            await conn.executemany(sql, rows)
            await conn.commit()

    async def get_results(
        self,
        job_id: str,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[IntruderResult], int]:
        """Query stored results with optional anomaly/timing/size filters."""
        filters = filters or {}
        conditions = ["job_id = ?"]
        params: List[Any] = [job_id]

        if filters.get("anomalies_only"):
            conditions.append("anomaly_reasons != '[]'")
        if filters.get("reflected_only"):
            conditions.append("reflected = 1")
        if filters.get("status_code") is not None:
            conditions.append("status_code = ?")
            params.append(filters["status_code"])
        if filters.get("min_size") is not None:
            conditions.append("response_size_bytes >= ?")
            params.append(filters["min_size"])
        if filters.get("max_size") is not None:
            conditions.append("response_size_bytes <= ?")
            params.append(filters["max_size"])
        if filters.get("min_time_ms") is not None:
            conditions.append("response_time_ms >= ?")
            params.append(filters["min_time_ms"])
        if filters.get("max_time_ms") is not None:
            conditions.append("response_time_ms <= ?")
            params.append(filters["max_time_ms"])
        if filters.get("payload_search"):
            conditions.append("payload LIKE ?")
            params.append(f"%{filters['payload_search']}%")

        where = f"WHERE {' AND '.join(conditions)}"
        offset = max(0, int(filters.get("offset", 0)))
        limit = max(1, min(int(filters.get("limit", 200)), 5000))

        async with get_connection(self.db_path) as conn:
            async with conn.execute(
                f"SELECT COUNT(*) AS cnt FROM intruder_results {where};", params
            ) as cursor:
                row = await cursor.fetchone()
                total = row["cnt"] if row else 0

            async with conn.execute(
                f"""
                SELECT * FROM intruder_results {where}
                ORDER BY request_index ASC LIMIT ? OFFSET ?;
                """,
                params + [limit, offset],
            ) as cursor:
                rows = await cursor.fetchall()
                results = [
                    IntruderResult(
                        request_index=r["request_index"],
                        position_label=r["position"],
                        payload=r["payload"],
                        status_code=r["status_code"],
                        response_time_ms=r["response_time_ms"],
                        response_size_bytes=r["response_size_bytes"],
                        reflected=bool(r["reflected"]),
                        anomaly_reasons=_parse_tags(r["anomaly_reasons"]),
                        error=r["error"],
                        timestamp=r["timestamp"],
                    )
                    for r in rows
                ]
        return results, total

    async def delete_job_with_results(self, job_id: str) -> bool:
        async with get_connection(self.db_path) as conn:
            await conn.execute("PRAGMA foreign_keys = ON;")
            cursor = await conn.execute("DELETE FROM intruder_jobs WHERE id = ?;", (job_id,))
            await conn.commit()
            return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Full data wipe
    # ------------------------------------------------------------------

    WIPE_TABLES = [
        "intruder_jobs",        # cascades intruder_results
        "proposals",            # stored findings / auto-proposals
        "websocket_messages",
        "parameters",
        "endpoints",
        "flows",                # cascades via triggers/FTS sync
    ]

    async def wipe_engagement_data(self, include_wordlists: bool = False) -> Dict[str, int]:
        """Delete all captured/synthesized engagement data. Returns per-table row counts."""
        tables = list(self.WIPE_TABLES)
        if include_wordlists:
            tables.append("custom_wordlists")
        counts: Dict[str, int] = {}
        async with get_connection(self.db_path) as conn:
            await conn.execute("PRAGMA foreign_keys = ON;")
            for table in tables:
                try:
                    cursor = await conn.execute(f"DELETE FROM {table};")
                    counts[table] = cursor.rowcount or 0
                except Exception:
                    counts[table] = -1
            await conn.execute("VACUUM;")
            await conn.commit()
        return counts
