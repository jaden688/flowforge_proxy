"""
SQLite async connection management and database initialization with WAL mode.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator, Optional
import aiosqlite

from flowforge.config import get_settings
from flowforge.db.schema import SCHEMA_SQL

COLUMN_MIGRATIONS: dict[str, list[tuple[str, str]]] = {
    "flows": [
        ("telemetry", "ALTER TABLE flows ADD COLUMN telemetry TEXT DEFAULT '{}'"),
    ],
}


async def configure_connection(conn: aiosqlite.Connection) -> None:
    """Apply performance PRAGMAs to SQLite connection."""
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode = WAL;")
    await conn.execute("PRAGMA synchronous = NORMAL;")
    await conn.execute("PRAGMA busy_timeout = 10000;")
    await conn.execute("PRAGMA foreign_keys = ON;")
    await conn.execute("PRAGMA cache_size = -64000;")  # 64MB cache
    await conn.execute("PRAGMA temp_store = MEMORY;")


async def _migrate_columns(conn: aiosqlite.Connection) -> None:
    """Add columns introduced after a table was first created, since CREATE TABLE IF NOT EXISTS cannot."""
    for table, migrations in COLUMN_MIGRATIONS.items():
        cursor = await conn.execute(f"PRAGMA table_info({table})")
        rows = await cursor.fetchall()
        existing = {row[1] for row in rows}
        for column, ddl in migrations:
            if column not in existing:
                await conn.execute(ddl)


async def init_db(db_path: Optional[str] = None) -> None:
    """Initialize database schema, tables, indexes, and triggers."""
    path = db_path or get_settings().db_path
    if path != ":memory:":
        parent_dir = Path(path).resolve().parent
        parent_dir.mkdir(parents=True, exist_ok=True)

    async with aiosqlite.connect(path) as conn:
        await configure_connection(conn)
        await conn.executescript(SCHEMA_SQL)
        await _migrate_columns(conn)
        await conn.commit()


@asynccontextmanager
async def get_connection(db_path: Optional[str] = None) -> AsyncGenerator[aiosqlite.Connection, None]:
    """Async context manager yielding a configured SQLite connection."""
    path = db_path or get_settings().db_path
    if path != ":memory:":
        parent_dir = Path(path).resolve().parent
        parent_dir.mkdir(parents=True, exist_ok=True)

    async with aiosqlite.connect(path) as conn:
        await configure_connection(conn)
        yield conn
