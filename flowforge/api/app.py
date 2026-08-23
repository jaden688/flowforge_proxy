"""
FastAPI application factory, lifespan state management, CORS, and router registration.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncGenerator, Callable, Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from flowforge.config import Settings, get_settings, set_settings
from flowforge.core.broadcaster import EventBroadcaster, get_broadcaster
from flowforge.core.engine import ProxyEngine
from flowforge.db.connection import init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter

from flowforge.api.routes.flows import router as flows_router
from flowforge.api.routes.streaming import router as streaming_router
from flowforge.api.routes.ca import router as ca_router
from flowforge.api.routes.proxy import router as proxy_router

logger = logging.getLogger("flowforge.api.app")


def _get_triage_callback() -> Optional[Callable[..., Any]]:
    """Dynamically discover passive heuristic triage pipeline if installed."""
    try:
        from flowforge.heuristics.pipeline import process_flow
        return process_flow
    except ImportError:
        try:
            from flowforge.heuristics import process_flow
            return process_flow
        except ImportError:
            return None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager initializing DB, single-writer queue, and proxy master."""
    settings = get_settings()
    settings.ensure_directories()

    # 1. Initialize SQLite tables, indexes, and FTS5 triggers
    await init_db(settings.db_path)

    # 2. Initialize FlowRepository
    repo = FlowRepository(settings.db_path)
    app.state.repo = repo

    # 3. Start AsyncDBWriter batch engine
    db_writer = AsyncDBWriter(
        db_path=settings.db_path,
        max_batch_size=settings.max_batch_size,
        flush_interval_ms=settings.batch_flush_interval_ms,
    )
    await db_writer.start()
    app.state.db_writer = db_writer

    # 4. Initialize Pub/Sub Broadcaster
    broadcaster = get_broadcaster()
    app.state.broadcaster = broadcaster

    # 4. Initialize and conditionally start ProxyEngine
    triage_cb = _get_triage_callback()
    proxy_engine = ProxyEngine(
        settings=settings,
        db_writer=db_writer,
        broadcaster=broadcaster,
        triage_callback=triage_cb,
    )
    app.state.proxy_engine = proxy_engine

    if settings.auto_start_proxy:
        try:
            await proxy_engine.start()
        except Exception as exc:
            logger.error("Failed to auto-start proxy engine: %s", exc)

    logger.info("FlowForge API Application initialized successfully.")

    yield

    # Teardown
    if proxy_engine.is_running:
        await proxy_engine.stop()
    await db_writer.stop()
    logger.info("FlowForge API Application shutdown complete.")


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    """Create and configure FastAPI application instance."""
    if settings:
        set_settings(settings)

    app = FastAPI(
        title="FlowForge Proxy & Security Testing Workbench",
        description="Intelligent HTTP/HTTPS/WebSocket Intercepting Proxy & Passive Heuristic Triage API",
        version="0.1.0",
        lifespan=lifespan,
    )

    cfg = get_settings()
    app.state.broadcaster = get_broadcaster()
    app.state.repo = FlowRepository(cfg.db_path)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register Core Milestone 1 Routers
    app.include_router(flows_router)
    app.include_router(streaming_router)
    app.include_router(ca_router)
    app.include_router(proxy_router)

    # Dynamically register Milestone 2 (Dossier) & Milestone 3 (Matrix, Diff) Routers if available
    try:
        from flowforge.api.routes.dossier import router as dossier_router
        app.include_router(dossier_router)
    except ImportError:
        pass

    try:
        from flowforge.api.routes.matrix import router as matrix_router
        app.include_router(matrix_router)
    except ImportError:
        pass

    try:
        from flowforge.api.routes.diff import router as diff_router
        app.include_router(diff_router)
    except ImportError:
        pass

    try:
        from flowforge.api.routes.curation import router as curation_router
        app.include_router(curation_router)
    except ImportError:
        pass

    try:
        from flowforge.api.routes.rules import router as rules_router
        app.include_router(rules_router)
    except ImportError:
        pass

    try:
        from flowforge.api.routes.tools import router as tools_router
        app.include_router(tools_router)
    except ImportError:
        pass

    try:
        from flowforge.api.routes.proposals import router as proposals_router
        app.include_router(proposals_router)
    except ImportError:
        pass

    @app.get("/health", tags=["System"])
    @app.get("/api/v1/health", tags=["System"])
    async def health_check() -> dict:
        """Health check endpoint for container orchestrators and monitoring probes."""
        return {"status": "ok", "version": "0.1.0"}

    _mount_frontend(app)

    return app


def _frontend_dist() -> Path:
    return Path(__file__).resolve().parents[2] / "frontend" / "dist"


def _mount_frontend(app: FastAPI) -> None:
    """Serve the built frontend (vite dist) if present, so one port hosts API + UI."""
    dist = _frontend_dist()
    index_html = dist / "index.html"
    if not index_html.is_file():
        logger.info("Frontend dist not found at %s; UI not served.", dist)
        return

    assets_dir = dist / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str) -> FileResponse:
        if full_path and not full_path.startswith(("api/", "ws/")):
            candidate = (dist / full_path).resolve()
            if candidate.is_file() and str(candidate).startswith(str(dist.resolve())):
                return FileResponse(candidate)
        return FileResponse(index_html)


# Default application instance for ASGI servers (uvicorn flowforge.api.app:app)
app = create_app()
