"""
Proxy engine management, runtime configuration, telemetry, and status endpoints.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from flowforge.config import Settings, get_settings
from flowforge.db.repository import FlowRepository

router = APIRouter(prefix="/api/v1/proxy", tags=["Proxy Control"])


class ProxyConfigUpdate(BaseModel):
    ssl_insecure: Optional[bool] = None
    upstream_proxy: Optional[str] = None
    intercept_enabled: Optional[bool] = None


@router.get("/status")
async def get_proxy_status(request: Request) -> Dict[str, Any]:
    """Retrieve operational status, ports, uptime, and telemetry of the proxy engine."""
    proxy_engine = getattr(request.app.state, "proxy_engine", None)
    db_writer = getattr(request.app.state, "db_writer", None)
    settings = get_settings()

    is_running = proxy_engine.is_running if proxy_engine else False
    uptime = proxy_engine.uptime_seconds if proxy_engine else 0.0

    repo = FlowRepository()
    db_stats = await repo.get_stats()

    return {
        "is_running": is_running,
        "proxy_host": settings.proxy_host,
        "proxy_port": settings.proxy_port,
        "api_port": settings.api_port,
        "ssl_insecure": settings.ssl_insecure,
        "intercept_enabled": settings.intercept_enabled,
        "upstream_proxy": settings.upstream_proxy,
        "uptime_seconds": uptime,
        "db_queue_size": db_writer.queue.qsize() if db_writer else 0,
        "stats": db_stats,
    }


@router.post("/config")
async def update_proxy_config(request: Request, payload: ProxyConfigUpdate) -> Dict[str, Any]:
    """Update runtime proxy configuration settings."""
    settings = get_settings()
    proxy_engine = getattr(request.app.state, "proxy_engine", None)

    if payload.ssl_insecure is not None:
        settings.ssl_insecure = payload.ssl_insecure
    if payload.upstream_proxy is not None:
        settings.upstream_proxy = payload.upstream_proxy or None
    if payload.intercept_enabled is not None:
        settings.intercept_enabled = payload.intercept_enabled

    if proxy_engine:
        proxy_engine.update_config(
            ssl_insecure=payload.ssl_insecure,
            upstream_proxy=payload.upstream_proxy,
            intercept_enabled=payload.intercept_enabled,
        )

    return {
        "ok": True,
        "ssl_insecure": settings.ssl_insecure,
        "upstream_proxy": settings.upstream_proxy,
        "intercept_enabled": settings.intercept_enabled,
    }


@router.post("/start")
async def start_proxy(request: Request) -> Dict[str, Any]:
    """Start the proxy engine if currently inactive."""
    proxy_engine = getattr(request.app.state, "proxy_engine", None)
    if not proxy_engine:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ProxyEngine instance not initialized on application state.",
        )
    if proxy_engine.is_running:
        return {"ok": True, "message": "Proxy engine is already running."}

    await proxy_engine.start()
    return {"ok": True, "message": "Proxy engine started successfully."}


@router.post("/stop")
async def stop_proxy(request: Request) -> Dict[str, Any]:
    """Stop the proxy engine."""
    proxy_engine = getattr(request.app.state, "proxy_engine", None)
    if not proxy_engine:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ProxyEngine instance not initialized on application state.",
        )
    if not proxy_engine.is_running:
        return {"ok": True, "message": "Proxy engine is already stopped."}

    await proxy_engine.stop()
    return {"ok": True, "message": "Proxy engine stopped successfully."}


@router.post("/restart")
async def restart_proxy(request: Request) -> Dict[str, Any]:
    """Restart the proxy engine."""
    proxy_engine = getattr(request.app.state, "proxy_engine", None)
    if not proxy_engine:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ProxyEngine instance not initialized on application state.",
        )
    await proxy_engine.restart()
    return {"ok": True, "message": "Proxy engine restarted successfully."}


@router.get("/stats")
async def get_live_stats(request: Request) -> Dict[str, Any]:
    """Fetch live telemetry stats across storage and proxy engine."""
    repo = FlowRepository()
    db_stats = await repo.get_stats()
    proxy_engine = getattr(request.app.state, "proxy_engine", None)
    broadcaster = getattr(request.app.state, "broadcaster", None)

    return {
        "db": db_stats,
        "is_running": proxy_engine.is_running if proxy_engine else False,
        "uptime_seconds": proxy_engine.uptime_seconds if proxy_engine else 0.0,
        "active_ws_subscribers": broadcaster.active_subscribers_count if broadcaster else 0,
    }


@router.post("/browser/launch")
async def launch_browser(request: Request) -> Dict[str, Any]:
    """Launch an isolated pre-configured Chromium browser pointing to FlowForge proxy."""
    import os
    import shutil
    import subprocess
    settings = get_settings()
    proxy_url = f"http://{settings.proxy_host}:{settings.proxy_port}"

    browser_bin = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    if not browser_bin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chromium or Google Chrome binary not found on the host system.",
        )

    profile_dir = os.path.expanduser("~/.config/flowforge-browser")
    os.makedirs(profile_dir, exist_ok=True)

    cmd = [
        browser_bin,
        f"--proxy-server={proxy_url}",
        '--proxy-bypass-list=<-loopback>',
        "--ignore-certificate-errors",
        "--ignore-urlfetcher-cert-requests",
        "--allow-insecure-localhost",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-sync",
        "--disable-background-networking",
        "--disable-features=Translate",
        f"http://{settings.proxy_host}:{settings.proxy_port}/",
    ]

    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        return {"ok": True, "message": "FlowForge isolated browser launched successfully."}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


class ProxyReplayRequest(BaseModel):
    method: str
    url: str
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None


@router.post("/replay")
async def proxy_replay(payload: ProxyReplayRequest) -> Dict[str, Any]:
    """Alias for replaying an arbitrary request through the proxy / flow engine."""
    from flowforge.api.routes.flows import send_custom_request, CustomSendRequest
    return await send_custom_request(CustomSendRequest(
        method=payload.method,
        url=payload.url,
        headers=payload.headers or {},
        body=payload.body,
    ))

