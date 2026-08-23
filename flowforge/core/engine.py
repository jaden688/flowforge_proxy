"""
Master Proxy Engine orchestrating Mitmproxy DumpMaster and background lifecycle.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Optional

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from flowforge.config import Settings, get_settings
from flowforge.core.addon import FlowForgeInterceptorAddon
from flowforge.core.broadcaster import EventBroadcaster, get_broadcaster
from flowforge.core.ca import CertificateManager
from flowforge.db.writer import AsyncDBWriter

logger = logging.getLogger("flowforge.core.engine")


class ProxyEngine:
    """Embedded high-performance MITM proxy backend embedding mitmproxy DumpMaster."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        db_writer: Optional[AsyncDBWriter] = None,
        broadcaster: Optional[EventBroadcaster] = None,
        triage_callback: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.db_writer = db_writer
        self.broadcaster = broadcaster or get_broadcaster()
        self.triage_callback = triage_callback
        self.cert_manager = CertificateManager(certs_dir=self.settings.certs_dir)

        self.master: Optional[DumpMaster] = None
        self.addon: Optional[FlowForgeInterceptorAddon] = None
        self._proxy_task: Optional[asyncio.Task[None]] = None
        self._stats_task: Optional[asyncio.Task[None]] = None
        self._running = False
        self._start_time: Optional[float] = None

    @property
    def is_running(self) -> bool:
        return self._running and self.master is not None

    @property
    def uptime_seconds(self) -> float:
        if not self._start_time or not self._running:
            return 0.0
        return max(0.0, time.time() - self._start_time)

    async def start(self) -> None:
        """Initialize mitmproxy options and launch DumpMaster on current event loop."""
        if self._running:
            logger.warning("ProxyEngine is already running.")
            return

        # Ensure certificates exist
        self.cert_manager.get_ca_cert_pem()

        # Configure Mitmproxy options
        opts = options.Options(
            listen_host=self.settings.proxy_host,
            listen_port=self.settings.proxy_port,
            confdir=str(self.cert_manager.certs_dir),
            ssl_insecure=self.settings.ssl_insecure,
        )

        if self.settings.upstream_proxy:
            opts.mode = [f"upstream:{self.settings.upstream_proxy}"]
        else:
            opts.mode = ["regular"]

        self.master = DumpMaster(
            opts,
            with_termlog=False,
            with_dumper=False,
        )

        # Attach custom interceptor addon
        self.addon = FlowForgeInterceptorAddon(
            db_writer=self.db_writer,
            broadcaster=self.broadcaster,
            triage_callback=self.triage_callback,
        )
        self.master.addons.add(self.addon)

        # Launch DumpMaster asynchronously
        self._running = True
        self._start_time = time.time()
        self._proxy_task = asyncio.create_task(self.master.run(), name="flowforge_proxy_master")
        self._stats_task = asyncio.create_task(self._stats_loop(), name="flowforge_proxy_stats")
        logger.info(
            "ProxyEngine listening on %s:%d (SSL Insecure: %s)",
            self.settings.proxy_host,
            self.settings.proxy_port,
            self.settings.ssl_insecure,
        )

    async def stop(self) -> None:
        """Gracefully shut down the proxy server."""
        if not self._running:
            return
        self._running = False
        logger.info("Stopping ProxyEngine...")

        if self._stats_task and not self._stats_task.done():
            self._stats_task.cancel()
            try:
                await self._stats_task
            except asyncio.CancelledError:
                pass

        if self.master:
            self.master.shutdown()

        if self._proxy_task and not self._proxy_task.done():
            try:
                await asyncio.wait_for(self._proxy_task, timeout=3.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

        self.master = None
        self._start_time = None
        logger.info("ProxyEngine stopped successfully.")

    async def restart(self) -> None:
        """Restart the proxy engine."""
        await self.stop()
        await asyncio.sleep(0.2)
        await self.start()

    def update_config(
        self,
        ssl_insecure: Optional[bool] = None,
        upstream_proxy: Optional[str] = None,
        intercept_enabled: Optional[bool] = None,
    ) -> None:
        """Update runtime proxy configuration."""
        if ssl_insecure is not None:
            self.settings.ssl_insecure = ssl_insecure
            if self.master and self.master.options:
                self.master.options.ssl_insecure = ssl_insecure
        if upstream_proxy is not None:
            self.settings.upstream_proxy = upstream_proxy or None
            if self.master and self.master.options:
                self.master.options.mode = [f"upstream:{upstream_proxy}"] if upstream_proxy else ["regular"]
        if intercept_enabled is not None:
            self.settings.intercept_enabled = intercept_enabled

    async def _stats_loop(self) -> None:
        """Periodic 1-second telemetry broadcast."""
        while self._running:
            try:
                await asyncio.sleep(1.0)
                stats = {
                    "is_running": self.is_running,
                    "listen_host": self.settings.proxy_host,
                    "listen_port": self.settings.proxy_port,
                    "uptime_seconds": self.uptime_seconds,
                    "active_subscribers": self.broadcaster.active_subscribers_count,
                    "db_queue_size": self.db_writer.queue.qsize() if self.db_writer else 0,
                    "ssl_insecure": self.settings.ssl_insecure,
                    "intercept_enabled": self.settings.intercept_enabled,
                }
                self.broadcaster.broadcast_stats(stats)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.debug("Error in stats loop: %s", exc)
