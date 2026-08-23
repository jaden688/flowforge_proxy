"""
FlowForge Proxy CLI entrypoint and server runner.
"""

from __future__ import annotations

import argparse
import sys
import uvicorn

from flowforge.config import Settings, set_settings
from flowforge.api.app import create_app


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="flowforge",
        description="FlowForge - Intelligent HTTP/HTTPS/WebSocket Intercepting Proxy & Security Testing Workbench",
    )
    parser.add_argument("--host", default="127.0.0.1", help="API server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="API server port (default: 8000)")
    parser.add_argument("--proxy-host", default="127.0.0.1", help="Proxy listen host (default: 127.0.0.1)")
    parser.add_argument("--proxy-port", type=int, default=8080, help="Proxy listen port (default: 8080)")
    parser.add_argument("--db-path", default="./data/flows.db", help="SQLite database path (default: ./data/flows.db)")
    parser.add_argument("--certs-dir", default="./data/certs", help="TLS CA certificates directory (default: ./data/certs)")
    parser.add_argument("--no-proxy", action="store_true", help="Start API only without embedded proxy")
    parser.add_argument("--ssl-insecure", action="store_true", default=True, help="Disable upstream TLS verification")
    parser.add_argument("--upstream-proxy", default=None, help="Forward traffic to upstream proxy (e.g. http://127.0.0.1:8080)")
    return parser.parse_args()


def main() -> None:
    """Run FlowForge application."""
    args = parse_args()

    settings = Settings(
        host=args.host,
        api_port=args.port,
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        db_path=args.db_path,
        certs_dir=args.certs_dir,
        auto_start_proxy=not args.no_proxy,
        ssl_insecure=args.ssl_insecure,
        upstream_proxy=args.upstream_proxy,
    )
    set_settings(settings)

    app = create_app(settings)

    print("=" * 60)
    print(" FlowForge Intercepting Proxy & Security Workbench")
    print(f" REST & WebSocket API: http://{settings.host}:{settings.api_port}")
    if settings.auto_start_proxy:
        print(f" MITM Proxy Engine:   http://{settings.proxy_host}:{settings.proxy_port}")
        print(f" Root CA Download:    http://{settings.host}:{settings.api_port}/cert")
    print(f" Database Storage:    {settings.db_path} (WAL Mode + FTS5)")
    print("=" * 60)

    uvicorn.run(
        app,
        host=settings.host,
        port=settings.api_port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
