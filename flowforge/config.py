"""
FlowForge application settings and configuration manager.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global configuration settings for FlowForge proxy and API services."""

    model_config = SettingsConfigDict(
        env_prefix="FLOWFORGE_",
        env_file=".env",
        extra="ignore",
    )

    # API Server Settings
    host: str = "127.0.0.1"
    api_port: int = 8000

    # Proxy Engine Settings
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    auto_start_proxy: bool = True
    ssl_insecure: bool = True
    upstream_proxy: Optional[str] = None
    intercept_enabled: bool = True

    # Storage & Persistence
    db_path: str = "./data/flows.db"
    max_body_size: int = 5 * 1024 * 1024  # 5 MB
    max_batch_size: int = 50
    batch_flush_interval_ms: int = 50

    # TLS & Certificates
    certs_dir: str = "./data/certs"
    ca_name: str = "FlowForge Intercepting CA"
    ca_organization: str = "FlowForge Security Workbench"
    ca_validity_days: int = 3650

    # CORS & Security
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])

    # Proposal synthesizer quality gates
    proposal_min_severity: str = "MEDIUM"   # INFO noise never stages
    proposal_max_per_flow: int = 12          # hard cap per intercepted flow
    proposal_payloads_per_finding: int = 2   # curated vectors per reflection
    proposal_header_crlf_enabled: bool = False  # CRLF response-header probes (noisy)

    # Wordlist Arsenal scan roots
    wordlist_dirs: List[str] = Field(
        default_factory=lambda: [
            "/usr/share/wordlists",
            "/usr/share/seclists",
            "/usr/share/payloadsallthethings",
            "/usr/share/dirb/wordlists",
            "/usr/share/wfuzz/wordlist",
            "~/PayloadsAllTheThings-master",
            "~/.flowforge/wordlists",
        ]
    )

    def ensure_directories(self) -> None:
        """Ensure that data and certificate directories exist on disk."""
        db_dir = Path(self.db_path).resolve().parent
        db_dir.mkdir(parents=True, exist_ok=True)
        certs_p = Path(self.certs_dir).resolve()
        certs_p.mkdir(parents=True, exist_ok=True)


_global_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get or create singleton global Settings instance."""
    global _global_settings
    if _global_settings is None:
        _global_settings = Settings()
        _global_settings.ensure_directories()
    return _global_settings


def set_settings(settings: Settings) -> None:
    """Override the global Settings instance (useful for testing)."""
    global _global_settings
    _global_settings = settings
    _global_settings.ensure_directories()
