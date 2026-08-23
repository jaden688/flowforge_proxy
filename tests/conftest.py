"""
Pytest configuration and shared fixtures for FlowForge automated verification suite.
Enables native async test function execution and provides database, reference target app, and client fixtures.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import tempfile
import time
import uuid
from typing import Any, Dict, Generator, Optional
import pytest

from flowforge.core.ca import CertificateManager
from flowforge.db.connection import get_connection, init_db
from flowforge.db.repository import FlowRepository
from flowforge.db.writer import AsyncDBWriter
from flowforge.heuristics.models import (
    EndpointCategory,
    ExtractedParameter,
    FindingSeverity,
    IdentifierFinding,
    IdentifierType,
    ParameterLocation,
    ReflectionContext,
    ReflectionFinding,
    EncodingStatus,
    TriageSummary,
)
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
from flowforge.models.websocket import WebSocketMessageModel
from tests.generator import SyntheticTrafficGenerator
from tests.target_app import TargetAppManager


def pytest_pyfunc_call(pyfuncitem: Any) -> Optional[bool]:
    """Hook to execute async def test functions directly without pytest-asyncio plugin."""
    if inspect.iscoroutinefunction(pyfuncitem.obj):
        argnames = pyfuncitem._fixtureinfo.argnames
        args = {arg: pyfuncitem.funcargs[arg] for arg in argnames}
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(pyfuncitem.obj(**args))
        finally:
            loop.close()
        return True
    return None


@pytest.fixture
def tmp_dir() -> Generator[str, None, None]:
    """Provides an isolated temporary directory cleaned up after test run."""
    with tempfile.TemporaryDirectory() as td:
        yield td


@pytest.fixture
def tmp_db_path(tmp_dir: str) -> str:
    """Provides path to an isolated temporary SQLite database."""
    return os.path.join(tmp_dir, f"test_flows_{uuid.uuid4().hex[:8]}.db")


@pytest.fixture
def ca_manager(tmp_dir: str) -> CertificateManager:
    """Provides a CertificateManager writing to a temporary certificates directory."""
    certs_dir = os.path.join(tmp_dir, "certs")
    return CertificateManager(certs_dir=certs_dir)


@pytest.fixture
def sample_flow_record() -> FlowRecord:
    """Returns a realistic pre-populated FlowRecord for testing."""
    return FlowRecord(
        id=str(uuid.uuid4()),
        timestamp_start=time.time() - 0.05,
        timestamp_end=time.time(),
        duration_ms=50.0,
        client_ip="127.0.0.1",
        server_host="api.target.com",
        server_port=443,
        scheme="https",
        http_version="HTTP/2.0",
        request=RequestModel(
            method="POST",
            url="https://api.target.com/api/v1/orders/1001/checkout?coupon=SAVE20",
            path="/api/v1/orders/1001/checkout",
            query_string="coupon=SAVE20",
            query_params={"coupon": "SAVE20"},
            headers={
                "Host": "api.target.com",
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDAxIn0.signature",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0",
            },
            content_type="application/json",
            content_length=45,
            body='{"order_id": 1001, "items": [{"id": 1, "qty": 2}]}',
            cookies={"session": "sess_12345"},
        ),
        response=ResponseModel(
            status_code=201,
            reason="Created",
            headers={"Content-Type": "application/json", "Location": "/api/v1/orders/1001"},
            content_type="application/json",
            content_length=95,
            body='{"status": "created", "order_id": 1001, "coupon": "SAVE20", "total": 45.00}',
            cookies={},
        ),
        tags=["mutation", "auth", "reflection", "idor_candidate"],
        triage_data={"summary": "Sample triage payload"},
    )
