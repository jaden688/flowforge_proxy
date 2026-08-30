"""Tests for the system clear endpoint and data flow leak detection (Phase 3)."""

import pytest
import httpx
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from flowforge.heuristics.models import TriageSummary, EndpointCategory


# ---------------------------------------------------------------------------
# Clear Flags model
# ---------------------------------------------------------------------------

class TestClearFlagsModel:
    def test_default_flags_all_false(self):
        from flowforge.api.routes.system import ClearFlags
        flags = ClearFlags()
        assert flags.flows is False
        assert flags.endpoints is False
        assert flags.proposals is False
        assert flags.intruder_jobs is False
        assert flags.wordlists is False
        assert flags.curated_payloads is False

    def test_partial_flags(self):
        from flowforge.api.routes.system import ClearFlags
        flags = ClearFlags(flows=True, proposals=True)
        assert flags.flows is True
        assert flags.proposals is True
        assert flags.endpoints is False
        assert flags.intruder_jobs is False


# ---------------------------------------------------------------------------
# Data Flow Leak Detection
# ---------------------------------------------------------------------------

class TestDataFlowLeakDetection:
    def _make_synthesizer(self):
        from flowforge.heuristics.proposal_synthesizer import ProposalSynthesizer
        return ProposalSynthesizer()

    def _make_flow_with_leak(self):
        from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
        return FlowRecord(
            id="leak-test-1",
            server_host="api.example.com",
            request=RequestModel(
                method="POST",
                url="https://api.example.com/api/users",
                path="/api/users",
                headers={"content-type": "application/json"},
                body='{"email": "secret@example.com", "name": "John Doe"}',
            ),
            response=ResponseModel(
                status_code=200,
                headers={"content-type": "application/json"},
                body='{"status": "ok", "email": "secret@example.com", "message": "User created"}',
            ),
        )

    def _make_flow_without_leak(self):
        from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
        return FlowRecord(
            id="no-leak-1",
            server_host="api.example.com",
            request=RequestModel(
                method="GET",
                url="https://api.example.com/api/users/123",
                path="/api/users/123",
                headers={},
            ),
            response=ResponseModel(
                status_code=200,
                headers={"content-type": "application/json"},
                body='{"id": 123, "name": "John"}',
            ),
        )

    def test_detects_leaked_email(self):
        synth = self._make_synthesizer()
        flow = self._make_flow_with_leak()
        triage = TriageSummary(
            flow_id="leak-test-1",
            canonical_endpoint="/api/users",
            endpoint_category=EndpointCategory.DATA_READ,
            tags=[],
        )
        proposals = synth.synthesize_data_flow_leaks(flow, triage)
        assert len(proposals) >= 1
        assert "Data Flow Leak" in proposals[0].title
        assert "secret@example.com" in proposals[0].description

    def test_no_leak_for_normal_response(self):
        synth = self._make_synthesizer()
        flow = self._make_flow_without_leak()
        triage = TriageSummary(
            flow_id="no-leak-1",
            canonical_endpoint="/api/users/123",
            endpoint_category=EndpointCategory.DATA_READ,
            tags=[],
        )
        proposals = synth.synthesize_data_flow_leaks(flow, triage)
        # No request body with values >= 5 chars should leak
        assert len(proposals) == 0

    def test_ignores_trivial_values(self):
        from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel
        flow = FlowRecord(
            id="trivial-1",
            server_host="api.example.com",
            request=RequestModel(
                method="GET",
                url="https://api.example.com/api/items?id=1",
                path="/api/items",
                query_params={"id": "1"},
            ),
            response=ResponseModel(
                status_code=200,
                body='{"id": 1, "name": "item"}',
            ),
        )
        synth = self._make_synthesizer()
        triage = TriageSummary(
            flow_id="trivial-1",
            canonical_endpoint="/api/items",
            endpoint_category=EndpointCategory.DATA_READ,
            tags=[],
        )
        proposals = synth.synthesize_data_flow_leaks(flow, triage)
        assert len(proposals) == 0
