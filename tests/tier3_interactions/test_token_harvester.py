"""Tests for the token harvesting pipeline (Phase 3C)."""

import pytest
from flowforge.heuristics.token_harvester import TokenHarvester, HarvestedToken
from flowforge.heuristics.models import TriageSummary, EndpointCategory
from flowforge.models.flow import FlowRecord, RequestModel, ResponseModel


def _make_flow(
    method="GET",
    host="api.example.com",
    path="/users/123",
    headers=None,
    cookies=None,
    body=None,
    resp_body=None,
    resp_headers=None,
):
    return FlowRecord(
        id="test-flow-1",
        server_host=host,
        request=RequestModel(
            method=method,
            url=f"https://{host}{path}",
            path=path,
            headers=headers or {},
            cookies=cookies or {},
            body=body,
        ),
        response=ResponseModel(
            status_code=200,
            headers=resp_headers or {},
            body=resp_body,
        ),
    )


def _make_triage():
    return TriageSummary(
        flow_id="test-flow-1",
        canonical_endpoint="/users/123",
        endpoint_category=EndpointCategory.DATA_READ,
        tags=[],
    )


class TestTokenExtraction:
    def test_extract_bearer_jwt(self):
        harvester = TokenHarvester()
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        flow = _make_flow(headers={"authorization": f"Bearer {jwt}"})
        tokens = harvester.extract_tokens(flow, _make_triage())
        assert len(tokens) == 1
        assert tokens[0].token_type == "jwt"
        assert tokens[0].header_name == "Authorization"

    def test_extract_bearer_generic_token(self):
        harvester = TokenHarvester()
        flow = _make_flow(headers={"authorization": "Bearer my_secret_token_abc123def456"})
        tokens = harvester.extract_tokens(flow, _make_triage())
        assert len(tokens) == 1
        assert tokens[0].token_type == "bearer"

    def test_extract_api_key_github(self):
        harvester = TokenHarvester()
        flow = _make_flow(headers={"x-api-key": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"})
        tokens = harvester.extract_tokens(flow, _make_triage())
        assert len(tokens) == 1
        assert tokens[0].token_type == "api_key"

    def test_extract_session_cookie(self):
        harvester = TokenHarvester()
        flow = _make_flow(cookies={"session": "abc123def456ghi789"})
        tokens = harvester.extract_tokens(flow, _make_triage())
        assert len(tokens) == 1
        assert tokens[0].token_type == "session_cookie"
        assert tokens[0].cookie_name == "session"

    def test_extract_jwt_from_response_body(self):
        harvester = TokenHarvester()
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123def456ghi789"
        flow = _make_flow(resp_body=f'{{"token": "{jwt}"}}')
        tokens = harvester.extract_tokens(flow, _make_triage())
        assert len(tokens) == 1
        assert tokens[0].token_type == "jwt"
        assert tokens[0].header_name == "response_body"

    def test_dedup_same_token(self):
        harvester = TokenHarvester()
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123def456ghi789"
        flow1 = _make_flow(headers={"authorization": f"Bearer {jwt}"})
        flow2 = _make_flow(path="/orders", headers={"authorization": f"Bearer {jwt}"})
        harvester.extract_tokens(flow1, _make_triage())
        tokens2 = harvester.extract_tokens(flow2, _make_triage())
        assert len(tokens2) == 0  # Should be deduped

    def test_no_tokens_in_empty_flow(self):
        harvester = TokenHarvester()
        flow = _make_flow()
        tokens = harvester.extract_tokens(flow, _make_triage())
        assert len(tokens) == 0


class TestTokenReplayCandidates:
    def test_replay_candidates_exclude_same_endpoint(self):
        harvester = TokenHarvester()
        flow1 = _make_flow(path="/users", headers={"authorization": "Bearer tok_user_a_1234567890abcdef"})
        flow2 = _make_flow(path="/orders", headers={"authorization": "Bearer tok_user_b_abcdef1234567890"})
        harvester.extract_tokens(flow1, _make_triage())
        harvester.extract_tokens(flow2, _make_triage())

        # Get candidates for ep1 - should not include its own token
        method, host, path = "GET", "api.example.com", "/users"
        import hashlib
        ep1_hash = hashlib.sha256(f"GET:api.example.com:/users".encode()).hexdigest()[:16]
        candidates = harvester.get_replay_candidates(ep1_hash)
        # Should only include tokens NOT from ep1
        for c in candidates:
            assert c.source_endpoint != ep1_hash

    def test_token_count(self):
        harvester = TokenHarvester()
        flow = _make_flow(headers={"authorization": "Bearer tok_test_value_1234567890"})
        harvester.extract_tokens(flow, _make_triage())
        assert harvester.get_token_count() == 1


class TestHarvestedTokenDataclass:
    def test_to_dict(self):
        t = HarvestedToken(
            token_type="jwt",
            token_preview="eyJhbG...",
            token_hash="abc123",
            source_endpoint="ep1",
            source_host="api.example.com",
            header_name="Authorization",
            context="bearer_jwt",
        )
        d = t.to_dict()
        assert d["token_type"] == "jwt"
        assert d["source_host"] == "api.example.com"
