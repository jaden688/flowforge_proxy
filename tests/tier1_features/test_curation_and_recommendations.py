"""
Tier 1 Feature Tests: Payload Curation, Selective Pruning, and Context-Aware
Strategy Recommendations (Features F15–F18).
"""

from __future__ import annotations

import json
import uuid
import pytest
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.heuristics.recommendations import StrategyRecommendationEngine, recommendation_engine
from flowforge.models.curation import (
    CuratedPayload,
    PayloadGroup,
    PruneFilterRequest,
    RankedStrategyResponse,
    RecommendStrategiesRequest,
)


# ===========================================================================
# F15: Payload Curation Models & In-Memory / DB Storage Tests
# ===========================================================================

def test_f15_payload_curation_models_structure():
    """Verify CuratedPayload and PayloadGroup data structures and default attributes."""
    payload = CuratedPayload(
        name="IDOR Sequential +1 Probe",
        category="IDOR_SEQUENTIAL",
        endpoint_path="/api/v1/users/1001/profile",
        method="GET",
        target_param_name="id",
        baseline_value=1001,
        mutated_value=1002,
        starred=True,
        tags=["idor", "bola", "high_priority"],
    )
    assert payload.starred is True
    assert payload.category == "IDOR_SEQUENTIAL"
    assert payload.group_id == "default"

    group = PayloadGroup(
        name="Active BOLA Probes",
        description="High-priority IDOR test vectors for operator review",
        items=[payload],
        payload_ids=[payload.id],
        item_count=1,
    )
    assert group.name == "Active BOLA Probes"
    assert group.item_count == 1
    assert group.payload_ids == [payload.id]


# ===========================================================================
# F16: Payload Curation & Selective Pruning REST APIs Tests
# ===========================================================================

async def test_f16_curation_groups_and_payloads_crud_api(tmp_dir: str):
    """Verify creating groups, adding payloads, starring, and retrieving items."""
    settings = Settings(db_path=f"{tmp_dir}/test_curation_api.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Create a custom payload group
        grp_resp = await client.post(
            "/api/v1/curation/groups",
            json={"name": "SQLi & Auth Bypass", "description": "Curated exploit payloads", "color": "#f43f5e"},
        )
        assert grp_resp.status_code == 200
        group_data = grp_resp.json()
        grp_id = group_data["id"]

        # 2. Add payload to group
        p_resp = await client.post(
            "/api/v1/curation/payloads",
            json={
                "group_id": grp_id,
                "name": "Auth Header Stripping Probe",
                "category": "AUTH_STRIPPING",
                "endpoint_path": "/api/v1/admin/users",
                "method": "GET",
                "target_param_name": "Authorization",
                "mutated_value": None,
                "starred": False,
            },
        )
        assert p_resp.status_code == 200
        p_data = p_resp.json()
        payload_id = p_data["id"]

        # 3. Star payload
        star_resp = await client.post(
            f"/api/v1/curation/payloads/{payload_id}/star",
            params={"starred": True},
        )
        assert star_resp.status_code == 200
        assert star_resp.json()["starred"] is True

        # 4. List payloads
        list_resp = await client.get(f"/api/v1/curation/payloads?group_id={grp_id}")
        assert list_resp.status_code == 200
        assert len(list_resp.json()) == 1


async def test_f16_selective_pruning_preserving_starred_items(tmp_dir: str):
    """Verify selective pruning deletes matching non-starred rows while preserving starred rows."""
    settings = Settings(db_path=f"{tmp_dir}/test_pruning.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create 3 payloads: 1 starred FAILED, 1 unstarred FAILED, 1 unstarred PASSED
        p1 = await client.post("/api/v1/curation/payloads", json={
            "name": "Starred Failed Probe",
            "status": "FAILED",
            "starred": True,
            "category": "IDOR_SEQUENTIAL",
        })
        p2 = await client.post("/api/v1/curation/payloads", json={
            "name": "Unstarred Failed Probe",
            "status": "FAILED",
            "starred": False,
            "category": "IDOR_SEQUENTIAL",
        })
        p3 = await client.post("/api/v1/curation/payloads", json={
            "name": "Passed Probe",
            "status": "PASSED",
            "starred": False,
            "category": "IDOR_SEQUENTIAL",
        })

        # Execute selective pruning on status=["FAILED"] with preserve_starred=True
        prune_resp = await client.post(
            "/api/v1/curation/prune",
            json={
                "preserve_starred": True,
                "status_filter": ["FAILED"],
            },
        )
        assert prune_resp.status_code == 200
        prune_result = prune_resp.json()
        assert prune_result["deleted_count"] >= 1
        assert prune_result["preserved_count"] >= 1


async def test_f16_curation_export_and_import_api(tmp_dir: str):
    """Verify exporting curation data to JSON and importing back."""
    settings = Settings(db_path=f"{tmp_dir}/test_curation_io.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Export
        exp_resp = await client.get("/api/v1/curation/export")
        assert exp_resp.status_code == 200
        exp_data = exp_resp.json()
        assert "groups" in exp_data
        assert "payloads" in exp_data

        # Import
        imp_resp = await client.post("/api/v1/curation/import", json=exp_data)
        assert imp_resp.status_code == 200
        assert imp_resp.json()["status"] == "success"


# ===========================================================================
# F17: Context-Aware Recommendation Engine Scoring & Ranking Tests
# ===========================================================================

def test_f17_recommendation_engine_reflection_elevation():
    """Verify reflection indicators dynamically elevate REFLECTION_CONTEXT to #1 (Recommended)."""
    engine = StrategyRecommendationEngine()

    res = engine.recommend(
        method="GET",
        path="/search",
        parameters=[{"name": "q", "value": "<test>", "data_type": "string"}],
        reflections=[{"parameter": "q", "context": "HTML_BODY"}],
        triage_tags=["reflection"],
    )

    assert len(res.recommendations) > 0
    top = res.top_recommended
    assert top is not None
    assert top.strategy_id == "REFLECTION_CONTEXT"
    assert top.rank == 1
    assert top.is_recommended is True
    assert top.badge == "#1 (Recommended)"
    assert "reflection" in top.reason.lower()


def test_f17_recommendation_engine_sequential_idor_elevation():
    """Verify sequential integer ID parameters elevate IDOR_SEQUENTIAL to #1 (Recommended)."""
    engine = StrategyRecommendationEngine()

    res = engine.recommend(
        method="GET",
        path="/api/v1/accounts/5042/statement",
        parameters=[
            {"name": "account_id", "value": 5042, "id_type": "sequential_integer", "idor_score": 0.85},
        ],
        triage_tags=["idor_candidate"],
    )

    top = res.top_recommended
    assert top is not None
    assert top.strategy_id == "IDOR_SEQUENTIAL"
    assert top.rank == 1
    assert top.is_recommended is True
    assert "sequential" in top.reason.lower() or "idor" in top.reason.lower()


def test_f17_recommendation_engine_jwt_forgery_elevation():
    """Verify presence of JWT tokens in headers elevates JWT_FORGERY_PROBES."""
    engine = StrategyRecommendationEngine()

    res = engine.recommend(
        method="GET",
        path="/api/v1/profile",
        parameters=[
            {"name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "inferred_format": "jwt"},
        ],
        triage_tags=["jwt", "auth"],
    )

    top_strategies = [r.strategy_id for r in res.recommendations[:2]]
    assert "JWT_FORGERY_PROBES" in top_strategies or "AUTH_STRIPPING" in top_strategies


# ===========================================================================
# F18: Strategy Recommendation REST API Endpoints Tests
# ===========================================================================

async def test_f18_recommend_strategies_post_endpoint(tmp_dir: str):
    """Verify POST /api/v1/matrix/strategies/recommend returns ranked strategies with badges."""
    settings = Settings(db_path=f"{tmp_dir}/test_rec_api.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "method": "POST",
            "path": "/api/v1/admin/roles",
            "parameters": [
                {"name": "role_id", "value": "admin", "data_type": "string"},
                {"name": "is_admin", "value": True, "data_type": "boolean"},
            ],
            "triage_tags": ["admin", "state_mutation"],
            "has_auth": True,
        }

        resp = await client.post("/api/v1/matrix/strategies/recommend", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "recommendations" in data
        assert len(data["recommendations"]) == 10  # Full strategy catalog accessible
        assert data["top_recommended"]["badge"] == "#1 (Recommended)"
        assert data["top_recommended"]["is_recommended"] is True


async def test_f18_endpoint_recommendations_get_by_hash(tmp_dir: str):
    """Verify GET /api/v1/matrix/recommendations/{endpoint_hash} returns recommendations."""
    settings = Settings(db_path=f"{tmp_dir}/test_rec_hash.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/v1/matrix/recommendations/hash_test_12345")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_strategies"] == 10
        assert data["top_recommended"] is not None
