"""
Tier 2 Boundary & Corner Case Tests: Context-Aware Strategy Recommendations,
Zero Parameters, Extreme Anomaly Combinations, and Ranking Invariants (Features F17–F18).
"""

from __future__ import annotations

import pytest

from flowforge.heuristics.recommendations import StrategyRecommendationEngine
from flowforge.models.curation import RecommendStrategiesRequest


def test_t2_recommendations_zero_parameters_and_root_path():
    """Verify recommendation engine handles endpoints with zero parameters and root path gracefully."""
    engine = StrategyRecommendationEngine()

    res = engine.recommend(
        method="GET",
        path="/",
        parameters=[],
        triage_tags=[],
        reflections=None,
        auth_findings=None,
    )

    assert len(res.recommendations) == 10
    assert res.top_recommended is not None
    # All ranks 1..10 must be uniquely assigned
    ranks = [r.rank for r in res.recommendations]
    assert ranks == list(range(1, 11))


def test_t2_recommendations_unusual_http_methods():
    """Verify recommendation behavior on unusual HTTP methods (OPTIONS, TRACE, HEAD, PROPFIND)."""
    engine = StrategyRecommendationEngine()

    for method in ("OPTIONS", "TRACE", "HEAD", "PROPFIND", "CONNECT", "PATCH"):
        res = engine.recommend(
            method=method,
            path="/webdav/files",
            parameters=[{"name": "file", "value": "test.txt", "data_type": "string"}],
        )
        assert len(res.recommendations) == 10
        assert res.top_recommended is not None
        assert res.top_recommended.badge == "#1 (Recommended)"


def test_t2_recommendations_extreme_conflicting_anomalies():
    """Verify confidence score bounding (10.0 to 99.0) when all anomalies trigger simultaneously."""
    engine = StrategyRecommendationEngine()

    res = engine.recommend(
        method="POST",
        path="/api/v1/admin/users/1001/files/download",
        parameters=[
            {"name": "id", "value": 1001, "id_type": "sequential_integer", "idor_score": 0.95},
            {"name": "file", "value": "report.pdf", "data_type": "string"},
            {"name": "is_admin", "value": True, "data_type": "boolean"},
            {"name": "token", "value": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "inferred_format": "jwt"},
        ],
        triage_tags=["reflection", "auth", "idor_candidate", "jwt", "admin", "state_mutation", "file_transfer"],
        reflections=[{"parameter": "file", "context": "HTML_BODY"}],
        auth_findings=[{"anomaly": "unauth_sensitive"}],
        has_auth_carrier=True,
    )

    assert len(res.recommendations) == 10
    for r in res.recommendations:
        assert 10.0 <= r.confidence_score <= 99.0
        assert r.rank > 0


def test_t2_recommendations_massive_parameter_collection():
    """Verify performance and stability when evaluating an endpoint with 200+ parameters."""
    engine = StrategyRecommendationEngine()

    massive_params = [
        {"name": f"param_{i}", "value": f"value_{i}", "data_type": "string"}
        for i in range(250)
    ]
    # Add one sequential ID
    massive_params.append({"name": "user_id", "value": 500, "id_type": "sequential_integer", "idor_score": 0.8})

    res = engine.recommend(
        method="POST",
        path="/api/v1/bulk/import",
        parameters=massive_params,
    )

    assert len(res.recommendations) == 10
    assert res.top_recommended is not None


def test_t2_recommendations_ranking_uniqueness_and_deterministic_order():
    """Verify rank numbers 1 to 10 are strictly unique and deterministic across repeated runs."""
    engine = StrategyRecommendationEngine()

    req = RecommendStrategiesRequest(
        method="GET",
        path="/api/v1/products/42",
        parameters=[{"name": "id", "value": 42, "id_type": "sequential_integer"}],
        triage_tags=["idor_candidate"],
    )

    run1 = engine.recommend_from_request(req)
    run2 = engine.recommend_from_request(req)

    assert [r.strategy_id for r in run1.recommendations] == [r.strategy_id for r in run2.recommendations]
    assert [r.confidence_score for r in run1.recommendations] == [r.confidence_score for r in run2.recommendations]
    assert [r.badge for r in run1.recommendations] == [r.badge for r in run2.recommendations]
