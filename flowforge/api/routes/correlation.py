"""Correlation graph API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/v1/correlation", tags=["Correlation"])


def _engine(request: Request):
    from flowforge.core.correlation import CorrelationEngine
    from flowforge.config import get_settings
    return CorrelationEngine(get_settings().db_path)


@router.get("/graph")
async def get_correlation_graph(request: Request):
    """Build and return the full endpoint correlation graph."""
    engine = _engine(request)
    graph = await engine.build_graph()
    return graph.to_dict()


@router.get("/neighbors/{endpoint_hash}")
async def get_correlation_neighbors(request: Request, endpoint_hash: str):
    """Return endpoints correlated with a specific endpoint."""
    engine = _engine(request)
    graph = await engine.build_graph()
    neighbors = graph.get_related_endpoints(endpoint_hash)
    edges = graph.get_neighbors(endpoint_hash)
    return {
        "endpoint_hash": endpoint_hash,
        "related_hashes": neighbors,
        "edges": [e.to_dict() for e in edges],
    }
