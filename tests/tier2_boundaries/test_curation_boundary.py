"""
Tier 2 Boundary & Corner Case Tests: Payload Curation, Selective Pruning Edge Cases,
Preservation Invariants, and API Error Handling (Features F15–F16).
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.models.curation import PruneFilterRequest


async def test_t2_curation_delete_default_group_rejection(tmp_dir: str):
    """Verify attempting to delete the system 'default' group is rejected with HTTP 400."""
    settings = Settings(db_path=f"{tmp_dir}/test_curation_b1.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.delete("/api/v1/curation/groups/default")
        assert resp.status_code == 400
        assert "default" in resp.json()["detail"].lower()


async def test_t2_curation_duplicate_group_id_rejection(tmp_dir: str):
    """Verify attempting to create a group with an already-existing ID raises HTTP 400."""
    settings = Settings(db_path=f"{tmp_dir}/test_curation_b2.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create group with explicit ID
        await client.post("/api/v1/curation/groups", json={"id": "grp-unique-1", "name": "Group 1"})

        # Attempt to create duplicate
        resp_dup = await client.post("/api/v1/curation/groups", json={"id": "grp-unique-1", "name": "Group Dup"})
        assert resp_dup.status_code == 400
        assert "already exists" in resp_dup.json()["detail"]


async def test_t2_curation_nonexistent_group_and_payload_404(tmp_dir: str):
    """Verify querying or deleting non-existent groups and payloads returns HTTP 404."""
    settings = Settings(db_path=f"{tmp_dir}/test_curation_b3.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp_g = await client.get("/api/v1/curation/groups/group-does-not-exist")
        assert resp_g.status_code == 404

        resp_p = await client.get("/api/v1/curation/payloads/payload-does-not-exist")
        assert resp_p.status_code == 404

        resp_del_p = await client.delete("/api/v1/curation/payloads/payload-does-not-exist")
        assert resp_del_p.status_code == 404


async def test_t2_curation_pruning_invalid_regex_rejection(tmp_dir: str):
    """Verify selective pruning with invalid regex raises HTTP 400 error."""
    settings = Settings(db_path=f"{tmp_dir}/test_curation_b4.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/curation/prune",
            json={
                "regex_filter": "([invalid_regex_unclosed",
                "preserve_starred": True,
            },
        )
        assert resp.status_code == 400
        assert "regex" in resp.json()["detail"].lower()


async def test_t2_curation_prune_empty_and_zero_match_collections(tmp_dir: str):
    """Verify pruning empty or non-matching collections returns deleted_count=0 without error."""
    settings = Settings(db_path=f"{tmp_dir}/test_curation_b5.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/curation/prune",
            json={
                "status_filter": ["NON_EXISTENT_STATUS_999"],
                "preserve_starred": True,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted_count"] == 0


async def test_t2_curation_prune_length_boundaries(tmp_dir: str):
    """Verify pruning with length_min and length_max filters."""
    settings = Settings(db_path=f"{tmp_dir}/test_curation_b6.db", auto_start_proxy=False)
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create a short payload and a long payload
        await client.post("/api/v1/curation/payloads", json={
            "name": "Short Payload",
            "mutated_value": "123",
            "starred": False,
        })
        await client.post("/api/v1/curation/payloads", json={
            "name": "Long Payload",
            "mutated_value": "A" * 500,
            "starred": False,
        })

        # Prune items with length_max = 10 (should prune Short Payload only)
        resp = await client.post(
            "/api/v1/curation/prune",
            json={
                "length_max": 10,
                "preserve_starred": False,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted_count"] >= 1
