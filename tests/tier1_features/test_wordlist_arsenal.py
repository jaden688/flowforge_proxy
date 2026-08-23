"""
Tier 1 Feature Tests: Wordlist Arsenal (discovery, categorization, streaming,
REST API) and Test Matrix integration with wordlist-driven fuzz cases.
"""

from __future__ import annotations

import gzip
import os
import pytest
from httpx import AsyncClient, ASGITransport

from flowforge.api.app import create_app
from flowforge.config import Settings
from flowforge.wordlists import (
    WordlistCategory,
    WordlistLoader,
    get_wordlist_loader,
    reset_wordlist_loader,
)


def _build_fake_arsenal(root: str) -> dict:
    """Create a realistic mini wordlist collection on disk and return its file map."""
    files = {
        os.path.join("seclists", "Discovery", "Web-Content", "common.txt"): "admin\n# comment\nbackup\nlogin\n\napi\n",
        os.path.join("seclists", "Discovery", "Web-Content", "big.txt"): "dashboard\nconsole\n",
        os.path.join("seclists", "Fuzzing", "XSS", "XSS-Enconding.txt"): "<svg onload=alert(1)>\"><script>alert(2)</script>\n",
        os.path.join("seclists", "SQLi", "sqli-generic.txt"): "' OR 1=1--\nadmin'--\n",
        os.path.join("seclists", "Parameters", "burp-parameter-names.txt"): "user_id\nemail\nrole\n",
        os.path.join("passlists", "top-passwords.txt.gz"): None,  # gzip written below
        os.path.join("exploitdb", "cve-pocs.txt"): "CVE-2021-44228-jndi\n",
        os.path.join("misc", "random-values.txt"): "qwe123\n",
    }
    for rel, content in files.items():
        fpath = os.path.join(root, rel)
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        if rel.endswith(".gz"):
            with gzip.open(fpath, "wb") as fh:
                fh.write(b"Password1!\nletmein\n# header comment\nhunter2\n")
        else:
            with open(fpath, "w", encoding="utf-8") as fh:
                fh.write(content)
    return files


@pytest.fixture
def arsenal(tmp_dir: str):
    _build_fake_arsenal(tmp_dir)
    reset_wordlist_loader()
    yield tmp_dir
    reset_wordlist_loader()


# ===========================================================================
# Loader: Discovery & Categorization
# ===========================================================================

def test_arsenal_loader_discovers_and_categorizes(arsenal: str):
    loader = WordlistLoader(roots=[arsenal])
    indexed = loader.refresh()

    assert indexed == 8

    categories = loader.category_counts()
    assert categories.get(WordlistCategory.DISCOVERY.value) == 2
    assert categories.get(WordlistCategory.ATTACK_PAYLOADS.value) == 2
    assert categories.get(WordlistCategory.PARAMETERS.value) == 1
    assert categories.get(WordlistCategory.AUTH_PASSWORDS.value) == 1
    assert categories.get(WordlistCategory.EXPLOITS.value) == 1
    assert categories.get(WordlistCategory.MISC.value) == 1


def test_arsenal_loader_ids_are_stable_and_resolvable(arsenal: str):
    loader = WordlistLoader(roots=[arsenal])
    items = loader.list_wordlists()
    assert len(items) == 8

    first = items[0]
    again = WordlistLoader(roots=[arsenal]).get(first.id)
    assert again is not None
    assert again.path == first.path

    resolved = loader.resolve_ids([first.id, "nonexistent00000000"])
    assert len(resolved) == 1
    assert resolved[0].id == first.id


def test_arsenal_loader_search_and_tag_filter(arsenal: str):
    loader = WordlistLoader(roots=[arsenal])

    by_name = loader.list_wordlists(search="common.txt")
    assert len(by_name) == 1
    assert by_name[0].filename == "common.txt"

    xss_tagged = loader.list_wordlists(category="xss")
    assert len(xss_tagged) == 1
    assert "xss" in xss_tagged[0].tags

    discovery = loader.list_wordlists(category=WordlistCategory.DISCOVERY.value)
    assert {e.filename for e in discovery} == {"common.txt", "big.txt"}


# ===========================================================================
# Loader: Entry Streaming
# ===========================================================================

def test_arsenal_read_entries_strips_comments_and_paginates(arsenal: str):
    loader = WordlistLoader(roots=[arsenal])
    common = next(e for e in loader.list_wordlists() if e.filename == "common.txt")

    page1 = loader.read_entries(common.id, offset=0, limit=2)
    assert page1["entries"] == ["admin", "backup"]

    page2 = loader.read_entries(common.id, offset=2, limit=2)
    assert page2["entries"] == ["login", "api"]

    empty = loader.read_entries(common.id, offset=99, limit=10)
    assert empty["entries"] == []


def test_arsenal_gzip_transparent_reading(arsenal: str):
    loader = WordlistLoader(roots=[arsenal])
    gz_list = next(e for e in loader.list_wordlists() if e.filename.endswith(".gz"))

    entries = loader.sample_entries(gz_list.id, n=10)
    assert entries == ["Password1!", "letmein", "hunter2"]

    count = loader.count_lines(gz_list.id)
    assert count == 3


def test_arsenal_sample_entries_even_sampling(arsenal: str):
    loader = WordlistLoader(roots=[arsenal])
    common = next(e for e in loader.list_wordlists() if e.filename == "common.txt")

    samples = loader.sample_entries(common.id, n=2)
    assert len(samples) == 2
    assert all(s in {"admin", "backup", "login", "api"} for s in samples)

    assert loader.sample_entries(common.id, n=0) == []


# ===========================================================================
# REST API Endpoints
# ===========================================================================

async def test_arsenal_api_list_categories_and_detail(arsenal: str):
    settings = Settings(
        db_path=f"{arsenal}/test_arsenal.db",
        auto_start_proxy=False,
        wordlist_dirs=[arsenal],
    )
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        listing = await client.get("/api/v1/wordlists")
        assert listing.status_code == 200
        body = listing.json()
        assert body["total"] == 8
        assert set(body["categories"].keys()) >= {"discovery", "attack_payloads"}
        assert any(r.endswith(str(arsenal)) or arsenal in r for r in body["roots"])

        filtered = await client.get("/api/v1/wordlists", params={"category": "discovery"})
        assert filtered.status_code == 200
        assert filtered.json()["total"] == 2

        cats = await client.get("/api/v1/wordlists/categories")
        assert cats.status_code == 200
        assert cats.json()["total_lists"] == 8

        target = filtered.json()["items"][0]
        detail = await client.get(f"/api/v1/wordlists/{target['id']}")
        assert detail.status_code == 200
        detail_body = detail.json()
        assert detail_body["line_count"] >= 2
        assert len(detail_body["preview"]) >= 2
        assert all("#" not in p for p in detail_body["preview"])


async def test_arsenal_api_entries_pagination_and_404(arsenal: str):
    settings = Settings(
        db_path=f"{arsenal}/test_arsenal_entries.db",
        auto_start_proxy=False,
        wordlist_dirs=[arsenal],
    )
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        listing = await client.get("/api/v1/wordlists", params={"search": "burp"})
        lid = listing.json()["items"][0]["id"]

        page1 = await client.get(f"/api/v1/wordlists/{lid}/entries", params={"limit": 2})
        assert page1.status_code == 200
        assert page1.json()["entries"] == ["user_id", "email"]

        page2 = await client.get(f"/api/v1/wordlists/{lid}/entries", params={"offset": 2, "limit": 5})
        assert page2.json()["entries"] == ["role"]

        missing = await client.get("/api/v1/wordlists/deadbeefdeadbeef/entries")
        assert missing.status_code == 404


async def test_arsenal_api_refresh_endpoint(arsenal: str):
    settings = Settings(
        db_path=f"{arsenal}/test_arsenal_refresh.db",
        auto_start_proxy=False,
        wordlist_dirs=[arsenal],
    )
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        refreshed = await client.post("/api/v1/wordlists/refresh")
        assert refreshed.status_code == 200
        assert refreshed.json()["indexed_lists"] == 8


# ===========================================================================
# Test Matrix Integration
# ===========================================================================

async def test_matrix_generate_with_arsenal_lists(arsenal: str):
    reset_wordlist_loader()
    settings = Settings(
        db_path=f"{arsenal}/test_matrix_arsenal.db",
        auto_start_proxy=False,
        wordlist_dirs=[arsenal],
    )
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        listing = await client.get("/api/v1/wordlists")
        all_ids = [item["id"] for item in listing.json()["items"]]

        resp = await client.post("/api/v1/matrix/generate", json={
            "endpoint_path": "/api/users/1001",
            "method": "GET",
            "wordlist_ids": all_ids,
            "fuzz_entries_per_list": 3,
        })
        assert resp.status_code == 200
        job = resp.json()

        categories = {case["category"] for case in job["cases"]}
        assert "WORDLIST_FUZZ" in categories
        assert "CONTENT_DISCOVERY" in categories

        fuzz_cases = [c for c in job["cases"] if c["category"] == "WORDLIST_FUZZ"]
        assert all(c["wordlist_id"] in all_ids for c in fuzz_cases)
        assert all(c["target_param_name"] == "id" for c in fuzz_cases)

        discovery_cases = [c for c in job["cases"] if c["category"] == "CONTENT_DISCOVERY"]
        assert all(c["method"] == "GET" for c in discovery_cases)
        assert all(c["mutated_value"].startswith("/api/") for c in discovery_cases)
        # common.txt has 4 usable entries; capped at fuzz_entries_per_list=3
        common_discovery = [c for c in discovery_cases if "/common.txt]" in c["name"]]
        assert len(common_discovery) == 3


async def test_matrix_generate_without_arsenal_lists_unchanged(arsenal: str):
    settings = Settings(
        db_path=f"{arsenal}/test_matrix_plain.db",
        auto_start_proxy=False,
        wordlist_dirs=[arsenal],
    )
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/v1/matrix/generate", json={
            "endpoint_path": "/api/users/1001",
            "method": "GET",
        })
        assert resp.status_code == 200
        job = resp.json()
        categories = {case["category"] for case in job["cases"]}
        assert "WORDLIST_FUZZ" not in categories
        assert "CONTENT_DISCOVERY" not in categories
        assert "IDOR_SEQUENTIAL" in categories


async def test_matrix_generate_category_filter_applies_to_arsenal_cases(arsenal: str):
    settings = Settings(
        db_path=f"{arsenal}/test_matrix_filtered.db",
        auto_start_proxy=False,
        wordlist_dirs=[arsenal],
    )
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        listing = await client.get("/api/v1/wordlists")
        all_ids = [item["id"] for item in listing.json()["items"]]

        resp = await client.post("/api/v1/matrix/generate", json={
            "endpoint_path": "/api/orders",
            "method": "POST",
            "wordlist_ids": all_ids,
            "categories": ["WORDLIST_FUZZ"],
            "fuzz_entries_per_list": 2,
        })
        assert resp.status_code == 200
        cases = resp.json()["cases"]
        assert cases
        assert {c["category"] for c in cases} == {"WORDLIST_FUZZ"}


async def test_matrix_generate_with_unknown_wordlist_id_is_safe(arsenal: str):
    settings = Settings(
        db_path=f"{arsenal}/test_matrix_unknown.db",
        auto_start_proxy=False,
        wordlist_dirs=[arsenal],
    )
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/v1/matrix/generate", json={
            "endpoint_path": "/api/users/7",
            "method": "GET",
            "wordlist_ids": ["does-not-exist-0000"],
        })
        assert resp.status_code == 200
        job = resp.json()
        assert "WORDLIST_FUZZ" not in {c["category"] for c in job["cases"]}
