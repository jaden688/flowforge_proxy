"""Tests for the cross-endpoint correlation engine (Phase 3A)."""

import pytest
import aiosqlite
import asyncio
from flowforge.core.correlation import (
    CorrelationEngine,
    CorrelationGraph,
    EndpointNode,
    CorrelationEdge,
    EndpointCluster,
    normalize_path,
    path_parent,
)


# ---------------------------------------------------------------------------
# Path normalization
# ---------------------------------------------------------------------------

class TestPathNormalization:
    def test_normalize_integer_segments(self):
        assert normalize_path("/api/users/123/orders") == "/api/users/{id}/orders"

    def test_normalize_uuid_segments(self):
        assert normalize_path("/api/items/550e8400-e29b-41d4-a716-446655440000") == "/api/items/{id}"

    def test_normalize_mongo_objectid(self):
        assert normalize_path("/api/docs/507f1f77bcf86cd799439011") == "/api/docs/{id}"

    def test_normalize_static_segments_unchanged(self):
        assert normalize_path("/api/users/me") == "/api/users/me"

    def test_normalize_empty_path(self):
        assert normalize_path("/") == "/"

    def test_path_parent_basic(self):
        assert path_parent("/api/users/123/orders", "/api/users/123") is True

    def test_path_parent_false_when_same(self):
        assert path_parent("/api/users/123", "/api/users/123") is False

    def test_path_parent_false_when_unrelated(self):
        assert path_parent("/api/orders", "/api/users") is False


# ---------------------------------------------------------------------------
# EndpointNode dataclass
# ---------------------------------------------------------------------------

class TestEndpointNode:
    def test_to_dict(self):
        node = EndpointNode(
            endpoint_hash="abc123",
            method="GET",
            host="api.example.com",
            path_pattern="/users/{id}",
            request_count=10,
            category="DATA_READ",
            parameter_names=["id"],
            parameter_values={"id": ["123", "456"]},
        )
        d = node.to_dict()
        assert d["endpoint_hash"] == "abc123"
        assert d["method"] == "GET"
        assert d["host"] == "api.example.com"
        assert d["parameter_names"] == ["id"]


# ---------------------------------------------------------------------------
# CorrelationGraph
# ---------------------------------------------------------------------------

class TestCorrelationGraph:
    def _make_graph(self):
        nodes = [
            EndpointNode("ep1", "GET", "api.example.com", "/users/{id}"),
            EndpointNode("ep2", "GET", "api.example.com", "/orders/{id}"),
            EndpointNode("ep3", "GET", "api.example.com", "/users/{id}/settings"),
        ]
        edges = [
            CorrelationEdge("ep1", "ep2", "shared_param", 1, {"param_name": "id"}),
            CorrelationEdge("ep1", "ep3", "path_hierarchy", 2),
        ]
        clusters = [
            EndpointCluster("c1", ["ep1", "ep2", "ep3"], ["id"], "api.example.com"),
        ]
        return CorrelationGraph(nodes=nodes, edges=edges, clusters=clusters)

    def test_get_neighbors(self):
        g = self._make_graph()
        neighbors = g.get_neighbors("ep1")
        assert len(neighbors) == 2

    def test_get_related_endpoints(self):
        g = self._make_graph()
        related = g.get_related_endpoints("ep1")
        assert "ep2" in related
        assert "ep3" in related

    def test_get_related_endpoints_unknown(self):
        g = self._make_graph()
        related = g.get_related_endpoints("unknown")
        assert related == []

    def test_to_dict(self):
        g = self._make_graph()
        d = g.to_dict()
        assert len(d["nodes"]) == 3
        assert len(d["edges"]) == 2
        assert len(d["clusters"]) == 1


# ---------------------------------------------------------------------------
# CorrelationEngine with real DB
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test.db")


def _insert_test_data(db_path):
    """Insert test data into a fresh SQLite database."""
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    # Create minimal tables
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS flows (
            id TEXT PRIMARY KEY,
            timestamp_start REAL NOT NULL,
            server_host TEXT NOT NULL,
            server_port INTEGER NOT NULL DEFAULT 80,
            scheme TEXT NOT NULL DEFAULT 'http',
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            path TEXT NOT NULL,
            query_string TEXT DEFAULT '',
            query_params TEXT DEFAULT '{}',
            request_headers TEXT DEFAULT '{}',
            response_status_code INTEGER,
            response_headers TEXT DEFAULT '{}',
            response_body TEXT DEFAULT '',
            tags TEXT DEFAULT '[]',
            triage_data TEXT DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS endpoints (
            endpoint_hash TEXT PRIMARY KEY,
            method TEXT NOT NULL,
            host TEXT NOT NULL,
            path_pattern TEXT NOT NULL,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            request_count INTEGER DEFAULT 1,
            category TEXT DEFAULT 'DATA_READ',
            schema_summary TEXT DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS parameters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id TEXT NOT NULL,
            endpoint_hash TEXT NOT NULL,
            location TEXT NOT NULL,
            name TEXT NOT NULL,
            value TEXT,
            data_type TEXT DEFAULT 'string',
            is_entropy_token INTEGER DEFAULT 0,
            is_identifier INTEGER DEFAULT 0,
            timestamp REAL NOT NULL
        );
    """)
    # Insert endpoints
    conn.execute(
        "INSERT INTO endpoints VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("ep_a", "GET", "api.example.com", "/users/{id}", 1000, 2000, 5, "DATA_READ", "{}"),
    )
    conn.execute(
        "INSERT INTO endpoints VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("ep_b", "GET", "api.example.com", "/orders/{id}", 1000, 2000, 5, "DATA_READ", "{}"),
    )
    conn.execute(
        "INSERT INTO endpoints VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("ep_c", "POST", "api.example.com", "/users/{id}/avatar", 1000, 2000, 3, "FILE_TRANSFER", "{}"),
    )
    # Insert parameters - both endpoints share "id" param
    conn.execute(
        "INSERT INTO parameters (flow_id, endpoint_hash, location, name, value, data_type, is_entropy_token, is_identifier, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("f1", "ep_a", "query", "id", "123", "integer", 0, 1, 1000),
    )
    conn.execute(
        "INSERT INTO parameters (flow_id, endpoint_hash, location, name, value, data_type, is_entropy_token, is_identifier, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("f2", "ep_b", "query", "id", "123", "integer", 0, 1, 1000),
    )
    conn.execute(
        "INSERT INTO parameters (flow_id, endpoint_hash, location, name, value, data_type, is_entropy_token, is_identifier, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("f3", "ep_a", "header", "authorization", "Bearer tok_abc123", "string", 1, 0, 1000),
    )
    conn.execute(
        "INSERT INTO parameters (flow_id, endpoint_hash, location, name, value, data_type, is_entropy_token, is_identifier, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("f4", "ep_c", "header", "authorization", "Bearer tok_abc123", "string", 1, 0, 1000),
    )
    conn.commit()
    conn.close()


class TestCorrelationEngine:
    @pytest.mark.asyncio
    async def test_build_graph_loads_endpoints(self, db_path):
        _insert_test_data(db_path)
        engine = CorrelationEngine(db_path)
        graph = await engine.build_graph()
        assert len(graph.nodes) == 3

    @pytest.mark.asyncio
    async def test_build_graph_finds_shared_param(self, db_path):
        _insert_test_data(db_path)
        engine = CorrelationEngine(db_path)
        graph = await engine.build_graph()
        shared_edges = [e for e in graph.edges if e.edge_type == "shared_param"]
        assert len(shared_edges) >= 1

    @pytest.mark.asyncio
    async def test_build_graph_finds_token_reuse(self, db_path):
        _insert_test_data(db_path)
        engine = CorrelationEngine(db_path)
        graph = await engine.build_graph()
        token_edges = [e for e in graph.edges if e.edge_type == "token_reuse"]
        assert len(token_edges) >= 1

    @pytest.mark.asyncio
    async def test_build_graph_finds_shared_value(self, db_path):
        """shared_value edges exist in raw analysis, but may be deduplicated
        against shared_param edges. Verify the raw method works correctly."""
        _insert_test_data(db_path)
        engine = CorrelationEngine(db_path)
        param_index = await engine._load_parameter_index()
        value_edges = engine._find_shared_value_edges({}, param_index)
        assert len(value_edges) >= 1
        assert value_edges[0].edge_type == "shared_value"

    @pytest.mark.asyncio
    async def test_build_graph_creates_clusters(self, db_path):
        _insert_test_data(db_path)
        engine = CorrelationEngine(db_path)
        graph = await engine.build_graph()
        assert len(graph.clusters) >= 1

    @pytest.mark.asyncio
    async def test_build_graph_empty_db(self, db_path):
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE endpoints (endpoint_hash TEXT PRIMARY KEY, method TEXT, host TEXT, path_pattern TEXT, first_seen REAL, last_seen REAL, request_count INTEGER, category TEXT, schema_summary TEXT);
            CREATE TABLE parameters (id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id TEXT, endpoint_hash TEXT, location TEXT, name TEXT, value TEXT, data_type TEXT, is_entropy_token INTEGER, is_identifier INTEGER, timestamp REAL);
        """)
        conn.close()
        engine = CorrelationEngine(db_path)
        graph = await engine.build_graph()
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    @pytest.mark.asyncio
    async def test_get_related_endpoints(self, db_path):
        _insert_test_data(db_path)
        engine = CorrelationEngine(db_path)
        graph = await engine.build_graph()
        related = graph.get_related_endpoints("ep_a")
        assert "ep_b" in related or "ep_c" in related
