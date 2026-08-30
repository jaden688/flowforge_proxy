"""Cross-endpoint correlation engine.

Builds an in-memory relationship graph between discovered API endpoints
based on shared parameter names, shared parameter values, path hierarchy,
and auth token reuse patterns. This graph is the foundation for cross-endpoint
IDOR proposals and token replay testing.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from flowforge.db.connection import get_connection


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class EndpointNode:
    """A single discovered endpoint in the correlation graph."""
    endpoint_hash: str
    method: str
    host: str
    path_pattern: str
    request_count: int = 1
    category: str = "DATA_READ"
    parameter_names: List[str] = field(default_factory=list)
    parameter_values: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint_hash": self.endpoint_hash,
            "method": self.method,
            "host": self.host,
            "path_pattern": self.path_pattern,
            "request_count": self.request_count,
            "category": self.category,
            "parameter_names": self.parameter_names,
            "parameter_values": self.parameter_values,
        }


@dataclass
class CorrelationEdge:
    """A relationship between two endpoints."""
    source_hash: str
    target_hash: str
    edge_type: str  # "shared_param", "shared_value", "path_hierarchy", "token_reuse"
    weight: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source_hash,
            "target": self.target_hash,
            "type": self.edge_type,
            "weight": self.weight,
            "metadata": self.metadata,
        }


@dataclass
class EndpointCluster:
    """A group of closely related endpoints."""
    cluster_id: str
    endpoint_hashes: List[str]
    shared_params: List[str]
    host: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "endpoint_hashes": self.endpoint_hashes,
            "shared_params": self.shared_params,
            "host": self.host,
        }


@dataclass
class CorrelationGraph:
    """Full correlation graph returned by the engine."""
    nodes: List[EndpointNode]
    edges: List[CorrelationEdge]
    clusters: List[EndpointCluster]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "clusters": [c.to_dict() for c in self.clusters],
        }

    def get_neighbors(self, endpoint_hash: str) -> List[CorrelationEdge]:
        """Return all edges connected to a given endpoint."""
        return [e for e in self.edges if e.source_hash == endpoint_hash or e.target_hash == endpoint_hash]

    def get_related_endpoints(self, endpoint_hash: str) -> List[str]:
        """Return endpoint hashes related to the given one."""
        neighbors = self.get_neighbors(endpoint_hash)
        related = set()
        for e in neighbors:
            related.add(e.source_hash if e.target_hash == endpoint_hash else e.target_hash)
        return list(related)


# ---------------------------------------------------------------------------
# Path normalization
# ---------------------------------------------------------------------------

# Patterns that look like path parameter placeholders
_PATH_PARAM_PATTERNS = [
    re.compile(r"^[0-9]+$"),                          # Pure integers: 123, 456
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-", re.I),  # UUIDs
    re.compile(r"^[0-9a-f]{24}$", re.I),              # MongoDB ObjectIds
]


def normalize_path(path: str) -> str:
    """Replace path segments that look like dynamic IDs with {id} placeholders.

    Examples:
        /api/users/123/orders -> /api/users/{id}/orders
        /api/items/abc-def-123 -> /api/items/{id}
        /api/v1/users/500/settings -> /api/v1/users/{id}/settings
    """
    segments = path.strip("/").split("/")
    normalized = []
    for seg in segments:
        is_dynamic = False
        for pattern in _PATH_PARAM_PATTERNS:
            if pattern.match(seg):
                is_dynamic = True
                break
        normalized.append("{id}" if is_dynamic else seg)
    return "/" + "/".join(normalized)


def path_parent(child: str, parent: str) -> bool:
    """Check if `parent` is a prefix path of `child`.

    /api/users/{id}/orders  is a child of  /api/users/{id}
    """
    child_norm = normalize_path(child).strip("/").split("/")
    parent_norm = normalize_path(parent).strip("/").split("/")
    return len(child_norm) > len(parent_norm) and child_norm[: len(parent_norm)] == parent_norm


# ---------------------------------------------------------------------------
# CorrelationEngine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Builds and queries an endpoint relationship graph from the database."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    async def build_graph(self) -> CorrelationGraph:
        """Construct the full correlation graph from DB data."""
        endpoints = await self._load_endpoints()
        param_index = await self._load_parameter_index()
        token_index = await self._load_token_index()

        # Build edges
        edges: List[CorrelationEdge] = []
        edges.extend(self._find_shared_param_edges(endpoints, param_index))
        edges.extend(self._find_shared_value_edges(endpoints, param_index))
        edges.extend(self._find_path_hierarchy_edges(endpoints))
        edges.extend(self._find_token_reuse_edges(endpoints, token_index))

        # Deduplicate edges (keep highest weight)
        edges = self._deduplicate_edges(edges)

        # Build clusters via union-find on edges
        clusters = self._build_clusters(endpoints, edges)

        return CorrelationGraph(
            nodes=list(endpoints.values()),
            edges=edges,
            clusters=clusters,
        )

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    async def _load_endpoints(self) -> Dict[str, EndpointNode]:
        """Load all discovered endpoints from the DB."""
        endpoints: Dict[str, EndpointNode] = {}
        async with get_connection(self.db_path) as conn:
            async with conn.execute(
                "SELECT endpoint_hash, method, host, path_pattern, request_count, category "
                "FROM endpoints;"
            ) as cursor:
                async for row in cursor:
                    node = EndpointNode(
                        endpoint_hash=row["endpoint_hash"],
                        method=row["method"],
                        host=row["host"],
                        path_pattern=row["path_pattern"],
                        request_count=row["request_count"] or 1,
                        category=row["category"] or "DATA_READ",
                    )
                    endpoints[node.endpoint_hash] = node
        return endpoints

    async def _load_parameter_index(self) -> Dict[str, Dict[str, Set[str]]]:
        """Build index: param_name -> {endpoint_hash -> set of observed values}."""
        index: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
        async with get_connection(self.db_path) as conn:
            async with conn.execute(
                "SELECT endpoint_hash, name, value "
                "FROM parameters WHERE endpoint_hash IS NOT NULL AND name IS NOT NULL;"
            ) as cursor:
                async for row in cursor:
                    ep_hash = row["endpoint_hash"]
                    name = row["name"]
                    value = row["value"] or ""
                    index[name][ep_hash].add(value)
        return index

    async def _load_token_index(self) -> Dict[str, Set[str]]:
        """Build index: token_value -> set of endpoint_hashes that use it.

        Looks for high-entropy parameter values (likely tokens) across all endpoints.
        """
        index: Dict[str, Set[str]] = defaultdict(set)
        async with get_connection(self.db_path) as conn:
            async with conn.execute(
                "SELECT endpoint_hash, value FROM parameters "
                "WHERE is_entropy_token = 1 AND value IS NOT NULL AND value != '';"
            ) as cursor:
                async for row in cursor:
                    ep_hash = row["endpoint_hash"]
                    token = row["value"]
                    index[token].add(ep_hash)
        return index

    # ------------------------------------------------------------------
    # Edge builders
    # ------------------------------------------------------------------

    def _find_shared_param_edges(
        self,
        endpoints: Dict[str, EndpointNode],
        param_index: Dict[str, Dict[str, Set[str]]],
    ) -> List[CorrelationEdge]:
        """Find edges between endpoints that share parameter names."""
        edges: List[CorrelationEdge] = []
        # For each parameter name, find all endpoints that use it
        param_to_endpoints: Dict[str, List[str]] = {}
        for name, ep_values in param_index.items():
            ep_list = list(ep_values.keys())
            if len(ep_list) >= 2:
                param_to_endpoints[name] = ep_list

        # Generate edges for each pair of endpoints sharing params
        seen_pairs: Set[Tuple[str, str]] = set()
        for name, ep_list in param_to_endpoints.items():
            for i in range(len(ep_list)):
                for j in range(i + 1, len(ep_list)):
                    a, b = sorted([ep_list[i], ep_list[j]])
                    pair = (a, b)
                    if pair not in seen_pairs:
                        seen_pairs.add(pair)
                        edges.append(CorrelationEdge(
                            source_hash=a,
                            target_hash=b,
                            edge_type="shared_param",
                            weight=1,
                            metadata={"param_name": name},
                        ))
                    else:
                        # Increase weight for additional shared params
                        for e in edges:
                            if e.source_hash == a and e.target_hash == b and e.edge_type == "shared_param":
                                e.weight += 1
                                if "param_names" not in e.metadata:
                                    e.metadata["param_names"] = [e.metadata.get("param_name", "")]
                                e.metadata["param_names"].append(name)
                                break
        return edges

    def _find_shared_value_edges(
        self,
        endpoints: Dict[str, EndpointNode],
        param_index: Dict[str, Dict[str, Set[str]]],
    ) -> List[CorrelationEdge]:
        """Find edges between endpoints that share the same parameter values."""
        edges: List[CorrelationEdge] = []
        # Build reverse index: value -> set of endpoint_hashes (only for non-empty values)
        value_to_endpoints: Dict[str, Set[str]] = defaultdict(set)
        for name, ep_values in param_index.items():
            for ep_hash, values in ep_values.items():
                for v in values:
                    if v and len(v) >= 2:  # Skip empty/single-char values
                        value_to_endpoints[v].add(ep_hash)

        seen_pairs: Set[Tuple[str, str]] = set()
        for value, ep_set in value_to_endpoints.items():
            if len(ep_set) < 2:
                continue
            ep_list = sorted(ep_set)
            for i in range(len(ep_list)):
                for j in range(i + 1, len(ep_list)):
                    a, b = ep_list[i], ep_list[j]
                    pair = (a, b)
                    if pair not in seen_pairs:
                        seen_pairs.add(pair)
                        edges.append(CorrelationEdge(
                            source_hash=a,
                            target_hash=b,
                            edge_type="shared_value",
                            weight=1,
                            metadata={"shared_value_preview": value[:50]},
                        ))
                    else:
                        for e in edges:
                            if e.source_hash == a and e.target_hash == b and e.edge_type == "shared_value":
                                e.weight += 1
                                break
        return edges

    def _find_path_hierarchy_edges(
        self,
        endpoints: Dict[str, EndpointNode],
    ) -> List[CorrelationEdge]:
        """Find parent-child relationships between endpoint paths."""
        edges: List[CorrelationEdge] = []
        ep_list = list(endpoints.values())
        for i in range(len(ep_list)):
            for j in range(len(ep_list)):
                if i == j:
                    continue
                a, b = ep_list[i], ep_list[j]
                # Only connect endpoints on the same host
                if a.host != b.host:
                    continue
                if path_parent(b.path_pattern, a.path_pattern):
                    edges.append(CorrelationEdge(
                        source_hash=a.endpoint_hash,
                        target_hash=b.endpoint_hash,
                        edge_type="path_hierarchy",
                        weight=2,  # Hierarchy is a strong signal
                        metadata={"parent": a.path_pattern, "child": b.path_pattern},
                    ))
        return edges

    def _find_token_reuse_edges(
        self,
        endpoints: Dict[str, EndpointNode],
        token_index: Dict[str, Set[str]],
    ) -> List[CorrelationEdge]:
        """Find edges between endpoints that share auth tokens."""
        edges: List[CorrelationEdge] = []
        seen_pairs: Set[Tuple[str, str]] = set()
        for token, ep_set in token_index.items():
            if len(ep_set) < 2:
                continue
            ep_list = sorted(ep_set)
            for i in range(len(ep_list)):
                for j in range(i + 1, len(ep_list)):
                    a, b = ep_list[i], ep_list[j]
                    pair = (a, b)
                    if pair not in seen_pairs:
                        seen_pairs.add(pair)
                        edges.append(CorrelationEdge(
                            source_hash=a,
                            target_hash=b,
                            edge_type="token_reuse",
                            weight=3,  # Token reuse is a very strong signal
                            metadata={"token_preview": token[:20] + "..."},
                        ))
                    else:
                        for e in edges:
                            if e.source_hash == a and e.target_hash == b and e.edge_type == "token_reuse":
                                e.weight += 1
                                break
        return edges

    # ------------------------------------------------------------------
    # Post-processing
    # ------------------------------------------------------------------

    def _deduplicate_edges(self, edges: List[CorrelationEdge]) -> List[CorrelationEdge]:
        """Keep the highest-weight edge for each (source, target) pair."""
        best: Dict[Tuple[str, str], CorrelationEdge] = {}
        for e in edges:
            key = (e.source_hash, e.target_hash)
            if key not in best or e.weight > best[key].weight:
                best[key] = e
        return list(best.values())

    def _build_clusters(
        self,
        endpoints: Dict[str, EndpointNode],
        edges: List[CorrelationEdge],
    ) -> List[EndpointCluster]:
        """Group connected endpoints into clusters using union-find."""
        parent: Dict[str, str] = {h: h for h in endpoints}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: str, y: str) -> None:
            rx, ry = find(x), find(y)
            if rx != ry:
                parent[rx] = ry

        for e in edges:
            union(e.source_hash, e.target_hash)

        # Group by root
        groups: Dict[str, List[str]] = defaultdict(list)
        for h in endpoints:
            groups[find(h)].append(h)

        clusters: List[EndpointCluster] = []
        for idx, (root, members) in enumerate(sorted(groups.items())):
            if len(members) < 2:
                continue  # Skip singletons
            # Find shared params within the cluster
            shared = self._find_cluster_shared_params(members, edges)
            host = endpoints[root].host if root in endpoints else ""
            clusters.append(EndpointCluster(
                cluster_id=f"cluster-{idx}",
                endpoint_hashes=members,
                shared_params=shared,
                host=host,
            ))
        return clusters

    def _find_cluster_shared_params(
        self,
        member_hashes: List[str],
        edges: List[CorrelationEdge],
    ) -> List[str]:
        """Find parameter names shared across members of a cluster."""
        hash_set = set(member_hashes)
        param_names: Set[str] = set()
        for e in edges:
            if e.source_hash in hash_set and e.target_hash in hash_set:
                if e.edge_type == "shared_param":
                    name = e.metadata.get("param_name", "")
                    if name:
                        param_names.add(name)
                    for n in e.metadata.get("param_names", []):
                        if n:
                            param_names.add(n)
        return sorted(param_names)
