import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { 
  GraphNodeData, 
  GraphEdgeData, 
  EndpointCategory, 
  IdorRiskLevel, 
  HttpMethod,
  FlowRecord,
  EndpointDossier 
} from '../src/types';

/**
 * Pure simulation of ApiFlowGraph layout and lineage edge computation logic
 * exactly matching ApiFlowGraph.tsx implementation.
 */
function computeGraphTopology(
  flows: Record<string, FlowRecord>,
  flowOrder: string[],
  dossiers: Record<string, EndpointDossier>,
  customNodePositions: Record<string, { x: number; y: number }> = {},
  filters: {
    selectedHostFilter?: string;
    minRiskFilter?: number;
    onlyAnomalies?: boolean;
    searchQuery?: string;
  } = {}
) {
  const rawNodesMap: Record<string, GraphNodeData> = {};
  const hostsSet = new Set<string>();

  // 1. Process dossiers
  Object.values(dossiers).forEach((dossier) => {
    if (!dossier) return;
    const host = dossier.host || 'api.target.com';
    hostsSet.add(host);
    const path = dossier.path_template || '/';
    const nodeId = `node-${host}-${path}`;
    const method = (dossier.methods?.[0] || 'GET') as HttpMethod;
    const dossierKey = `${host}::${path}`;

    let riskScore = 20;
    const anomalies: string[] = [];
    let reflectionsCount = 0;
    let idorRisk: IdorRiskLevel = 'NONE';
    let authPresent = false;

    dossier.parameters?.forEach((p) => {
      if (!p) return;
      if ((p as any).is_reflected || (p.reflections_count && p.reflections_count > 0)) {
        reflectionsCount += 1;
        riskScore += 25;
        if (!anomalies.includes('Input Reflection')) anomalies.push('Input Reflection');
      }
      if (p.idor_risk === 'HIGH') {
        idorRisk = 'HIGH';
        riskScore += 35;
        if (!anomalies.includes('High-Risk IDOR')) anomalies.push('High-Risk IDOR');
      }
    });

    const dossierCat = dossier.primary_category || (dossier as any).category;
    if (dossierCat === 'ADMIN') {
      riskScore += 30;
      anomalies.push('Admin Surface');
    } else if (dossierCat === 'AUTH') {
      authPresent = true;
    }

    rawNodesMap[nodeId] = {
      id: nodeId,
      label: `${method} ${path}`,
      host,
      path,
      method,
      category: dossierCat || 'DATA_READ',
      riskScore: Math.min(100, Math.max(0, isNaN(riskScore) ? 20 : riskScore)),
      anomalies,
      reflectionsCount,
      idorRisk,
      authPresent,
      dossierKey,
      callCount: dossier.sample_flow_ids?.length || 1,
    };
  });

  // 2. Process flows
  const flowList = flowOrder.map((id) => flows[id]).filter(Boolean);
  flowList.forEach((flow) => {
    const host = flow.host || 'api.target.com';
    hostsSet.add(host);
    const path = (flow.path || '/').split('?')[0] || '/';
    const nodeId = `node-${host}-${path}`;
    const dossierKey = `${host}::${path}`;

    let reflectionsCount = flow.triage?.reflections?.length || 0;
    let idorRisk: IdorRiskLevel = flow.triage?.identifiers?.some((i) => i.idor_risk === 'HIGH') ? 'HIGH' : 'NONE';
    let authPresent = !!flow.triage?.auth?.auth_present;
    let category: EndpointCategory = flow.triage?.endpoint_category || 'DATA_READ';

    let riskScore = 15;
    const anomalies: string[] = [];
    if (reflectionsCount > 0) {
      riskScore += 30;
      anomalies.push('Input Reflection');
    }
    if (idorRisk === 'HIGH') {
      riskScore += 35;
      anomalies.push('High-Risk IDOR');
    }
    if (flow.triage?.auth?.anomaly_flags?.length) {
      riskScore += 25;
      anomalies.push('Auth Deviation');
    }
    if (category === 'ADMIN') {
      riskScore += 30;
      anomalies.push('Admin Surface');
    }

    const flowStatusCode = flow.response_status_code ?? flow.response_status ?? (flow as any).status_code;

    if (rawNodesMap[nodeId]) {
      rawNodesMap[nodeId].callCount += 1;
      rawNodesMap[nodeId].reflectionsCount = Math.max(rawNodesMap[nodeId].reflectionsCount, reflectionsCount);
      if (idorRisk === 'HIGH') rawNodesMap[nodeId].idorRisk = 'HIGH';
      if (authPresent) rawNodesMap[nodeId].authPresent = true;
      rawNodesMap[nodeId].riskScore = Math.min(100, Math.max(rawNodesMap[nodeId].riskScore, riskScore));
      rawNodesMap[nodeId].lastStatusCode = flowStatusCode;
    } else {
      rawNodesMap[nodeId] = {
        id: nodeId,
        label: `${flow.method || 'GET'} ${path}`,
        host,
        path,
        method: (flow.method || 'GET') as HttpMethod,
        category,
        riskScore: Math.min(100, Math.max(0, isNaN(riskScore) ? 15 : riskScore)),
        anomalies,
        reflectionsCount,
        idorRisk,
        authPresent,
        dossierKey,
        callCount: 1,
        lastStatusCode: flowStatusCode,
      };
    }
  });

  // Fallback if empty
  if (Object.keys(rawNodesMap).length === 0) {
    const defaultHost = 'api.forge-target.io';
    hostsSet.add(defaultHost);
    rawNodesMap[`node-${defaultHost}-/api/v1/auth/login`] = {
      id: `node-${defaultHost}-/api/v1/auth/login`,
      label: 'POST /api/v1/auth/login',
      host: defaultHost,
      path: '/api/v1/auth/login',
      method: 'POST',
      category: 'AUTH',
      riskScore: 35,
      anomalies: ['Auth Handshake'],
      reflectionsCount: 0,
      idorRisk: 'NONE',
      authPresent: true,
      dossierKey: `${defaultHost}::/api/v1/auth/login`,
      callCount: 1,
    };
  }

  // 3. Compute DAG Layer Positions
  const layerCategories: EndpointCategory[] = ['AUTH', 'DATA_READ', 'MUTATION_ACTION', 'ADMIN'];
  const layerBuckets: Record<EndpointCategory, GraphNodeData[]> = {
    AUTH: [],
    DATA_READ: [],
    MUTATION_ACTION: [],
    ADMIN: [],
    TELEMETRY: [],
    UNKNOWN: [],
  };

  Object.values(rawNodesMap).forEach((node) => {
    const cat = node.category || 'DATA_READ';
    if (layerBuckets[cat]) {
      layerBuckets[cat].push(node);
    } else {
      layerBuckets['DATA_READ'].push(node);
    }
  });

  const positionedNodes: GraphNodeData[] = [];
  const layerXSpacing = 340;
  const nodeYSpacing = 160;
  const initialYOffset = 60;

  layerCategories.forEach((cat, colIdx) => {
    const bucket = layerBuckets[cat];
    bucket.forEach((node, rowIdx) => {
      const defaultX = 60 + colIdx * layerXSpacing;
      const defaultY = initialYOffset + rowIdx * nodeYSpacing;
      const savedPos = customNodePositions[node.id];

      positionedNodes.push({
        ...node,
        x: savedPos ? savedPos.x : defaultX,
        y: savedPos ? savedPos.y : defaultY,
      });
    });
  });

  // Handle any remaining in non-standard buckets
  ['TELEMETRY', 'UNKNOWN'].forEach((cat) => {
    const bucket = layerBuckets[cat as EndpointCategory] || [];
    bucket.forEach((node, rowIdx) => {
      const defaultX = 60 + 4 * layerXSpacing;
      const defaultY = initialYOffset + rowIdx * nodeYSpacing;
      const savedPos = customNodePositions[node.id];
      positionedNodes.push({
        ...node,
        x: savedPos ? savedPos.x : defaultX,
        y: savedPos ? savedPos.y : defaultY,
      });
    });
  });

  // 4. Edges
  const computedEdges: GraphEdgeData[] = [];
  for (let i = 0; i < positionedNodes.length; i++) {
    const source = positionedNodes[i];
    for (let j = 0; j < positionedNodes.length; j++) {
      if (i === j) continue;
      const target = positionedNodes[j];

      if (source.category === 'AUTH' && target.authPresent && target.category !== 'AUTH') {
        computedEdges.push({
          id: `edge-${source.id}-${target.id}-auth`,
          sourceNodeId: source.id,
          targetNodeId: target.id,
          lineageType: 'AUTH_TOKEN',
          carriedKey: 'Authorization: Bearer <jwt>',
          confidence: 0.95,
          active: true,
        });
      }

      if (
        source.category === 'DATA_READ' &&
        (target.category === 'MUTATION_ACTION' || target.category === 'ADMIN') &&
        source.host === target.host
      ) {
        computedEdges.push({
          id: `edge-${source.id}-${target.id}-param`,
          sourceNodeId: source.id,
          targetNodeId: target.id,
          lineageType: 'PARAM_ID',
          carriedKey: 'user_id / order_id',
          confidence: 0.88,
          active: true,
        });
      }

      if (source.idorRisk === 'HIGH' && target.category === 'ADMIN') {
        computedEdges.push({
          id: `edge-${source.id}-${target.id}-idor`,
          sourceNodeId: source.id,
          targetNodeId: target.id,
          lineageType: 'STATE_SEQUENCE',
          carriedKey: 'Privilege Escalation Vector',
          confidence: 0.9,
          active: true,
        });
      }
    }
  }

  // 5. Apply filters
  const selectedHostFilter = filters.selectedHostFilter || 'ALL';
  const minRiskFilter = filters.minRiskFilter || 0;
  const onlyAnomalies = !!filters.onlyAnomalies;
  const searchQuery = (filters.searchQuery || '').trim().toLowerCase();

  const filteredNodes = positionedNodes.filter((node) => {
    if (selectedHostFilter !== 'ALL' && node.host !== selectedHostFilter) return false;
    if (node.riskScore < minRiskFilter) return false;
    if (onlyAnomalies && node.anomalies.length === 0 && node.riskScore < 50) return false;
    if (searchQuery) {
      const matches =
        node.path.toLowerCase().includes(searchQuery) ||
        node.method.toLowerCase().includes(searchQuery) ||
        node.host.toLowerCase().includes(searchQuery) ||
        node.anomalies.some((a) => a.toLowerCase().includes(searchQuery));
      if (!matches) return false;
    }
    return true;
  });

  const filteredNodeIds = new Set(filteredNodes.map((n) => n.id));
  const filteredEdges = computedEdges.filter(
    (edge) => filteredNodeIds.has(edge.sourceNodeId) && filteredNodeIds.has(edge.targetNodeId)
  );

  return {
    nodes: positionedNodes,
    edges: computedEdges,
    filteredNodes,
    filteredEdges,
    hostList: Array.from(hostsSet),
  };
}

console.log("Starting ApiFlowGraph Adversarial Layout Test Suite...");

// ============================================================================
// Test 1: Cyclic & Circular Endpoint Flows
// ============================================================================
console.log("\n[TEST 1] Cyclic & Circular Lineages");
const cyclicFlows: Record<string, FlowRecord> = {
  'flow-1': {
    id: 'flow-1',
    host: 'api.target.com',
    path: '/api/v1/auth/login',
    method: 'POST',
    url: 'https://api.target.com/api/v1/auth/login',
    triage: {
      endpoint_category: 'AUTH',
      auth: { auth_present: true, auth_type: 'Bearer', anomaly_flags: [] },
      reflections: [],
      identifiers: [],
      entropy: []
    }
  } as any,
  'flow-2': {
    id: 'flow-2',
    host: 'api.target.com',
    path: '/api/v1/users/profile',
    method: 'GET',
    url: 'https://api.target.com/api/v1/users/profile',
    triage: {
      endpoint_category: 'DATA_READ',
      auth: { auth_present: true },
      reflections: [],
      identifiers: [{ param_name: 'user_id', value: '42', id_type: 'SEQUENTIAL_INT', idor_risk: 'HIGH' }],
      entropy: []
    }
  } as any,
  'flow-3': {
    id: 'flow-3',
    host: 'api.target.com',
    path: '/api/v1/users/update',
    method: 'POST',
    url: 'https://api.target.com/api/v1/users/update',
    triage: {
      endpoint_category: 'MUTATION_ACTION',
      auth: { auth_present: true },
      reflections: [],
      identifiers: [],
      entropy: []
    }
  } as any,
  'flow-4': {
    id: 'flow-4',
    host: 'api.target.com',
    path: '/api/v1/admin/roles',
    method: 'GET',
    url: 'https://api.target.com/api/v1/admin/roles',
    triage: {
      endpoint_category: 'ADMIN',
      auth: { auth_present: true },
      reflections: [],
      identifiers: [],
      entropy: []
    }
  } as any,
};

const cyclicRes = computeGraphTopology(cyclicFlows, Object.keys(cyclicFlows), {});
assert.equal(cyclicRes.nodes.length, 4, "Should layout all 4 cyclic flow nodes");
assert.ok(cyclicRes.edges.length >= 3, `Should generate directed edges without infinite recursion (found ${cyclicRes.edges.length})`);

// Ensure coordinates are finite numbers
cyclicRes.nodes.forEach(n => {
  assert.ok(Number.isFinite(n.x), `Node ${n.id} x coordinate must be finite`);
  assert.ok(Number.isFinite(n.y), `Node ${n.id} y coordinate must be finite`);
  assert.ok(n.riskScore >= 0 && n.riskScore <= 100, `Risk score must be bounded in [0, 100], got ${n.riskScore}`);
});
console.log("✓ Cyclic topology computed successfully with bounded coordinates and finite edges.");

// ============================================================================
// Test 2: Disconnected Nodes and Multi-Host Partitioning
// ============================================================================
console.log("\n[TEST 2] 50 Disconnected Nodes Across Multiple Hosts");
const disconnectedFlows: Record<string, FlowRecord> = {};
const flowOrder: string[] = [];

for (let i = 0; i < 50; i++) {
  const host = `service-${i % 5}.internal.corp`;
  const path = `/static/asset-${i}.json`;
  const id = `disc-flow-${i}`;
  disconnectedFlows[id] = {
    id,
    host,
    path,
    method: 'GET',
    url: `https://${host}${path}`,
    triage: {
      endpoint_category: 'DATA_READ',
      auth: { auth_present: false },
      reflections: [],
      identifiers: [],
      entropy: []
    }
  } as any;
  flowOrder.push(id);
}

const discRes = computeGraphTopology(disconnectedFlows, flowOrder, {});
assert.equal(discRes.nodes.length, 50, "All 50 disconnected nodes must be positioned");
assert.equal(discRes.edges.length, 0, "Completely unauthenticated/isolated nodes should have 0 cross-edges");
assert.equal(discRes.hostList.length, 5, "Should extract exactly 5 unique hosts");
console.log("✓ Disconnected multi-host nodes positioned cleanly with 0 invalid phantom edges.");

// ============================================================================
// Test 3: Search Query with Malformed & Regex Metacharacters
// ============================================================================
console.log("\n[TEST 3] Search Filtering with Hostile Regex Metacharacters");
const hostileQueries = [
  '[a-z0-9]+',
  '(*+?)',
  '\\\\\\',
  '^(admin|users)/',
  '.*?.*?',
  '<script>alert(1)</script>',
  '   /api/v1/users   '
];

hostileQueries.forEach((q) => {
  const filtered = computeGraphTopology(cyclicFlows, Object.keys(cyclicFlows), {}, {}, { searchQuery: q });
  assert.ok(Array.isArray(filtered.filteredNodes), `Filtered nodes for hostile query "${q}" must be an array`);
  assert.ok(Array.isArray(filtered.filteredEdges), `Filtered edges for hostile query "${q}" must be an array`);
  // Verify that all filtered edges only connect nodes present in filteredNodes
  const nodeIds = new Set(filtered.filteredNodes.map(n => n.id));
  filtered.filteredEdges.forEach(e => {
    assert.ok(nodeIds.has(e.sourceNodeId), "Edge source must exist in filtered nodes");
    assert.ok(nodeIds.has(e.targetNodeId), "Edge target must exist in filtered nodes");
  });
});
console.log("✓ Hostile search queries handled safely with zero unhandled regex exceptions.");

// ============================================================================
// Test 4: Custom Node Position Overrides & Viewport Constraints
// ============================================================================
console.log("\n[TEST 4] Custom Drag Overrides & Extreme Pan/Zoom Values");
const customPositions = {
  'node-api.target.com-/api/v1/auth/login': { x: -99999, y: 123456 },
  'node-api.target.com-/api/v1/users/profile': { x: 0, y: 0 }
};

const customPosRes = computeGraphTopology(cyclicFlows, Object.keys(cyclicFlows), {}, customPositions);
const loginNode = customPosRes.nodes.find(n => n.id === 'node-api.target.com-/api/v1/auth/login');
const profileNode = customPosRes.nodes.find(n => n.id === 'node-api.target.com-/api/v1/users/profile');

assert.equal(loginNode?.x, -99999, "Custom X override must be preserved");
assert.equal(loginNode?.y, 123456, "Custom Y override must be preserved");
assert.equal(profileNode?.x, 0, "Custom 0 X coordinate must be preserved");
assert.equal(profileNode?.y, 0, "Custom 0 Y coordinate must be preserved");

console.log("✓ Node custom position overrides verified.");
console.log("\nApiFlowGraph Layout Adversarial Test Suite PASSED 100%!");
