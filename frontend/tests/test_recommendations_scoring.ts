import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { 
  getStrategyRecommendations, 
  formatRankLabel, 
  getTopRecommendedStrategy, 
  STRATEGY_DEFINITIONS 
} from '../src/utils/recommendations';
import { FlowRecord, EndpointDossier } from '../src/types';

console.log("Starting Strategy Recommendations Scoring Adversarial Test Suite...");

// ============================================================================
// Test 1: Zero-Parameter Endpoints & Null Objects
// ============================================================================
console.log("\n[TEST 1] Zero-Parameter Endpoints & Null Inputs");
const zeroParamFlow: FlowRecord = {
  id: 'flow-zero',
  host: 'api.example.com',
  path: '/',
  method: 'GET',
  url: 'https://api.example.com/',
  query_params: {},
  request_headers: {},
  request_body: '',
  response_status: 200,
  response_headers: {},
  response_body: '',
  timestamp: String(Date.now()),
  client_ip: '127.0.0.1',
};

const zeroRecs = getStrategyRecommendations(zeroParamFlow, null);
assert.equal(zeroRecs.length, 8, "Must return exactly 8 strategy recommendations");

// Check ranking integrity
const ranks = zeroRecs.map((r) => r.rank);
assert.deepEqual(ranks, [1, 2, 3, 4, 5, 6, 7, 8], "Ranks must be strictly ordered from 1 to 8 without gaps");

// Check scores are descending
for (let i = 0; i < zeroRecs.length - 1; i++) {
  assert.ok(
    zeroRecs[i].score >= zeroRecs[i + 1].score,
    `Scores must be monotonic descending: ${zeroRecs[i].score} vs ${zeroRecs[i + 1].score}`
  );
}

// Check rank 1 is recommended
assert.equal(zeroRecs[0].rank, 1);
assert.equal(zeroRecs[0].isRecommended, true);

// Test completely null / undefined inputs
const nullRecs = getStrategyRecommendations(null, null);
assert.equal(nullRecs.length, 8);
assert.equal(nullRecs[0].rank, 1);
assert.equal(nullRecs[0].isRecommended, true);

const undefinedRecs = getStrategyRecommendations(undefined, undefined);
assert.equal(undefinedRecs.length, 8);

console.log("✓ Zero-parameter and null/undefined inputs produce valid 8-strategy ranked matrices.");

// ============================================================================
// Test 2: Arbitrary & Exotic HTTP Methods
// ============================================================================
console.log("\n[TEST 2] Arbitrary & Exotic HTTP Methods");
const exoticMethods = [
  'PROPFIND',
  'OPTIONS',
  'HEAD',
  'TRACE',
  'CONNECT',
  'SEARCH',
  'PURGE',
  'MKCOL',
  'CUSTOM_METHOD_XYZ',
  '',
  'INVALID METHOD WITH SPACES',
];

exoticMethods.forEach((method) => {
  const flow: FlowRecord = {
    id: `flow-${method}`,
    host: 'api.example.com',
    path: '/resource',
    method: method as any,
    url: `https://api.example.com/resource`,
    client_ip: '127.0.0.1',
    timestamp: String(Date.now()),
    request_headers: {},
    request_body: '',
  };

  const recs = getStrategyRecommendations(flow, null);
  assert.equal(recs.length, 8);
  assert.ok(recs.every((r) => Number.isFinite(r.score) && !isNaN(r.score)));
  assert.ok(recs.every((r) => r.suggestedPayloads && r.suggestedPayloads.length > 0));
});
console.log("✓ All 11 exotic HTTP methods scored deterministically without unhandled errors.");

// ============================================================================
// Test 3: Missing, Null, and Auth Variations
// ============================================================================
console.log("\n[TEST 3] Header Variations & Auth Deviations");

// 3a. Standard request headers fallback detection
const headerVariations = [
  { authorization: 'Bearer eyJhbGci...' },
  { Authorization: 'Bearer eyJhbGci...' },
  { cookie: 'session_id=xyz123' },
];

headerVariations.forEach((headers) => {
  const flow: FlowRecord = {
    id: 'flow-auth',
    host: 'api.target.com',
    path: '/api/v1/secure',
    method: 'GET',
    url: 'https://api.target.com/api/v1/secure',
    client_ip: '127.0.0.1',
    timestamp: String(Date.now()),
    request_headers: headers as any,
  };

  const recs = getStrategyRecommendations(flow, null);
  const authStrat = recs.find((r) => r.category === 'AUTH_STRIPPING');
  assert.ok(authStrat, "AUTH_STRIPPING strategy must exist");
  assert.ok(authStrat.score >= 89, `AUTH_STRIPPING score must be elevated (>=89), got ${authStrat.score}`);
});

// 3b. Triage auth present detection
const triageAuthFlow: FlowRecord = {
  id: 'flow-triage-auth',
  host: 'api.target.com',
  path: '/api/v1/user/settings',
  method: 'GET',
  url: 'https://api.target.com/api/v1/user/settings',
  client_ip: '127.0.0.1',
  timestamp: String(Date.now()),
  triage: {
    endpoint_category: 'DATA_READ',
    auth: {
      auth_present: true,
      auth_type: 'BEARER_JWT',
      anomaly_flags: [],
    },
    reflections: [],
    identifiers: [],
    entropy: [],
    has_anomalies: false,
  },
};

const triageAuthRecs = getStrategyRecommendations(triageAuthFlow, null);
const triageAuthStrat = triageAuthRecs.find((r) => r.category === 'AUTH_STRIPPING');
assert.ok(triageAuthStrat);
assert.ok(triageAuthStrat.score >= 89);

// 3c. Auth anomaly flag elevates score to 97 and CRITICAL
const anomalyFlow: FlowRecord = {
  id: 'flow-auth-anom',
  host: 'api.target.com',
  path: '/api/v1/admin',
  method: 'GET',
  url: 'https://api.target.com/api/v1/admin',
  client_ip: '127.0.0.1',
  timestamp: String(Date.now()),
  triage: {
    endpoint_category: 'ADMIN',
    auth: {
      auth_present: true,
      auth_type: 'BEARER_JWT',
      anomaly_flags: ['TOKEN_EXPIRED_IN_FLIGHT', 'ALG_NONE_BYPASS'],
    },
    reflections: [],
    identifiers: [],
    entropy: [],
    has_anomalies: true,
  },
};

const anomRecs = getStrategyRecommendations(anomalyFlow, null);
const anomAuth = anomRecs.find((r) => r.category === 'AUTH_STRIPPING');
assert.equal(anomAuth?.score, 97);
assert.equal(anomAuth?.severityLikelihood, 'CRITICAL');
console.log("✓ Header variations and auth anomaly elevations confirmed.");

// ============================================================================
// Test 4: Reflection & IDOR Heuristic Scoring Tests
// ============================================================================
console.log("\n[TEST 4] Reflection & IDOR Specific Elevators");

// 4a. Input Reflection Test
const reflectionFlow: FlowRecord = {
  id: 'flow-refl',
  host: 'api.target.com',
  path: '/search',
  method: 'GET',
  url: 'https://api.target.com/search?q=test',
  client_ip: '127.0.0.1',
  timestamp: String(Date.now()),
  triage: {
    endpoint_category: 'DATA_READ',
    reflections: [
      { param_name: 'q', value: 'test', context: 'HTML_BODY', source: 'query', match_type: 'exact', offsets: [[0, 4]], xss_indicator: true },
    ],
    auth: { auth_present: false, auth_type: 'NONE', anomaly_flags: [] },
    identifiers: [],
    entropy: [],
    has_anomalies: true,
  },
};

const reflRecs = getStrategyRecommendations(reflectionFlow, null);
assert.equal(reflRecs[0].category, 'SPECIAL_CHAR_FUZZ', "Reflection must elevate SPECIAL_CHAR_FUZZ to #1");
assert.equal(reflRecs[0].score, 98);
assert.equal(reflRecs[0].severityLikelihood, 'CRITICAL');
assert.ok(reflRecs[0].targetParams?.includes('q'));

// 4b. Sequential IDOR in Path & Triage Identifiers
const idorFlow: FlowRecord = {
  id: 'flow-idor',
  host: 'api.target.com',
  path: '/api/v1/users/1042',
  method: 'GET',
  url: 'https://api.target.com/api/v1/users/1042',
  client_ip: '127.0.0.1',
  timestamp: String(Date.now()),
  triage: {
    endpoint_category: 'DATA_READ',
    identifiers: [
      { param_name: 'user_id', value: '1042', id_type: 'SEQUENTIAL_INT', idor_risk: 'HIGH' },
    ],
    reflections: [],
    auth: { auth_present: false, auth_type: 'NONE', anomaly_flags: [] },
    entropy: [],
    has_anomalies: true,
  },
};

const idorRecs = getStrategyRecommendations(idorFlow, null);
const idorStrat = idorRecs.find((r) => r.category === 'IDOR_SEQUENTIAL');
assert.ok(idorStrat);
assert.equal(idorStrat.score, 96);
assert.equal(idorStrat.severityLikelihood, 'CRITICAL');

// 4c. POST with JSON body elevates Mass Assignment & Schema Mutation
const jsonFlow: FlowRecord = {
  id: 'flow-json',
  host: 'api.target.com',
  path: '/api/v1/users',
  method: 'POST',
  url: 'https://api.target.com/api/v1/users',
  client_ip: '127.0.0.1',
  timestamp: String(Date.now()),
  request_body: '{"name": "Alice", "email": "alice@example.com"}',
};

const jsonRecs = getStrategyRecommendations(jsonFlow, null);
const massAssign = jsonRecs.find((r) => r.category === 'MASS_ASSIGNMENT');
const schemaMut = jsonRecs.find((r) => r.category === 'SCHEMA_MUTATION');
assert.equal(massAssign?.score, 87);
assert.equal(schemaMut?.score, 82);

console.log("✓ Heuristic triggers (Reflection, IDOR, Mass Assignment) correctly score and rank.");

// ============================================================================
// Test 5: Top Recommendation & Rank Label Helpers
// ============================================================================
console.log("\n[TEST 5] Top Strategy & Rank Label Formatting Invariants");
const topStrat = getTopRecommendedStrategy(reflRecs);
assert.equal(topStrat.rank, 1);
assert.equal(topStrat.isRecommended, true);
assert.equal(topStrat.category, 'SPECIAL_CHAR_FUZZ');

// Label formatting
assert.equal(formatRankLabel(1, true), '#1 (Recommended)');
assert.equal(formatRankLabel(2, true), '#2 (High Fit)');
assert.equal(formatRankLabel(2, false), '#2');
assert.equal(formatRankLabel(8, false), '#8');

console.log("✓ Top strategy and rank label helper functions verified.");
console.log("\nStrategy Recommendations Scoring Adversarial Test Suite PASSED 100%!");
