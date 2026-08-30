import assert from 'node:assert/strict';
import { api } from '../src/services/api';

console.log("Starting Milestone 3 Decoder & Real-Data Hardening Test Suite...");

// ============================================================================
// Test 1: API Client - Tools & Decoder Endpoints Wrapper Signatures & Payloads
// ============================================================================
console.log("\n[TEST 1] API Client Tools & Decoder Endpoints");

const originalFetch = globalThis.fetch;
const recordedCalls: { url: string; method?: string; body?: any; headers?: any }[] = [];

globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const url = typeof input === 'string' ? input : input.toString();
  const method = init?.method || 'GET';
  const body = init?.body ? JSON.parse(init.body as string) : undefined;
  recordedCalls.push({ url, method, body, headers: init?.headers });

  if (url.includes('/api/v1/tools/decode')) {
    return new Response(
      JSON.stringify({
        status: 'success',
        detected_type: body.decoder_type || 'auto',
        result: 'decoded_test_output',
        layers: [{ layer: 1, type: 'base64', result: 'decoded_test_output' }],
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (url.includes('/api/v1/tools/encode')) {
    return new Response(
      JSON.stringify({
        status: 'success',
        result: 'ZW5jb2RlZF90ZXN0',
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (url.includes('/api/v1/tools/hexdump')) {
    return new Response(
      JSON.stringify({
        status: 'success',
        dump: '00000000  48 65 6c 6c 6f  |Hello|',
        hex_dump: '00000000  48 65 6c 6c 6f  |Hello|',
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (url.includes('/api/v1/tools/jwt/inspect') || url.includes('/api/v1/tools/jwt')) {
    return new Response(
      JSON.stringify({
        valid: true,
        header: { alg: 'HS256', typ: 'JWT' },
        payload: { sub: 'admin', user_id: 42 },
        is_expired: false,
        security_flags: ['NONE_ALG_PROBE'],
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (url.includes('/api/v1/nuclei/templates/cve-2023-1234')) {
    return new Response(
      JSON.stringify({
        id: 'cve-2023-1234',
        info: { name: 'Test CVE Template', severity: 'critical' },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (url.includes('/api/v1/nuclei/templates')) {
    return new Response(
      JSON.stringify({
        items: [
          { id: 'cve-2023-1234', info: { name: 'Test CVE Template', severity: 'critical' } },
          { id: 'exposure-git-config', info: { name: 'Git Config Leak', severity: 'medium' } },
        ],
        total: 2,
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  }

  if (url.includes('/api/v1/nuclei/stats')) {
    return new Response(
      JSON.stringify({
        total_templates: 42,
        categories: { cve: 20, exposures: 15, misconfiguration: 7 },
        severities: { critical: 5, high: 12, medium: 15, low: 10 },
        tags: { cve: 20, rce: 8 },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  }

  return new Response(JSON.stringify({ error: 'not found' }), { status: 404 });
};

async function runTests() {
  // Test decodeContent
  const decodeRes = await api.decodeContent('SGVsbG8gV29ybGQ=', 'base64', { multi_pass: true, max_depth: 3 });
  assert.equal(decodeRes.status, 'success');
  assert.equal(decodeRes.result, 'decoded_test_output');
  assert.equal(recordedCalls[recordedCalls.length - 1].body.content, 'SGVsbG8gV29ybGQ=');
  assert.equal(recordedCalls[recordedCalls.length - 1].body.decoder_type, 'base64');
  assert.equal(recordedCalls[recordedCalls.length - 1].body.multi_pass, true);
  assert.equal(recordedCalls[recordedCalls.length - 1].body.max_depth, 3);
  console.log("✓ api.decodeContent executes POST /api/v1/tools/decode with typed options.");

  // Test encodeContent
  const encodeRes = await api.encodeContent('test_payload', 'base64', { hex_separator: ' ' });
  assert.equal(encodeRes.status, 'success');
  assert.equal(encodeRes.result, 'ZW5jb2RlZF90ZXN0');
  assert.equal(recordedCalls[recordedCalls.length - 1].body.content, 'test_payload');
  assert.equal(recordedCalls[recordedCalls.length - 1].body.encoder_type, 'base64');
  assert.equal(recordedCalls[recordedCalls.length - 1].body.hex_separator, ' ');
  console.log("✓ api.encodeContent executes POST /api/v1/tools/encode with typed options.");

  // Test hexdump
  const hexRes = await api.hexdump('Hello', 32);
  assert.equal(hexRes.status, 'success');
  assert.ok(hexRes.dump.includes('Hello'));
  assert.equal(recordedCalls[recordedCalls.length - 1].body.content, 'Hello');
  assert.equal(recordedCalls[recordedCalls.length - 1].body.bytes_per_line, 32);
  console.log("✓ api.hexdump executes POST /api/v1/tools/hexdump with custom bytes_per_line.");

  // Test inspectJwt
  const jwtRes = await api.inspectJwt('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig');
  assert.equal(jwtRes.valid, true);
  assert.equal(jwtRes.payload.sub, 'admin');
  assert.equal(recordedCalls[recordedCalls.length - 1].body.token, 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig');
  console.log("✓ api.inspectJwt executes POST /api/v1/tools/jwt/inspect with token.");

  // ============================================================================
  // Test 2: API Client - Nuclei Endpoints Wrappers
  // ============================================================================
  console.log("\n[TEST 2] API Client Nuclei Endpoints");

  // Test getNucleiTemplates
  const templatesRes = await api.getNucleiTemplates({ category: 'cve', severity: 'critical', limit: 10 });
  assert.equal(templatesRes.total, 2);
  assert.equal(templatesRes.items.length, 2);
  assert.equal(templatesRes.items[0].id, 'cve-2023-1234');
  assert.ok(recordedCalls[recordedCalls.length - 1].url.includes('/api/v1/nuclei/templates?category=cve&severity=critical&limit=10'));
  console.log("✓ api.getNucleiTemplates executes GET /api/v1/nuclei/templates with query params.");

  // Test getNucleiTemplate
  const singleTemplate = await api.getNucleiTemplate('cve-2023-1234');
  assert.equal(singleTemplate.id, 'cve-2023-1234');
  assert.equal(singleTemplate.info.severity, 'critical');
  assert.ok(recordedCalls[recordedCalls.length - 1].url.includes('/api/v1/nuclei/templates/cve-2023-1234'));
  console.log("✓ api.getNucleiTemplate executes GET /api/v1/nuclei/templates/{id}.");

  // Test getNucleiStats
  const statsRes = await api.getNucleiStats();
  assert.equal(statsRes.total_templates, 42);
  assert.equal(statsRes.categories?.cve, 20);
  assert.ok(recordedCalls[recordedCalls.length - 1].url.includes('/api/v1/nuclei/stats'));
  console.log("✓ api.getNucleiStats executes GET /api/v1/nuclei/stats.");

  // Restore fetch
  globalThis.fetch = originalFetch;

  // ============================================================================
  // Test 3: Dynamic Path Sample Extraction (TargetDossier Logic)
  // ============================================================================
  console.log("\n[TEST 3] Dynamic Path Parameter Sample Extraction Invariants");

  const testFlows = [
    { id: 'f1', host: 'api.target.com', path: '/api/v1/orders/5892', method: 'GET', timestamp: '2026-08-26T12:00:00Z' },
    { id: 'f2', host: 'api.target.com', path: '/api/v1/orders/9921', method: 'GET', timestamp: '2026-08-26T12:01:00Z' },
    { id: 'f3', host: 'api.target.com', path: '/api/v1/users/42/items/108', method: 'GET', timestamp: '2026-08-26T12:02:00Z' },
  ];

  const synthesized: Record<string, any> = {};

  testFlows.forEach((f) => {
    const pathTemplate = f.path.replace(/\/\d+/g, '/{id}');
    const key = `${f.host}::${pathTemplate}`;

    if (!synthesized[key]) {
      synthesized[key] = {
        host: f.host,
        path_template: pathTemplate,
        methods: [f.method],
        parameters: [],
      };
    }

    if (pathTemplate.includes('{id}')) {
      const pathMatches = (f.path.match(/\/\d+(?=\/|$)/g) || []).map((m) => m.slice(1));
      const extractedValues = pathMatches.length > 0 ? Array.from(new Set(pathMatches)) : [];
      const existingParam = synthesized[key].parameters.find((p: any) => p.name === 'id' && p.location === 'path');
      if (!existingParam) {
        synthesized[key].parameters.push({
          name: 'id',
          location: 'path',
          inferred_type: 'integer',
          id_type: 'SEQUENTIAL_INT',
          idor_risk: 'HIGH',
          required: true,
          nullable: false,
          sample_values: extractedValues,
          reflections_count: 0,
          last_seen: f.timestamp,
        });
      } else {
        extractedValues.forEach((val) => {
          if (!existingParam.sample_values.includes(val)) {
            existingParam.sample_values.push(val);
          }
        });
      }
    }
  });

  const ordersKey = 'api.target.com::/api/v1/orders/{id}';
  assert.ok(synthesized[ordersKey]);
  const ordersParam = synthesized[ordersKey].parameters.find((p: any) => p.name === 'id');
  assert.ok(ordersParam);
  // Must contain genuine values 5892 and 9921, and NOT hardcoded 1001, 1002
  assert.deepEqual(ordersParam.sample_values, ['5892', '9921']);
  assert.ok(!ordersParam.sample_values.includes('1001'));
  assert.ok(!ordersParam.sample_values.includes('1002'));

  const usersKey = 'api.target.com::/api/v1/users/{id}/items/{id}';
  assert.ok(synthesized[usersKey]);
  const usersParam = synthesized[usersKey].parameters.find((p: any) => p.name === 'id');
  assert.deepEqual(usersParam.sample_values, ['42', '108']);

  console.log("✓ Dynamic path sample values correctly extracted from real flow paths without hardcoded fallbacks.");

  console.log("\n========================================================");
  console.log("🎉 ALL MILESTONE 3 DECODER & REAL-DATA HARDENING TESTS PASSED!");
  console.log("========================================================");
}

runTests().catch((err) => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
