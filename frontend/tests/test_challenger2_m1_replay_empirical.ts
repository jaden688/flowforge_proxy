import { api } from '../src/services/api';
import { FlowReplayRequest, FlowReplayResponse } from '../src/types';

function assert(condition: boolean, msg: string) {
  if (!condition) {
    console.error(`❌ ASSERTION FAILED: ${msg}`);
    throw new Error(msg);
  }
}

async function runEmpiricalReplayTests() {
  console.log("================================================================================");
  console.log("CHALLENGER 2: EMPIRICAL 1-CLICK REPLAY & FRONTEND API ADVERSARIAL HARNESS");
  console.log("================================================================================\n");

  // Save original fetch
  const originalFetch = global.fetch;

  let testCount = 0;
  let passCount = 0;

  // --------------------------------------------------------------------------
  // TEST 1: api.replayFlow - Normal flow replay & response shape
  // --------------------------------------------------------------------------
  testCount++;
  console.log(`[TEST ${testCount}] api.replayFlow - standard execution`);
  {
    let capturedUrl = '';
    let capturedOptions: any = null;

    global.fetch = async (url: any, opts: any) => {
      capturedUrl = String(url);
      capturedOptions = opts;
      const mockResponse: FlowReplayResponse = {
        ok: true,
        replayed_flow_id: 'flow-replayed-12345',
        status_code: 200,
        reason: 'OK',
        headers: { 'content-type': 'application/json', 'server': 'uvicorn' },
        duration_ms: 42.5,
        body: '{"status":"success","user_id":1001}',
        content_length: 34,
      };
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => mockResponse,
      } as any;
    };

    const res = await api.replayFlow('flow-orig-999');
    assert(capturedUrl.endsWith('/api/v1/flows/flow-orig-999/replay'), `URL must target replay endpoint, got: ${capturedUrl}`);
    assert(capturedOptions.method === 'POST', 'HTTP method must be POST');
    assert(capturedOptions.headers['Content-Type'] === 'application/json', 'Content-Type must be application/json');
    assert(capturedOptions.body === '{}', 'Empty body should default to {} JSON');
    assert(res.ok === true, 'Response ok should be true');
    assert(res.replayed_flow_id === 'flow-replayed-12345', 'Replayed flow id must match');
    assert(res.status_code === 200, 'Status code must be 200');
    assert(res.duration_ms === 42.5, 'Duration ms must match');
    assert(res.content_length === 34, 'Content length must match');

    console.log('✓ api.replayFlow standard flow verified.');
    passCount++;
  }

  // --------------------------------------------------------------------------
  // TEST 2: api.replayFlow - Flow ID with special characters & URL encoding
  // --------------------------------------------------------------------------
  testCount++;
  console.log(`\n[TEST ${testCount}] api.replayFlow - URL encoding with special characters`);
  {
    let capturedUrl = '';
    global.fetch = async (url: any, opts: any) => {
      capturedUrl = String(url);
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          ok: true,
          replayed_flow_id: 'replayed-special',
          status_code: 200,
          headers: {},
          duration_ms: 10,
          body: '',
          content_length: 0,
        }),
      } as any;
    };

    const complexId = 'flow/uuid:123+456#test?param=1';
    await api.replayFlow(complexId);
    assert(capturedUrl.includes(encodeURIComponent(complexId)), `URL must properly encode flow ID with slashes and query chars: ${capturedUrl}`);

    console.log('✓ api.replayFlow URL encoding verified.');
    passCount++;
  }

  // --------------------------------------------------------------------------
  // TEST 3: api.replayFlow - Overrides serialization (method, headers, body, url)
  // --------------------------------------------------------------------------
  testCount++;
  console.log(`\n[TEST ${testCount}] api.replayFlow - Overrides parameter transmission`);
  {
    let capturedBody: any = null;
    global.fetch = async (url: any, opts: any) => {
      capturedBody = JSON.parse(opts.body);
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          ok: true,
          replayed_flow_id: 'replayed-custom',
          status_code: 201,
          headers: { 'content-type': 'application/json' },
          duration_ms: 55,
          body: '{"created":true}',
          content_length: 16,
        }),
      } as any;
    };

    const overrides: FlowReplayRequest = {
      override_method: 'PUT',
      override_url: 'https://custom-target.internal/api/v2/items',
      override_headers: { 'X-Custom-Header': 'AdversarialTest123', 'Authorization': 'Bearer test-token' },
      override_body: '{"custom":"payload","id":999}',
    };

    const res = await api.replayFlow('flow-override-test', overrides);
    assert(capturedBody.override_method === 'PUT', 'override_method should be PUT');
    assert(capturedBody.override_url === 'https://custom-target.internal/api/v2/items', 'override_url should match');
    assert(capturedBody.override_headers['X-Custom-Header'] === 'AdversarialTest123', 'Custom header present');
    assert(capturedBody.override_body === '{"custom":"payload","id":999}', 'override_body should match');
    assert(res.status_code === 201, 'Status code should match 201');

    console.log('✓ api.replayFlow overrides serialization verified.');
    passCount++;
  }

  // --------------------------------------------------------------------------
  // TEST 4: api.replayFlow - Server error (404/500/502) error throwing
  // --------------------------------------------------------------------------
  testCount++;
  console.log(`\n[TEST ${testCount}] api.replayFlow - Error handling on non-ok HTTP status`);
  {
    global.fetch = async (url: any, opts: any) => {
      return {
        ok: false,
        status: 404,
        statusText: 'Not Found',
        text: async () => 'Flow record not found in database',
      } as any;
    };

    let caught = false;
    try {
      await api.replayFlow('flow-nonexistent');
    } catch (err: any) {
      caught = true;
      assert(err.message.includes('Failed to replay flow flow-nonexistent: Not Found'), `Expected error message, got: ${err.message}`);
    }
    assert(caught, 'Must throw error when server returns 404');

    console.log('✓ api.replayFlow HTTP error propagation verified.');
    passCount++;
  }

  // --------------------------------------------------------------------------
  // TEST 5: api.replayRequest - Raw custom request dispatch
  // --------------------------------------------------------------------------
  testCount++;
  console.log(`\n[TEST ${testCount}] api.replayRequest - Raw custom request execution`);
  {
    let capturedUrl = '';
    let capturedPayload: any = null;

    global.fetch = async (url: any, opts: any) => {
      capturedUrl = String(url);
      capturedPayload = JSON.parse(opts.body);
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          ok: true,
          status_code: 200,
          response_headers: { 'content-type': 'text/plain' },
          response_body: 'PONG',
          duration_ms: 12.3,
        }),
      } as any;
    };

    const payload = {
      method: 'POST',
      url: 'http://test-server.internal/ping',
      headers: { 'X-Ping': '1' },
      body: 'ping-data',
    };

    const res = await api.replayRequest(payload);
    assert(capturedUrl.endsWith('/api/v1/flows/send'), `Target must be /flows/send, got: ${capturedUrl}`);
    assert(capturedPayload.method === 'POST', 'Payload method matches');
    assert(capturedPayload.url === 'http://test-server.internal/ping', 'Payload url matches');
    assert(res.ok === true, 'Result ok should be true');
    assert(res.response_body === 'PONG', 'Response body matches');

    console.log('✓ api.replayRequest dispatch verified.');
    passCount++;
  }

  // --------------------------------------------------------------------------
  // TEST 6: Simulated SplitInspector State Machine & Replay Lifecycle
  // --------------------------------------------------------------------------
  testCount++;
  console.log(`\n[TEST ${testCount}] SplitInspector Replay State Machine Lifecycle`);
  {
    // Simulating SplitInspector's handleReplayFlow logic
    let isReplaying = false;
    let replayFeedback: string | null = null;

    // Simulate clicking replay on flow "flow-ui-test"
    const flowId = 'flow-ui-test';

    // Mock successful 200 replay
    global.fetch = async () => {
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          ok: true,
          replayed_flow_id: 'flow-ui-replayed-1',
          status_code: 200,
          reason: 'OK',
          headers: {},
          duration_ms: 25,
          body: '{"ok":true}',
          content_length: 11,
        }),
      } as any;
    };

    async function handleReplayFlow() {
      if (isReplaying) return 'BLOCKED_REENTRANT';
      isReplaying = true;
      replayFeedback = 'Replaying...';

      try {
        const res = await api.replayFlow(flowId);
        if (res.ok) {
          replayFeedback = `Replayed (${res.status_code})`;
        } else {
          replayFeedback = 'Replay Failed';
        }
      } catch (err: any) {
        replayFeedback = `Error: ${err?.message || 'Failed'}`;
      } finally {
        isReplaying = false;
      }
      return 'COMPLETED';
    }

    // Check initial state
    assert(isReplaying === false, 'Initial isReplaying is false');
    assert(replayFeedback === null, 'Initial replayFeedback is null');

    // Run replay
    const replayPromise = handleReplayFlow();
    assert(isReplaying === true, 'isReplaying is true during in-flight request');
    assert(replayFeedback === 'Replaying...', 'replayFeedback is "Replaying..." during flight');

    // Attempt concurrent re-entrant call
    const secondCall = await handleReplayFlow();
    assert(secondCall === 'BLOCKED_REENTRANT', 'Concurrent second call must be blocked');

    // Await completion
    const finalResult = await replayPromise;
    assert(finalResult === 'COMPLETED', 'Initial replay completed');
    assert(isReplaying === false, 'isReplaying reset to false');
    assert(replayFeedback === 'Replayed (200)', 'Feedback shows Replayed (200)');

    console.log('✓ SplitInspector Replay State Machine Lifecycle (success + re-entrancy prevention) verified.');
    passCount++;
  }

  // --------------------------------------------------------------------------
  // TEST 7: SplitInspector State Machine under Replay Failure / Exception
  // --------------------------------------------------------------------------
  testCount++;
  console.log(`\n[TEST ${testCount}] SplitInspector Replay State Machine under Network Error`);
  {
    let isReplaying = false;
    let replayFeedback: string | null = null;
    const flowId = 'flow-error-test';

    // Mock network drop / connection failure
    global.fetch = async () => {
      throw new Error('Connection refused: target host unreachable');
    };

    async function handleReplayFlow() {
      if (isReplaying) return 'BLOCKED';
      isReplaying = true;
      replayFeedback = 'Replaying...';

      try {
        const res = await api.replayFlow(flowId);
        if (res.ok) {
          replayFeedback = `Replayed (${res.status_code})`;
        } else {
          replayFeedback = 'Replay Failed';
        }
      } catch (err: any) {
        replayFeedback = `Error: ${err?.message || 'Failed'}`;
      } finally {
        isReplaying = false;
      }
      return 'COMPLETED';
    }

    await handleReplayFlow();
    assert(isReplaying === false, 'isReplaying must reset to false after error');
    assert(replayFeedback !== null && replayFeedback.includes('Connection refused'), `Feedback must describe error, got: ${replayFeedback}`);

    console.log('✓ SplitInspector Replay State Machine error handling verified.');
    passCount++;
  }

  // --------------------------------------------------------------------------
  // TEST 8: SplitInspector State Machine with Backend 502 / Non-OK status
  // --------------------------------------------------------------------------
  testCount++;
  console.log(`\n[TEST ${testCount}] SplitInspector Replay State Machine under 502 Bad Gateway`);
  {
    let isReplaying = false;
    let replayFeedback: string | null = null;
    const flowId = 'flow-502-test';

    // Mock backend returning 502 Bad Gateway
    global.fetch = async () => {
      return {
        ok: false,
        status: 502,
        statusText: 'Bad Gateway',
        text: async () => 'Upstream connection failed',
      } as any;
    };

    async function handleReplayFlow() {
      if (isReplaying) return 'BLOCKED';
      isReplaying = true;
      replayFeedback = 'Replaying...';

      try {
        const res = await api.replayFlow(flowId);
        if (res.ok) {
          replayFeedback = `Replayed (${res.status_code})`;
        } else {
          replayFeedback = 'Replay Failed';
        }
      } catch (err: any) {
        replayFeedback = `Error: ${err?.message || 'Failed'}`;
      } finally {
        isReplaying = false;
      }
      return 'COMPLETED';
    }

    await handleReplayFlow();
    assert(isReplaying === false, 'isReplaying must reset to false on 502');
    assert(replayFeedback?.includes('Bad Gateway'), `Feedback must report Bad Gateway error: ${replayFeedback}`);

    console.log('✓ SplitInspector Replay State Machine 502 handling verified.');
    passCount++;
  }

  // Restore fetch
  global.fetch = originalFetch;

  console.log("\n================================================================================");
  console.log(`EMPIRICAL CHALLENGER 2 HARNESS: ${passCount}/${testCount} TESTS PASSED`);
  console.log("================================================================================");

  if (passCount !== testCount) {
    process.exit(1);
  }
}

runEmpiricalReplayTests().catch((err) => {
  console.error("FATAL HARNESS ERROR:", err);
  process.exit(1);
});
