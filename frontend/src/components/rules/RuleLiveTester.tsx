import React, { useState, useMemo, useEffect } from 'react';
import { 
  CustomRule, 
  FlowRecord, 
  ConditionEvalResult, 
  RuleLiveMatchResult, 
  HttpMethod, 
  MatchCondition 
} from '../../types';
import { useFlowStore } from '../../store/flowStore';
import { 
  Play, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Zap, 
  RefreshCw, 
  Sparkles, 
  Layers, 
  ArrowRight, 
  ShieldCheck, 
  ShieldAlert 
} from 'lucide-react';
import { Badge } from '../common/Badge';

interface RuleLiveTesterProps {
  rule: CustomRule;
}

// Shannon entropy calculation helper
function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const frequencies: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

// Client-side rule condition evaluator
function evaluateConditionOnFlow(
  cond: MatchCondition,
  index: number,
  flowData: {
    url: string;
    path: string;
    method: string;
    statusCode: number;
    requestHeaders: Record<string, string>;
    responseHeaders: Record<string, string>;
    requestBody: string;
    responseBody: string;
    contentType: string;
    latencyMs: number;
    entropy: number;
  }
): ConditionEvalResult {
  let actualRaw: any = undefined;

  switch (cond.field) {
    case 'url':
      actualRaw = flowData.url;
      break;
    case 'path':
      actualRaw = flowData.path;
      break;
    case 'method':
      actualRaw = flowData.method;
      break;
    case 'header': {
      const k = (cond.key || '').toLowerCase();
      actualRaw = flowData.requestHeaders[k] || flowData.responseHeaders[k];
      break;
    }
    case 'query_param': {
      try {
        const u = new URL(flowData.url.startsWith('http') ? flowData.url : `http://dummy.com${flowData.url}`);
        actualRaw = u.searchParams.get(cond.key || '') ?? undefined;
      } catch (e) {
        actualRaw = undefined;
      }
      break;
    }
    case 'request_body':
      actualRaw = flowData.requestBody;
      break;
    case 'response_body':
      actualRaw = flowData.responseBody;
      break;
    case 'status_code':
      actualRaw = flowData.statusCode;
      break;
    case 'entropy':
      actualRaw = flowData.entropy;
      break;
    case 'content_type':
      actualRaw = flowData.contentType;
      break;
    case 'latency_ms':
      actualRaw = flowData.latencyMs;
      break;
    default:
      actualRaw = '';
  }

  const actualStr = actualRaw !== undefined && actualRaw !== null ? String(actualRaw) : '';
  const targetValStr = String(cond.value ?? '');
  const caseSensitive = !!cond.case_sensitive;

  const compareActual = caseSensitive ? actualStr : actualStr.toLowerCase();
  const compareTarget = caseSensitive ? targetValStr : targetValStr.toLowerCase();

  let passed = false;
  let reason = '';

  switch (cond.operator) {
    case 'equals':
      passed = compareActual === compareTarget;
      reason = passed ? `Equals '${targetValStr}'` : `Expected '${targetValStr}', received '${actualStr}'`;
      break;
    case 'not_equals':
      passed = compareActual !== compareTarget;
      reason = passed ? `Not equals '${targetValStr}'` : `Matches disallowed value '${targetValStr}'`;
      break;
    case 'contains':
      passed = compareActual.includes(compareTarget);
      reason = passed ? `Found '${targetValStr}' in value` : `'${targetValStr}' not found in value`;
      break;
    case 'not_contains':
      passed = !compareActual.includes(compareTarget);
      reason = passed ? `Does not contain '${targetValStr}'` : `Disallowed token '${targetValStr}' was found`;
      break;
    case 'starts_with':
      passed = compareActual.startsWith(compareTarget);
      reason = passed ? `Starts with '${targetValStr}'` : `Does not start with '${targetValStr}'`;
      break;
    case 'ends_with':
      passed = compareActual.endsWith(compareTarget);
      reason = passed ? `Ends with '${targetValStr}'` : `Does not end with '${targetValStr}'`;
      break;
    case 'exists':
      passed = actualRaw !== undefined && actualRaw !== null && actualStr.trim() !== '';
      reason = passed ? `Field exists and is non-empty` : `Field is absent or empty`;
      break;
    case 'not_exists':
      passed = actualRaw === undefined || actualRaw === null || actualStr.trim() === '';
      reason = passed ? `Field is absent` : `Field exists with value '${actualStr}'`;
      break;
    case 'gt': {
      const numAct = Number(actualRaw);
      const numTgt = Number(cond.value);
      passed = !isNaN(numAct) && !isNaN(numTgt) && numAct > numTgt;
      reason = passed ? `${numAct} > ${numTgt}` : `${numAct} is not > ${numTgt}`;
      break;
    }
    case 'lt': {
      const numAct = Number(actualRaw);
      const numTgt = Number(cond.value);
      passed = !isNaN(numAct) && !isNaN(numTgt) && numAct < numTgt;
      reason = passed ? `${numAct} < ${numTgt}` : `${numAct} is not < ${numTgt}`;
      break;
    }
    case 'regex': {
      try {
        const rx = new RegExp(targetValStr, caseSensitive ? '' : 'i');
        passed = rx.test(actualStr);
        reason = passed ? `Matches pattern /${targetValStr}/` : `Does not match regex /${targetValStr}/`;
      } catch (e: any) {
        passed = false;
        reason = `Invalid Regex pattern: ${e.message}`;
      }
      break;
    }
    default:
      passed = false;
      reason = `Unknown operator: ${cond.operator}`;
  }

  return {
    conditionIndex: index,
    field: cond.field,
    operator: cond.operator,
    passed,
    actualValue: actualStr || '<undefined>',
    reason,
  };
}

export const RuleLiveTester: React.FC<RuleLiveTesterProps> = ({ rule }) => {
  const flows = useFlowStore((s) => s.flows);
  const flowOrder = useFlowStore((s) => s.flowOrder);
  const selectedFlowId = useFlowStore((s) => s.selectedFlowId);

  // Test Sandbox Flow Data state
  const [selectedFlowSelect, setSelectedFlowSelect] = useState<string>(selectedFlowId || flowOrder[0] || 'custom');
  const [method, setMethod] = useState<HttpMethod>('GET');
  const [url, setUrl] = useState<string>('https://api.target.com/api/v1/admin/users?id=1001');
  const [statusCode, setStatusCode] = useState<number>(200);
  const [requestHeadersJson, setRequestHeadersJson] = useState<string>('{\n  "Authorization": "Bearer eyJhbGciOi...",\n  "X-Role": "admin"\n}');
  const [responseHeadersJson, setResponseHeadersJson] = useState<string>('{\n  "Content-Type": "application/json"\n}');
  const [requestBody, setRequestBody] = useState<string>('{"role": "superuser"}');
  const [responseBody, setResponseBody] = useState<string>('{"status": "success", "user": {"id": 1001, "role": "admin"}}');
  const [latencyMs, setLatencyMs] = useState<number>(42);

  // Load flow into sandbox when selected from dropdown
  useEffect(() => {
    if (selectedFlowSelect && selectedFlowSelect !== 'custom') {
      const f = flows[selectedFlowSelect];
      if (f) {
        setMethod(f.method);
        setUrl(f.url);
        setStatusCode(f.response_status_code ?? f.response_status ?? (f as any).status_code ?? 200);
        setRequestHeadersJson(JSON.stringify(f.request_headers || {}, null, 2));
        setResponseHeadersJson(JSON.stringify(f.response_headers || {}, null, 2));
        setRequestBody(f.request_body || '');
        setResponseBody(f.response_body || '');
        setLatencyMs(f.latency_ms ?? f.duration_ms ?? (f as any).timing_ms ?? 35);
      }
    }
  }, [selectedFlowSelect, flows]);

  // Execute Live Evaluation against current sandbox state
  const matchResult: RuleLiveMatchResult = useMemo(() => {
    let parsedReqHeaders: Record<string, string> = {};
    let parsedResHeaders: Record<string, string> = {};

    try {
      const obj = JSON.parse(requestHeadersJson);
      Object.entries(obj).forEach(([k, v]) => (parsedReqHeaders[k.toLowerCase()] = String(v)));
    } catch (e) {}

    try {
      const obj = JSON.parse(responseHeadersJson);
      Object.entries(obj).forEach(([k, v]) => (parsedResHeaders[k.toLowerCase()] = String(v)));
    } catch (e) {}

    let path = '/';
    try {
      const u = new URL(url.startsWith('http') ? url : `http://dummy.com${url}`);
      path = u.pathname;
    } catch (e) {
      path = url.split('?')[0] || '/';
    }

    const entropy = calculateShannonEntropy(responseBody || requestBody || '');
    const contentType = parsedResHeaders['content-type'] || 'application/json';

    const flowData = {
      url,
      path,
      method,
      statusCode,
      requestHeaders: parsedReqHeaders,
      responseHeaders: parsedResHeaders,
      requestBody,
      responseBody,
      contentType,
      latencyMs,
      entropy,
    };

    const conditionResults = (rule.conditions || []).map((c, i) =>
      evaluateConditionOnFlow(c, i, flowData)
    );

    let isMatched = false;
    if (conditionResults.length === 0) {
      isMatched = false;
    } else if (rule.match_logic === 'ANY') {
      isMatched = conditionResults.some((c) => c.passed);
    } else {
      isMatched = conditionResults.every((c) => c.passed);
    }

    return {
      ruleId: rule.id,
      ruleName: rule.name,
      severity: rule.severity,
      matched: isMatched,
      conditionResults,
      timestamp: new Date().toISOString(),
    };
  }, [rule, method, url, statusCode, requestHeadersJson, responseHeadersJson, requestBody, responseBody, latencyMs]);

  const loadPresetVulnerable = () => {
    setSelectedFlowSelect('custom');
    setMethod('GET');
    setUrl('https://api.target.com/api/v1/admin/dashboard');
    setStatusCode(200);
    setRequestHeadersJson('{\n  "Host": "api.target.com"\n}');
    setResponseHeadersJson('{\n  "Content-Type": "application/json"\n}');
    setRequestBody('');
    setResponseBody('{"admin": true, "secret_key": "eyJhbGciOi..."}');
    setLatencyMs(45);
  };

  const loadPresetBenign = () => {
    setSelectedFlowSelect('custom');
    setMethod('GET');
    setUrl('https://api.target.com/static/images/logo.png');
    setStatusCode(200);
    setRequestHeadersJson('{\n  "Host": "api.target.com"\n}');
    setResponseHeadersJson('{\n  "Content-Type": "image/png"\n}');
    setRequestBody('');
    setResponseBody('');
    setLatencyMs(12);
  };

  return (
    <div className="bg-[#0B101B] border border-border rounded-xl overflow-hidden font-mono text-xs text-slate-200 flex flex-col h-full space-y-4 p-4 overflow-y-auto">
      {/* Top Header & Preset Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-orange-500/20 text-orange-400 border border-orange-500/30">
            <Zap className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-bold text-slate-100 text-xs">
              Live Heuristic Evaluation Sandbox
            </h3>
            <span className="text-[10px] text-slate-400">
              Test &apos;{rule.name}&apos; against real intercepted traffic or custom sandbox requests
            </span>
          </div>
        </div>

        {/* Preset & Flow Selector */}
        <div className="flex items-center gap-2">
          <select
            value={selectedFlowSelect}
            onChange={(e) => setSelectedFlowSelect(e.target.value)}
            className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-primary max-w-xs truncate"
          >
            <option value="custom">-- Custom Synthetic Request --</option>
            {flowOrder.map((id) => {
              const f = flows[id];
              return (
                <option key={id} value={id}>
                  {f ? `${f.method} ${f.path}` : id}
                </option>
              );
            })}
          </select>

          <button
            type="button"
            onClick={loadPresetVulnerable}
            className="px-2.5 py-1 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/40 text-xs font-semibold"
          >
            Vulnerable Preset
          </button>
          <button
            type="button"
            onClick={loadPresetBenign}
            className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold"
          >
            Benign Preset
          </button>
        </div>
      </div>

      {/* Live Match Verdict Card */}
      <div
        className={`p-4 rounded-xl border flex items-center justify-between transition-all shadow-lg ${
          matchResult.matched
            ? 'bg-gradient-to-r from-emerald-950/60 to-cyan-950/40 border-emerald-500/60 shadow-emerald-500/10'
            : 'bg-slate-900/80 border-slate-800'
        }`}
      >
        <div className="flex items-center gap-3">
          {matchResult.matched ? (
            <div className="p-2 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 animate-pulse">
              <ShieldAlert className="w-6 h-6" />
            </div>
          ) : (
            <div className="p-2 rounded-full bg-slate-800 text-slate-500">
              <ShieldCheck className="w-6 h-6" />
            </div>
          )}

          <div>
            <div className="flex items-center gap-2">
              <span className={`text-sm font-bold ${matchResult.matched ? 'text-emerald-300' : 'text-slate-400'}`}>
                {matchResult.matched ? 'RULE MATCH TRIGGERED ⚠️' : 'NO RULE MATCH'}
              </span>
              <Badge variant={rule.severity === 'CRITICAL' ? 'danger' : rule.severity === 'HIGH' ? 'warning' : 'primary'} size="sm">
                {rule.severity}
              </Badge>
              <span className="text-[10px] text-slate-500 font-mono">
                Match Logic: {rule.match_logic} ({matchResult.conditionResults.filter(c => c.passed).length}/{matchResult.conditionResults.length} conditions met)
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              {matchResult.matched
                ? `Flow satisfies all required conditions under [${rule.match_logic}] operator logic.`
                : `Flow does not satisfy the specified conditions.`}
            </p>
          </div>
        </div>

        <div className="text-right font-mono text-[10px] text-slate-500 hidden sm:block">
          Evaluated: {new Date(matchResult.timestamp).toLocaleTimeString()}
        </div>
      </div>

      {/* Condition Results Breakdown Table */}
      <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2">
        <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
          Condition-by-Condition Evaluation Trace
        </h4>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 text-[10px]">
              <tr>
                <th className="py-2 px-3 w-16 text-center">Status</th>
                <th className="py-2 px-3 w-40">Field &amp; Operator</th>
                <th className="py-2 px-3 w-48">Target Criterion</th>
                <th className="py-2 px-3">Actual Value from Flow</th>
                <th className="py-2 px-3 w-56">Evaluation Reason</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
              {matchResult.conditionResults.map((res, idx) => (
                <tr key={idx} className={res.passed ? 'bg-emerald-950/10' : 'bg-rose-950/10'}>
                  <td className="py-2 px-3 text-center">
                    {res.passed ? (
                      <span className="inline-flex items-center gap-1 text-emerald-400 font-bold text-[11px]">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>PASS</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-rose-400 font-bold text-[11px]">
                        <XCircle className="w-3.5 h-3.5" />
                        <span>FAIL</span>
                      </span>
                    )}
                  </td>
                  <td className="py-2 px-3 text-cyan-300 font-semibold">
                    {res.field} <span className="text-slate-400 font-normal">({res.operator})</span>
                  </td>
                  <td className="py-2 px-3 text-slate-200">
                    {String(rule.conditions[idx]?.value ?? '')}
                  </td>
                  <td className="py-2 px-3 text-slate-300 truncate max-w-[200px]" title={res.actualValue}>
                    {res.actualValue}
                  </td>
                  <td className="py-2 px-3 text-slate-400 text-[11px]">
                    {res.reason}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Synthetic Flow Inputs Sandbox Form */}
      <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
        <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
          Sandbox Request / Response Data
        </h4>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
          {/* Method & URL */}
          <div className="md:col-span-2">
            <label className="block text-[10px] text-slate-400 mb-1">Method</label>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value as HttpMethod)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100 font-bold focus:outline-none focus:border-primary"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
              <option value="PATCH">PATCH</option>
            </select>
          </div>

          <div className="md:col-span-8">
            <label className="block text-[10px] text-slate-400 mb-1">Target URL</label>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-primary"
            />
          </div>

          <div className="md:col-span-2">
            <label className="block text-[10px] text-slate-400 mb-1">Status Code</label>
            <input
              type="number"
              value={statusCode}
              onChange={(e) => setStatusCode(Number(e.target.value))}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-primary font-bold"
            />
          </div>

          {/* Request Headers JSON */}
          <div className="md:col-span-6">
            <label className="block text-[10px] text-slate-400 mb-1">Request Headers (JSON)</label>
            <textarea
              rows={4}
              value={requestHeadersJson}
              onChange={(e) => setRequestHeadersJson(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-primary font-mono"
            />
          </div>

          {/* Response Headers JSON */}
          <div className="md:col-span-6">
            <label className="block text-[10px] text-slate-400 mb-1">Response Headers (JSON)</label>
            <textarea
              rows={4}
              value={responseHeadersJson}
              onChange={(e) => setResponseHeadersJson(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-primary font-mono"
            />
          </div>

          {/* Request Body */}
          <div className="md:col-span-6">
            <label className="block text-[10px] text-slate-400 mb-1">Request Body</label>
            <textarea
              rows={4}
              value={requestBody}
              onChange={(e) => setRequestBody(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-primary font-mono"
            />
          </div>

          {/* Response Body */}
          <div className="md:col-span-6">
            <label className="block text-[10px] text-slate-400 mb-1">Response Body</label>
            <textarea
              rows={4}
              value={responseBody}
              onChange={(e) => setResponseBody(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-primary font-mono"
            />
          </div>
        </div>
      </div>
    </div>
  );
};
