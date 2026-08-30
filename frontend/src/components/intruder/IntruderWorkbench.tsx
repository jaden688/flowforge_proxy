import React, { useEffect, useState } from 'react';
import { Crosshair, Play, Square, Plus, Trash2, Upload, RefreshCw } from 'lucide-react';
import { useFlowStore } from '../../store/flowStore';
import { useIntruder } from '../../hooks/useIntruder';
import { api } from '../../services/api';
import { CustomWordlist, ArsenalWordlist, InjectionPoint, IntruderJobConfig, IntruderSuggestions } from '../../types';
import { SuggestInput } from '../common/SuggestInput';
import { IntruderResultsTable } from './IntruderResultsTable';

const DEFAULT_CONFIG = {
  method: 'GET',
  url: '',
  headersText: '{}',
  body: '',
};

export const IntruderWorkbench: React.FC = () => {
  const selectedFlowId = useFlowStore((s) => s.selectedFlowId);
  const flows = useFlowStore((s) => s.flows);

  const {
    activeIntruderJob,
    isLaunching,
    error,
    launchJob,
    abortJob,
    refreshResults,
  } = useIntruder();

  // ---- Target configuration -------------------------------------------------
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('');
  const [headersText, setHeadersText] = useState('{}');
  const [body, setBody] = useState('');

  // Pre-fill from the currently selected flow.
  useEffect(() => {
    if (!selectedFlowId) return;
    const flow = flows[selectedFlowId];
    if (!flow) return;
    setMethod(flow.method || 'GET');
    setUrl(flow.url || '');
    if (flow.request_headers) {
      try {
        setHeadersText(JSON.stringify(flow.request_headers, null, 0));
      } catch {
        /* ignore */
      }
    }
    setBody((flow as any).request_body || (flow as any).body || '');
  }, [selectedFlowId]);

  // ---- Injection points ------------------------------------------------------
  const [points, setPoints] = useState<InjectionPoint[]>([
    { position: 'query', key: 'id', prefix: '', suffix: '' },
  ]);
  const addPoint = () =>
    setPoints([...points, { position: 'query', key: '', prefix: '', suffix: '' }]);
  const updatePoint = (i: number, patch: Partial<InjectionPoint>) =>
    setPoints(points.map((p, idx) => (idx === i ? { ...p, ...patch } : p)));
  const removePoint = (i: number) => setPoints(points.filter((_, idx) => idx !== i));

  // ---- Execution controls ----------------------------------------------------
  const [concurrency, setConcurrency] = useState(4);
  const [rateLimit, setRateLimit] = useState<string>('');
  const [timeoutSeconds, setTimeoutSeconds] = useState('10');

  // ---- Dynamic suggestions (mined from capture history) ----------------------
  const [suggestions, setSuggestions] = useState<IntruderSuggestions | null>(null);
  const loadSuggestions = async () => {
    try {
      setSuggestions(await api.getIntruderSuggestions());
    } catch {
      /* backend warming up */
    }
  };
  useEffect(() => {
    loadSuggestions();
  }, []);

  const storeFlowUrls = Object.values(flows)
    .filter((f) => f.url && !f.path?.startsWith('/api/v1/'))
    .map((f) => `${f.method} ${f.url}`);

  const backendUrls = (suggestions?.urls ?? []).map((u) => `${u.method} ${u.url}`);
  const combinedUrlSuggestions = Array.from(new Set([...storeFlowUrls, ...backendUrls]));

  const urlSuggestions = combinedUrlSuggestions.length > 0
    ? combinedUrlSuggestions
    : (suggestions?.urls ?? []).map((u) => `${u.method} ${u.url}`);

  const pointKeySuggestions =
    points.length > 0 && points[0]?.position === 'header'
      ? suggestions?.header_names ?? []
      : suggestions?.query_params ?? [];

  // ---- Payload sets ------------------------------------------------------------
  const [customLists, setCustomLists] = useState<CustomWordlist[]>([]);
  const [arsenalLists, setArsenalLists] = useState<ArsenalWordlist[]>([]);
  const [arsenalSearch, setArsenalSearch] = useState('');
  const [selectedCustomIds, setSelectedCustomIds] = useState<string[]>([]);
  const [selectedArsenalIds, setSelectedArsenalIds] = useState<string[]>([]);
  const [inlinePayloads, setInlinePayloads] = useState('');

  // Upload form
  const [uploadName, setUploadName] = useState('');
  const [uploadTags, setUploadTags] = useState('');
  const [uploadContent, setUploadContent] = useState('');
  const [uploading, setUploading] = useState(false);

  const loadCustomLists = async () => {
    try {
      const data = await api.getCustomWordlists();
      setCustomLists(data.items);
    } catch {
      /* backend warming up */
    }
  };

  useEffect(() => {
    loadCustomLists();
  }, []);

  useEffect(() => {
    const t = window.setTimeout(async () => {
      try {
        const data = await api.getArsenalWordlists(undefined, arsenalSearch || undefined);
        setArsenalLists(data.items.slice(0, 300));
      } catch {
        /* ignore */
      }
    }, 250);
    return () => clearTimeout(t);
  }, [arsenalSearch]);

  const toggle = (list: string[], id: string) =>
    list.includes(id) ? list.filter((x) => x !== id) : [...list, id];

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uploadName.trim() || !uploadContent.trim()) return;
    setUploading(true);
    try {
      const created = await api.uploadCustomWordlist({
        name: uploadName.trim(),
        tags: uploadTags.split(',').map((t) => t.trim()).filter(Boolean),
        content: uploadContent,
      });
      setCustomLists((prev) => [created, ...prev]);
      setSelectedCustomIds((prev) => [...prev, created.id]);
      setUploadName('');
      setUploadTags('');
      setUploadContent('');
    } catch (err: any) {
      alert(`Upload failed: ${err.message}`);
    } finally {
      setUploading(false);
    }
  };

  const handleDeleteList = async (id: string) => {
    try {
      await api.deleteCustomWordlist(id);
      setCustomLists((prev) => prev.filter((w) => w.id !== id));
      setSelectedCustomIds((prev) => prev.filter((x) => x !== id));
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  const handleLaunch = async () => {
    let headers: Record<string, string> = {};
    try {
      headers = JSON.parse(headersText || '{}');
    } catch {
      alert('Headers must be valid JSON');
      return;
    }
    const config: IntruderJobConfig = {
      flow_id: selectedFlowId,
      method,
      url,
      headers,
      body: body || null,
      injection_points: points,
      custom_wordlist_ids: selectedCustomIds,
      arsenal_wordlist_ids: selectedArsenalIds,
      inline_payloads: inlinePayloads.split('\n').map((l) => l.trim()).filter(Boolean),
      concurrency,
      rate_limit_rps: rateLimit ? Number(rateLimit) : null,
      timeout_seconds: Number(timeoutSeconds) || 10,
    };
    await launchJob(config);
  };

  const running = activeIntruderJob?.status === 'RUNNING' || activeIntruderJob?.status === 'PENDING';
  const progressPct =
    activeIntruderJob && activeIntruderJob.total_requests > 0
      ? Math.round((activeIntruderJob.completed_requests / activeIntruderJob.total_requests) * 100)
      : 0;

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="h-11 px-4 flex items-center justify-between border-b border-border bg-surface shrink-0">
        <div className="flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-rose-400" />
          <span className="font-bold text-sm text-white font-mono">INTRUDER</span>
          {activeIntruderJob && (
            <span
              className={`px-2 py-0.5 rounded-full text-[10px] font-mono border ${
                running
                  ? 'bg-amber-500/15 text-amber-300 border-amber-500/40 animate-pulse'
                  : activeIntruderJob.status === 'COMPLETED'
                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40'
                  : activeIntruderJob.status === 'ABORTED'
                  ? 'bg-slate-600/30 text-slate-300 border-slate-500/40'
                  : 'bg-rose-500/15 text-rose-300 border-rose-500/40'
              }`}
            >
              {activeIntruderJob.status}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {activeIntruderJob && (
            <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
              <span>
                {activeIntruderJob.completed_requests}/{activeIntruderJob.total_requests} reqs
              </span>
              <span className="text-rose-300">{activeIntruderJob.anomaly_count} anomalies</span>
              <div className="w-40 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all"
                  style={{ width: `${progressPct}%` }}
                />
              </div>
            </div>
          )}
          {running ? (
            <button
              onClick={() => abortJob()}
              className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-md shadow-rose-500/20"
            >
              <Square className="w-3.5 h-3.5" /> Abort
            </button>
          ) : (
            <button
              onClick={handleLaunch}
              disabled={isLaunching || !url}
              className="px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover disabled:opacity-40 disabled:cursor-not-allowed text-slate-950 text-xs font-semibold flex items-center gap-1.5 shadow-md shadow-primary/20"
            >
              <Play className="w-3.5 h-3.5" /> {isLaunching ? 'Launching…' : 'Attack'}
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="px-4 py-1.5 bg-rose-500/10 border-b border-rose-500/30 text-rose-300 text-xs font-mono">
          {error}
        </div>
      )}

      <div className="flex-1 flex min-h-0">
        {/* Left: Configuration */}
        <div className="w-[380px] shrink-0 overflow-y-auto border-r border-border p-3 space-y-4">
          {/* Target */}
          <section className="space-y-2">
            <h3 className="text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">Target</h3>
            <div className="flex gap-2">
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded-lg px-2 py-1.5 text-xs font-mono font-bold text-primary focus:outline-none"
              >
                {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => (
                  <option key={m}>{m}</option>
                ))}
              </select>
              <SuggestInput
                value={url}
                onChange={(v) => {
                  setUrl(v);
                  // Accept "METHOD url" suggestion format
                  const m = v.match(/^(GET|POST|PUT|PATCH|DELETE)\s+(https?:\/\/.+)$/i);
                  if (m) {
                    setMethod(m[1].toUpperCase());
                    setUrl(m[2]);
                  }
                }}
                suggestions={urlSuggestions}
                placeholder={`${window.location.protocol}//target/api/users/1001?q=`}
                className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-2 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
                title="Auto-suggested from intercepted traffic"
              />
            </div>
            <div className="flex items-center gap-2">
              {selectedFlowId && (
                <p className="text-[10px] text-cyan-400/80 font-mono flex-1">
                  ⬅ pre-filled from selected flow ({flows[selectedFlowId]?.path})
                </p>
              )}
              <button
                onClick={loadSuggestions}
                className="ml-auto p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 border border-slate-700"
                title="Refresh history suggestions"
              >
                <RefreshCw className="w-3 h-3" />
              </button>
            </div>
            {Object.keys(flows).length > 0 && (
              <div className="pt-1">
                <select
                  className="bg-slate-900 border border-slate-700/80 rounded-lg px-2 py-1 text-[11px] font-mono text-slate-300 w-full focus:outline-none focus:border-cyan-500 cursor-pointer"
                  onChange={(e) => {
                    const fid = e.target.value;
                    if (!fid) return;
                    const f = flows[fid];
                    if (f) {
                      setMethod(f.method || 'GET');
                      setUrl(f.url || '');
                      if (f.request_headers) {
                        try {
                          setHeadersText(JSON.stringify(f.request_headers, null, 0));
                        } catch { /* ignore */ }
                      }
                      setBody((f as any).request_body || (f as any).body || '');
                    }
                  }}
                  defaultValue=""
                >
                  <option value="" disabled>-- Load from captured live traffic --</option>
                  {Object.values(flows)
                    .filter((f) => !f.path?.startsWith('/api/v1/'))
                    .map((f) => (
                      <option key={f.id} value={f.id}>
                        {f.method} {f.host || ''}{f.path || f.url}
                      </option>
                    ))}
                </select>
              </div>
            )}
            <textarea
              rows={3}
              value={headersText}
              onChange={(e) => setHeadersText(e.target.value)}
              placeholder='{"Authorization": "Bearer …"}'
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
            />
            <textarea
              rows={3}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder='Request body (POST/PUT)'
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
            />
          </section>

          {/* Injection points */}
          <section className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">Injection Points</h3>
              <button onClick={addPoint} className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">
                <Plus className="w-3.5 h-3.5" />
              </button>
            </div>
            {points.map((p, i) => (
              <div key={i} className="flex items-center gap-1.5">
                <select
                  value={p.position}
                  onChange={(e) => updatePoint(i, { position: e.target.value as InjectionPoint['position'] })}
                  className="bg-slate-900 border border-slate-700 rounded px-1.5 py-1 text-[11px] font-mono text-primary focus:outline-none"
                >
                  <option value="query">query</option>
                  <option value="header">header</option>
                  <option value="body">body</option>
                </select>
                {p.position !== 'body' && (
                  <SuggestInput
                    value={p.key ?? ''}
                    onChange={(v) => updatePoint(i, { key: v })}
                    suggestions={pointKeySuggestions}
                    placeholder={p.position === 'header' ? 'Header-Name' : 'param'}
                    className="w-28 bg-slate-900 border border-slate-700 rounded px-1.5 py-1 text-[11px] font-mono text-slate-200 focus:outline-none focus:border-primary"
                    title={`Observed ${p.position} parameters from captured traffic`}
                  />
                )}
                <SuggestInput
                  value={p.prefix ?? ''}
                  onChange={(v) => updatePoint(i, { prefix: v })}
                  suggestions={(suggestions?.body_fields ?? []).map((f) => `{"${f}":"`)}
                  placeholder="prefix"
                  className="w-16 bg-slate-900 border border-slate-700 rounded px-1.5 py-1 text-[11px] font-mono text-slate-400 focus:outline-none focus:border-primary"
                />
                <input
                  value={p.suffix}
                  onChange={(e) => updatePoint(i, { suffix: e.target.value })}
                  placeholder="suffix"
                  className="w-16 bg-slate-900 border border-slate-700 rounded px-1.5 py-1 text-[11px] font-mono text-slate-400 focus:outline-none focus:border-primary"
                />
                <button onClick={() => removePoint(i)} className="p-1 rounded text-slate-500 hover:text-rose-400">
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </section>

          {/* Engine controls */}
          <section className="space-y-2">
            <h3 className="text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">Engine</h3>
            <div className="grid grid-cols-3 gap-2">
              <label className="text-[10px] font-mono text-slate-500">
                Concurrency
                <input
                  type="number" min={1} max={64}
                  value={concurrency}
                  onChange={(e) => setConcurrency(Math.max(1, Number(e.target.value)))}
                  className="mt-0.5 w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
                />
              </label>
              <label className="text-[10px] font-mono text-slate-500">
                Rate (rps)
                <input
                  type="number" min={1} placeholder="∞"
                  value={rateLimit}
                  onChange={(e) => setRateLimit(e.target.value)}
                  className="mt-0.5 w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
                />
              </label>
              <label className="text-[10px] font-mono text-slate-500">
                Timeout (s)
                <input
                  type="number" min={1} max={120}
                  value={timeoutSeconds}
                  onChange={(e) => setTimeoutSeconds(e.target.value)}
                  className="mt-0.5 w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
                />
              </label>
            </div>
          </section>

          {/* Inline payloads */}
          <section className="space-y-1">
            <h3 className="text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">Inline Payloads</h3>
            <textarea
              rows={4}
              value={inlinePayloads}
              onChange={(e) => setInlinePayloads(e.target.value)}
              placeholder={'one payload per line\n\' OR 1=1--\n<script>alert(1)</script>'}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
            />
          </section>

          {/* Custom wordlists */}
          <section className="space-y-2">
            <h3 className="text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">
              My Payload Sets ({selectedCustomIds.length}/{customLists.length})
            </h3>
            <div className="max-h-32 overflow-y-auto space-y-1">
              {customLists.map((wl) => (
                <div key={wl.id} className="flex items-center gap-2 group">
                  <label className="flex items-center gap-2 flex-1 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedCustomIds.includes(wl.id)}
                      onChange={() => setSelectedCustomIds(toggle(selectedCustomIds, wl.id))}
                      className="accent-primary"
                    />
                    <span className="text-xs font-mono text-slate-200 truncate">{wl.name}</span>
                    <span className="text-[10px] text-slate-500">{wl.line_count}</span>
                    {wl.tags.map((t) => (
                      <span key={t} className="px-1 rounded bg-slate-800 border border-slate-700 text-[9px] text-slate-400">{t}</span>
                    ))}
                  </label>
                  <button
                    onClick={() => handleDeleteList(wl.id)}
                    className="opacity-0 group-hover:opacity-100 p-0.5 text-slate-600 hover:text-rose-400 transition-opacity"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              ))}
              {customLists.length === 0 && (
                <p className="text-[11px] text-slate-600 font-mono">No custom lists uploaded yet.</p>
              )}
            </div>

            {/* Upload form */}
            <details className="bg-slate-900/60 border border-slate-800 rounded-lg p-2">
              <summary className="text-[11px] font-mono text-slate-400 cursor-pointer flex items-center gap-1.5">
                <Upload className="w-3 h-3" /> Upload new list
              </summary>
              <form onSubmit={handleUpload} className="mt-2 space-y-1.5">
                <input
                  value={uploadName}
                  onChange={(e) => setUploadName(e.target.value)}
                  placeholder="list name"
                  required
                  className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-[11px] font-mono text-slate-200 focus:outline-none focus:border-primary"
                />
                <input
                  value={uploadTags}
                  onChange={(e) => setUploadTags(e.target.value)}
                  placeholder="tags, comma, separated"
                  className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-[11px] font-mono text-slate-200 focus:outline-none focus:border-primary"
                />
                <textarea
                  rows={4}
                  value={uploadContent}
                  onChange={(e) => setUploadContent(e.target.value)}
                  placeholder={'one entry per line'}
                  required
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-[11px] font-mono text-slate-200 focus:outline-none focus:border-primary"
                />
                <button
                  type="submit"
                  disabled={uploading}
                  className="w-full py-1 rounded bg-primary hover:bg-primary-hover disabled:opacity-50 text-slate-950 text-[11px] font-semibold"
                >
                  {uploading ? 'Saving…' : 'Save Wordlist'}
                </button>
              </form>
            </details>
          </section>

          {/* Arsenal lists */}
          <section className="space-y-2">
            <h3 className="text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">
              Wordlist Arsenal ({selectedArsenalIds.length})
            </h3>
            <input
              value={arsenalSearch}
              onChange={(e) => setArsenalSearch(e.target.value)}
              placeholder="search seclists / payloads…"
              className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-[11px] font-mono text-slate-200 focus:outline-none focus:border-primary"
            />
            <div className="max-h-48 overflow-y-auto space-y-1">
              {arsenalLists.map((wl) => (
                <label key={wl.id} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedArsenalIds.includes(wl.id)}
                    onChange={() => setSelectedArsenalIds(toggle(selectedArsenalIds, wl.id))}
                    className="accent-primary"
                  />
                  <span className="text-xs font-mono text-slate-300 truncate">{wl.filename}</span>
                  <span className="text-[9px] px-1 rounded bg-slate-800 border border-slate-700 text-slate-500">{wl.category}</span>
                </label>
              ))}
            </div>
          </section>
        </div>

        {/* Right: Live results */}
        <div className="flex-1 min-w-0">
          <IntruderResultsTable />
        </div>
      </div>
    </div>
  );
};
