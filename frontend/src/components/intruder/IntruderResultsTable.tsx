import React from 'react';
import { useFlowStore } from '../../store/flowStore';
import { IntruderResult } from '../../types';

const STATUS_COLORS: Record<number, string> = {
  2: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  3: 'text-sky-400 bg-sky-500/10 border-sky-500/30',
  4: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  5: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
};

const ANOMALY_STYLES: Record<string, string> = {
  REFLECTION: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/40',
  SIZE_ANOMALY: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40',
  TIMING_ANOMALY: 'bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/40',
  SERVER_ERROR: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
  REQUEST_ERROR: 'bg-slate-600/30 text-slate-300 border-slate-500/40',
};

function statusClass(code?: number | null): string {
  if (!code) return 'text-slate-500 bg-slate-800 border-slate-700';
  return STATUS_COLORS[Math.floor(code / 100)] || 'text-slate-400 bg-slate-800 border-slate-700';
}

export const IntruderResultsTable: React.FC = () => {
  const results = useFlowStore((s) => s.intruderResults);
  const filters = useFlowStore((s) => s.intruderResultFilters);
  const setFilters = useFlowStore((s) => s.setIntruderResultFilters);

  return (
    <div className="flex flex-col h-full">
      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-2 px-3 py-2 border-b border-border bg-slate-900/60">
        <button
          onClick={() => setFilters({ anomaliesOnly: !filters.anomaliesOnly })}
          className={`px-2.5 py-1 rounded-md text-xs font-mono border transition-colors ${
            filters.anomaliesOnly
              ? 'bg-rose-500/20 border-rose-500/50 text-rose-300'
              : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200'
          }`}
          title="Show only rows flagged by anomaly detection"
        >
          ⚠ Anomalies
        </button>
        <button
          onClick={() => setFilters({ reflectedOnly: !filters.reflectedOnly })}
          className={`px-2.5 py-1 rounded-md text-xs font-mono border transition-colors ${
            filters.reflectedOnly
              ? 'bg-yellow-500/20 border-yellow-500/50 text-yellow-300'
              : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200'
          }`}
          title="Show only payloads echoed in responses"
        >
          ✦ Reflected
        </button>

        <input
          type="number"
          placeholder="min size"
          value={filters.minSize ?? ''}
          onChange={(e) => setFilters({ minSize: e.target.value ? Number(e.target.value) : null })}
          className="w-20 px-2 py-1 bg-slate-900 border border-slate-700 rounded-md text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
        />
        <input
          type="number"
          placeholder="max size"
          value={filters.maxSize ?? ''}
          onChange={(e) => setFilters({ maxSize: e.target.value ? Number(e.target.value) : null })}
          className="w-20 px-2 py-1 bg-slate-900 border border-slate-700 rounded-md text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
        />
        <input
          type="number"
          placeholder="min ms"
          value={filters.minTimeMs ?? ''}
          onChange={(e) => setFilters({ minTimeMs: e.target.value ? Number(e.target.value) : null })}
          className="w-16 px-2 py-1 bg-slate-900 border border-slate-700 rounded-md text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
        />
        <input
          type="number"
          placeholder="max ms"
          value={filters.maxTimeMs ?? ''}
          onChange={(e) => setFilters({ maxTimeMs: e.target.value ? Number(e.target.value) : null })}
          className="w-16 px-2 py-1 bg-slate-900 border border-slate-700 rounded-md text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
        />
        <select
          multiple={false}
          value={filters.statusCodes[0] ?? ''}
          onChange={(e) => setFilters({ statusCodes: e.target.value ? [Number(e.target.value)] : [] })}
          className="px-2 py-1 bg-slate-900 border border-slate-700 rounded-md text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
        >
          <option value="">any code</option>
          {[200, 301, 302, 400, 401, 403, 404, 500].map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        <input
          type="text"
          placeholder="payload search…"
          value={filters.payloadSearch}
          onChange={(e) => setFilters({ payloadSearch: e.target.value })}
          className="flex-1 min-w-[120px] px-2 py-1 bg-slate-900 border border-slate-700 rounded-md text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
        />
      </div>

      {/* Results Grid */}
      <div className="flex-1 overflow-auto">
        {results.length === 0 ? (
          <div className="h-full flex items-center justify-center text-slate-500 text-sm font-mono">
            Configure targets &amp; payload sets, then launch the attack.
          </div>
        ) : (
          <table className="w-full text-xs font-mono">
            <thead className="sticky top-0 bg-surface z-10">
              <tr className="text-left text-slate-400 border-b border-border">
                <th className="px-2 py-1.5">#</th>
                <th className="px-2 py-1.5">Position</th>
                <th className="px-2 py-1.5">Payload</th>
                <th className="px-2 py-1.5">Status</th>
                <th className="px-2 py-1.5">Size</th>
                <th className="px-2 py-1.5">Time</th>
                <th className="px-2 py-1.5">Flags</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r: IntruderResult, i) => (
                <tr key={`${r.request_index}-${i}`} className="border-b border-slate-800/60 hover:bg-slate-800/40">
                  <td className="px-2 py-1 text-slate-500">{r.request_index}</td>
                  <td className="px-2 py-1 text-slate-400 whitespace-nowrap">{r.position_label}</td>
                  <td className="px-2 py-1 text-slate-200 max-w-[280px] truncate" title={r.payload}>
                    {r.payload}
                  </td>
                  <td className="px-2 py-1">
                    <span className={`px-1.5 py-0.5 rounded border ${statusClass(r.status_code)}`}>
                      {r.error ? 'ERR' : r.status_code}
                    </span>
                  </td>
                  <td className="px-2 py-1 text-slate-400">{r.response_size_bytes ?? '—'}</td>
                  <td className="px-2 py-1 text-slate-400">
                    {r.response_time_ms != null ? `${Math.round(r.response_time_ms)}ms` : '—'}
                  </td>
                  <td className="px-2 py-1">
                    <div className="flex gap-1">
                      {r.reflected && (
                        <span className={`px-1 py-0.5 rounded border text-[10px] ${ANOMALY_STYLES.REFLECTION}`}>
                          REFLECT
                        </span>
                      )}
                      {(r.anomaly_reasons || [])
                        .filter((a) => a !== 'REFLECTION')
                        .map((a) => (
                          <span key={a} className={`px-1 py-0.5 rounded border text-[10px] ${ANOMALY_STYLES[a] || ''}`}>
                            {a.replace('_ANOMALY', '')}
                          </span>
                        ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
