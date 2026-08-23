import React, { useCallback, useEffect, useState } from 'react';
import { FindingRecord, FindingsStats } from '../../types';
import { useFlowStore } from '../../store/flowStore';
import {
  AlertTriangle,
  ShieldAlert,
  Sparkles,
  Lock,
  RefreshCw,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';

const VERDICT_META: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
  CRITICAL_IDOR: { label: 'CRITICAL IDOR / BOLA', color: 'text-rose-300 bg-rose-500/10 border-rose-500/40', icon: <ShieldAlert className="w-3.5 h-3.5" /> },
  AUTH_BYPASS: { label: 'AUTH BYPASS', color: 'text-purple-300 bg-purple-500/10 border-purple-500/40', icon: <Lock className="w-3.5 h-3.5" /> },
  HIGH_REFLECTION: { label: 'CONFIRMED REFLECTION', color: 'text-yellow-300 bg-yellow-500/10 border-yellow-500/40', icon: <Sparkles className="w-3.5 h-3.5" /> },
};

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'text-rose-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-amber-300',
  LOW: 'text-slate-400',
  INFO: 'text-slate-500',
};

const MethodBadge: React.FC<{ method: string }> = ({ method }) => {
  const colors: Record<string, string> = {
    GET: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
    POST: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    PUT: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    DELETE: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
    PATCH: 'bg-violet-500/15 text-violet-300 border-violet-500/30',
  };
  return (
    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-mono font-bold ${colors[method] || 'bg-slate-800 text-slate-300 border-slate-700'}`}>
      {method}
    </span>
  );
};

export const FindingsView: React.FC = () => {
  const selectFlow = useFlowStore((s) => s.selectFlow);
  const setActiveView = useFlowStore((s) => s.setActiveView);

  const [stats, setStats] = useState<FindingsStats | null>(null);
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const sRes = await fetch('/api/v1/findings/stats');
      if (sRes.ok) setStats(await sRes.json());
      const q = verdictFilter !== 'ALL' ? `?verdict=${verdictFilter}&page_size=200` : '?page_size=200';
      const fRes = await fetch(`/api/v1/findings${q}`);
      if (fRes.ok) {
        const d = await fRes.json();
        setFindings(d.items || []);
      }
    } catch (e) {
      console.error('Failed to load findings', e);
    } finally {
      setLoading(false);
    }
  }, [verdictFilter]);

  useEffect(() => {
    fetchAll();
    const t = setInterval(fetchAll, 20000);
    return () => clearInterval(t);
  }, [fetchAll]);

  const inspectExecutedFlow = (f: FindingRecord) => {
    if (f.executed_flow_id) {
      selectFlow(f.executed_flow_id);
    }
    setActiveView('stream');
  };

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden bg-[#0A0E17]">
      {/* Header */}
      <div className="p-3 border-b border-border flex flex-wrap items-center justify-between gap-3 bg-surface/50">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-rose-400" />
          <h1 className="text-sm font-bold text-white font-mono tracking-wide">CONFIRMED FINDINGS</h1>
          <span className="px-2 py-0.5 rounded-full bg-rose-500/15 border border-rose-500/40 text-rose-300 text-xs font-mono font-bold">
            {stats?.total_findings ?? '...'} verified
          </span>
        </div>
        <button
          onClick={fetchAll}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-mono text-slate-300 transition-colors"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Verdict Filter Chips */}
      <div className="px-3 py-2 border-b border-border flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
        <span className="text-slate-500 uppercase font-bold mr-1">Verdict:</span>
        <button
          onClick={() => setVerdictFilter('ALL')}
          className={`px-2 py-0.5 rounded border transition-colors ${
            verdictFilter === 'ALL'
              ? 'bg-slate-200 text-slate-950 border-slate-300 font-bold'
              : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-slate-200'
          }`}
        >
          ALL ({stats?.total_findings ?? 0})
        </button>
        {Object.entries(stats?.by_verdict || {}).map(([v, n]) => {
          const meta = VERDICT_META[v] || { label: v, color: 'text-sky-300 bg-sky-500/10 border-sky-500/40', icon: <AlertTriangle className="w-3.5 h-3.5" /> };
          const active = verdictFilter === v;
          return (
            <button
              key={v}
              onClick={() => setVerdictFilter(active ? 'ALL' : v)}
              className={`px-2 py-0.5 rounded border flex items-center gap-1 transition-colors ${meta.color} ${active ? 'ring-1 ring-white/40 font-bold' : ''}`}
            >
              {meta.icon}
              <span>{meta.label} ({n})</span>
            </button>
          );
        })}
      </div>

      {/* Findings List */}
      <div className="flex-1 overflow-y-auto p-3 space-y-2">
        {findings.length === 0 && !loading && (
          <div className="flex flex-col items-center justify-center h-64 text-slate-500 font-mono text-xs">
            <ShieldAlert className="w-8 h-8 mb-2 opacity-30" />
            <span>No confirmed findings yet.</span>
            <span className="text-[11px] text-slate-600 mt-1">Approve and execute proposals - anomalous replays surface here automatically.</span>
          </div>
        )}
        {findings.map((f) => (
          <FindingCard
            key={f.finding_id}
            finding={f}
            expanded={expandedId === f.finding_id}
            onToggle={() => setExpandedId(expandedId === f.finding_id ? null : f.finding_id)}
            onInspect={() => inspectExecutedFlow(f)}
          />
        ))}
      </div>
    </div>
  );
};

const FindingCard: React.FC<{
  finding: FindingRecord;
  expanded: boolean;
  onToggle: () => void;
  onInspect: () => void;
}> = ({ finding: f, expanded, onToggle, onInspect }) => {
  const meta = VERDICT_META[f.verdict_level] || {
    label: f.verdict_level,
    color: 'text-sky-300 bg-sky-500/10 border-sky-500/40',
    icon: <AlertTriangle className="w-3.5 h-3.5" />,
  };

  return (
    <div className={`rounded-lg border ${expanded ? 'border-primary/50' : 'border-border'} bg-surface/60 overflow-hidden`}>
      <div
        className="p-2.5 flex flex-wrap items-center gap-2 cursor-pointer hover:bg-slate-900/40"
        onClick={onToggle}
      >
        {expanded ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
        <span className={`px-2 py-0.5 rounded border text-[11px] font-mono font-bold flex items-center gap-1 ${meta.color}`}>
          {meta.icon}
          {meta.label}
        </span>
        <span className={`text-[11px] font-mono font-bold ${SEVERITY_COLOR[f.severity] || 'text-slate-400'}`}>
          [{f.severity}]
        </span>
        <MethodBadge method={f.method} />
        <span className="text-xs font-mono text-slate-200 truncate max-w-[340px]" title={f.endpoint_path}>
          {f.endpoint_path}
        </span>
        <span className="text-[11px] text-slate-500 font-mono ml-auto">
          {new Date((f.executed_at || 0) * 1000).toLocaleTimeString()}
        </span>
      </div>

      {expanded && (
        <div className="border-t border-border p-3 space-y-3 bg-[#090D15]">
          <p className="text-xs text-slate-300 leading-relaxed">{f.verdict_description}</p>

          {/* Evidence metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] font-mono">
            <EvidenceChip label="Status Delta" value={f.status_delta || 'n/a'} />
            <EvidenceChip label="Length Delta" value={`${(f.length_delta_bytes ?? 0) >= 0 ? '+' : ''}${f.length_delta_bytes ?? 0} B`} />
            <EvidenceChip label="Latency Delta" value={`${Math.round(f.latency_delta_ms ?? 0)} ms`} />
            <EvidenceChip label="Payload Reflected" value={f.reflected ? 'YES' : 'NO'} highlight={f.reflected} />
          </div>

          {/* Target mutation */}
          <div className="text-[11px] font-mono space-y-1">
            <div className="flex gap-2">
              <span className="text-slate-500 w-28 shrink-0">Target:</span>
              <span className="text-cyan-300">{f.target_param_location}.{f.target_param_name || '(global)'}</span>
            </div>
            {f.mutated_value != null && (
              <div className="flex gap-2">
                <span className="text-slate-500 w-28 shrink-0">Injected:</span>
                <code className="text-rose-300 break-all bg-rose-500/5 border border-rose-500/20 rounded px-1">
                  {typeof f.mutated_value === 'string' ? f.mutated_value : JSON.stringify(f.mutated_value).slice(0, 300)}
                </code>
              </div>
            )}
          </div>

          {/* Response preview */}
          {f.response_body_preview && (
            <div>
              <div className="text-[10px] uppercase font-bold text-slate-500 mb-1 tracking-wider">Executed Response Preview</div>
              <pre className="p-2 bg-[#0A0E17] border border-border rounded max-h-40 overflow-auto text-[11px] text-slate-300 whitespace-pre-wrap break-all">
                {f.response_body_preview.slice(0, 2000)}
              </pre>
            </div>
          )}

          <div className="flex items-center gap-2 pt-1">
            <button
              onClick={(e) => { e.stopPropagation(); onInspect(); }}
              className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[11px] font-mono transition-colors"
            >
              Inspect Executed Flow
            </button>
            {f.flow_id && (
              <span className="text-[10px] text-slate-600 font-mono">baseline: {f.flow_id.slice(0, 8)}</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

const EvidenceChip: React.FC<{ label: string; value: string; highlight?: boolean }> = ({ label, value, highlight }) => (
  <div className={`p-2 rounded border ${highlight ? 'bg-rose-500/10 border-rose-500/30' : 'bg-[#0A0E17] border-border'}`}>
    <div className="text-slate-500 text-[10px] uppercase">{label}</div>
    <div className={`font-bold mt-0.5 ${highlight ? 'text-rose-300' : 'text-slate-200'}`}>{value}</div>
  </div>
);
