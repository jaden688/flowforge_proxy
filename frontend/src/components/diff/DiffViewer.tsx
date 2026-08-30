import React from 'react';
import { useFlowStore } from '../../store/flowStore';
import { useDiff } from '../../hooks/useDiff';
import { DeltaMetricsBar } from './DeltaMetricsBar';
import { AnomalyBanner } from './AnomalyBanner';
import { SideBySidePane } from './SideBySidePane';
import { ArrowLeftRight, GitCompare, RefreshCw } from 'lucide-react';

export const DiffViewer: React.FC = () => {
  const flows = useFlowStore((s) => s.flows);
  const flowOrder = useFlowStore((s) => s.flowOrder);
  const {
    flowAId,
    flowBId,
    flowA,
    flowB,
    comparisonResult,
    isLoading,
    error,
    diffMode,
    setDiffMode,
    diffScope,
    setDiffScope,
    executeDiff,
    swapFlows,
    setFlowA,
    setFlowB,
  } = useDiff();

  return (
    <div className="flex-1 overflow-y-auto p-4 bg-[#090D15] space-y-4 font-mono text-xs">
      {/* Diff Toolbar */}
      <div className="p-4 bg-surface/80 border border-border rounded-xl shadow-lg space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-purple-500/20 text-purple-400 border border-purple-500/30">
              <GitCompare className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                Request / Response Diff & Surface Delta Inspector
              </h2>
              <p className="text-[11px] text-slate-400">
                Compare baseline vs mutated requests with visual highlighting of status, body length, and payload reflections
              </p>
            </div>
          </div>

          <button
            onClick={() => executeDiff()}
            disabled={isLoading}
            className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5 text-xs font-semibold transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Recompute Delta</span>
          </button>
        </div>

        {/* Flow Selectors & Scope Bar */}
        <div className="flex flex-wrap items-center gap-3 pt-3 border-t border-border/60">
          {/* Baseline Flow A Selector */}
          <div className="flex items-center gap-2 flex-1 min-w-[200px]">
            <span className="text-slate-400 text-[11px] font-bold">Baseline A:</span>
            <select
              value={flowAId || ''}
              onChange={(e) => setFlowA(e.target.value || null)}
              className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-primary truncate"
            >
              <option value="">Select baseline flow...</option>
              {flowOrder.map((id) => {
                const f = flows[id];
                return (
                  <option key={id} value={id}>
                    {f ? `[#${f.method} ${f.response_status ?? '---'}] ${f.path}` : id}
                  </option>
                );
              })}
            </select>
          </div>

          {/* Swap Button */}
          <button
            onClick={swapFlows}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
            title="Swap Flow A and Flow B"
          >
            <ArrowLeftRight className="w-3.5 h-3.5 text-primary" />
          </button>

          {/* Mutated Flow B Selector */}
          <div className="flex items-center gap-2 flex-1 min-w-[200px]">
            <span className="text-cyan-400 text-[11px] font-bold">Mutated B:</span>
            <select
              value={flowBId || ''}
              onChange={(e) => setFlowB(e.target.value || null)}
              className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-primary truncate"
            >
              <option value="">Select mutated flow...</option>
              {flowOrder.map((id) => {
                const f = flows[id];
                return (
                  <option key={id} value={id}>
                    {f ? `[#${f.method} ${f.response_status ?? '---'}] ${f.path}` : id}
                  </option>
                );
              })}
            </select>
          </div>

          {/* Diff Scope Selector */}
          <div className="flex items-center gap-1">
            <span className="text-slate-500 text-[10px] uppercase font-bold mr-1">Scope:</span>
            {(['all', 'body', 'headers'] as const).map((s) => (
              <button
                key={s}
                onClick={() => setDiffScope(s)}
                className={`px-2 py-1 rounded text-[11px] uppercase transition-colors ${
                  diffScope === s
                    ? 'bg-slate-200 text-slate-950 font-bold'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="p-2.5 bg-rose-500/10 border border-rose-500/30 rounded text-rose-300 text-xs">
            {error}
          </div>
        )}
      </div>

      {/* Anomaly Banner & Delta Metrics */}
      {comparisonResult ? (
        <>
          <AnomalyBanner verdict={comparisonResult.anomaly_verdict} />
          <DeltaMetricsBar comparison={comparisonResult} />
          <SideBySidePane
            flowA={comparisonResult.flow_a}
            flowB={comparisonResult.flow_b}
            headerDiffs={comparisonResult.header_diffs}
            bodyDiffSegments={comparisonResult.body_diff_segments}
            mode={diffMode}
            scope={diffScope}
          />
        </>
      ) : (
        <div className="p-12 text-center text-slate-500 bg-[#0A0E17] border border-border rounded-xl">
          <GitCompare className="w-10 h-10 mx-auto mb-2 opacity-30 animate-pulse" />
          <div className="font-bold text-slate-300">No Flows Selected for Diff Analysis</div>
          <p className="text-slate-500 text-xs mt-1">
            Select Baseline (Flow A) and Mutated (Flow B) above or click "Diff" on any flow in the stream table
          </p>
        </div>
      )}
    </div>
  );
};
