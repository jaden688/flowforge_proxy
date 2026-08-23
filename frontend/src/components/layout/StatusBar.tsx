import React from 'react';
import { useFlowStore } from '../../store/flowStore';
import { Database, HardDrive, Cpu, Filter } from 'lucide-react';

export const StatusBar: React.FC = () => {
  const stats = useFlowStore((s) => s.stats);
  const flowOrder = useFlowStore((s) => s.flowOrder);
  const flows = useFlowStore((s) => s.flows);
  const filters = useFlowStore((s) => s.filters);
  const isPaused = useFlowStore((s) => s.isPaused);

  // Compute filtered flows count
  const filteredCount = flowOrder.filter((id) => {
    const flow = flows[id];
    if (!flow) return false;
    if (filters.methods.length && !filters.methods.includes(flow.method)) return false;
    if (filters.host && !flow.host.toLowerCase().includes(filters.host.toLowerCase())) return false;
    if (filters.search) {
      const q = filters.search.toLowerCase();
      const matchUrl = flow.url.toLowerCase().includes(q);
      const matchMethod = flow.method.toLowerCase().includes(q);
      const matchStatus = flow.response_status ? String(flow.response_status).includes(q) : false;
      if (!matchUrl && !matchMethod && !matchStatus) return false;
    }
    return true;
  }).length;

  const hasActiveFilters = Boolean(
    filters.search || filters.methods.length || filters.statusGroup !== 'all' || filters.tags.length || filters.host
  );

  return (
    <footer className="h-7 bg-[#090D14] border-t border-border px-3 flex items-center justify-between text-[11px] font-mono text-slate-400 select-none z-20">
      {/* Left: Stream Counts */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1.5">
          <Database className="w-3.5 h-3.5 text-primary" />
          <span className="text-slate-200 font-semibold">{stats.totalFlows}</span>
          <span>flows captured</span>
          {hasActiveFilters && (
            <span className="text-cyan-400">
              (showing {filteredCount})
            </span>
          )}
        </div>

        {isPaused && (
          <span className="px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[10px]">
            STREAM PAUSED
          </span>
        )}

        {hasActiveFilters && (
          <div className="flex items-center gap-1 text-slate-500">
            <Filter className="w-3 h-3 text-cyan-400" />
            <span>Filters active</span>
          </div>
        )}
      </div>

      {/* Center: Keyboard shortcuts */}
      <div className="hidden md:flex items-center gap-3 text-slate-500 text-[10px]">
        <span><kbd className="px-1 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">Space</kbd> Pause</span>
        <span><kbd className="px-1 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">Esc</kbd> Deselect</span>
      </div>

      {/* Right: Health Metrics */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1">
          <HardDrive className="w-3 h-3 text-slate-500" />
          <span>SQLite WAL</span>
        </div>
        <div className="flex items-center gap-1">
          <Cpu className="w-3 h-3 text-emerald-400" />
          <span className="text-emerald-400">Heuristics Active</span>
        </div>
      </div>
    </footer>
  );
};
