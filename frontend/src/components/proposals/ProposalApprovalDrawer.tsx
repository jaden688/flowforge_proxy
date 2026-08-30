import React, { useState, useMemo, useEffect, useRef } from 'react';
import { useFlowStore } from '../../store/flowStore';
import { ProposalCard } from './ProposalCard';
import { ProposalDiffModal } from './ProposalDiffModal';
import { api } from '../../services/api';
import { 
  X, 
  Zap, 
  CheckCheck, 
  Trash2, 
  RefreshCw, 
  Filter, 
  Search, 
  SlidersHorizontal,
  Sparkles,
  ShieldAlert,
  Loader2,
  AlertCircle,
  StopCircle,
  Clock
} from 'lucide-react';
import { TestProposal } from '../../types';

export const ProposalApprovalDrawer: React.FC = () => {
  const isOpen = useFlowStore((s) => s.isApprovalDrawerOpen);
  const toggleApprovalDrawer = useFlowStore((s) => s.toggleApprovalDrawer);
  const activeProposalFlowId = useFlowStore((s) => s.activeProposalFlowId);
  const proposals = useFlowStore((s) => s.proposals);
  const proposalOrder = useFlowStore((s) => s.proposalOrder);
  const setProposals = useFlowStore((s) => s.setProposals);
  const approveProposal = useFlowStore((s) => s.approveProposal);
  const dismissAllProposals = useFlowStore((s) => s.dismissAllProposals);

  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('PENDING');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isBatchApproving, setIsBatchApproving] = useState<boolean>(false);
  const [batchPacingMs, setBatchPacingMs] = useState<number>(1000);
  const [batchProgress, setBatchProgress] = useState<{ current: number; total: number; title: string } | null>(null);
  const abortBatchRef = useRef<boolean>(false);
  const [isSweeping, setIsSweeping] = useState<boolean>(false);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        toggleApprovalDrawer(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, toggleApprovalDrawer]);

  // Fetch proposals from API on open or refresh
  const fetchProposals = async () => {
    setIsRefreshing(true);
    setErrorMessage(null);
    try {
      const data = await api.getProposals();
      if (data && data.items) {
        setProposals(data.items);
      }
    } catch (err: any) {
      // Backend may be running without proposals initially
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchProposals();
    }
  }, [isOpen]);

  // Compute filtered proposals
  const filteredProposals = useMemo(() => {
    const allList = proposalOrder.map((id) => proposals[id]).filter(Boolean) as TestProposal[];
    
    return allList.filter((p) => {
      // Flow ID filter if active
      if (activeProposalFlowId && p.flow_id !== activeProposalFlowId) {
        return false;
      }

      // Status filter
      const pStatus = p.status || p.state || 'PENDING';
      if (statusFilter !== 'ALL') {
        if (statusFilter === 'PENDING' && pStatus !== 'PENDING' && pStatus !== 'APPROVED' && pStatus !== 'EXECUTING') {
          return false;
        }
        if (statusFilter === 'EXECUTED' && pStatus !== 'EXECUTED' && pStatus !== 'COMPLETED') {
          return false;
        }
        if (statusFilter === 'DISMISSED' && pStatus !== 'DISMISSED') {
          return false;
        }
      }

      // Severity filter
      if (severityFilter !== 'ALL' && p.severity !== severityFilter) {
        return false;
      }

      // Category filter
      if (categoryFilter !== 'ALL') {
        const catStr = `${p.inferred_vuln_category} ${p.anomaly_type || ''} ${p.category || ''}`.toUpperCase();
        if (categoryFilter === 'IDOR' && !catStr.includes('IDOR') && !catStr.includes('BOLA')) return false;
        if (categoryFilter === 'REFLECTION' && !catStr.includes('REFLECT') && !catStr.includes('XSS')) return false;
        if (categoryFilter === 'AUTH' && !catStr.includes('AUTH') && !catStr.includes('JWT')) return false;
        if (categoryFilter === 'JSON' && !catStr.includes('JSON') && !catStr.includes('SCHEMA') && !catStr.includes('MASS')) return false;
      }

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchPath = p.endpoint_path.toLowerCase().includes(q);
        const matchParam = p.target_param_name.toLowerCase().includes(q);
        const matchRationale = (p.risk_rationale || '').toLowerCase().includes(q);
        const matchCat = (p.inferred_vuln_category || '').toLowerCase().includes(q);
        if (!matchPath && !matchParam && !matchRationale && !matchCat) {
          return false;
        }
      }

      return true;
    });
  }, [proposals, proposalOrder, activeProposalFlowId, statusFilter, severityFilter, categoryFilter, searchQuery]);

  const pendingVisibleProposals = filteredProposals.filter(
    (p) => p.status === 'PENDING' || p.state === 'PENDING' || !p.status
  );

  const handleApproveAllVisible = async () => {
    if (pendingVisibleProposals.length === 0 || isBatchApproving) return;
    setIsBatchApproving(true);
    setErrorMessage(null);
    abortBatchRef.current = false;

    const total = pendingVisibleProposals.length;
    let successCount = 0;

    try {
      for (let i = 0; i < total; i++) {
        if (abortBatchRef.current) {
          break;
        }

        const p = pendingVisibleProposals[i];
        setBatchProgress({
          current: i + 1,
          total,
          title: `${p.method} ${p.endpoint_path}`,
        });

        try {
          await approveProposal(p.id);
          successCount++;
        } catch (e: any) {
          console.warn(`Failed proposal execution for ${p.id}:`, e);
        }

        // Paced inter-step delay unless final item or aborted
        if (i < total - 1 && !abortBatchRef.current) {
          await new Promise((resolve) => setTimeout(resolve, Math.max(500, batchPacingMs)));
        }
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Batch approval failed');
    } finally {
      setIsBatchApproving(false);
      setBatchProgress(null);
    }
  };

  const handleCancelBatch = () => {
    abortBatchRef.current = true;
    setIsBatchApproving(false);
    setBatchProgress(null);
  };

  const handleDismissAllVisible = () => {
    if (activeProposalFlowId) {
      dismissAllProposals(activeProposalFlowId);
    } else {
      dismissAllProposals();
    }
  };

  const sweepProposalsToIntruder = useFlowStore((s) => s.sweepProposalsToIntruder);

  const handleSweepAll = async () => {
    setIsSweeping(true);
    setErrorMessage(null);
    try {
      const result = await sweepProposalsToIntruder({
        min_confidence: 60,
        max_proposals: 20,
      });
      if (!result?.ok) {
        setErrorMessage(result?.error || 'Sweep failed');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Sweep failed');
    } finally {
      setIsSweeping(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden font-mono text-xs">
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black/75 backdrop-blur-sm transition-opacity animate-in fade-in duration-200"
        onClick={() => toggleApprovalDrawer(false)}
      />

      {/* Drawer Panel */}
      <div className="fixed inset-y-0 right-0 w-full max-w-2xl bg-[#0B101A] border-l border-border shadow-2xl flex flex-col z-50 animate-in slide-in-from-right duration-250">
        {/* Drawer Top Header */}
        <div className="p-4 bg-[#0E1524] border-b border-border flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-amber-500 to-orange-500 flex items-center justify-center shadow-lg shadow-amber-500/20 text-slate-950 font-bold">
              ⚡
            </div>
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <span>Auto-Proposals Staging Workbench</span>
                <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 text-xs">
                  {Object.values(proposals).filter(p => p.status === 'PENDING' || p.state === 'PENDING').length} Pending
                </span>
              </h2>
              <p className="text-[11px] text-slate-400">
                1-click operator review, replay diffing, and test matrix staging
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={fetchProposals}
              disabled={isRefreshing}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
              title="Refresh proposals from server"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-amber-400' : ''}`} />
            </button>
            <button
              onClick={() => toggleApprovalDrawer(false)}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700 transition-colors"
              title="Close drawer (Esc)"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Active Flow Filter Banner (if opened from specific flow) */}
        {activeProposalFlowId && (
          <div className="px-4 py-2 bg-amber-950/30 border-b border-amber-500/30 flex items-center justify-between text-[11px] text-amber-200">
            <div className="flex items-center gap-1.5 truncate">
              <span className="font-bold">Filtered to Flow:</span>
              <code className="text-amber-300 bg-amber-950/60 px-1.5 py-0.5 rounded border border-amber-500/30 truncate max-w-xs">
                {activeProposalFlowId}
              </code>
            </div>
            <button
              onClick={() => toggleApprovalDrawer(true, null)}
              className="text-[10px] text-amber-400 hover:text-amber-200 underline shrink-0 ml-2"
            >
              Show All Flows
            </button>
          </div>
        )}

        {/* Filters Toolbar */}
        <div className="p-3 bg-surface/70 border-b border-border space-y-2 text-[11px]">
          {/* Search bar */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search by parameter, endpoint path, or rationale..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-400 transition-colors"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex flex-wrap items-center justify-between gap-2">
            {/* Category Filter */}
            <div className="flex items-center gap-1">
              <span className="text-slate-500 text-[10px] uppercase font-bold">Category:</span>
              {(['ALL', 'IDOR', 'REFLECTION', 'AUTH', 'JSON'] as const).map((cat) => (
                <button
                  key={cat}
                  onClick={() => setCategoryFilter(cat)}
                  className={`px-2 py-0.5 rounded text-[10px] transition-colors ${
                    categoryFilter === cat
                      ? 'bg-amber-500 text-slate-950 font-bold'
                      : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>

            {/* Severity Filter */}
            <div className="flex items-center gap-1">
              <span className="text-slate-500 text-[10px] uppercase font-bold">Sev:</span>
              {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'] as const).map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-1.5 py-0.5 rounded text-[10px] transition-colors ${
                    severityFilter === sev
                      ? 'bg-slate-200 text-slate-950 font-bold'
                      : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            {/* Status Filter */}
            <div className="flex items-center gap-1">
              <span className="text-slate-500 text-[10px] uppercase font-bold">Status:</span>
              {(['PENDING', 'EXECUTED', 'ALL'] as const).map((st) => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`px-1.5 py-0.5 rounded text-[10px] transition-colors ${
                    statusFilter === st
                      ? 'bg-cyan-500 text-slate-950 font-bold'
                      : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Batch Actions Bar */}
        <div className="px-4 py-2.5 bg-[#0A0E17] border-b border-border flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-slate-400">
              Showing <strong className="text-slate-200">{filteredProposals.length}</strong> proposals
              {pendingVisibleProposals.length > 0 && (
                <span> (<strong className="text-amber-300">{pendingVisibleProposals.length}</strong> ready to run)</span>
              )}
            </span>

            {/* Pacing Speed Selector for Batch Execution */}
            <div className="flex items-center gap-1 bg-slate-900 border border-slate-700 rounded px-2 py-0.5 text-[10px] text-slate-400">
              <Clock className="w-3 h-3 text-cyan-400" />
              <span>Delay:</span>
              <select
                value={batchPacingMs}
                onChange={(e) => setBatchPacingMs(Number(e.target.value))}
                disabled={isBatchApproving}
                className="bg-slate-950 border border-slate-700 text-cyan-300 rounded px-1 py-0.2 font-mono font-bold focus:outline-none"
              >
                <option value={500}>500ms</option>
                <option value={1000}>1000ms</option>
                <option value={2000}>2000ms</option>
                <option value={5000}>5000ms</option>
              </select>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {pendingVisibleProposals.length > 0 && (
              <button
                onClick={handleSweepAll}
                disabled={isSweeping || isBatchApproving}
                className="px-3 py-1 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white font-bold text-[11px] flex items-center gap-1.5 transition-all shadow-md shadow-violet-600/20"
                title="Launch Intruder campaigns for all high-confidence staged proposals"
              >
                {isSweeping ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Zap className="w-3.5 h-3.5" />
                )}
                <span>Sweep All to Intruder</span>
              </button>
            )}

            {isBatchApproving ? (
              <button
                onClick={handleCancelBatch}
                className="px-3 py-1 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-[11px] flex items-center gap-1.5 transition-all shadow-md shadow-rose-600/20 animate-pulse"
                title="Cancel batch execution in progress"
              >
                <StopCircle className="w-3.5 h-3.5" />
                <span>Cancel Batch</span>
              </button>
            ) : (
              pendingVisibleProposals.length > 0 && (
                <button
                  onClick={handleApproveAllVisible}
                  disabled={isBatchApproving}
                  className="px-3 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-[11px] flex items-center gap-1.5 transition-all shadow-md shadow-emerald-600/20"
                  title="Approve and execute all visible staged proposals with pacing"
                >
                  <CheckCheck className="w-3.5 h-3.5" />
                  <span>Approve All Visible ({pendingVisibleProposals.length})</span>
                </button>
              )
            )}

            {filteredProposals.length > 0 && (
              <button
                onClick={handleDismissAllVisible}
                disabled={isBatchApproving}
                className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-rose-500/20 disabled:opacity-50 text-slate-400 hover:text-rose-300 border border-slate-700 hover:border-rose-500/40 text-[11px] flex items-center gap-1 transition-colors"
                title="Dismiss all matching proposals"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Dismiss All</span>
              </button>
            )}
          </div>
        </div>

        {/* Live Batch Execution Progress Indicator */}
        {batchProgress && (
          <div className="px-4 py-2.5 bg-emerald-950/40 border-b border-emerald-500/30 flex items-center justify-between text-[11px] text-emerald-300">
            <div className="flex items-center gap-2 truncate">
              <Loader2 className="w-3.5 h-3.5 animate-spin text-emerald-400 shrink-0" />
              <span className="truncate">
                Executing <strong>{batchProgress.current}</strong> of <strong>{batchProgress.total}</strong>: <code className="text-emerald-200 bg-emerald-950/60 px-1 py-0.5 rounded border border-emerald-500/30 font-bold">{batchProgress.title}</code>
              </span>
            </div>
            <span className="font-bold text-[10px] bg-emerald-900/60 px-2 py-0.5 rounded border border-emerald-500/40 text-emerald-200 shrink-0 ml-2">
              {Math.round((batchProgress.current / batchProgress.total) * 100)}%
            </span>
          </div>
        )}

        {/* Error message */}
        {errorMessage && (
          <div className="p-3 bg-rose-950/40 border-b border-rose-500/40 text-rose-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Proposal Card Feed */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {filteredProposals.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-slate-500 space-y-2 text-center">
              <Zap className="w-8 h-8 text-slate-600 opacity-40 animate-pulse" />
              <p className="font-bold text-slate-400 text-xs">No Staged Test Proposals Found</p>
              <p className="text-[11px] text-slate-600 max-w-sm">
                Proposals are generated automatically when reflections, IDOR integer patterns, or auth anomalies are intercepted in the live traffic stream.
              </p>
            </div>
          ) : (
            filteredProposals.map((proposal) => (
              <ProposalCard key={proposal.id} proposal={proposal} />
            ))
          )}
        </div>
      </div>
    </div>
  );
};
