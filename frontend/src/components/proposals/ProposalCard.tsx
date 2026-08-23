import React, { useState } from 'react';
import { TestProposal, HttpMethod, RuleSeverity } from '../../types';
import { useFlowStore } from '../../store/flowStore';
import { Badge } from '../common/Badge';
import { 
  Check, 
  Edit3, 
  Star, 
  X, 
  Play, 
  AlertTriangle, 
  Sparkles, 
  Zap, 
  ShieldCheck, 
  Key, 
  FileText, 
  Layers, 
  Eye,
  Loader2,
  ArrowRight
} from 'lucide-react';

export interface ProposalCardProps {
  proposal: TestProposal;
  onApproveAndRun?: (proposal: TestProposal) => Promise<void> | void;
  onEditInMatrix?: (proposal: TestProposal) => void;
  onSaveToCurated?: (proposal: TestProposal) => void;
  onDismiss?: (id: string) => void;
  onViewDiff?: (proposal: TestProposal) => void;
}

export const ProposalCard: React.FC<ProposalCardProps> = ({
  proposal,
  onApproveAndRun,
  onEditInMatrix,
  onSaveToCurated,
  onDismiss,
  onViewDiff,
}) => {
  const approveProposal = useFlowStore((s) => s.approveProposal);
  const dismissProposal = useFlowStore((s) => s.dismissProposal);
  const transferProposalToMatrix = useFlowStore((s) => s.transferProposalToMatrix);
  const saveProposalToCurated = useFlowStore((s) => s.saveProposalToCurated);
  const setActiveDiffProposal = useFlowStore((s) => s.setActiveDiffProposal);

  const [isRunning, setIsRunning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isSaved, setIsSaved] = useState(false);

  const isPending = proposal.status === 'PENDING' || proposal.state === 'PENDING';
  const isExecuting = proposal.status === 'EXECUTING' || isRunning;
  const isExecuted = proposal.status === 'EXECUTED' || proposal.status === 'COMPLETED';
  const isDismissed = proposal.status === 'DISMISSED';

  const getMethodBadgeVariant = (method: string): any => {
    switch (method.toUpperCase()) {
      case 'GET': return 'primary';
      case 'POST': return 'success';
      case 'PUT': return 'warning';
      case 'DELETE': return 'danger';
      case 'PATCH': return 'mutation';
      default: return 'neutral';
    }
  };

  const getSeverityBadgeVariant = (severity: string): any => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 'danger';
      case 'HIGH': return 'idor';
      case 'MEDIUM': return 'warning';
      case 'LOW': return 'primary';
      default: return 'neutral';
    }
  };

  const handleApproveAndRun = async () => {
    setErrorMsg(null);
    setIsRunning(true);
    try {
      if (onApproveAndRun) {
        await onApproveAndRun(proposal);
      } else {
        await approveProposal(proposal.id);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Execution failed');
    } finally {
      setIsRunning(false);
    }
  };

  const handleEditInMatrix = () => {
    if (onEditInMatrix) {
      onEditInMatrix(proposal);
    } else {
      transferProposalToMatrix(proposal.id);
    }
  };

  const handleSaveToCurated = () => {
    setIsSaved(true);
    if (onSaveToCurated) {
      onSaveToCurated(proposal);
    } else {
      saveProposalToCurated(proposal.id);
    }
    setTimeout(() => setIsSaved(false), 2500);
  };

  const handleDismiss = () => {
    if (onDismiss) {
      onDismiss(proposal.id);
    } else {
      dismissProposal(proposal.id);
    }
  };

  const handleOpenDiff = () => {
    if (onViewDiff) {
      onViewDiff(proposal);
    } else {
      setActiveDiffProposal(proposal);
    }
  };

  return (
    <div className={`p-4 rounded-xl border transition-all font-mono text-xs ${
      isDismissed
        ? 'bg-slate-950/40 border-slate-900 opacity-60'
        : isExecuted
        ? 'bg-[#0E1524] border-emerald-500/30 shadow-md shadow-emerald-950/20'
        : 'bg-[#0E1524] border-slate-800 hover:border-slate-700 shadow-lg shadow-black/40'
    }`}>
      {/* Card Header: Method, Path, Vulnerability Category & Severity */}
      <div className="flex items-start justify-between gap-2 mb-2.5">
        <div className="space-y-1.5 min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant={getMethodBadgeVariant(proposal.method)} size="sm">
              {proposal.method}
            </Badge>
            <span 
              className="font-bold text-slate-100 truncate max-w-sm md:max-w-md" 
              title={proposal.endpoint_path}
            >
              {proposal.endpoint_path}
            </span>
            {proposal.host && (
              <span className="text-[11px] text-slate-500 truncate" title={proposal.host}>
                ({proposal.host})
              </span>
            )}
          </div>

          <div className="flex items-center gap-2 text-[11px] flex-wrap">
            <Badge variant={getSeverityBadgeVariant(proposal.severity)} size="sm">
              {proposal.severity}
            </Badge>
            <span className="text-amber-300 font-semibold flex items-center gap-1">
              <Zap className="w-3 h-3 text-amber-400" />
              <span>{proposal.inferred_vuln_category}</span>
            </span>
            <span className="text-slate-600">•</span>
            <span className="text-cyan-400 font-semibold bg-cyan-950/40 px-1.5 py-0.5 rounded border border-cyan-500/20">
              {proposal.target_param_location}.{proposal.target_param_name}
            </span>
            {proposal.confidence_score !== undefined && (
              <>
                <span className="text-slate-600">•</span>
                <span className="text-slate-400 text-[10px]">
                  Conf: {Math.round(proposal.confidence_score)}%
                </span>
              </>
            )}
          </div>
        </div>

        {/* Status Pill Badge */}
        <div className="shrink-0">
          {isExecuted && (
            <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold flex items-center gap-1">
              <Check className="w-3 h-3" />
              <span>EXECUTED</span>
            </span>
          )}
          {isExecuting && (
            <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 text-[10px] font-bold flex items-center gap-1 animate-pulse">
              <Loader2 className="w-3 h-3 animate-spin" />
              <span>RUNNING</span>
            </span>
          )}
          {isDismissed && (
            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-500 border border-slate-700 text-[10px] font-bold">
              DISMISSED
            </span>
          )}
          {isPending && (
            <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 text-[10px] font-bold flex items-center gap-1">
              <span>⚡</span>
              <span>STAGED</span>
            </span>
          )}
        </div>
      </div>

      {/* Risk Rationale Banner */}
      <div className="p-2.5 bg-slate-900/90 border border-slate-800/90 rounded-lg text-slate-300 text-[11px] leading-relaxed mb-3">
        <span className="text-amber-400/90 font-bold mr-1.5 flex-inline items-center gap-1">
          <span>⚡ Risk Rationale:</span>
        </span>
        <span className="text-slate-300">{proposal.risk_rationale || proposal.description}</span>
      </div>

      {/* Mutation Preview Box: Baseline vs Mutated */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] mb-3">
        <div className="p-2 bg-slate-950/80 rounded border border-slate-800">
          <span className="text-slate-500 block mb-1 text-[10px] uppercase font-bold">
            Baseline Value
          </span>
          <code className="text-slate-300 font-mono break-all line-clamp-2 block">
            {proposal.baseline_value !== undefined && proposal.baseline_value !== null
              ? String(proposal.baseline_value)
              : '<empty/null>'}
          </code>
        </div>
        <div className="p-2 bg-amber-950/20 rounded border border-amber-500/30">
          <span className="text-amber-400/90 block mb-1 text-[10px] uppercase font-bold flex items-center gap-1">
            <Sparkles className="w-2.5 h-2.5 text-amber-400" />
            <span>Mutated Candidate</span>
          </span>
          <code className="text-amber-300 font-mono font-bold break-all line-clamp-2 block">
            {proposal.mutated_value !== undefined && proposal.mutated_value !== null
              ? String(proposal.mutated_value)
              : '<empty/null>'}
          </code>
        </div>
      </div>

      {/* Payload Preview (if present) */}
      {proposal.payload_preview && (
        <div className="p-2 bg-slate-950/60 rounded border border-slate-800/80 text-[10px] text-slate-400 mb-3 font-mono break-all">
          <span className="text-slate-500 font-semibold block mb-0.5">Payload Preview:</span>
          <pre className="text-slate-300 whitespace-pre-wrap">{proposal.payload_preview}</pre>
        </div>
      )}

      {/* Execution Diff Summary (if executed) */}
      {proposal.diff_summary && (
        <div className="p-2.5 bg-emerald-950/20 border border-emerald-500/30 rounded-lg text-[11px] mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-3">
            <span className="font-bold text-emerald-300 flex items-center gap-1">
              <Check className="w-3 h-3 text-emerald-400" />
              <span>Result: {proposal.diff_summary.status_code} OK</span>
            </span>
            <span className="text-slate-400">
              Delta: {proposal.diff_summary.length_delta >= 0 ? `+${proposal.diff_summary.length_delta}` : proposal.diff_summary.length_delta} B
            </span>
            {proposal.diff_summary.latency_ms > 0 && (
              <span className="text-slate-400">{Math.round(proposal.diff_summary.latency_ms)}ms</span>
            )}
            {proposal.diff_summary.verdict_level && (
              <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 text-[10px] font-bold">
                {proposal.diff_summary.verdict_level}
              </span>
            )}
          </div>
          <button
            onClick={handleOpenDiff}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-xs font-semibold flex items-center gap-1 transition-colors"
          >
            <Eye className="w-3 h-3" />
            <span>View Diff</span>
          </button>
        </div>
      )}

      {/* Error Banner */}
      {errorMsg && (
        <div className="p-2 bg-rose-950/40 border border-rose-500/40 rounded text-[11px] text-rose-300 mb-3 flex items-center gap-1.5">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-rose-400" />
          <span className="truncate">{errorMsg}</span>
        </div>
      )}

      {/* 4 Essential Action Buttons */}
      <div className="flex flex-wrap items-center justify-between gap-2 pt-2.5 border-t border-slate-800/80">
        <div className="flex items-center gap-2 flex-wrap">
          {/* 1. [✓ Approve & Run] */}
          <button
            onClick={handleApproveAndRun}
            disabled={isExecuting}
            className={`px-3 py-1.5 rounded-lg font-bold flex items-center gap-1.5 transition-all text-xs shadow-md ${
              isExecuting
                ? 'bg-emerald-800 text-slate-300 cursor-not-allowed opacity-75'
                : isExecuted
                ? 'bg-emerald-700 hover:bg-emerald-600 text-white shadow-emerald-700/20'
                : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-600/25 hover:scale-[1.02]'
            }`}
            title="Execute test proposal replay and inspect delta diff"
          >
            {isExecuting ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Check className="w-3.5 h-3.5" />
            )}
            <span>{isExecuted ? 'Re-Run & Diff' : 'Approve & Run'}</span>
          </button>

          {/* 2. [✏️ Edit in Matrix] */}
          <button
            onClick={handleEditInMatrix}
            className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 flex items-center gap-1.5 transition-colors text-xs hover:border-cyan-500/40"
            title="Load proposal into Matrix Builder for parameter tuning"
          >
            <Edit3 className="w-3.5 h-3.5" />
            <span>Edit in Matrix</span>
          </button>

          {/* 3. [⭐ Save to Curated] */}
          <button
            onClick={handleSaveToCurated}
            className={`px-2.5 py-1.5 rounded-lg border flex items-center gap-1.5 transition-colors text-xs ${
              isSaved
                ? 'bg-yellow-500/30 border-yellow-400 text-yellow-200 font-bold'
                : 'bg-slate-800 hover:bg-slate-700 text-yellow-300 border-slate-700 hover:border-yellow-500/40'
            }`}
            title="Pin proposal and mutated payload into Curated Collections"
          >
            <Star className={`w-3.5 h-3.5 ${isSaved ? 'fill-yellow-300 text-yellow-300' : 'text-yellow-400'}`} />
            <span>{isSaved ? 'Saved!' : 'Save to Curated'}</span>
          </button>
        </div>

        {/* 4. [✕ Dismiss / Ignore] */}
        {!isDismissed && (
          <button
            onClick={handleDismiss}
            className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 border border-transparent hover:border-rose-500/20 transition-colors"
            title="Dismiss proposal"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
};
