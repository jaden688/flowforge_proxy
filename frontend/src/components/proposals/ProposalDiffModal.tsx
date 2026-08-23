import React, { useState, useEffect } from 'react';
import { useFlowStore } from '../../store/flowStore';
import { TestProposal, FlowRecord, FlowComparisonResult } from '../../types';
import { api } from '../../services/api';
import { Modal } from '../common/Modal';
import { Badge } from '../common/Badge';
import { 
  Check, 
  AlertTriangle, 
  Zap, 
  Sparkles, 
  ShieldCheck, 
  Edit3, 
  Star, 
  ArrowRight, 
  ArrowLeftRight,
  Clock, 
  Hash, 
  FileText,
  Copy,
  ExternalLink,
  Code2
} from 'lucide-react';

export interface ProposalDiffModalProps {
  proposal?: TestProposal | null;
  isOpen?: boolean;
  onClose?: () => void;
}

export const ProposalDiffModal: React.FC<ProposalDiffModalProps> = ({
  proposal: propProposal,
  isOpen: propIsOpen,
  onClose: propOnClose,
}) => {
  const activeDiffProposal = useFlowStore((s) => s.activeDiffProposal);
  const setActiveDiffProposal = useFlowStore((s) => s.setActiveDiffProposal);
  const transferProposalToMatrix = useFlowStore((s) => s.transferProposalToMatrix);
  const saveProposalToCurated = useFlowStore((s) => s.saveProposalToCurated);
  const flows = useFlowStore((s) => s.flows);

  const proposal = propProposal !== undefined ? propProposal : activeDiffProposal;
  const isOpen = propIsOpen !== undefined ? propIsOpen : !!activeDiffProposal;

  const [activeTab, setActiveTab] = useState<'overview' | 'request' | 'response' | 'headers'>('overview');
  const [comparison, setComparison] = useState<FlowComparisonResult | null>(null);
  const [isLoadingDiff, setIsLoadingDiff] = useState<boolean>(false);
  const [isCopied, setIsCopied] = useState<boolean>(false);

  const baselineFlow: FlowRecord | undefined = proposal ? flows[proposal.flow_id] : undefined;
  const executedFlow: FlowRecord | undefined = proposal?.executed_flow_id ? flows[proposal.executed_flow_id] : undefined;

  // If we have baseline and executed flows, compute server diff comparison
  useEffect(() => {
    if (!proposal || !proposal.flow_id || !proposal.executed_flow_id) {
      setComparison(null);
      return;
    }

    let isMounted = true;
    const fetchDiff = async () => {
      setIsLoadingDiff(true);
      try {
        const diffResult = await api.computeDiff({
          flow_id_a: proposal.flow_id,
          flow_id_b: proposal.executed_flow_id,
        });
        if (isMounted) {
          setComparison(diffResult);
        }
      } catch (err) {
        // Fallback to local diff telemetry
      } finally {
        if (isMounted) setIsLoadingDiff(false);
      }
    };

    fetchDiff();
    return () => { isMounted = false; };
  }, [proposal?.flow_id, proposal?.executed_flow_id]);

  const handleClose = () => {
    if (propOnClose) {
      propOnClose();
    } else {
      setActiveDiffProposal(null);
    }
  };

  if (!isOpen || !proposal) return null;

  const exec = proposal.execution_result;
  const diffSummary = proposal.diff_summary;

  const statusCode = exec?.status_code || diffSummary?.status_code || executedFlow?.response_status || 200;
  const baselineStatus = baselineFlow?.response_status || baselineFlow?.response_status_code || 200;
  const statusMatch = baselineStatus === statusCode;

  const lengthDelta = exec?.length_delta_bytes ?? diffSummary?.length_delta ?? 0;
  const latencyDelta = exec?.latency_delta_ms ?? diffSummary?.latency_ms ?? 0;
  const isReflected = exec?.reflected ?? diffSummary?.reflected ?? false;

  const verdictLevel = exec?.verdict_level || diffSummary?.verdict_level || comparison?.anomaly_verdict?.level || 'INFO_DIFF';
  const verdictDesc = exec?.verdict_description || diffSummary?.verdict_description || comparison?.anomaly_verdict?.description || '';

  const getVerdictBannerStyles = (level: string) => {
    switch (level) {
      case 'CRITICAL_IDOR':
        return {
          bg: 'bg-rose-950/40 border-rose-500/50 text-rose-200',
          badge: 'bg-rose-500 text-slate-950 font-bold',
          icon: <Zap className="w-5 h-5 text-rose-400 shrink-0" />,
          title: 'CRITICAL IDOR / BOLA PRIVILEGE ESCALATION',
          fallbackDesc: 'The server returned 200 OK with distinct object payload for the mutated identifier without authorization challenge.',
        };
      case 'HIGH_REFLECTION':
        return {
          bg: 'bg-amber-950/40 border-amber-500/50 text-amber-200',
          badge: 'bg-amber-500 text-slate-950 font-bold',
          icon: <Sparkles className="w-5 h-5 text-amber-400 shrink-0" />,
          title: 'HIGH RISK INPUT REFLECTION DETECTED',
          fallbackDesc: 'The mutated test payload was directly reflected into the HTTP response stream context.',
        };
      case 'AUTH_BYPASS':
        return {
          bg: 'bg-purple-950/40 border-purple-500/50 text-purple-200',
          badge: 'bg-purple-500 text-white font-bold',
          icon: <ShieldCheck className="w-5 h-5 text-purple-400 shrink-0" />,
          title: 'AUTHENTICATION STATE ANOMALY / BYPASS',
          fallbackDesc: 'The endpoint processed the request successfully despite missing or altered authentication tokens.',
        };
      default:
        return {
          bg: 'bg-cyan-950/40 border-cyan-500/40 text-cyan-200',
          badge: 'bg-cyan-600 text-white font-bold',
          icon: <AlertTriangle className="w-5 h-5 text-cyan-400 shrink-0" />,
          title: 'RESPONSE DELTA & BEHAVIORAL VARIATION',
          fallbackDesc: 'Server response behavior shifted in response to the mutated parameter candidate.',
        };
    }
  };

  const banner = getVerdictBannerStyles(verdictLevel);

  const handleCopyPayload = () => {
    navigator.clipboard.writeText(String(proposal.mutated_value ?? ''));
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title={`Replay Execution Delta & Diff Inspector`}
      maxWidth="max-w-4xl"
    >
      <div className="space-y-4 font-mono text-xs">
        {/* Proposal Header Banner */}
        <div className="flex flex-wrap items-center justify-between gap-2 p-3 bg-slate-900/90 border border-slate-800 rounded-lg">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Badge variant="primary" size="sm">{proposal.method}</Badge>
              <span className="font-bold text-slate-100 text-sm">{proposal.endpoint_path}</span>
            </div>
            <div className="flex items-center gap-2 text-[11px] text-slate-400">
              <span className="text-amber-300 font-semibold">{proposal.inferred_vuln_category}</span>
              <span>•</span>
              <span className="text-cyan-400">{proposal.target_param_location}.{proposal.target_param_name}</span>
              <span>•</span>
              <span className="text-slate-500">ID: {proposal.id}</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                transferProposalToMatrix(proposal.id);
                handleClose();
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 flex items-center gap-1.5 transition-colors text-xs"
              title="Transfer to Matrix Builder"
            >
              <Edit3 className="w-3.5 h-3.5" />
              <span>Edit in Matrix</span>
            </button>

            <button
              onClick={() => saveProposalToCurated(proposal.id)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-yellow-300 border border-slate-700 flex items-center gap-1.5 transition-colors text-xs"
              title="Save to Curated"
            >
              <Star className="w-3.5 h-3.5 fill-yellow-400 text-yellow-400" />
              <span>Curate</span>
            </button>
          </div>
        </div>

        {/* Anomaly Verdict Banner */}
        <div className={`p-3.5 rounded-xl border flex items-start gap-3 ${banner.bg}`}>
          {banner.icon}
          <div className="space-y-1 flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className={`px-2 py-0.5 rounded text-[10px] tracking-wide ${banner.badge}`}>
                {verdictLevel}
              </span>
              <span className="font-bold text-sm tracking-tight">{banner.title}</span>
            </div>
            <p className="text-xs opacity-90 leading-relaxed">
              {verdictDesc || banner.fallbackDesc}
            </p>
          </div>
        </div>

        {/* Delta Metrics Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
          {/* Status Delta */}
          <div className="p-2.5 bg-slate-900/80 border border-slate-800 rounded-lg">
            <span className="text-slate-500 block text-[10px] uppercase font-bold mb-1">Status Code</span>
            <div className="flex items-center justify-center gap-1.5 font-bold">
              <span className="text-slate-400">{baselineStatus}</span>
              <ArrowRight className="w-3 h-3 text-slate-500" />
              <span className={statusMatch ? 'text-emerald-400' : 'text-amber-400'}>
                {statusCode}
              </span>
            </div>
          </div>

          {/* Body Length Delta */}
          <div className="p-2.5 bg-slate-900/80 border border-slate-800 rounded-lg">
            <span className="text-slate-500 block text-[10px] uppercase font-bold mb-1">Body Length Delta</span>
            <span className={`font-bold ${lengthDelta !== 0 ? 'text-cyan-400' : 'text-slate-400'}`}>
              {lengthDelta > 0 ? `+${lengthDelta} B` : `${lengthDelta} B`}
            </span>
          </div>

          {/* Latency Delta */}
          <div className="p-2.5 bg-slate-900/80 border border-slate-800 rounded-lg">
            <span className="text-slate-500 block text-[10px] uppercase font-bold mb-1">Latency</span>
            <span className="font-bold text-slate-300">
              {Math.round(latencyDelta)}ms
            </span>
          </div>

          {/* Reflection Indicator */}
          <div className="p-2.5 bg-slate-900/80 border border-slate-800 rounded-lg">
            <span className="text-slate-500 block text-[10px] uppercase font-bold mb-1">Reflection</span>
            <span className={`font-bold ${isReflected ? 'text-yellow-300' : 'text-slate-500'}`}>
              {isReflected ? '⚡ Reflected' : 'Not Reflected'}
            </span>
          </div>
        </div>

        {/* Mutation Value Delta Box */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 font-bold text-[11px]">Original Baseline Parameter</span>
              <span className="text-[10px] text-slate-500">{proposal.target_param_location}</span>
            </div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800 text-slate-300 break-all font-mono">
              {proposal.baseline_value !== undefined && proposal.baseline_value !== null
                ? String(proposal.baseline_value)
                : '<none>'}
            </div>
          </div>

          <div className="p-3 bg-amber-950/20 border border-amber-500/40 rounded-lg space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-amber-300 font-bold text-[11px] flex items-center gap-1">
                <Sparkles className="w-3 h-3 text-amber-400" />
                <span>Mutated Candidate Payload</span>
              </span>
              <button
                onClick={handleCopyPayload}
                className="text-[10px] text-amber-400 hover:text-amber-200 flex items-center gap-1 transition-colors"
              >
                <Copy className="w-2.5 h-2.5" />
                <span>{isCopied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="p-2 bg-amber-950/40 rounded border border-amber-500/40 text-amber-200 font-bold break-all font-mono">
              {proposal.mutated_value !== undefined && proposal.mutated_value !== null
                ? String(proposal.mutated_value)
                : '<none>'}
            </div>
          </div>
        </div>

        {/* View Tabs */}
        <div className="flex border-b border-border text-xs">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-4 py-2 font-medium border-b-2 transition-colors ${
              activeTab === 'overview'
                ? 'border-primary text-primary font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Overview &amp; Rationale
          </button>
          <button
            onClick={() => setActiveTab('response')}
            className={`px-4 py-2 font-medium border-b-2 transition-colors ${
              activeTab === 'response'
                ? 'border-primary text-primary font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Response Body Comparison
          </button>
          <button
            onClick={() => setActiveTab('request')}
            className={`px-4 py-2 font-medium border-b-2 transition-colors ${
              activeTab === 'request'
                ? 'border-primary text-primary font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Request Payloads
          </button>
        </div>

        {/* Tab Contents */}
        {activeTab === 'overview' && (
          <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg space-y-2 text-slate-300">
            <h4 className="font-bold text-slate-200 text-xs flex items-center gap-1.5">
              <span>Security Analysis Rationale:</span>
            </h4>
            <p className="text-xs leading-relaxed text-slate-300">
              {proposal.risk_rationale || proposal.description}
            </p>
            {proposal.auth_override && (
              <div className="pt-2 border-t border-slate-800 text-[11px] text-purple-300">
                <span className="font-bold text-slate-400">Auth Override Applied: </span>
                <code>{proposal.auth_override}</code>
              </div>
            )}
          </div>
        )}

        {activeTab === 'response' && (
          <div className="space-y-2">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {/* Baseline Response Preview */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span className="font-bold text-slate-300">Baseline Response (Flow A)</span>
                  <span>Status: {baselineStatus}</span>
                </div>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 max-h-56 overflow-y-auto text-[11px] text-slate-300">
                  {baselineFlow?.response_body ? (
                    <pre className="whitespace-pre-wrap font-mono">{baselineFlow.response_body}</pre>
                  ) : (
                    <span className="text-slate-600">&lt;Empty response body&gt;</span>
                  )}
                </div>
              </div>

              {/* Mutated Replay Response Preview */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span className="font-bold text-emerald-300">Mutated Replay (Flow B)</span>
                  <span>Status: {statusCode}</span>
                </div>
                <div className="p-3 bg-slate-950 rounded-lg border border-emerald-500/30 max-h-56 overflow-y-auto text-[11px] text-slate-200">
                  {exec?.response_body_preview ? (
                    <pre className="whitespace-pre-wrap font-mono text-emerald-200/90">{exec.response_body_preview}</pre>
                  ) : executedFlow?.response_body ? (
                    <pre className="whitespace-pre-wrap font-mono text-emerald-200/90">{executedFlow.response_body}</pre>
                  ) : (
                    <span className="text-slate-600">&lt;Response recorded with status {statusCode}&gt;</span>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'request' && (
          <div className="space-y-2">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {/* Baseline Request */}
              <div className="space-y-1">
                <span className="text-[11px] font-bold text-slate-300 block">Baseline Request URL &amp; Body</span>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] text-slate-300 space-y-2">
                  <div>
                    <span className="text-slate-500 text-[10px] uppercase font-bold block">URL:</span>
                    <code className="text-cyan-300 break-all">{baselineFlow?.url || proposal.endpoint_path}</code>
                  </div>
                  {baselineFlow?.request_body && (
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase font-bold block">Body:</span>
                      <pre className="whitespace-pre-wrap text-slate-300">{baselineFlow.request_body}</pre>
                    </div>
                  )}
                </div>
              </div>

              {/* Mutated Request */}
              <div className="space-y-1">
                <span className="text-[11px] font-bold text-amber-300 block">Mutated Candidate Request</span>
                <div className="p-3 bg-amber-950/20 rounded-lg border border-amber-500/30 text-[11px] text-amber-200 space-y-2">
                  <div>
                    <span className="text-amber-400/80 text-[10px] uppercase font-bold block">Target Parameter:</span>
                    <code className="text-amber-300 font-bold">{proposal.target_param_location}.{proposal.target_param_name} = {String(proposal.mutated_value)}</code>
                  </div>
                  {proposal.payload_preview && (
                    <div>
                      <span className="text-amber-400/80 text-[10px] uppercase font-bold block">Payload Preview:</span>
                      <pre className="whitespace-pre-wrap text-amber-200">{proposal.payload_preview}</pre>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Modal Footer */}
        <div className="flex items-center justify-between pt-3 border-t border-slate-800">
          <span className="text-[11px] text-slate-500">
            FlowForge Autonomous Proposal Verification Pipeline
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={handleClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </Modal>
  );
};
