import React, { useState, useEffect } from 'react';
import { useFlowStore } from '../../store/flowStore';
import { ProposalCard } from '../proposals/ProposalCard';
import { MultiLayerDecoderModal } from '../decoder/MultiLayerDecoderModal';
import { Badge } from '../common/Badge';
import { 
  Bot, 
  Zap, 
  Sparkles, 
  ShieldAlert, 
  Key, 
  Lock, 
  Play, 
  RefreshCw, 
  CheckCircle2, 
  AlertTriangle, 
  SlidersHorizontal,
  Flame,
  ArrowRight,
  Code2,
  Terminal,
  Layers,
  Database,
  Search,
  Filter,
  CheckCheck
} from 'lucide-react';
import { api } from '../../services/api';
import { TestProposal } from '../../types';

export const OperatorCockpit: React.FC = () => {
  const flows = useFlowStore((s) => s.flows);
  const flowOrder = useFlowStore((s) => s.flowOrder);
  const stats = useFlowStore((s) => s.stats);
  const proposals = useFlowStore((s) => s.proposals);
  const proposalOrder = useFlowStore((s) => s.proposalOrder);
  const approveProposal = useFlowStore((s) => s.approveProposal);
  const dismissProposal = useFlowStore((s) => s.dismissProposal);
  const setActiveView = useFlowStore((s) => s.setActiveView);
  const setFilters = useFlowStore((s) => s.setFilters);

  const [activeFilter, setActiveFilter] = useState<'ALL' | 'REFLECTION' | 'IDOR' | 'AUTH' | 'COMPLETED'>('ALL');
  const [autoPilotEnabled, setAutoPilotEnabled] = useState(false);
  const [isBatchRunning, setIsBatchRunning] = useState(false);
  const [decoderText, setDecoderText] = useState('');
  const [isDecoderOpen, setIsDecoderOpen] = useState(false);
  const [autoLog, setAutoLog] = useState<string[]>([
    'System initialized. Heuristic proposal pipeline active.',
    'Monitoring intercepted proxy stream for reflection contexts and IDOR candidates.',
  ]);

  const proposalList = Object.values(proposals);
  const pendingProposals = proposalList.filter((p) => p.status === 'PENDING' || p.state === 'PENDING');
  const completedProposals = proposalList.filter((p) => p.status === 'COMPLETED' || p.status === 'EXECUTED' || p.state === 'COMPLETED');
  
  const reflectionProposals = proposalList.filter((p) => p.anomaly_type?.includes('REFL') || p.tags?.includes('reflection'));
  const idorProposals = proposalList.filter((p) => 
    p.anomaly_type?.includes('IDOR') || 
    p.tags?.includes('idor') || 
    (typeof p.category === 'string' && p.category.includes('IDOR')) || 
    p.title?.toLowerCase().includes('idor') || 
    p.title?.toLowerCase().includes('sequential')
  );
  const authProposals = proposalList.filter((p) => 
    p.anomaly_type?.includes('AUTH') || 
    p.tags?.includes('auth') || 
    p.anomaly_type?.includes('JWT') || 
    p.title?.toLowerCase().includes('auth') || 
    p.title?.toLowerCase().includes('role')
  );
  const secretProposals = proposalList.filter((p) => 
    p.anomaly_type?.includes('SECRET') || 
    p.tags?.includes('secrets') || 
    p.tags?.includes('jwt')
  );

  const filteredProposals = proposalList.filter((p) => {
    if (activeFilter === 'REFLECTION') return p.anomaly_type?.includes('REFL') || p.tags?.includes('reflection');
    if (activeFilter === 'IDOR') return p.anomaly_type?.includes('IDOR') || p.tags?.includes('idor') || (typeof p.category === 'string' && p.category.includes('IDOR')) || p.title?.toLowerCase().includes('idor') || p.title?.toLowerCase().includes('sequential');
    if (activeFilter === 'AUTH') return p.anomaly_type?.includes('AUTH') || p.tags?.includes('auth') || p.anomaly_type?.includes('JWT') || p.title?.toLowerCase().includes('auth') || p.title?.toLowerCase().includes('role');
    if (activeFilter === 'COMPLETED') return p.status === 'COMPLETED' || p.status === 'EXECUTED' || p.state === 'COMPLETED';
    return true;
  });



  // Auto-Pilot Execution Loop: When active, auto-approves pending proposals
  useEffect(() => {
    if (!autoPilotEnabled) return;

    const interval = setInterval(async () => {
      const pendingHighConfidence = pendingProposals.filter((p) => (p.confidence_score || 70) >= 60);
      if (pendingHighConfidence.length > 0) {
        const next = pendingHighConfidence[0];
        try {
          setAutoLog((prev) => [
            `[Auto-Pilot] Executing proposal: ${next.title} on ${next.endpoint_path}`,
            ...prev.slice(0, 40),
          ]);
          await approveProposal(next.id);
        } catch (e: any) {
          setAutoLog((prev) => [
            `[Auto-Pilot Error] Failed on ${next.id}: ${e.message}`,
            ...prev.slice(0, 40),
          ]);
        }
      }
    }, 2500);

    return () => clearInterval(interval);
  }, [autoPilotEnabled, pendingProposals, approveProposal]);

  const handleRunAllPending = async () => {
    setIsBatchRunning(true);
    try {
      for (const p of pendingProposals) {
        await approveProposal(p.id);
      }
      setAutoLog((prev) => [
        `[Batch] Executed ${pendingProposals.length} pending test proposals successfully.`,
        ...prev.slice(0, 40),
      ]);
    } catch (err: any) {
      alert(`Batch execution error: ${err.message}`);
    } finally {
      setIsBatchRunning(false);
    }
  };

  const openQuickDecoder = (sample?: string) => {
    if (sample) setDecoderText(sample);
    setIsDecoderOpen(true);
  };

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-[#0B0F19] text-slate-100 overflow-y-auto">
      {/* Top Banner: Mission HUD & Autonomous Control */}
      <div className="p-4 border-b border-slate-800 bg-[#0E1524]/90 sticky top-0 z-20 backdrop-blur-md">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-amber-500 to-orange-500 flex items-center justify-center shadow-lg shadow-orange-500/20 animate-pulse">
              <Bot className="w-6 h-6 text-slate-950" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold font-mono tracking-tight text-slate-100">
                  OPERATOR MISSION COCKPIT
                </h1>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-300 font-bold">
                  Full Autonomous Testing Hub
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Autonomous heuristic attack synthesis, live replay diffing, and in-depth parameter analysis.
              </p>
            </div>
          </div>

          {/* Action & Auto-Pilot Controls */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Auto-Pilot Switch */}
            <button
              onClick={() => {
                const next = !autoPilotEnabled;
                setAutoPilotEnabled(next);
                setAutoLog((prev) => [
                  `[Auto-Pilot] ${next ? 'ACTIVATED — Automatically executing verified proposals' : 'PAUSED'}`,
                  ...prev.slice(0, 40),
                ]);
              }}
              className={`px-3.5 py-1.5 rounded-lg border text-xs font-mono font-bold flex items-center gap-2 transition-all shadow-md ${
                autoPilotEnabled
                  ? 'bg-emerald-500 text-slate-950 border-emerald-400 shadow-emerald-500/20 animate-pulse'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 border-slate-700'
              }`}
              title="Toggle Autonomous Background Test Execution"
            >
              <Bot className="w-4 h-4" />
              <span>{autoPilotEnabled ? '🤖 AUTO-PILOT ACTIVE' : '🤖 ENABLE AUTO-PILOT'}</span>
            </button>

            {/* Run All Staged Button */}
            <button
              onClick={handleRunAllPending}
              disabled={isBatchRunning || pendingProposals.length === 0}
              className="px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover disabled:opacity-50 text-slate-950 text-xs font-mono font-bold flex items-center gap-1.5 transition-all shadow-md shadow-primary/20"
            >
              <Play className={`w-3.5 h-3.5 ${isBatchRunning ? 'animate-spin' : ''}`} />
              <span>Run All Staged ({pendingProposals.length})</span>
            </button>

            {/* Open Multi-Format Decoder */}
            <button
              onClick={() => openQuickDecoder()}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-300 text-xs font-mono font-semibold flex items-center gap-1.5 transition-all"
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>Decoder Studio</span>
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto p-4 space-y-6 w-full">
        {/* ========================================================================= */}
        {/* 1. What's Going On & What We Need Intelligence HUD */}
        {/* ========================================================================= */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Card 1: Reflection Surface */}
          <div 
            onClick={() => setActiveFilter('REFLECTION')}
            className="p-3.5 rounded-xl bg-slate-900/60 border border-yellow-500/20 hover:border-yellow-500/50 cursor-pointer transition-all hover:bg-slate-900/90"
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-yellow-400">
                <Sparkles className="w-4 h-4" />
                <span>Reflections</span>
              </div>
              <span className="text-base font-bold font-mono text-yellow-300">
                {Math.max(stats.reflectionsCount, reflectionProposals.length)}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 leading-tight">
              Parameters echoed in response bodies. <span className="text-yellow-400 font-semibold">Needs context-escaping probes</span>.
            </p>
          </div>

          {/* Card 2: Predictable IDs & IDOR */}
          <div 
            onClick={() => setActiveFilter('IDOR')}
            className="p-3.5 rounded-xl bg-slate-900/60 border border-orange-500/20 hover:border-orange-500/50 cursor-pointer transition-all hover:bg-slate-900/90"
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-orange-400">
                <Flame className="w-4 h-4" />
                <span>Predictable IDs</span>
              </div>
              <span className="text-base font-bold font-mono text-orange-300">
                {Math.max(stats.idorCount, idorProposals.length)}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 leading-tight">
              Sequential numeric object IDs. <span className="text-orange-400 font-semibold">Needs horizontal boundary checks</span>.
            </p>
          </div>

          {/* Card 3: Auth Deviations */}
          <div 
            onClick={() => setActiveFilter('AUTH')}
            className="p-3.5 rounded-xl bg-slate-900/60 border border-purple-500/20 hover:border-purple-500/50 cursor-pointer transition-all hover:bg-slate-900/90"
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-purple-400">
                <Lock className="w-4 h-4" />
                <span>Auth Deviations</span>
              </div>
              <span className="text-base font-bold font-mono text-purple-300">
                {Math.max(stats.authAnomaliesCount, authProposals.length)}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 leading-tight">
              Unauthenticated endpoints & token variance. <span className="text-purple-400 font-semibold">Needs auth stripping tests</span>.
            </p>
          </div>

          {/* Card 4: High-Entropy Secrets & Tokens */}
          <div 
            onClick={() => openQuickDecoder()}
            className="p-3.5 rounded-xl bg-slate-900/60 border border-cyan-500/20 hover:border-cyan-500/50 cursor-pointer transition-all hover:bg-slate-900/90"
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-1.5 text-xs font-mono font-semibold text-cyan-400">
                <Key className="w-4 h-4" />
                <span>High-Entropy Secrets</span>
              </div>
              <span className="text-base font-bold font-mono text-cyan-300">
                {Math.max(stats.secretsCount, secretProposals.length)}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 leading-tight">
              Discovered JWTs & API tokens. <span className="text-cyan-400 font-semibold">Ready for 1-click decoding</span>.
            </p>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* 2. Action Directives Feed: "What We Need To Do" */}
        {/* ========================================================================= */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-primary" />
              <h2 className="text-xs font-bold font-mono uppercase text-slate-200 tracking-wider">
                Operator Action Directives (What We Need Right Now)
              </h2>
            </div>
            <span className="text-[10px] font-mono text-slate-400">
              {pendingProposals.length} action items staged
            </span>
          </div>

          {pendingProposals.length === 0 ? (
            <div className="p-4 rounded-lg bg-slate-950/50 border border-slate-800/80 text-center">
              <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-1.5" />
              <p className="text-xs text-slate-300 font-medium font-mono">
                All auto-synthesized test proposals executed or no active anomalies in current traffic.
              </p>
              <p className="text-[11px] text-slate-500 mt-1">
                Browse through target applications using the proxy to capture new flows and trigger auto-synthesis.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {pendingProposals.slice(0, 4).map((prop) => (
                <div 
                  key={prop.id}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-start justify-between gap-3 hover:border-slate-700 transition-colors"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-primary/15 text-primary border border-primary/30">
                        {prop.method} {prop.endpoint_path}
                      </span>
                      <span className="text-[10px] font-mono text-amber-400 font-bold">
                        {prop.anomaly_type}
                      </span>
                    </div>
                    <p className="text-xs text-slate-200 font-medium truncate">
                      {prop.title}
                    </p>
                    <p className="text-[11px] text-slate-400 line-clamp-1">
                      {prop.description}
                    </p>
                  </div>

                  <button
                    onClick={() => approveProposal(prop.id)}
                    className="px-2.5 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-slate-950 text-[11px] font-mono font-bold flex items-center gap-1 shrink-0 transition-colors"
                  >
                    <Play className="w-3 h-3" />
                    <span>Run</span>
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ========================================================================= */}
        {/* 3. Staged Proposals Queue & Verification Matrix */}
        {/* ========================================================================= */}
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-amber-400" />
              <h2 className="text-sm font-bold font-mono text-slate-100">
                Active Test Proposals & Verified Findings ({filteredProposals.length})
              </h2>
            </div>

            {/* Filter Tabs */}
            <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs font-mono">
              <button
                onClick={() => setActiveFilter('ALL')}
                className={`px-2.5 py-1 rounded ${activeFilter === 'ALL' ? 'bg-primary text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-200'}`}
              >
                All ({proposalList.length})
              </button>
              <button
                onClick={() => setActiveFilter('REFLECTION')}
                className={`px-2.5 py-1 rounded ${activeFilter === 'REFLECTION' ? 'bg-yellow-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-yellow-300'}`}
              >
                Reflections ({reflectionProposals.length})
              </button>
              <button
                onClick={() => setActiveFilter('IDOR')}
                className={`px-2.5 py-1 rounded ${activeFilter === 'IDOR' ? 'bg-orange-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-orange-300'}`}
              >
                IDORs ({idorProposals.length})
              </button>
              <button
                onClick={() => setActiveFilter('AUTH')}
                className={`px-2.5 py-1 rounded ${activeFilter === 'AUTH' ? 'bg-purple-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-purple-300'}`}
              >
                Auth ({authProposals.length})
              </button>
              <button
                onClick={() => setActiveFilter('COMPLETED')}
                className={`px-2.5 py-1 rounded ${activeFilter === 'COMPLETED' ? 'bg-emerald-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-emerald-300'}`}
              >
                Verified ({completedProposals.length})
              </button>
            </div>
          </div>

          {filteredProposals.length === 0 ? (
            <div className="p-8 text-center bg-slate-900/30 border border-slate-800 rounded-xl">
              <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto mb-2" />
              <p className="text-sm font-mono text-slate-400">
                No test proposals matching filter '{activeFilter}'.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredProposals.map((proposal) => (
                <ProposalCard
                  key={proposal.id}
                  proposal={proposal}
                />
              ))}
            </div>
          )}
        </div>

        {/* ========================================================================= */}
        {/* 4. Live Autonomous Action Log */}
        {/* ========================================================================= */}
        <div className="bg-slate-950 border border-slate-800/80 rounded-xl p-3 font-mono text-xs">
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/60 text-slate-400">
            <span className="flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-primary" />
              <span>Autonomous Operator Event Log</span>
            </span>
            <span className="text-[10px] text-slate-500">Live Telemetry</span>
          </div>
          <div className="max-h-36 overflow-y-auto space-y-1 text-slate-300 select-text">
            {autoLog.map((log, i) => (
              <div key={i} className="leading-relaxed">
                <span className="text-slate-600 mr-2">[{new Date().toLocaleTimeString()}]</span>
                <span className={log.includes('Auto-Pilot') ? 'text-emerald-400' : log.includes('Error') ? 'text-rose-400' : 'text-slate-300'}>
                  {log}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Multi-Layer Decoder Modal */}
      <MultiLayerDecoderModal
        isOpen={isDecoderOpen}
        onClose={() => setIsDecoderOpen(false)}
        initialInput={decoderText}
      />

    </div>
  );
};
