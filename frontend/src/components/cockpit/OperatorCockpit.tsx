import React, { useState, useEffect, useRef } from 'react';
import { useFlowStore } from '../../store/flowStore';
import { ProposalCard } from '../proposals/ProposalCard';
import { MultiLayerDecoderModal } from '../decoder/MultiLayerDecoderModal';
import { Badge } from '../common/Badge';
import { 
  Bot, 
  Zap, 
  Sparkles, 
  ShieldAlert, 
  Shield,
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
  CheckCheck,
  StopCircle,
  XCircle,
  Sliders,
  Activity
} from 'lucide-react';
import { api } from '../../services/api';
import { TestProposal, TelemetryLogEntry } from '../../types';

export const OperatorCockpit: React.FC = () => {
  const flows = useFlowStore((s) => s.flows);
  const flowOrder = useFlowStore((s) => s.flowOrder);
  const selectedFlowId = useFlowStore((s) => s.selectedFlowId);
  const stats = useFlowStore((s) => s.stats);
  const proposals = useFlowStore((s) => s.proposals);
  const proposalOrder = useFlowStore((s) => s.proposalOrder);
  const approveProposal = useFlowStore((s) => s.approveProposal);
  const dismissProposal = useFlowStore((s) => s.dismissProposal);
  const setActiveView = useFlowStore((s) => s.setActiveView);
  const setFilters = useFlowStore((s) => s.setFilters);
  const telemetryLogs = useFlowStore((s) => s.telemetryLogs);
  const addTelemetryLog = useFlowStore((s) => s.addTelemetryLog);
  const clearTelemetryLogs = useFlowStore((s) => s.clearTelemetryLogs);

  const [activeFilter, setActiveFilter] = useState<'ALL' | 'REFLECTION' | 'IDOR' | 'AUTH' | 'COMPLETED'>('ALL');
  const [autoPilotEnabled, setAutoPilotEnabled] = useState(false);
  const [autoPilotPacingMs, setAutoPilotPacingMs] = useState(2000);
  const [stopOnAnomaly, setStopOnAnomaly] = useState(true);
  const [minConfidence, setMinConfidence] = useState(60);
  const [autoPilotCategory, setAutoPilotCategory] = useState<'ALL' | 'IDOR' | 'REFLECTION' | 'AUTH' | 'MASS_ASSIGNMENT'>('ALL');

  const [isBatchRunning, setIsBatchRunning] = useState(false);
  const [decoderText, setDecoderText] = useState('');
  const [isDecoderOpen, setIsDecoderOpen] = useState(false);

  // Execution lock and scheduler refs
  const isExecutingRef = useRef(false);
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const abortBatchRef = useRef(false);

  // Synchronized refs for background execution loop
  const autoPilotEnabledRef = useRef(autoPilotEnabled);
  autoPilotEnabledRef.current = autoPilotEnabled;
  const pacingMsRef = useRef(autoPilotPacingMs);
  pacingMsRef.current = autoPilotPacingMs;
  const minConfidenceRef = useRef(minConfidence);
  minConfidenceRef.current = minConfidence;
  const stopOnAnomalyRef = useRef(stopOnAnomaly);
  stopOnAnomalyRef.current = stopOnAnomaly;
  const categoryRef = useRef(autoPilotCategory);
  categoryRef.current = autoPilotCategory;

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

  // Auto-Pilot Execution Loop: Recursive setTimeout with execution lock and state decoupling
  useEffect(() => {
    if (!autoPilotEnabled) {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      isExecutingRef.current = false;
      return;
    }

    let isMounted = true;

    const scheduleNext = (delayMs: number) => {
      if (!isMounted || !autoPilotEnabledRef.current) return;
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(runAutoPilotStep, delayMs);
    };

    const runAutoPilotStep = async () => {
      if (!isMounted || !autoPilotEnabledRef.current || isExecutingRef.current) {
        return;
      }

      isExecutingRef.current = true;
      try {
        // Read directly from store state to decouple from component re-renders
        const allProposals = Object.values(useFlowStore.getState().proposals);
        
        // Filter candidates matching pending status, confidence threshold, and scoped category
        const eligible = allProposals.filter((p) => {
          const isPending = p.status === 'PENDING' || p.state === 'PENDING' || !p.status;
          if (!isPending) return false;

          const conf = p.confidence_score ?? 70;
          if (conf < minConfidenceRef.current) return false;

          const cat = categoryRef.current;
          if (cat !== 'ALL') {
            const catStr = `${p.inferred_vuln_category || ''} ${p.anomaly_type || ''} ${p.category || ''} ${p.title || ''}`.toUpperCase();
            if (cat === 'IDOR' && !catStr.includes('IDOR') && !catStr.includes('BOLA') && !catStr.includes('SEQUENTIAL')) return false;
            if (cat === 'REFLECTION' && !catStr.includes('REFL') && !catStr.includes('XSS')) return false;
            if (cat === 'AUTH' && !catStr.includes('AUTH') && !catStr.includes('JWT') && !catStr.includes('ROLE')) return false;
            if (cat === 'MASS_ASSIGNMENT' && !catStr.includes('MASS') && !catStr.includes('SCHEMA') && !catStr.includes('JSON')) return false;
          }

          return true;
        });

        if (eligible.length === 0) {
          // No eligible proposal right now; wait for next cycle
          scheduleNext(pacingMsRef.current);
          return;
        }

        const next = eligible[0];
        addTelemetryLog({
          id: `log-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          timestamp: new Date().toLocaleTimeString(),
          type: 'AUTOPILOT',
          message: `Executing proposal (${pacingMsRef.current}ms pacing): ${next.title || next.inferred_vuln_category}`,
          method: next.method,
          endpointPath: next.endpoint_path,
          proposalId: next.id,
        });

        const result = await approveProposal(next.id);

        const verdictLevel = result?.proposal?.execution_result?.verdict_level || 
                             result?.diff?.anomaly_verdict?.level || 
                             result?.execution_result?.verdict_level ||
                             'INFO_DIFF';
        const statusCode = result?.executed_flow?.response_status ?? 
                           result?.diff?.flow_b?.response_status ?? 
                           result?.proposal?.execution_result?.status_code ??
                           result?.status_code ??
                           200;
        const statusDelta = result?.diff?.status_delta;
        const lenDelta = result?.diff?.length_delta_bytes ?? result?.proposal?.execution_result?.length_delta_bytes ?? 0;
        const latMs = result?.diff?.latency_delta_ms ?? result?.proposal?.execution_result?.latency_delta_ms ?? 0;

        addTelemetryLog({
          id: `log-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          timestamp: new Date().toLocaleTimeString(),
          type: 'AUTOPILOT',
          message: `Completed ${next.method} ${next.endpoint_path}`,
          method: next.method,
          endpointPath: next.endpoint_path,
          proposalId: next.id,
          statusCode,
          statusDelta,
          lengthDeltaBytes: lenDelta,
          latencyMs: latMs,
          verdictLevel,
          verdictDescription: result?.diff?.anomaly_verdict?.description,
        });

        // Safety Brake Trigger Check
        const isCriticalAnomaly = verdictLevel === 'CRITICAL_IDOR' || 
                                 verdictLevel === 'HIGH_REFLECTION' || 
                                 verdictLevel === 'AUTH_BYPASS';

        if (stopOnAnomalyRef.current && isCriticalAnomaly) {
          setAutoPilotEnabled(false);
          addTelemetryLog({
            id: `log-${Date.now()}-brake`,
            timestamp: new Date().toLocaleTimeString(),
            type: 'SAFETY_BRAKE',
            message: `SAFETY BRAKE TRIGGERED: Auto-Pilot halted on ${verdictLevel} (${next.endpoint_path})`,
            method: next.method,
            endpointPath: next.endpoint_path,
            proposalId: next.id,
            verdictLevel,
            statusCode,
          });
          return; // Stop without scheduling next tick
        }

        // Schedule next execution step with configured pacing delay
        scheduleNext(pacingMsRef.current);
      } catch (err: any) {
        addTelemetryLog({
          id: `log-${Date.now()}-err`,
          timestamp: new Date().toLocaleTimeString(),
          type: 'ERROR',
          message: `Auto-Pilot execution failed: ${err.message}`,
        });
        scheduleNext(pacingMsRef.current);
      } finally {
        isExecutingRef.current = false;
      }
    };

    // Kick off first step immediately
    scheduleNext(100);

    return () => {
      isMounted = false;
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      isExecutingRef.current = false;
    };
  }, [autoPilotEnabled, approveProposal, addTelemetryLog]);

  const handleRunAllPending = async () => {
    if (isBatchRunning) {
      abortBatchRef.current = true;
      setIsBatchRunning(false);
      return;
    }

    setIsBatchRunning(true);
    abortBatchRef.current = false;

    try {
      for (let i = 0; i < pendingProposals.length; i++) {
        if (abortBatchRef.current) {
          addTelemetryLog({
            id: `log-${Date.now()}-abort`,
            timestamp: new Date().toLocaleTimeString(),
            type: 'BATCH',
            message: `Batch execution aborted by operator after ${i} proposals.`,
          });
          break;
        }

        const p = pendingProposals[i];
        addTelemetryLog({
          id: `log-${Date.now()}-${p.id}`,
          timestamp: new Date().toLocaleTimeString(),
          type: 'BATCH',
          message: `[Batch ${i + 1}/${pendingProposals.length}] Executing ${p.method} ${p.endpoint_path}...`,
          method: p.method,
          endpointPath: p.endpoint_path,
          proposalId: p.id,
        });

        await approveProposal(p.id);

        if (i < pendingProposals.length - 1 && !abortBatchRef.current) {
          await new Promise((resolve) => setTimeout(resolve, Math.max(500, autoPilotPacingMs)));
        }
      }

      if (!abortBatchRef.current) {
        addTelemetryLog({
          id: `log-${Date.now()}-done`,
          timestamp: new Date().toLocaleTimeString(),
          type: 'BATCH',
          message: `Batch executed ${pendingProposals.length} pending test proposals successfully.`,
        });
      }
    } catch (err: any) {
      addTelemetryLog({
        id: `log-${Date.now()}-err`,
        timestamp: new Date().toLocaleTimeString(),
        type: 'ERROR',
        message: `Batch execution error: ${err.message}`,
      });
    } finally {
      setIsBatchRunning(false);
    }
  };

  const openQuickDecoder = (sample?: string) => {
    if (sample) {
      setDecoderText(sample);
    } else if (selectedFlowId && flows[selectedFlowId]) {
      const f = flows[selectedFlowId];
      const authHdr = f.request_headers?.['authorization'] || f.request_headers?.['Authorization'];
      setDecoderText(authHdr || f.request_body || f.response_body || f.url || '');
    }
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
                addTelemetryLog({
                  id: `log-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                  timestamp: new Date().toLocaleTimeString(),
                  type: 'SYSTEM',
                  message: `[Auto-Pilot] ${next ? `ACTIVATED (${autoPilotPacingMs / 1000}s pacing)` : 'PAUSED'}`,
                });
              }}
              className={`px-3 py-1.5 rounded-lg border text-xs font-mono font-bold flex items-center gap-2 transition-all shadow-md ${
                autoPilotEnabled
                  ? 'bg-emerald-500 text-slate-950 border-emerald-400 shadow-emerald-500/20 animate-pulse'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 border-slate-700'
              }`}
              title="Toggle Autonomous Background Test Execution"
            >
              <Bot className="w-4 h-4" />
              <span>{autoPilotEnabled ? '🤖 AUTO-PILOT ACTIVE' : '🤖 ENABLE AUTO-PILOT'}</span>
            </button>

            {/* Pacing Speed Selector & Slider */}
            <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1 text-xs">
              <span className="text-slate-400 font-mono text-[10px] uppercase font-bold">Pacing:</span>
              <select
                value={[500, 1000, 2000, 5000].includes(autoPilotPacingMs) ? autoPilotPacingMs : 'custom'}
                onChange={(e) => {
                  const val = e.target.value;
                  if (val !== 'custom') {
                    const num = Number(val);
                    setAutoPilotPacingMs(num);
                    addTelemetryLog({
                      id: `log-${Date.now()}-pace`,
                      timestamp: new Date().toLocaleTimeString(),
                      type: 'SYSTEM',
                      message: `[Pacing Control] Updated execution delay to ${num / 1000}s`,
                    });
                  }
                }}
                className="bg-slate-950 border border-slate-700 text-cyan-300 rounded px-1.5 py-0.5 text-xs font-mono font-bold focus:outline-none"
              >
                <option value={500}>⚡ 500ms (Fast)</option>
                <option value={1000}>⏱️ 1000ms (1.0s)</option>
                <option value={2000}>🎯 2000ms (2.0s Default)</option>
                <option value={5000}>🐢 5000ms (5.0s Safe)</option>
                <option value="custom">⚙️ Custom Slider</option>
              </select>

              <input
                type="range"
                min={250}
                max={10000}
                step={250}
                value={autoPilotPacingMs}
                onChange={(e) => setAutoPilotPacingMs(Number(e.target.value))}
                className="w-16 accent-cyan-400 cursor-pointer h-1.5 bg-slate-800 rounded-lg"
                title={`Pacing delay: ${(autoPilotPacingMs / 1000).toFixed(2)}s`}
              />
              <span className="text-cyan-400 font-mono text-[10px] font-bold min-w-[28px]">
                {(autoPilotPacingMs / 1000).toFixed(1)}s
              </span>
            </div>

            {/* Stop on Anomaly Brake Toggle */}
            <label 
              className={`flex items-center gap-1.5 cursor-pointer border rounded-lg px-2.5 py-1 text-xs select-none transition-colors ${
                stopOnAnomaly 
                  ? 'bg-rose-950/30 border-rose-500/40 text-rose-300' 
                  : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-600'
              }`}
              title="Automatically pause Auto-Pilot when a critical anomaly is detected"
            >
              <input
                type="checkbox"
                checked={stopOnAnomaly}
                onChange={(e) => setStopOnAnomaly(e.target.checked)}
                className="rounded bg-slate-950 border-slate-700 text-rose-500 focus:ring-0 w-3.5 h-3.5 accent-rose-500 cursor-pointer"
              />
              <span className="font-mono text-[10px] font-bold">
                🛡️ Stop on Anomaly
              </span>
            </label>

            {/* Minimum Confidence Slider */}
            <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1 text-xs">
              <span className="text-slate-400 font-mono text-[10px] uppercase font-bold">Min Conf:</span>
              <input
                type="range"
                min={0}
                max={100}
                step={5}
                value={minConfidence}
                onChange={(e) => setMinConfidence(Number(e.target.value))}
                className="w-14 accent-amber-400 cursor-pointer h-1.5 bg-slate-800 rounded-lg"
                title={`Minimum confidence threshold: ${minConfidence}%`}
              />
              <span className="text-amber-300 font-mono text-[10px] font-bold min-w-[28px]">
                {minConfidence}%
              </span>
            </div>

            {/* Category Filter Selector */}
            <div className="flex items-center gap-1 bg-slate-900 border border-slate-700 rounded-lg px-2 py-1 text-xs font-mono">
              <span className="text-slate-400 text-[10px] uppercase font-bold">Scope:</span>
              <select
                value={autoPilotCategory}
                onChange={(e) => setAutoPilotCategory(e.target.value as any)}
                className="bg-slate-950 border border-slate-700 text-amber-300 rounded px-1.5 py-0.5 text-xs font-mono font-bold focus:outline-none"
              >
                <option value="ALL">🌐 All Categories</option>
                <option value="IDOR">🔥 IDOR & BOLA</option>
                <option value="REFLECTION">✨ Reflection / XSS</option>
                <option value="AUTH">🔒 Auth & Roles</option>
                <option value="MASS_ASSIGNMENT">📦 Mass Assignment</option>
              </select>
            </div>

            {/* Run All Staged Button */}
            <button
              onClick={handleRunAllPending}
              disabled={pendingProposals.length === 0 && !isBatchRunning}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-all shadow-md ${
                isBatchRunning 
                  ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-600/20' 
                  : 'bg-primary hover:bg-primary-hover disabled:opacity-50 text-slate-950 shadow-primary/20'
              }`}
            >
              {isBatchRunning ? (
                <>
                  <StopCircle className="w-3.5 h-3.5 animate-pulse" />
                  <span>Cancel Batch</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  <span>Run All Staged ({pendingProposals.length})</span>
                </>
              )}
            </button>

            {/* Open Multi-Format Decoder */}
            <button
              onClick={() => openQuickDecoder()}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-300 text-xs font-mono font-semibold flex items-center gap-1.5 transition-all"
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>Decoder Studio</span>
              {selectedFlowId && flows[selectedFlowId] && (
                <span className="text-[9px] text-cyan-500 font-normal ml-1">
                  [{flows[selectedFlowId].method} {flows[selectedFlowId].path?.split('/').pop() || 'flow'}]
                </span>
              )}
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
        {/* 4. Live HUD Telemetry Event Log */}
        {/* ========================================================================= */}
        <div className="bg-slate-950 border border-slate-800/80 rounded-xl p-3 font-mono text-xs">
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/60 text-slate-400">
            <div className="flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-primary" />
              <span className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
                Live HUD Telemetry Event Stream
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                {telemetryLogs.length} events
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={clearTelemetryLogs}
                className="text-[10px] text-slate-500 hover:text-slate-300 transition-colors"
              >
                Clear Log
              </button>
              <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                Live Stream
              </span>
            </div>
          </div>

          <div className="max-h-48 overflow-y-auto space-y-1.5 text-slate-300 select-text font-mono text-[11px] pr-1">
            {telemetryLogs.length === 0 ? (
              <div className="text-slate-500 text-center py-4">
                Telemetry log initialized. Waiting for test proposal executions or stream activity...
              </div>
            ) : (
              telemetryLogs.map((log) => (
                <div 
                  key={log.id} 
                  className={`p-1.5 rounded border flex flex-wrap items-center justify-between gap-2 leading-tight ${
                    log.type === 'SAFETY_BRAKE'
                      ? 'bg-rose-950/40 border-rose-500/50 text-rose-200'
                      : log.type === 'ERROR'
                      ? 'bg-red-950/30 border-red-500/40 text-red-300'
                      : 'bg-slate-900/60 border-slate-800/80 text-slate-300'
                  }`}
                >
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-slate-500 text-[10px]">[{log.timestamp}]</span>
                    
                    {/* Type Badge */}
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${
                      log.type === 'AUTOPILOT' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' :
                      log.type === 'SAFETY_BRAKE' ? 'bg-rose-500 text-slate-950 font-bold animate-pulse' :
                      log.type === 'BATCH' ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30' :
                      log.type === 'SYSTEM' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                      'bg-slate-800 text-slate-400'
                    }`}>
                      {log.type}
                    </span>

                    {/* Method & Endpoint */}
                    {log.method && log.endpointPath && (
                      <span className="text-slate-200 font-bold">
                        <span className="text-amber-400 mr-1">{log.method}</span>
                        <span>{log.endpointPath}</span>
                      </span>
                    )}

                    <span className="text-slate-300">{log.message}</span>
                  </div>

                  {/* Telemetry Metrics Bar */}
                  {(log.statusCode !== undefined || log.verdictLevel) && (
                    <div className="flex items-center gap-2 text-[10px] shrink-0 font-mono">
                      {log.statusCode !== undefined && (
                        <span className={`px-1.5 py-0.5 rounded font-bold ${
                          log.statusCode >= 200 && log.statusCode < 300 ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/30' :
                          log.statusCode >= 400 && log.statusCode < 500 ? 'bg-amber-950 text-amber-400 border border-amber-500/30' :
                          'bg-rose-950 text-rose-400 border border-rose-500/30'
                        }`}>
                          {log.statusDelta || `${log.statusCode} OK`}
                        </span>
                      )}
                      {log.lengthDeltaBytes !== undefined && (
                        <span className="text-cyan-400">
                          {log.lengthDeltaBytes >= 0 ? `+${log.lengthDeltaBytes}` : log.lengthDeltaBytes} B
                        </span>
                      )}
                      {log.latencyMs !== undefined && (
                        <span className="text-slate-400">{Math.round(log.latencyMs)}ms</span>
                      )}
                      {log.verdictLevel && (
                        <span className={`px-1.5 py-0.5 rounded font-bold text-[9px] ${
                          log.verdictLevel === 'CRITICAL_IDOR' ? 'bg-rose-500 text-slate-950' :
                          log.verdictLevel === 'HIGH_REFLECTION' ? 'bg-amber-500 text-slate-950' :
                          log.verdictLevel === 'AUTH_BYPASS' ? 'bg-purple-500 text-white' :
                          'bg-cyan-900 text-cyan-300'
                        }`}>
                          {log.verdictLevel}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
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
