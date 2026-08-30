import React, { useState } from 'react';
import { 
  Activity, 
  ShieldAlert, 
  Sparkles, 
  GitCompare, 
  Layers, 
  Play, 
  Pause, 
  Trash2, 
  Search, 
  Download, 
  Send,
  Zap,
  Globe,
  Network,
  SlidersHorizontal,
  Filter,
  Crosshair
} from 'lucide-react';
import { useFlowStore } from '../../store/flowStore';
import { ActiveView } from '../../types';
import { Modal } from '../common/Modal';
import { api } from '../../services/api';

export const HeaderNav: React.FC = () => {
  const activeView = useFlowStore((s) => s.activeView);
  const setActiveView = useFlowStore((s) => s.setActiveView);
  const wsConnected = useFlowStore((s) => s.wsConnected);
  const wsLatencyMs = useFlowStore((s) => s.wsLatencyMs);
  const isPaused = useFlowStore((s) => s.isPaused);
  const setPaused = useFlowStore((s) => s.setPaused);
  const stats = useFlowStore((s) => s.stats);
  const filters = useFlowStore((s) => s.filters);
  const setFilters = useFlowStore((s) => s.setFilters);

  // Proposal state and actions
  const proposals = useFlowStore((s) => s.proposals);
  const filterOnlyWithProposals = useFlowStore((s) => s.filterOnlyWithProposals);
  const setFilterOnlyWithProposals = useFlowStore((s) => s.setFilterOnlyWithProposals);
  const toggleApprovalDrawer = useFlowStore((s) => s.toggleApprovalDrawer);

  const pendingProposalsCount = Object.values(proposals).filter(
    (p) => p.status === 'PENDING' || p.status === 'APPROVED' || p.status === 'EXECUTING'
  ).length;

  const [isLaunchingBrowser, setIsLaunchingBrowser] = useState(false);
  const [isReplayModalOpen, setIsReplayModalOpen] = useState(false);
  const [isClearModalOpen, setIsClearModalOpen] = useState(false);
  const [isClearing, setIsClearing] = useState(false);
  const [confirmText, setConfirmText] = useState('');

  // Clear dialog checkbox state
  const [clearFlows, setClearFlows] = useState(true);
  const [clearEndpoints, setClearEndpoints] = useState(false);
  const [clearProposals, setClearProposals] = useState(true);
  const [clearIntruder, setClearIntruder] = useState(true);
  const [clearWordlists, setClearWordlists] = useState(false);
  const [clearCurated, setClearCurated] = useState(false);
  const [systemStats, setSystemStats] = useState<Record<string, number> | null>(null);

  const clearCapturedData = useFlowStore((s) => s.clearCapturedData);

  const [replayMethod, setReplayMethod] = useState('GET');
  const [replayUrl, setReplayUrl] = useState('https://');
  const [replayBody, setReplayBody] = useState('');
  const [isReplaying, setIsReplaying] = useState(false);

  const navTabs: { id: ActiveView; label: string; icon: React.ReactNode }[] = [
    { id: 'cockpit', label: 'Operator Cockpit', icon: <Zap className="w-4 h-4 text-amber-400" /> },
    { id: 'stream', label: 'Live Stream', icon: <Activity className="w-4 h-4" /> },
    { id: 'findings', label: 'Findings', icon: <ShieldAlert className="w-4 h-4 text-rose-400" /> },
    { id: 'dossier', label: 'Target Dossier', icon: <Layers className="w-4 h-4" /> },
    { id: 'matrix', label: 'Test Matrix', icon: <Zap className="w-4 h-4" /> },
    { id: 'diff', label: 'Diff Viewer', icon: <GitCompare className="w-4 h-4" /> },
    { id: 'graph', label: 'Flow Graph', icon: <Network className="w-4 h-4" /> },
    { id: 'rules', label: 'Rule Engine', icon: <SlidersHorizontal className="w-4 h-4" /> },
    { id: 'intruder', label: 'Intruder', icon: <Crosshair className="w-4 h-4 text-rose-400" /> },
  ];


  const handleReplaySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsReplaying(true);
    try {
      await api.replayRequest({
        method: replayMethod,
        url: replayUrl,
        body: replayBody || null,
      });
      setIsReplayModalOpen(false);
    } catch (err: any) {
      alert(`Replay failed: ${err.message}`);
    } finally {
      setIsReplaying(false);
    }
  };

  const handleClear = async () => {
    setIsClearing(true);
    try {
      await clearCapturedData({
        flows: clearFlows,
        endpoints: clearEndpoints,
        proposals: clearProposals,
        intruder_jobs: clearIntruder,
        wordlists: clearWordlists,
        curated_payloads: clearCurated,
      });
      setIsClearModalOpen(false);
      setConfirmText('');
    } catch (err: any) {
      alert(`Clear failed: ${err.message}`);
    } finally {
      setIsClearing(false);
    }
  };

  const openClearModal = async () => {
    setConfirmText('');
    setIsClearModalOpen(true);
    try {
      const stats = await api.getSystemStats();
      setSystemStats(stats);
    } catch {
      setSystemStats(null);
    }
  };

  const anyChecked = clearFlows || clearEndpoints || clearProposals || clearIntruder || clearWordlists || clearCurated;

  const handleLaunchBrowser = async () => {
    setIsLaunchingBrowser(true);
    try {
      await api.launchBrowser();
    } catch (err: any) {
      alert(`Could not launch browser: ${err.message}`);
    } finally {
      setIsLaunchingBrowser(false);
    }
  };

  return (

    <>
      <header className="h-14 bg-surface border-b border-border px-4 flex items-center justify-between select-none z-30">
        {/* Left Section: Logo & Connection Badge */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-600 to-sky-400 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <span className="font-bold tracking-tight text-white font-mono text-base">
                FLOW<span className="text-primary">FORGE</span>
              </span>
              <span className="text-[10px] text-slate-400 font-mono ml-1.5 px-1 py-0.5 rounded bg-slate-800 border border-slate-700">
                v1.0 MITM
              </span>
            </div>
          </div>

          {/* WebSocket Live Status */}
          <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs font-mono">
            <span
              className={`w-2 h-2 rounded-full ${
                wsConnected ? 'bg-emerald-400 animate-pulse shadow-sm shadow-emerald-400' : 'bg-rose-500'
              }`}
            />
            <span className={wsConnected ? 'text-slate-300' : 'text-rose-400'}>
              {wsConnected ? `Live (${wsLatencyMs}ms)` : 'Disconnected'}
            </span>
          </div>

          {/* Security Findings Summary Counters */}
          <div className="hidden lg:flex items-center gap-1.5 text-xs font-mono">
            <div 
              className="px-2 py-0.5 rounded bg-yellow-500/10 border border-yellow-500/30 text-yellow-300 flex items-center gap-1 cursor-pointer hover:bg-yellow-500/20"
              onClick={() => {
                setActiveView('stream');
                setFilters({ tags: ['reflection'] });
              }}
              title="Reflected Parameters"
            >
              <Sparkles className="w-3 h-3 text-yellow-400" />
              <span>{stats.reflectionsCount} Reflections</span>
            </div>

            <div 
              className="px-2 py-0.5 rounded bg-orange-500/10 border border-orange-500/30 text-orange-300 flex items-center gap-1 cursor-pointer hover:bg-orange-500/20"
              onClick={() => {
                setActiveView('stream');
                setFilters({ tags: ['idor'] });
              }}
              title="High Risk IDOR Identifiers"
            >
              <span className="font-bold">⚡</span>
              <span>{stats.idorCount} IDORs</span>
            </div>

            {stats.authAnomaliesCount > 0 && (
              <div 
                className="px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-300 flex items-center gap-1 cursor-pointer hover:bg-purple-500/20"
                onClick={() => {
                  setActiveView('stream');
                  setFilters({ tags: ['auth_anomaly'] });
                }}
                title="Authentication State Deviations"
              >
                <span>🔒</span>
                <span>{stats.authAnomaliesCount} Auth Deviations</span>
              </div>
            )}

            {/* Auto-Proposals Notification Badge & 1-Click Filter Toggle */}
            {pendingProposalsCount > 0 && (
              <div className="flex items-center gap-1.5 ml-1">
                <button
                  onClick={() => toggleApprovalDrawer(true, null)}
                  className="px-2.5 py-1 rounded-lg bg-gradient-to-r from-amber-500/20 via-orange-500/20 to-amber-500/20 hover:from-amber-500/30 hover:to-orange-500/30 text-amber-300 border border-amber-500/50 text-xs font-mono font-bold flex items-center gap-1.5 transition-all shadow-md shadow-amber-500/20 animate-pulse hover:scale-105"
                  title="Open Operator Approval Drawer"
                >
                  <span>⚡</span>
                  <span>{pendingProposalsCount} Auto-Proposals</span>
                </button>

                <button
                  onClick={() => setFilterOnlyWithProposals(!filterOnlyWithProposals)}
                  className={`p-1.5 rounded-lg border text-xs transition-all ${
                    filterOnlyWithProposals
                      ? 'bg-amber-500 text-slate-950 border-amber-400 font-bold shadow-md shadow-amber-500/30'
                      : 'bg-slate-800 text-slate-400 hover:text-amber-300 border-slate-700'
                  }`}
                  title="1-Click Filter: Show only flows with staged proposals"
                >
                  <Filter className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Center: Search & View Tabs */}
        <div className="flex items-center gap-3">
          {/* Global Search Bar */}
          <div className="relative w-64 md:w-80">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search url, method:POST, 200..."
              value={filters.search}
              onChange={(e) => setFilters({ search: e.target.value })}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-700/80 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-primary transition-colors"
            />
          </div>

          {/* Navigation View Tabs */}
          <nav className="flex items-center bg-slate-900/80 p-1 rounded-lg border border-slate-800">
            {navTabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveView(tab.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  activeView === tab.id
                    ? 'bg-primary text-slate-950 font-semibold shadow-md shadow-primary/20'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                {tab.icon}
                <span>{tab.label}</span>
              </button>
            ))}
          </nav>
        </div>

        {/* Right Section: Stream & Quick Actions */}
        <div className="flex items-center gap-2">
          {/* 1-Click Launch Intercept Browser */}
          <button
            onClick={handleLaunchBrowser}
            disabled={isLaunchingBrowser}
            className="px-2.5 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-xs font-medium flex items-center gap-1.5 transition-colors shadow-sm shadow-cyan-500/10"
            title="Launch pre-configured isolated Chromium browser (no manual proxy or cert setup required)"
          >
            <Globe className={`w-3.5 h-3.5 ${isLaunchingBrowser ? 'animate-spin' : 'text-cyan-400'}`} />
            <span className="hidden sm:inline">Open Browser</span>
          </button>

          {/* Pause / Resume */}

          <button
            onClick={() => setPaused(!isPaused)}
            className={`p-2 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-colors ${
              isPaused
                ? 'bg-amber-500/20 border-amber-500/40 text-amber-300 hover:bg-amber-500/30'
                : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
            }`}
            title={isPaused ? 'Resume live capture' : 'Pause live capture'}
          >
            {isPaused ? <Play className="w-3.5 h-3.5 text-amber-400" /> : <Pause className="w-3.5 h-3.5" />}
            <span className="hidden sm:inline">{isPaused ? 'Paused' : 'Capturing'}</span>
          </button>

          {/* Clear Stream */}
          <button
            onClick={openClearModal}
            className="p-2 rounded-lg bg-slate-800 hover:bg-rose-500/20 text-slate-400 hover:text-rose-300 border border-slate-700 hover:border-rose-500/40 transition-colors"
            title="Clear captured data (select categories)"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>

          {/* Replay Custom Request */}
          <button
            onClick={() => setIsReplayModalOpen(true)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-medium flex items-center gap-1.5 transition-colors"
            title="Compose and send custom request"
          >
            <Send className="w-3.5 h-3.5 text-primary" />
            <span className="hidden sm:inline">Replay</span>
          </button>

          {/* Download Root CA */}
          <a
            href="/api/v1/ca/cert.pem"
            download="flowforge-ca.pem"
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700 transition-colors"
            title="Download FlowForge Root CA Certificate (.pem)"
          >
            <Download className="w-3.5 h-3.5" />
          </a>
        </div>
      </header>

      {/* Selective Clear Data Dialog */}
      <Modal
        isOpen={isClearModalOpen}
        onClose={() => { setIsClearModalOpen(false); setConfirmText(''); }}
        title="Clear Captured Data"
      >
        <div className="space-y-4">
          <p className="text-xs text-slate-300 font-mono leading-relaxed">
            Select which data categories to clear. This cannot be undone.
          </p>

          {/* Category checkboxes with row counts */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-2.5">
            <label className="flex items-center gap-3 text-xs font-mono text-slate-300 cursor-pointer hover:text-slate-100">
              <input
                type="checkbox"
                checked={clearFlows}
                onChange={(e) => setClearFlows(e.target.checked)}
                className="accent-rose-500"
              />
              <span className="flex-1">Captured Flows &amp; WebSocket Messages</span>
              {systemStats && (
                <span className="text-slate-500 tabular-nums">
                  {(systemStats.flows || 0).toLocaleString()} flows, {(systemStats.websocket_messages || 0).toLocaleString()} WS msgs
                </span>
              )}
            </label>

            <label className="flex items-center gap-3 text-xs font-mono text-slate-300 cursor-pointer hover:text-slate-100">
              <input
                type="checkbox"
                checked={clearEndpoints}
                onChange={(e) => setClearEndpoints(e.target.checked)}
                className="accent-rose-500"
              />
              <span className="flex-1">Discovered Endpoints &amp; Parameters</span>
              {systemStats && (
                <span className="text-slate-500 tabular-nums">
                  {(systemStats.endpoints || 0).toLocaleString()} endpoints, {(systemStats.parameters || 0).toLocaleString()} params
                </span>
              )}
            </label>

            <label className="flex items-center gap-3 text-xs font-mono text-slate-300 cursor-pointer hover:text-slate-100">
              <input
                type="checkbox"
                checked={clearProposals}
                onChange={(e) => setClearProposals(e.target.checked)}
                className="accent-rose-500"
              />
              <span className="flex-1">Auto-Proposals &amp; Findings</span>
              {systemStats && (
                <span className="text-slate-500 tabular-nums">
                  {(systemStats.proposals || 0).toLocaleString()} proposals
                </span>
              )}
            </label>

            <label className="flex items-center gap-3 text-xs font-mono text-slate-300 cursor-pointer hover:text-slate-100">
              <input
                type="checkbox"
                checked={clearIntruder}
                onChange={(e) => setClearIntruder(e.target.checked)}
                className="accent-rose-500"
              />
              <span className="flex-1">Intruder Jobs &amp; Results</span>
              {systemStats && (
                <span className="text-slate-500 tabular-nums">
                  {(systemStats.intruder_jobs || 0).toLocaleString()} jobs, {(systemStats.intruder_results || 0).toLocaleString()} results
                </span>
              )}
            </label>

            <label className="flex items-center gap-3 text-xs font-mono text-slate-300 cursor-pointer hover:text-slate-100">
              <input
                type="checkbox"
                checked={clearWordlists}
                onChange={(e) => setClearWordlists(e.target.checked)}
                className="accent-rose-500"
              />
              <span className="flex-1">Uploaded Wordlists</span>
              {systemStats && (
                <span className="text-slate-500 tabular-nums">
                  {(systemStats.custom_wordlists || 0).toLocaleString()} wordlists
                </span>
              )}
            </label>

            <label className="flex items-center gap-3 text-xs font-mono text-slate-300 cursor-pointer hover:text-slate-100">
              <input
                type="checkbox"
                checked={clearCurated}
                onChange={(e) => setClearCurated(e.target.checked)}
                className="accent-rose-500"
              />
              <span className="flex-1">Curated Payloads &amp; Groups</span>
              <span className="text-slate-500">in-memory</span>
            </label>
          </div>

          {/* Typing confirmation */}
          {anyChecked && (
            <div className="space-y-1.5">
              <label className="text-xs font-mono text-slate-400">
                Type <span className="text-rose-400 font-bold">CLEAR</span> to confirm:
              </label>
              <input
                type="text"
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
                placeholder="Type CLEAR"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-rose-500"
              />
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
            <button
              onClick={() => { setIsClearModalOpen(false); setConfirmText(''); }}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
            >
              Cancel
            </button>
            <button
              onClick={handleClear}
              disabled={isClearing || !anyChecked || confirmText !== 'CLEAR'}
              className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-semibold flex items-center gap-1.5"
            >
              <Trash2 className="w-3.5 h-3.5" />
              {isClearing ? 'Clearing…' : 'Clear Selected'}
            </button>
          </div>
        </div>
      </Modal>

      {/* Manual Request Replay Modal */}
      <Modal
        isOpen={isReplayModalOpen}
        onClose={() => setIsReplayModalOpen(false)}
        title="Compose & Replay HTTP Request"
      >
        <form onSubmit={handleReplaySubmit} className="space-y-4">
          <div className="flex gap-2">
            <select
              value={replayMethod}
              onChange={(e) => setReplayMethod(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono font-bold text-primary focus:outline-none"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
              <option value="PATCH">PATCH</option>
            </select>
            <input
              type="text"
              required
              value={replayUrl}
              onChange={(e) => setReplayUrl(e.target.value)}
              placeholder="https://api.target.com/api/v1/orders"
              className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Request Body (JSON / Text)
            </label>
            <textarea
              rows={6}
              value={replayBody}
              onChange={(e) => setReplayBody(e.target.value)}
              placeholder='{"order_id": 1002, "reason": "test"}'
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-primary"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsReplayModalOpen(false)}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isReplaying}
              className="px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-slate-950 text-xs font-semibold flex items-center gap-1.5"
            >
              {isReplaying ? <span className="animate-spin">⏳</span> : <Send className="w-3.5 h-3.5" />}
              <span>Send Request</span>
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
};
