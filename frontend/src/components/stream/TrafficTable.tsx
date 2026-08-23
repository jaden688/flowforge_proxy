import React from 'react';
import { useFlowStore } from '../../store/flowStore';
import { FlowRecord, HttpMethod } from '../../types';
import { Badge } from '../common/Badge';
import { Sparkles, ShieldCheck, Zap, Key, ArrowUpDown } from 'lucide-react';

export const TrafficTable: React.FC = () => {
  const flows = useFlowStore((s) => s.flows);
  const flowOrder = useFlowStore((s) => s.flowOrder);
  const selectedFlowId = useFlowStore((s) => s.selectedFlowId);
  const selectFlow = useFlowStore((s) => s.selectFlow);
  const filters = useFlowStore((s) => s.filters);
  const setFilters = useFlowStore((s) => s.setFilters);

  // Proposal state and actions
  const proposals = useFlowStore((s) => s.proposals);
  const filterOnlyWithProposals = useFlowStore((s) => s.filterOnlyWithProposals);
  const setFilterOnlyWithProposals = useFlowStore((s) => s.setFilterOnlyWithProposals);
  const toggleApprovalDrawer = useFlowStore((s) => s.toggleApprovalDrawer);

  // Filter flows
  const filteredFlows = flowOrder
    .map((id) => flows[id])
    .filter((flow): flow is FlowRecord => {
      if (!flow) return false;

      // Filter only flows with staged proposals
      if (filterOnlyWithProposals) {
        const hasStagedProposals = Object.values(proposals).some(
          (p) => p.flow_id === flow.id && (p.status === 'PENDING' || p.status === 'APPROVED' || p.status === 'EXECUTING')
        );
        if (!hasStagedProposals) return false;
      }

      // Method filter
      if (filters.methods.length && !filters.methods.includes(flow.method)) {
        return false;
      }

      // Status group filter
      if (filters.statusGroup !== 'all' && flow.response_status) {
        const status = flow.response_status;
        if (filters.statusGroup === '2xx' && (status < 200 || status >= 300)) return false;
        if (filters.statusGroup === '3xx' && (status < 300 || status >= 400)) return false;
        if (filters.statusGroup === '4xx' && (status < 400 || status >= 500)) return false;
        if (filters.statusGroup === '5xx' && status < 500) return false;
      }

      // Tags filter
      if (filters.tags.length) {
        const flowTags = flow.tags || [];
        const hasMatch = filters.tags.some((t) => flowTags.includes(t));
        if (!hasMatch) return false;
      }

      // Search query
      if (filters.search) {
        const q = filters.search.toLowerCase();
        const matchUrl = flow.url.toLowerCase().includes(q);
        const matchMethod = flow.method.toLowerCase().includes(q);
        const matchStatus = flow.response_status ? String(flow.response_status).includes(q) : false;
        const matchTags = (flow.tags || []).some(t => t.toLowerCase().includes(q));
        if (!matchUrl && !matchMethod && !matchStatus && !matchTags) return false;
      }

      return true;
    });

  const getMethodBadgeVariant = (method: HttpMethod) => {
    switch (method) {
      case 'GET': return 'primary';
      case 'POST': return 'success';
      case 'PUT': return 'warning';
      case 'DELETE': return 'danger';
      case 'PATCH': return 'mutation';
      default: return 'neutral';
    }
  };

  const getStatusColor = (status?: number | null) => {
    if (!status) return 'text-slate-500';
    if (status >= 200 && status < 300) return 'text-emerald-400 font-semibold';
    if (status >= 300 && status < 400) return 'text-sky-400';
    if (status >= 400 && status < 500) return 'text-amber-400 font-semibold';
    return 'text-rose-400 font-bold';
  };

  const availableMethods: HttpMethod[] = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];

  const toggleMethodFilter = (m: HttpMethod) => {
    const active = filters.methods;
    if (active.includes(m)) {
      setFilters({ methods: active.filter((x) => x !== m) });
    } else {
      setFilters({ methods: [...active, m] });
    }
  };

  const toggleTagFilter = (tag: string) => {
    const active = filters.tags;
    if (active.includes(tag)) {
      setFilters({ tags: active.filter((x) => x !== tag) });
    } else {
      setFilters({ tags: [...active, tag] });
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#0A0E17] border-r border-border overflow-hidden">
      {/* Stream Filter Toolbar */}
      <div className="p-2.5 bg-surface/50 border-b border-border flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
        {/* Method Toggles */}
        <div className="flex items-center gap-1">
          <span className="text-slate-500 text-[10px] uppercase font-bold mr-1">Method:</span>
          {availableMethods.map((m) => {
            const isSelected = filters.methods.includes(m);
            return (
              <button
                key={m}
                onClick={() => toggleMethodFilter(m)}
                className={`px-2 py-0.5 rounded font-mono text-[11px] transition-colors ${
                  isSelected
                    ? 'bg-primary text-slate-950 font-bold'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
                }`}
              >
                {m}
              </button>
            );
          })}
        </div>

        {/* Status Group Filter */}
        <div className="flex items-center gap-1">
          <span className="text-slate-500 text-[10px] uppercase font-bold mr-1">Status:</span>
          {(['all', '2xx', '3xx', '4xx', '5xx'] as const).map((sg) => (
            <button
              key={sg}
              onClick={() => setFilters({ statusGroup: sg })}
              className={`px-2 py-0.5 rounded font-mono text-[11px] uppercase transition-colors ${
                filters.statusGroup === sg
                  ? 'bg-slate-200 text-slate-950 font-bold'
                  : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
              }`}
            >
              {sg}
            </button>
          ))}
        </div>

        {/* Triage Tag Quick Filters */}
        <div className="flex items-center gap-1">
          <span className="text-slate-500 text-[10px] uppercase font-bold mr-1">Triage:</span>
          <button
            onClick={() => toggleTagFilter('reflection')}
            className={`px-2 py-0.5 rounded text-[11px] flex items-center gap-1 border ${
              filters.tags.includes('reflection')
                ? 'bg-yellow-500/30 border-yellow-400 text-yellow-200 font-bold'
                : 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/20'
            }`}
          >
            <Sparkles className="w-2.5 h-2.5" />
            <span>Reflections</span>
          </button>

          <button
            onClick={() => toggleTagFilter('idor')}
            className={`px-2 py-0.5 rounded text-[11px] flex items-center gap-1 border ${
              filters.tags.includes('idor')
                ? 'bg-orange-500/30 border-orange-400 text-orange-200 font-bold'
                : 'bg-orange-500/10 border-orange-500/30 text-orange-400 hover:bg-orange-500/20'
            }`}
          >
            <Zap className="w-2.5 h-2.5" />
            <span>IDORs</span>
          </button>

          <button
            onClick={() => toggleTagFilter('auth_anomaly')}
            className={`px-2 py-0.5 rounded text-[11px] flex items-center gap-1 border ${
              filters.tags.includes('auth_anomaly')
                ? 'bg-purple-500/30 border-purple-400 text-purple-200 font-bold'
                : 'bg-purple-500/10 border-purple-500/30 text-purple-400 hover:bg-purple-500/20'
            }`}
          >
            <ShieldCheck className="w-2.5 h-2.5" />
            <span>Auth</span>
          </button>

          {/* Staged Proposals Filter Toggle */}
          <button
            onClick={() => setFilterOnlyWithProposals(!filterOnlyWithProposals)}
            className={`px-2 py-0.5 rounded text-[11px] flex items-center gap-1 border transition-all ${
              filterOnlyWithProposals
                ? 'bg-amber-500/30 border-amber-400 text-amber-200 font-bold shadow-sm shadow-amber-500/20'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-amber-300'
            }`}
            title="Show only flows with staged test proposals"
          >
            <span>⚡</span>
            <span>Proposals Only</span>
          </button>
        </div>
      </div>

      {/* Traffic Table Viewport */}
      <div className="flex-1 overflow-y-auto">
        {filteredFlows.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-slate-500 font-mono text-xs">
            <ArrowUpDown className="w-8 h-8 mb-2 opacity-30 animate-bounce" />
            <span>Waiting for intercepted traffic...</span>
            <span className="text-[11px] text-slate-600 mt-1">Configure your browser/client to proxy through :8080</span>
          </div>
        ) : (
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead className="sticky top-0 bg-[#0E1522] border-b border-border text-slate-400 select-none z-10">
              <tr>
                <th className="py-2 px-3 w-16 text-center">#</th>
                <th className="py-2 px-3 w-20">Method</th>
                <th className="py-2 px-3 w-16">Status</th>
                <th className="py-2 px-3 w-40">Host</th>
                <th className="py-2 px-3">Path</th>
                <th className="py-2 px-3 w-20 text-right">Size</th>
                <th className="py-2 px-3 w-20 text-right">Time</th>
                <th className="py-2 px-3 w-48">Triage Findings</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {filteredFlows.map((flow, index) => {
                const isSelected = selectedFlowId === flow.id;
                const status = flow.response_status || flow.response_status_code;
                const latency = flow.latency_ms || flow.duration_ms;
                const size = (flow as any).response_content_length
                  ?? (flow as any).response?.content_length
                  ?? flow.response_size
                  ?? (flow as any).telemetry?.bandwidth?.response_body_bytes
                  ?? (flow.response_body ? flow.response_body.length : 0);

                const formatSize = (bytes: number | null | undefined) => {
                  if (bytes === undefined || bytes === null || bytes === 0) return '0 B';
                  if (bytes < 1024) return `${bytes} B`;
                  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
                  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
                };

                const reflections = flow.triage?.reflections || [];
                const highIdors = (flow.triage?.identifiers || []).filter(i => i.idor_risk === 'HIGH');
                const authDevs = flow.triage?.auth?.anomaly_flags || [];
                const secrets = flow.triage?.entropy || [];

                const flowProposals = Object.values(proposals).filter(
                  (p) => p.flow_id === flow.id && (p.status === 'PENDING' || p.status === 'APPROVED' || p.status === 'EXECUTING')
                );

                return (
                  <tr
                    key={flow.id}
                    onClick={() => selectFlow(flow.id)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-cyan-950/40 border-l-4 border-l-primary text-slate-100'
                        : 'hover:bg-slate-900/60 text-slate-300'
                    }`}
                  >
                    <td className="py-2 px-3 text-center text-slate-500 text-[11px]">
                      {index + 1}
                    </td>
                    <td className="py-2 px-3">
                      <Badge variant={getMethodBadgeVariant(flow.method)} size="sm">
                        {flow.method}
                      </Badge>
                    </td>
                    <td className="py-2 px-3">
                      <span className={getStatusColor(status)}>
                        {status ? status : '...'}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-400 truncate max-w-[160px]" title={flow.host}>
                      {flow.host}
                    </td>
                    <td className="py-2 px-3 text-slate-200 font-mono truncate max-w-[280px]" title={flow.path}>
                      {flow.path}
                    </td>
                    <td className="py-2 px-3 text-right text-slate-300 font-mono">
                      {formatSize(size)}
                    </td>
                    <td className="py-2 px-3 text-right text-slate-400">
                      {latency ? `${Math.round(latency)}ms` : '-'}
                    </td>
                    <td className="py-2 px-3">
                      <div className="flex flex-wrap items-center gap-1">
                        {flowProposals.length > 0 && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              toggleApprovalDrawer(true, flow.id);
                            }}
                            className="px-2 py-0.5 rounded text-[11px] font-mono font-bold flex items-center gap-1 bg-gradient-to-r from-amber-500/20 via-orange-500/20 to-amber-500/20 text-amber-300 border border-amber-500/50 shadow-md shadow-amber-500/20 hover:shadow-amber-500/40 hover:scale-105 transition-all animate-pulse"
                            title={`Review ${flowProposals.length} auto-generated test proposals for this flow`}
                          >
                            <span>⚡</span>
                            <span>{flowProposals.length} Tests Staged</span>
                          </button>
                        )}
                        {reflections.length > 0 && (
                          <Badge variant="reflection" size="sm">
                            <Sparkles className="w-2.5 h-2.5" />
                            <span>{reflections.length} Refl</span>
                          </Badge>
                        )}
                        {highIdors.length > 0 && (
                          <Badge variant="idor" size="sm">
                            <Zap className="w-2.5 h-2.5" />
                            <span>IDOR</span>
                          </Badge>
                        )}
                        {authDevs.length > 0 && (
                          <Badge variant="danger" size="sm">
                            <ShieldCheck className="w-2.5 h-2.5" />
                            <span>Auth Dev</span>
                          </Badge>
                        )}
                        {secrets.length > 0 && (
                          <Badge variant="warning" size="sm">
                            <Key className="w-2.5 h-2.5" />
                            <span>Secret</span>
                          </Badge>
                        )}
                        {flow.triage?.endpoint_category === 'MUTATION_ACTION' && (
                          <Badge variant="mutation" size="sm">
                            Mutate
                          </Badge>
                        )}
                        {flow.triage?.endpoint_category === 'ADMIN' && (
                          <Badge variant="danger" size="sm">
                            Admin
                          </Badge>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
