import React, { useState } from 'react';
import { useFlowStore } from '../../store/flowStore';
import { EndpointDossier, HttpMethod } from '../../types';
import { Badge } from '../common/Badge';
import { ChevronDown, ChevronRight, Globe, Layers, Search } from 'lucide-react';

interface EndpointTreeProps {
  dossiers: EndpointDossier[];
  selectedKey: string | null;
  onSelect: (key: string) => void;
}

export const EndpointTree: React.FC<EndpointTreeProps> = ({
  dossiers,
  selectedKey,
  onSelect,
}) => {
  const [search, setSearch] = useState('');
  const [expandedHosts, setExpandedHosts] = useState<Record<string, boolean>>({});

  // Group by Host
  const grouped: Record<string, EndpointDossier[]> = {};
  dossiers.forEach((d) => {
    if (!grouped[d.host]) grouped[d.host] = [];
    grouped[d.host].push(d);
  });

  const toggleHost = (host: string) => {
    setExpandedHosts((prev) => ({
      ...prev,
      [host]: prev[host] === undefined ? false : !prev[host],
    }));
  };

  const getMethodBadgeVariant = (m: HttpMethod) => {
    switch (m) {
      case 'GET': return 'primary';
      case 'POST': return 'success';
      case 'PUT': return 'warning';
      case 'DELETE': return 'danger';
      case 'PATCH': return 'mutation';
      default: return 'neutral';
    }
  };

  return (
    <div className="h-full flex flex-col bg-[#0A0E17] border-r border-border font-mono text-xs overflow-hidden">
      {/* Search Bar */}
      <div className="p-3 bg-surface/50 border-b border-border">
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Filter host / path..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded-md text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-primary"
          />
        </div>
      </div>

      {/* Host / Endpoint List */}
      <div className="flex-1 overflow-y-auto p-2 space-y-2">
        {Object.keys(grouped).length === 0 ? (
          <div className="p-6 text-center text-slate-500 text-xs">
            No endpoints cataloged yet. Send traffic to start building the dossier.
          </div>
        ) : (
          Object.entries(grouped).map(([host, hostDossiers]) => {
            const isExpanded = expandedHosts[host] !== false; // Default true

            const filteredDossiers = hostDossiers.filter((d) => {
              if (!search) return true;
              return (
                d.host.toLowerCase().includes(search.toLowerCase()) ||
                d.path_template.toLowerCase().includes(search.toLowerCase())
              );
            });

            if (filteredDossiers.length === 0) return null;

            return (
              <div key={host} className="bg-slate-900/40 rounded-lg border border-border/60 overflow-hidden">
                {/* Host Group Header */}
                <button
                  onClick={() => toggleHost(host)}
                  className="w-full p-2 bg-slate-900/80 hover:bg-slate-800 flex items-center justify-between text-left transition-colors"
                >
                  <div className="flex items-center gap-2 overflow-hidden">
                    {isExpanded ? (
                      <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                    ) : (
                      <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
                    )}
                    <Globe className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
                    <span className="font-bold text-slate-200 truncate">{host}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 px-1.5 py-0.5 rounded bg-slate-800">
                    {filteredDossiers.length}
                  </span>
                </button>

                {/* Endpoint Subnodes */}
                {isExpanded && (
                  <div className="divide-y divide-border/30">
                    {filteredDossiers.map((d) => {
                      const key = `${d.host}::${d.path_template}`;
                      const isSelected = selectedKey === key;

                      return (
                        <button
                          key={key}
                          onClick={() => onSelect(key)}
                          className={`w-full p-2 text-left flex items-center justify-between gap-2 transition-colors ${
                            isSelected
                              ? 'bg-cyan-950/50 text-cyan-300 border-l-2 border-primary font-semibold'
                              : 'hover:bg-slate-800/50 text-slate-400'
                          }`}
                        >
                          <div className="flex items-center gap-2 truncate">
                            <Badge variant={getMethodBadgeVariant(d.methods[0] || 'GET')} size="sm">
                              {d.methods[0] || 'GET'}
                            </Badge>
                            <span className="truncate text-[11px] text-slate-200" title={d.path_template}>
                              {d.path_template}
                            </span>
                          </div>

                          <div className="flex items-center gap-1 flex-shrink-0">
                            {d.primary_category === 'MUTATION_ACTION' && (
                              <span className="w-1.5 h-1.5 rounded-full bg-purple-400" title="Mutation Endpoint" />
                            )}
                            {d.primary_category === 'ADMIN' && (
                              <span className="w-1.5 h-1.5 rounded-full bg-rose-400" title="Admin Endpoint" />
                            )}
                            {d.parameters.some(p => p.idor_risk === 'HIGH') && (
                              <span className="w-1.5 h-1.5 rounded-full bg-orange-400" title="High IDOR Risk" />
                            )}
                            <span className="text-[10px] text-slate-500">
                              {d.parameters.length}p
                            </span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
