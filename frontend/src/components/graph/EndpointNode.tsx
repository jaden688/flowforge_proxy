import React from 'react';
import { GraphNodeData } from '../../types';
import { Badge } from '../common/Badge';
import { 
  Sparkles, 
  ShieldAlert, 
  Lock, 
  Layers, 
  Activity, 
  ArrowUpRight,
  ExternalLink
} from 'lucide-react';

interface EndpointNodeProps {
  node: GraphNodeData;
  isSelected: boolean;
  onSelect: (node: GraphNodeData) => void;
  onNavigateDossier: (dossierKey: string) => void;
  onDragStart?: (e: React.MouseEvent, node: GraphNodeData) => void;
}

export const EndpointNode: React.FC<EndpointNodeProps> = ({
  node,
  isSelected,
  onSelect,
  onNavigateDossier,
  onDragStart,
}) => {
  const getMethodBadgeVariant = (m: string) => {
    switch (m) {
      case 'GET': return 'primary';
      case 'POST': return 'success';
      case 'PUT': return 'warning';
      case 'DELETE': return 'danger';
      case 'PATCH': return 'mutation';
      default: return 'outline';
    }
  };

  const getRiskBorderGlow = () => {
    if (node.riskScore >= 80 || node.idorRisk === 'HIGH') {
      return 'border-rose-500 shadow-lg shadow-rose-500/20 ring-1 ring-rose-500/50';
    }
    if (node.reflectionsCount > 0) {
      return 'border-yellow-500 shadow-md shadow-yellow-500/10 ring-1 ring-yellow-500/40';
    }
    if (node.authPresent) {
      return 'border-purple-500/80 shadow-md shadow-purple-500/10 ring-1 ring-purple-500/40';
    }
    return 'border-slate-700/80 hover:border-cyan-500/60';
  };

  const getRiskScoreBadge = () => {
    if (node.riskScore >= 80) {
      return (
        <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
          Risk: {node.riskScore}
        </span>
      );
    }
    if (node.riskScore >= 40) {
      return (
        <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-yellow-500/20 text-yellow-300 border border-yellow-500/40">
          Risk: {node.riskScore}
        </span>
      );
    }
    return (
      <span className="px-1.5 py-0.2 rounded text-[10px] text-slate-400 bg-slate-800 border border-slate-700">
        Risk: {node.riskScore}
      </span>
    );
  };

  return (
    <div
      onClick={(e) => {
        e.stopPropagation();
        onSelect(node);
      }}
      onMouseDown={(e) => {
        if (onDragStart) onDragStart(e, node);
      }}
      style={{
        transform: `translate(${node.x || 0}px, ${node.y || 0}px)`,
        position: 'absolute',
      }}
      className={`w-64 bg-[#0F172A] rounded-xl border p-3 cursor-pointer select-none transition-all font-mono text-xs ${getRiskBorderGlow()} ${
        isSelected ? 'ring-2 ring-primary bg-slate-900 shadow-2xl scale-[1.02]' : 'hover:bg-slate-900/90'
      }`}
    >
      {/* Node Header */}
      <div className="flex items-center justify-between gap-1.5 mb-1.5">
        <div className="flex items-center gap-1.5">
          <Badge variant={getMethodBadgeVariant(node.method)} size="sm">
            {node.method}
          </Badge>
          <span className="text-[10px] text-slate-400 truncate max-w-[90px]" title={node.host}>
            {node.host}
          </span>
        </div>

        <div className="flex items-center gap-1">
          {getRiskScoreBadge()}
          <button
            onClick={(e) => {
              e.stopPropagation();
              onNavigateDossier(node.dossierKey);
            }}
            className="p-1 rounded bg-slate-800 hover:bg-cyan-500/20 text-slate-400 hover:text-cyan-300 transition-colors"
            title="Open Target Dossier"
          >
            <ExternalLink className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Path Display */}
      <div className="mb-2">
        <span className="font-bold text-slate-100 text-xs break-all line-clamp-2" title={node.path}>
          {node.path}
        </span>
      </div>

      {/* Security Finding Pills */}
      <div className="flex flex-wrap items-center gap-1">
        {node.reflectionsCount > 0 && (
          <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-yellow-500/10 text-yellow-300 border border-yellow-500/30 flex items-center gap-1">
            <Sparkles className="w-2.5 h-2.5 text-yellow-400" />
            <span>{node.reflectionsCount} Refl</span>
          </span>
        )}

        {node.idorRisk === 'HIGH' && (
          <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 flex items-center gap-1">
            <ShieldAlert className="w-2.5 h-2.5 text-rose-400" />
            <span>IDOR High</span>
          </span>
        )}

        {node.authPresent && (
          <span className="px-1.5 py-0.2 rounded text-[10px] bg-purple-500/10 text-purple-300 border border-purple-500/30 flex items-center gap-1">
            <Lock className="w-2.5 h-2.5 text-purple-400" />
            <span>Auth</span>
          </span>
        )}

        <span className="ml-auto text-[10px] text-slate-500 flex items-center gap-0.5 font-mono">
          <Activity className="w-2.5 h-2.5" />
          <span>{node.callCount}x</span>
        </span>
      </div>
    </div>
  );
};
