import React from 'react';
import { FlowComparisonResult } from '../../types';
import { Badge } from '../common/Badge';
import { Activity, ArrowRight, HardDrive, Clock, Sparkles } from 'lucide-react';

interface DeltaMetricsBarProps {
  comparison: FlowComparisonResult;
}

export const DeltaMetricsBar: React.FC<DeltaMetricsBarProps> = ({ comparison }) => {
  const {
    status_match,
    status_delta,
    length_delta_bytes,
    length_delta_percent,
    latency_delta_ms,
    flow_a,
    flow_b,
  } = comparison;

  const lenA = flow_a.response_size || (flow_a.response_body ? flow_a.response_body.length : 0);
  const lenB = flow_b.response_size || (flow_b.response_body ? flow_b.response_body.length : 0);

  const reflectionsA = flow_a.triage?.reflections?.length || 0;
  const reflectionsB = flow_b.triage?.reflections?.length || 0;

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs select-none">
      {/* HTTP Status Delta */}
      <div className="p-3 bg-[#0A0E17] border border-border rounded-lg flex items-center justify-between">
        <div>
          <span className="text-slate-500 text-[10px] uppercase font-bold block mb-1">
            HTTP Status Delta
          </span>
          <div className="flex items-center gap-1.5 font-bold text-slate-200">
            <span className={flow_a.response_status === 200 ? 'text-emerald-400' : 'text-amber-400'}>
              {flow_a.response_status || 200}
            </span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span className={flow_b.response_status === 200 ? 'text-emerald-400' : 'text-amber-400'}>
              {flow_b.response_status || 200}
            </span>
          </div>
        </div>
        <Badge variant={status_match ? 'neutral' : 'warning'} size="sm">
          {status_match ? 'MATCH' : 'CHANGED'}
        </Badge>
      </div>

      {/* Response Size Delta */}
      <div className="p-3 bg-[#0A0E17] border border-border rounded-lg flex items-center justify-between">
        <div>
          <span className="text-slate-500 text-[10px] uppercase font-bold block mb-1">
            Body Length Delta
          </span>
          <div className="flex items-center gap-1.5 font-bold text-slate-200">
            <span>{lenA} B</span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span className={length_delta_bytes !== 0 ? 'text-cyan-400' : 'text-slate-300'}>
              {lenB} B
            </span>
          </div>
        </div>
        <Badge
          variant={Math.abs(length_delta_bytes) > 200 ? 'idor' : 'neutral'}
          size="sm"
        >
          {length_delta_bytes >= 0 ? `+${length_delta_bytes} B` : `${length_delta_bytes} B`}
          {length_delta_percent ? ` (${length_delta_percent > 0 ? '+' : ''}${length_delta_percent}%)` : ''}
        </Badge>
      </div>

      {/* Latency Delta */}
      <div className="p-3 bg-[#0A0E17] border border-border rounded-lg flex items-center justify-between">
        <div>
          <span className="text-slate-500 text-[10px] uppercase font-bold block mb-1">
            Latency Delta
          </span>
          <div className="flex items-center gap-1.5 font-bold text-slate-200">
            <span>{Math.round(flow_a.latency_ms || 30)}ms</span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span>{Math.round(flow_b.latency_ms || 35)}ms</span>
          </div>
        </div>
        <Badge variant="neutral" size="sm">
          {latency_delta_ms >= 0 ? `+${latency_delta_ms}ms` : `${latency_delta_ms}ms`}
        </Badge>
      </div>

      {/* Reflections Delta */}
      <div className="p-3 bg-[#0A0E17] border border-border rounded-lg flex items-center justify-between">
        <div>
          <span className="text-slate-500 text-[10px] uppercase font-bold block mb-1">
            Reflected Inputs
          </span>
          <div className="flex items-center gap-1.5 font-bold text-slate-200">
            <span>{reflectionsA}</span>
            <ArrowRight className="w-3 h-3 text-slate-600" />
            <span className={reflectionsB > 0 ? 'text-yellow-400' : 'text-slate-300'}>
              {reflectionsB}
            </span>
          </div>
        </div>
        <Badge variant={reflectionsB > 0 ? 'reflection' : 'neutral'} size="sm">
          <Sparkles className="w-2.5 h-2.5" />
          <span>{reflectionsB > 0 ? 'Reflected' : 'Clean'}</span>
        </Badge>
      </div>
    </div>
  );
};
