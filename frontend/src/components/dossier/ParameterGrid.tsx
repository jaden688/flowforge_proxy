import React from 'react';
import { ParameterCatalogItem } from '../../types';
import { Badge } from '../common/Badge';
import { Sparkles, Zap, CheckCircle2 } from 'lucide-react';

interface ParameterGridProps {
  parameters: ParameterCatalogItem[];
}

export const ParameterGrid: React.FC<ParameterGridProps> = ({ parameters }) => {
  if (!parameters || parameters.length === 0) {
    return (
      <div className="p-8 text-center text-slate-500 font-mono text-xs bg-[#0A0E17] border border-border rounded-lg">
        No parameters observed for this endpoint yet.
      </div>
    );
  }

  const getLocationBadgeVariant = (loc: string) => {
    switch (loc) {
      case 'path': return 'primary';
      case 'query': return 'warning';
      case 'body': return 'success';
      case 'header': return 'mutation';
      default: return 'neutral';
    }
  };

  return (
    <div className="bg-[#0A0E17] border border-border rounded-lg overflow-hidden font-mono text-xs">
      <div className="p-3 bg-surface/60 border-b border-border flex items-center justify-between">
        <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
          Aggregated Parameter Catalog ({parameters.length} total)
        </h4>
        <span className="text-[11px] text-slate-400">
          Synthesized from observed traffic flows
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead className="bg-[#0E1522] border-b border-border text-slate-400 select-none">
            <tr>
              <th className="py-2.5 px-3 w-36">Param Name</th>
              <th className="py-2.5 px-3 w-20">Location</th>
              <th className="py-2.5 px-3 w-32">Inferred Type</th>
              <th className="py-2.5 px-3">Observed Sample Values</th>
              <th className="py-2.5 px-3 w-32 text-center">Triage Indicators</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/40">
            {parameters.map((param, idx) => (
              <tr key={idx} className="hover:bg-slate-900/60 transition-colors">
                <td className="py-2.5 px-3 font-semibold text-cyan-300">
                  {param.name}
                  {param.required && (
                    <span className="text-rose-400 ml-1 text-xs" title="Observed in all calls">*</span>
                  )}
                </td>
                <td className="py-2.5 px-3">
                  <Badge variant={getLocationBadgeVariant(param.location)} size="sm">
                    {param.location}
                  </Badge>
                </td>
                <td className="py-2.5 px-3">
                  <span className="text-slate-300 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                    {param.inferred_type}
                    {param.id_type && ` (${param.id_type})`}
                  </span>
                </td>
                <td className="py-2.5 px-3">
                  <div className="flex flex-wrap items-center gap-1 max-w-md">
                    {param.sample_values?.slice(0, 5).map((val, vIdx) => (
                      <span
                        key={vIdx}
                        className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 text-[11px] truncate max-w-[120px]"
                        title={String(val)}
                      >
                        {String(val)}
                      </span>
                    ))}
                    {param.sample_values?.length > 5 && (
                      <span className="text-slate-500 text-[10px]">
                        +{param.sample_values.length - 5} more
                      </span>
                    )}
                  </div>
                </td>
                <td className="py-2.5 px-3 text-center">
                  <div className="flex items-center justify-center gap-1">
                    {param.idor_risk === 'HIGH' && (
                      <Badge variant="idor" size="sm">
                        <Zap className="w-2.5 h-2.5" />
                        <span>HIGH IDOR</span>
                      </Badge>
                    )}
                    {param.reflections_count > 0 && (
                      <Badge variant="reflection" size="sm">
                        <Sparkles className="w-2.5 h-2.5" />
                        <span>{param.reflections_count} Refl</span>
                      </Badge>
                    )}
                    {param.idor_risk === 'NONE' && param.reflections_count === 0 && (
                      <span className="text-slate-500 text-[10px] flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                        Normal
                      </span>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
