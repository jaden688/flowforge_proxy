import React from 'react';
import { AnomalyVerdict } from '../../types';
import { ShieldAlert, AlertTriangle, Sparkles, CheckCircle2 } from 'lucide-react';

interface AnomalyBannerProps {
  verdict: AnomalyVerdict;
}

export const AnomalyBanner: React.FC<AnomalyBannerProps> = ({ verdict }) => {
  const { level, description } = verdict;

  if (level === 'IDENTICAL') {
    return (
      <div className="p-3 bg-slate-900/60 border border-border rounded-lg flex items-center gap-2.5 font-mono text-xs text-slate-400">
        <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
        <span>{description}</span>
      </div>
    );
  }

  if (level === 'CRITICAL_IDOR') {
    return (
      <div className="p-3.5 bg-rose-500/15 border-2 border-rose-500/50 rounded-xl flex items-center justify-between gap-3 font-mono text-xs shadow-lg shadow-rose-500/10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-rose-500/30 text-rose-300">
            <ShieldAlert className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <span className="font-bold text-rose-200 text-sm block">
              CRITICAL IDOR VULNERABILITY DETECTED
            </span>
            <p className="text-rose-300 text-xs mt-0.5">{description}</p>
          </div>
        </div>
        <span className="px-2.5 py-1 rounded bg-rose-500 text-slate-950 font-bold text-xs">
          HIGH SEVERITY
        </span>
      </div>
    );
  }

  if (level === 'AUTH_BYPASS') {
    return (
      <div className="p-3.5 bg-purple-500/15 border-2 border-purple-500/50 rounded-xl flex items-center justify-between gap-3 font-mono text-xs shadow-lg shadow-purple-500/10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-purple-500/30 text-purple-300">
            <AlertTriangle className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <span className="font-bold text-purple-200 text-sm block">
              POTENTIAL AUTHENTICATION BYPASS DETECTED
            </span>
            <p className="text-purple-300 text-xs mt-0.5">{description}</p>
          </div>
        </div>
        <span className="px-2.5 py-1 rounded bg-purple-500 text-slate-950 font-bold text-xs">
          HIGH SEVERITY
        </span>
      </div>
    );
  }

  if (level === 'HIGH_REFLECTION') {
    return (
      <div className="p-3.5 bg-yellow-500/15 border-2 border-yellow-500/50 rounded-xl flex items-center justify-between gap-3 font-mono text-xs shadow-lg shadow-yellow-500/10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-yellow-500/30 text-yellow-300">
            <Sparkles className="w-5 h-5 text-yellow-400" />
          </div>
          <div>
            <span className="font-bold text-yellow-200 text-sm block">
              PAYLOAD REFLECTION DETECTED IN RESPONSE
            </span>
            <p className="text-yellow-300 text-xs mt-0.5">{description}</p>
          </div>
        </div>
        <span className="px-2.5 py-1 rounded bg-yellow-500 text-slate-950 font-bold text-xs">
          XSS CANDIDATE
        </span>
      </div>
    );
  }

  return (
    <div className="p-3 bg-slate-900/80 border border-border rounded-lg flex items-center gap-2.5 font-mono text-xs text-slate-300">
      <AlertTriangle className="w-4 h-4 text-cyan-400 flex-shrink-0" />
      <span>{description}</span>
    </div>
  );
};
