import React from 'react';
import { TestMatrixJob } from '../../types';
import { Badge } from '../common/Badge';
import { AlertCircle, CheckCircle2, Terminal, ShieldAlert, Sparkles } from 'lucide-react';

interface ExecutionFeedProps {
  job: TestMatrixJob | null;
}

export const ExecutionFeed: React.FC<ExecutionFeedProps> = ({ job }) => {
  if (!job) {
    return (
      <div className="p-6 bg-[#0A0E17] border border-border rounded-lg text-slate-500 font-mono text-xs text-center">
        No active execution job. Click "Execute Matrix" to run test cases.
      </div>
    );
  }

  const executedCases = job.cases.filter((c) => c.status === 'PASSED' || c.status === 'ANOMALY_DETECTED');
  const anomalyCases = job.cases.filter((c) => c.status === 'ANOMALY_DETECTED');

  return (
    <div className="space-y-4 font-mono text-xs">
      {/* Execution Progress Banner */}
      <div className="p-3 bg-surface/70 border border-border rounded-lg flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <div>
            <span className="font-bold text-slate-200">Execution Progress</span>
            <div className="text-[11px] text-slate-400">
              {job.completed_count} of {job.total_count} cases executed
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {anomalyCases.length > 0 && (
            <Badge variant="danger" size="md">
              <AlertCircle className="w-3 h-3" />
              <span>{anomalyCases.length} Anomalies Flagged</span>
            </Badge>
          )}
          <span className="text-slate-400 text-xs">
            {Math.round((job.completed_count / Math.max(1, job.total_count)) * 100)}%
          </span>
        </div>
      </div>

      {/* Anomaly Alerts Box */}
      {anomalyCases.length > 0 && (
        <div className="p-3.5 bg-rose-500/10 border border-rose-500/30 rounded-lg space-y-2">
          <div className="flex items-center gap-2 text-rose-300 font-bold">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <span>CRITICAL SURFACE ANOMALIES DETECTED ({anomalyCases.length})</span>
          </div>

          <div className="space-y-1.5">
            {anomalyCases.map((c) => (
              <div key={c.id} className="p-2 bg-slate-950/80 rounded border border-rose-500/20 text-xs flex items-center justify-between">
                <div>
                  <span className="font-semibold text-slate-200">{c.name}</span>
                  <div className="text-[11px] text-rose-300 mt-0.5">
                    Flag: {c.result_summary?.anomaly_flag} (Status: {c.result_summary?.status_code}, Δ {c.result_summary?.length_delta}B)
                  </div>
                </div>
                <Badge variant="danger" size="sm">
                  Investigate
                </Badge>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Live Stream Event Log */}
      <div className="bg-[#0A0E17] border border-border rounded-lg overflow-hidden">
        <div className="p-2.5 bg-[#0E1522] border-b border-border font-bold text-slate-300 text-[11px] uppercase tracking-wider">
          Recent Test Case Executions
        </div>

        <div className="divide-y divide-border/30 max-h-64 overflow-y-auto">
          {executedCases.length === 0 ? (
            <div className="p-4 text-slate-500 text-center text-xs">
              Waiting for execution output...
            </div>
          ) : (
            executedCases.map((c) => (
              <div key={c.id} className="p-2.5 hover:bg-slate-900/50 flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 truncate">
                  {c.status === 'ANOMALY_DETECTED' ? (
                    <AlertCircle className="w-3.5 h-3.5 text-rose-400 flex-shrink-0" />
                  ) : (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                  )}
                  <span className="text-slate-200 font-medium truncate">{c.name}</span>
                </div>

                <div className="flex items-center gap-2 text-slate-400 text-[11px] flex-shrink-0">
                  <span className={c.result_summary?.status_code === 200 ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
                    HTTP {c.result_summary?.status_code ?? '---'}
                  </span>
                  <span>{c.result_summary?.latency_ms ?? 0}ms</span>
                  {c.result_summary?.reflected && (
                    <Badge variant="reflection" size="sm">
                      <Sparkles className="w-2.5 h-2.5" />
                      Reflected
                    </Badge>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
