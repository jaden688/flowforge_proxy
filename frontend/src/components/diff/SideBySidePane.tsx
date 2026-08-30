import React from 'react';
import { FlowRecord, HeaderDiff, DiffSegment } from '../../types';
import { Badge } from '../common/Badge';

interface SideBySidePaneProps {
  flowA: FlowRecord;
  flowB: FlowRecord;
  headerDiffs: HeaderDiff[];
  bodyDiffSegments: DiffSegment[];
  mode: 'sideBySide' | 'unified';
  scope: 'all' | 'request' | 'response' | 'body' | 'headers';
}

export const SideBySidePane: React.FC<SideBySidePaneProps> = ({
  flowA,
  flowB,
  headerDiffs,
  bodyDiffSegments,
  mode,
  scope,
}) => {
  const showHeaders = scope === 'all' || scope === 'headers' || scope === 'request' || scope === 'response';
  const showBody = scope === 'all' || scope === 'body' || scope === 'request' || scope === 'response';

  const formatJson = (content?: string | null) => {
    if (!content) return '';
    try {
      return JSON.stringify(JSON.parse(content), null, 2);
    } catch {
      return content;
    }
  };

  return (
    <div className="space-y-4 font-mono text-xs">
      {/* Side-by-Side Comparison Container */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Baseline Pane (Flow A) */}
        <div className="bg-[#0A0E17] border border-border rounded-xl overflow-hidden flex flex-col">
          <div className="p-3 bg-[#0E1522] border-b border-border flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-slate-400" />
              <span className="font-bold text-slate-200">BASELINE (Flow A)</span>
            </div>
            <Badge variant="primary" size="sm">
              {flowA.method} {flowA.response_status ?? '---'}
            </Badge>
          </div>

          <div className="p-3 space-y-3 flex-1 overflow-y-auto max-h-[600px]">
            {/* Request Summary */}
            <div className="p-2 bg-slate-900/60 rounded border border-slate-800 text-slate-300 break-all">
              <span className="text-cyan-400 font-bold">{flowA.method}</span> {flowA.url}
            </div>

            {/* Headers Diff Panel */}
            {showHeaders && (
              <div>
                <h5 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1.5">
                  Headers
                </h5>
                <div className="bg-slate-950 rounded border border-slate-800 p-2 space-y-1">
                  {headerDiffs.map((h, i) => (
                    <div
                      key={i}
                      className={`flex justify-between py-0.5 px-1 rounded ${
                        h.status === 'removed' ? 'bg-rose-500/20 text-rose-300' :
                        h.status === 'modified' ? 'bg-amber-500/20 text-amber-300' :
                        h.status === 'added' ? 'opacity-30 text-slate-500' : 'text-slate-300'
                      }`}
                    >
                      <span className="font-semibold">{h.key}:</span>
                      <span className="truncate max-w-[200px]">{h.val_a || '<absent>'}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Body Panel */}
            {showBody && (
              <div>
                <h5 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1.5">
                  Response Body ({flowA.response_size || (flowA.response_body?.length || 0)} B)
                </h5>
                <pre className="p-3 bg-slate-950 rounded border border-slate-800 text-slate-300 overflow-x-auto whitespace-pre leading-5">
                  {formatJson(flowA.response_body)}
                </pre>
              </div>
            )}
          </div>
        </div>

        {/* Comparison / Mutated Pane (Flow B) */}
        <div className="bg-[#0A0E17] border border-border rounded-xl overflow-hidden flex flex-col">
          <div className="p-3 bg-[#0E1522] border-b border-border flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
              <span className="font-bold text-cyan-300">MUTATED (Flow B)</span>
            </div>
            <Badge variant={flowB.response_status === 200 ? 'success' : 'danger'} size="sm">
              {flowB.method} {flowB.response_status ?? '---'}
            </Badge>
          </div>

          <div className="p-3 space-y-3 flex-1 overflow-y-auto max-h-[600px]">
            {/* Request Summary */}
            <div className="p-2 bg-slate-900/60 rounded border border-slate-800 text-slate-300 break-all">
              <span className="text-cyan-400 font-bold">{flowB.method}</span> {flowB.url}
            </div>

            {/* Headers Diff Panel */}
            {showHeaders && (
              <div>
                <h5 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1.5">
                  Headers
                </h5>
                <div className="bg-slate-950 rounded border border-slate-800 p-2 space-y-1">
                  {headerDiffs.map((h, i) => (
                    <div
                      key={i}
                      className={`flex justify-between py-0.5 px-1 rounded ${
                        h.status === 'added' ? 'bg-emerald-500/20 text-emerald-300 font-bold' :
                        h.status === 'modified' ? 'bg-amber-500/20 text-amber-300 font-bold' :
                        h.status === 'removed' ? 'opacity-30 text-slate-500 line-through' : 'text-slate-300'
                      }`}
                    >
                      <span className="font-semibold">{h.key}:</span>
                      <span className="truncate max-w-[200px]">{h.val_b || '<absent>'}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Body Panel */}
            {showBody && (
              <div>
                <h5 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1.5">
                  Response Body ({flowB.response_size || (flowB.response_body?.length || 0)} B)
                </h5>
                <pre className="p-3 bg-slate-950 rounded border border-slate-800 text-slate-300 overflow-x-auto whitespace-pre leading-5">
                  {formatJson(flowB.response_body)}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Tokenized Line Diff Segment Viewer (Unified Diff) */}
      {bodyDiffSegments.length > 0 && (
        <div className="bg-[#0A0E17] border border-border rounded-xl overflow-hidden">
          <div className="p-2.5 bg-[#0E1522] border-b border-border flex items-center justify-between">
            <span className="font-bold text-slate-300 text-[11px] uppercase tracking-wider">
              Tokenized Line Delta Breakdown
            </span>
            <span className="text-[11px] text-slate-500">
              Green (+) = Mutated Additions | Red (-) = Baseline Removals
            </span>
          </div>

          <div className="p-3 overflow-x-auto max-h-72">
            <table className="border-collapse w-full">
              <tbody>
                {bodyDiffSegments.map((seg, idx) => (
                  <tr
                    key={idx}
                    className={`leading-5 font-mono text-xs ${
                      seg.type === 'added' ? 'bg-emerald-950/40 text-emerald-300 font-semibold' :
                      seg.type === 'removed' ? 'bg-rose-950/40 text-rose-300 line-through opacity-80' :
                      'text-slate-400'
                    }`}
                  >
                    <td className="w-8 text-center select-none opacity-50 pr-2">
                      {seg.type === 'added' ? '+' : seg.type === 'removed' ? '-' : ' '}
                    </td>
                    <td className="whitespace-pre break-all">{seg.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
