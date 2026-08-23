import React, { useState, useMemo } from 'react';
import { TestMatrixCase, TestExecutionStatus, PruneOptions } from '../../types';
import { 
  Filter, 
  Trash2, 
  ShieldCheck, 
  AlertTriangle, 
  Check, 
  SlidersHorizontal,
  X,
  Search
} from 'lucide-react';
import { Modal } from '../common/Modal';

interface SelectivePrunerProps {
  isOpen: boolean;
  onClose: () => void;
  cases: TestMatrixCase[];
  onExecutePrune: (options: PruneOptions) => void;
}

export const SelectivePruner: React.FC<SelectivePrunerProps> = ({
  isOpen,
  onClose,
  cases,
  onExecutePrune,
}) => {
  // Pruner filter parameters
  const [selectedStatuses, setSelectedStatuses] = useState<TestExecutionStatus[]>(['FAILED']);
  const [filterStatusCode, setFilterStatusCode] = useState<string>(''); // e.g. "404, 502"
  const [pruneZeroLengthDelta, setPruneZeroLengthDelta] = useState<boolean>(false);
  const [regexPattern, setRegexPattern] = useState<string>('');
  const [onlyUnselected, setOnlyUnselected] = useState<boolean>(false);
  const [keepPinnedAndStarred, setKeepPinnedAndStarred] = useState<boolean>(true);

  const statusOptions: { value: TestExecutionStatus; label: string; count: number }[] = [
    { value: 'PASSED', label: 'Passed (200 OK without anomaly)', count: cases.filter(c => c.status === 'PASSED').length },
    { value: 'FAILED', label: 'Failed (Network error / dropped)', count: cases.filter(c => c.status === 'FAILED').length },
    { value: 'READY', label: 'Ready (Unexecuted)', count: cases.filter(c => c.status === 'READY').length },
    { value: 'QUEUED', label: 'Queued', count: cases.filter(c => c.status === 'QUEUED').length },
    { value: 'ANOMALY_DETECTED', label: 'Anomaly Detected ⚠️', count: cases.filter(c => c.status === 'ANOMALY_DETECTED').length },
  ];

  const toggleStatus = (status: TestExecutionStatus) => {
    setSelectedStatuses((prev) => 
      prev.includes(status) ? prev.filter(s => s !== status) : [...prev, status]
    );
  };

  // Compute matching and protected cases
  const { matchingCases, protectedCases, prunedCasesCount } = useMemo(() => {
    let regex: RegExp | null = null;
    if (regexPattern.trim()) {
      try {
        regex = new RegExp(regexPattern.trim(), 'i');
      } catch (e) {
        regex = null;
      }
    }

    const statusCodes = filterStatusCode
      .split(',')
      .map(s => parseInt(s.trim(), 10))
      .filter(n => !isNaN(n));

    let matched: TestMatrixCase[] = [];
    let protectedCount = 0;

    cases.forEach((c) => {
      // Check if matches status
      let matches = false;

      if (selectedStatuses.includes(c.status)) {
        matches = true;
      }

      // Check status code filter
      if (statusCodes.length > 0 && c.result_summary) {
        if (statusCodes.includes(c.result_summary.status_code)) {
          matches = true;
        }
      }

      // Check zero length delta
      if (pruneZeroLengthDelta && c.result_summary) {
        if (c.result_summary.length_delta === 0) {
          matches = true;
        }
      }

      // Check regex filter on name, param, or mutated value
      if (regex) {
        const strVal = String(c.mutated_value || '');
        if (regex.test(c.name) || regex.test(c.target_param_name) || regex.test(strVal)) {
          matches = true;
        }
      }

      // Check unselected only
      if (onlyUnselected && c.selected) {
        matches = false;
      }

      if (matches) {
        const isProtected = keepPinnedAndStarred && (c.is_pinned || c.is_starred);
        if (isProtected) {
          protectedCount++;
        } else {
          matched.push(c);
        }
      }
    });

    return {
      matchingCases: matched,
      protectedCases: protectedCount,
      prunedCasesCount: matched.length,
    };
  }, [cases, selectedStatuses, filterStatusCode, pruneZeroLengthDelta, regexPattern, onlyUnselected, keepPinnedAndStarred]);

  const handlePruneConfirm = () => {
    onExecutePrune({
      statuses: selectedStatuses,
      statusCodeFilter: filterStatusCode,
      regexPattern: regexPattern.trim() || undefined,
      onlyUnselected,
      keepPinnedAndStarred,
    });
    onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Selective Test Case & Mutation Pruner"
    >
      <div className="space-y-4 font-mono text-xs text-slate-200">
        <p className="text-slate-400 text-[11px]">
          Remove uninteresting, non-responsive, or noisy mutation rows based on status codes, length deltas, and regex matching without wiping valuable findings.
        </p>

        {/* Protection Alert */}
        <div className="p-3 bg-emerald-950/30 border border-emerald-500/30 rounded-lg flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="text-emerald-300 font-semibold text-xs">
              Pin & Star Protection
            </span>
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={keepPinnedAndStarred}
              onChange={(e) => setKeepPinnedAndStarred(e.target.checked)}
              className="rounded border-slate-700 text-emerald-500 focus:ring-0"
            />
            <span className="text-[11px] text-slate-300">Protect Pinned & Starred Rows</span>
          </label>
        </div>

        {/* Execution Status Multi-Select */}
        <div>
          <label className="block text-[11px] font-bold text-slate-300 mb-1.5">
            Prune by Execution Status:
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {statusOptions.map((opt) => {
              const isChecked = selectedStatuses.includes(opt.value);
              return (
                <div
                  key={opt.value}
                  onClick={() => toggleStatus(opt.value)}
                  className={`p-2 rounded-lg border cursor-pointer flex items-center justify-between transition-colors ${
                    isChecked
                      ? 'bg-rose-950/30 border-rose-500/50 text-rose-200'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-2 truncate">
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => {}}
                      className="rounded border-slate-700 text-rose-500 focus:ring-0"
                    />
                    <span className="truncate text-xs">{opt.label}</span>
                  </div>
                  <span className="px-1.5 py-0.2 rounded bg-slate-800 text-[10px] text-slate-300 font-bold ml-1">
                    {opt.count}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* HTTP Status Code Filter */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label className="block text-[11px] text-slate-300 mb-1">
              Prune Specific HTTP Status Codes (comma separated):
            </label>
            <input
              type="text"
              placeholder="e.g. 404, 500, 502"
              value={filterStatusCode}
              onChange={(e) => setFilterStatusCode(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-primary"
            />
          </div>

          <div>
            <label className="block text-[11px] text-slate-300 mb-1">
              Prune by Name/Payload Regex:
            </label>
            <input
              type="text"
              placeholder="e.g. ^temp_|test_ignore|undefined"
              value={regexPattern}
              onChange={(e) => setRegexPattern(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-primary"
            />
          </div>
        </div>

        {/* Checkbox Options */}
        <div className="space-y-2 pt-1 border-t border-slate-800">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={pruneZeroLengthDelta}
              onChange={(e) => setPruneZeroLengthDelta(e.target.checked)}
              className="rounded border-slate-700 text-primary focus:ring-0"
            />
            <span className="text-slate-300 text-xs">
              Prune cases with 0 byte length delta (identical response size)
            </span>
          </label>

          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={onlyUnselected}
              onChange={(e) => setOnlyUnselected(e.target.checked)}
              className="rounded border-slate-700 text-primary focus:ring-0"
            />
            <span className="text-slate-300 text-xs">
              Only prune unselected checkboxes (leave currently selected rows intact)
            </span>
          </label>
        </div>

        {/* Live Preview Summary Bar */}
        <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-between">
          <div>
            <span className="text-slate-400 text-xs">Prune Target Count:</span>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="text-sm font-bold text-rose-400 font-mono">
                {prunedCasesCount} of {cases.length} cases
              </span>
              {protectedCases > 0 && (
                <span className="text-[11px] text-emerald-400 font-mono">
                  ({protectedCases} protected by Pin/Star)
                </span>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handlePruneConfirm}
              disabled={prunedCasesCount === 0}
              className="px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-40 text-white text-xs font-bold flex items-center gap-1.5 transition-colors shadow-lg shadow-rose-600/20"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Prune {prunedCasesCount} Rows</span>
            </button>
          </div>
        </div>
      </div>
    </Modal>
  );
};
