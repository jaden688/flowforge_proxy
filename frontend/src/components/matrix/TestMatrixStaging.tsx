import React, { useState, useEffect } from 'react';
import { useFlowStore } from '../../store/flowStore';
import { useMatrix } from '../../hooks/useMatrix';
import { MatrixBuilderGrid } from './MatrixBuilderGrid';
import { ExecutionFeed } from './ExecutionFeed';
import { CurationCanvas } from './CurationCanvas';
import { SelectivePruner } from './SelectivePruner';
import { StrategySelectDropdown } from './StrategySelectDropdown';
import { Badge } from '../common/Badge';
import { 
  Zap, 
  Play, 
  Sparkles, 
  RefreshCw, 
  Download, 
  CheckSquare, 
  Layers,
  SlidersHorizontal
} from 'lucide-react';
import { TestMatrixCase } from '../../types';

export const TestMatrixStaging: React.FC = () => {
  const selectedFlowId = useFlowStore((s) => s.selectedFlowId);
  const flows = useFlowStore((s) => s.flows);
  const flowOrder = useFlowStore((s) => s.flowOrder);
  const dossiers = useFlowStore((s) => s.dossiers);
  const payloadGroups = useFlowStore((s) => s.payloadGroups);
  const toggleStarCase = useFlowStore((s) => s.toggleStarCase);
  const togglePinCase = useFlowStore((s) => s.togglePinCase);
  const assignCasesToGroup = useFlowStore((s) => s.assignCasesToGroup);
  const pruneCases = useFlowStore((s) => s.pruneCases);

  const {
    job,
    isGenerating,
    isExecuting,
    error,
    generateMatrixForFlow,
    generateMatrixForEndpoint,
    executeSelectedTests,
    updateMatrixCase,
    toggleCaseSelected,
    toggleAllCasesSelected,
  } = useMatrix();

  const [selectedTargetFlowId, setSelectedTargetFlowId] = useState<string>(selectedFlowId || flowOrder[0] || '');
  const [selectedCategoryFilter, setSelectedCategoryFilter] = useState<string>('ALL');
  const [concurrency, setConcurrency] = useState<number>(2);
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [isPrunerOpen, setIsPrunerOpen] = useState<boolean>(false);

  // If no job exists and we have flows, auto-generate initial test matrix
  useEffect(() => {
    if (!job && selectedTargetFlowId) {
      generateMatrixForFlow(selectedTargetFlowId);
    }
  }, [job, selectedTargetFlowId, generateMatrixForFlow]);

  const handleGenerate = () => {
    if (!selectedTargetFlowId) return;
    const cats = selectedCategoryFilter === 'ALL' ? undefined : [selectedCategoryFilter];
    generateMatrixForFlow(selectedTargetFlowId, cats);
  };

  const handleAddCase = (newCase: TestMatrixCase) => {
    if (!job) return;
    useFlowStore.getState().setMatrixJob({
      ...job,
      cases: [newCase, ...job.cases],
      total_count: job.total_count + 1,
    });
  };

  const handleDeleteCase = (id: string) => {
    if (!job) return;
    useFlowStore.getState().setMatrixJob({
      ...job,
      cases: job.cases.filter((c) => c.id !== id),
      total_count: Math.max(0, job.total_count - 1),
    });
  };

  const handleExportMatrixJson = () => {
    if (!job) return;
    const blob = new Blob([JSON.stringify(job, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `test_matrix_${job.job_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const cases = job?.cases || [];
  
  // Filter cases based on active curation group filter
  const displayedCases = cases.filter((c) => {
    if (selectedGroupId === null) return true;
    if (selectedGroupId === '__STARRED__') return !!c.is_starred;
    if (selectedGroupId === '__PINNED__') return !!c.is_pinned;
    const grp = payloadGroups[selectedGroupId];
    if (!grp) return true;
    return c.group_id === selectedGroupId || grp.case_ids?.includes(c.id);
  });

  const selectedCount = displayedCases.filter((c) => c.selected).length;

  const currentFlow = flows[selectedTargetFlowId] || null;
  const currentDossierKey = currentFlow ? `${currentFlow.host}::${currentFlow.path}` : null;
  const currentDossier = currentDossierKey ? dossiers[currentDossierKey] || null : null;

  return (
    <div className="flex-1 overflow-y-auto p-4 bg-[#090D15] space-y-4 font-mono text-xs">
      {/* Staging Header & Controls */}
      <div className="p-4 bg-surface/80 border border-border rounded-xl shadow-lg space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-orange-500/20 text-orange-400 border border-orange-500/30">
              <Zap className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                Test Matrix Staging & Contextual Mutation Generator
              </h2>
              <p className="text-[11px] text-slate-400">
                Synthesizes IDOR, type confusion, boundary fuzz, and privilege escalation test suites
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsPrunerOpen(true)}
              disabled={!job || cases.length === 0}
              className="px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 disabled:opacity-40 text-rose-300 border border-rose-500/30 flex items-center gap-1.5 transition-colors text-xs font-semibold"
              title="Selectively prune uninteresting or non-responsive mutation rows"
            >
              <SlidersHorizontal className="w-3.5 h-3.5" />
              <span>Prune Mutations</span>
            </button>

            <button
              onClick={handleExportMatrixJson}
              disabled={!job}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-colors text-xs font-semibold"
            >
              <Download className="w-3.5 h-3.5 text-primary" />
              <span>Export Matrix</span>
            </button>

            <button
              onClick={() => executeSelectedTests(concurrency)}
              disabled={isExecuting || selectedCount === 0}
              className="px-4 py-1.5 rounded-lg bg-primary hover:bg-primary-hover disabled:opacity-50 text-slate-950 font-bold flex items-center gap-1.5 transition-colors text-xs shadow-lg shadow-primary/20"
            >
              {isExecuting ? (
                <span className="animate-spin">⏳</span>
              ) : (
                <Play className="w-3.5 h-3.5 fill-current" />
              )}
              <span>Execute {selectedCount} Tests</span>
            </button>
          </div>
        </div>

        {/* Generator Controls Bar */}
        <div className="flex flex-wrap items-center gap-3 pt-3 border-t border-border/60">
          {/* Target Flow Selector */}
          <div className="flex items-center gap-2">
            <span className="text-slate-400 text-[11px]">Target Endpoint:</span>
            <select
              value={selectedTargetFlowId}
              onChange={(e) => setSelectedTargetFlowId(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-primary max-w-xs"
            >
              {flowOrder.map((id) => {
                const f = flows[id];
                return (
                  <option key={id} value={id}>
                    {f ? `${f.method} ${f.path}` : id}
                  </option>
                );
              })}
            </select>
          </div>

          {/* Context-Aware Ranked Mutation Category Selector */}
          <div className="flex items-center gap-2">
            <span className="text-slate-400 text-[11px]">Strategy:</span>
            <StrategySelectDropdown
              selectedCategory={selectedCategoryFilter}
              onSelectCategory={setSelectedCategoryFilter}
              flow={currentFlow}
              dossier={currentDossier}
            />
          </div>

          {/* Regenerate Button */}
          <button
            onClick={handleGenerate}
            disabled={isGenerating}
            className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5 text-xs font-semibold transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin' : ''}`} />
            <span>Generate Cases</span>
          </button>
        </div>

        {error && (
          <div className="p-2.5 bg-rose-500/10 border border-rose-500/30 rounded text-rose-300 text-xs">
            {error}
          </div>
        )}
      </div>

      {/* Payload Curation & Grouping Canvas */}
      <CurationCanvas
        cases={cases}
        selectedGroupId={selectedGroupId}
        onSelectGroup={setSelectedGroupId}
        onToggleStar={toggleStarCase}
        onTogglePin={togglePinCase}
        onAssignToGroup={assignCasesToGroup}
      />

      {/* Test Matrix Builder Grid */}
      <MatrixBuilderGrid
        cases={displayedCases}
        onToggleSelected={toggleCaseSelected}
        onToggleAll={toggleAllCasesSelected}
        onUpdateCase={updateMatrixCase}
        onAddCase={handleAddCase}
        onDeleteCase={handleDeleteCase}
      />

      {/* Selective Pruner Modal */}
      <SelectivePruner
        isOpen={isPrunerOpen}
        onClose={() => setIsPrunerOpen(false)}
        cases={cases}
        onExecutePrune={pruneCases}
      />

      {/* Live Execution Feed & Anomaly Monitor */}
      <ExecutionFeed job={job} />
    </div>
  );
};

