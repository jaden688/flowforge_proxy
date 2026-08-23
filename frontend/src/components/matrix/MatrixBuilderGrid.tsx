import React, { useState } from 'react';
import { TestMatrixCase, MutationCategory } from '../../types';
import { Badge } from '../common/Badge';
import { Trash2, Plus, AlertCircle, CheckCircle2, Clock, GitCompare, Star, Pin } from 'lucide-react';
import { useFlowStore } from '../../store/flowStore';

interface MatrixBuilderGridProps {
  cases: TestMatrixCase[];
  onToggleSelected: (id: string) => void;
  onToggleAll: (selected: boolean) => void;
  onUpdateCase: (id: string, updates: Partial<TestMatrixCase>) => void;
  onAddCase: (newCase: TestMatrixCase) => void;
  onDeleteCase: (id: string) => void;
}

export const MatrixBuilderGrid: React.FC<MatrixBuilderGridProps> = ({
  cases,
  onToggleSelected,
  onToggleAll,
  onUpdateCase,
  onAddCase,
  onDeleteCase,
}) => {
  const setDiffPair = useFlowStore((s) => s.setDiffPair);
  const setActiveView = useFlowStore((s) => s.setActiveView);
  const toggleStarCase = useFlowStore((s) => s.toggleStarCase);
  const togglePinCase = useFlowStore((s) => s.togglePinCase);

  const [isAdding, setIsAdding] = useState(false);
  const [newParamName, setNewParamName] = useState('order_id');
  const [newLocation, setNewLocation] = useState<'path' | 'query' | 'body' | 'header'>('path');
  const [newCategory, setNewCategory] = useState<MutationCategory>('IDOR_SEQUENTIAL');
  const [newBaselineVal, setNewBaselineVal] = useState('1001');
  const [newMutatedVal, setNewMutatedVal] = useState('1002');

  const allSelected = cases.length > 0 && cases.every((c) => c.selected);

  const getStatusBadge = (status: string, anomalyFlag?: string | null) => {
    switch (status) {
      case 'PASSED':
        return (
          <Badge variant="success" size="sm">
            <CheckCircle2 className="w-2.5 h-2.5" />
            <span>Passed (200 OK)</span>
          </Badge>
        );
      case 'ANOMALY_DETECTED':
        return (
          <Badge variant="danger" size="sm" className="animate-pulse">
            <AlertCircle className="w-2.5 h-2.5" />
            <span>{anomalyFlag || 'Anomaly ⚠️'}</span>
          </Badge>
        );
      case 'RUNNING':
        return (
          <Badge variant="primary" size="sm">
            <span className="animate-spin">⏳</span>
            <span>Running...</span>
          </Badge>
        );
      case 'QUEUED':
        return (
          <Badge variant="neutral" size="sm">
            <Clock className="w-2.5 h-2.5" />
            <span>Queued</span>
          </Badge>
        );
      default:
        return (
          <Badge variant="outline" size="sm">
            Ready
          </Badge>
        );
    }
  };

  const getCategoryBadgeVariant = (cat: string) => {
    if (cat.includes('IDOR')) return 'idor';
    if (cat.includes('AUTH')) return 'danger';
    if (cat.includes('TYPE')) return 'mutation';
    if (cat.includes('BOUNDARY')) return 'warning';
    return 'primary';
  };

  const handleAddCustom = (e: React.FormEvent) => {
    e.preventDefault();
    const created: TestMatrixCase = {
      id: `case-custom-${Date.now().toString(36)}`,
      name: `Custom: ${newCategory} on ${newParamName}`,
      endpoint_path: cases[0]?.endpoint_path || '/api/v1/resource',
      method: cases[0]?.method || 'GET',
      category: newCategory,
      target_param_location: newLocation,
      target_param_name: newParamName,
      baseline_value: newBaselineVal,
      mutated_value: newMutatedVal,
      selected: true,
      status: 'READY',
      baseline_flow_id: cases[0]?.baseline_flow_id,
      is_pinned: false,
      is_starred: false,
    };
    onAddCase(created);
    setIsAdding(false);
  };

  const handleSendToDiff = (c: TestMatrixCase) => {
    if (c.baseline_flow_id) {
      setDiffPair(c.baseline_flow_id, c.executed_flow_id || null);
      setActiveView('diff');
    }
  };

  return (
    <div className="bg-[#0A0E17] border border-border rounded-lg overflow-hidden font-mono text-xs">
      <div className="p-3 bg-surface/60 border-b border-border flex items-center justify-between">
        <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
          Staged Test Mutation Matrix ({cases.length} test cases)
        </h4>
        <button
          onClick={() => setIsAdding(!isAdding)}
          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 flex items-center gap-1.5 transition-colors text-[11px]"
        >
          <Plus className="w-3 h-3" />
          <span>Add Custom Test</span>
        </button>
      </div>

      {/* Add Custom Test Row Drawer */}
      {isAdding && (
        <form onSubmit={handleAddCustom} className="p-3 bg-slate-900/90 border-b border-border grid grid-cols-1 md:grid-cols-5 gap-2 items-end animate-in fade-in">
          <div>
            <label className="block text-[10px] text-slate-400 mb-1">Target Param</label>
            <input
              type="text"
              value={newParamName}
              onChange={(e) => setNewParamName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs"
            />
          </div>

          <div>
            <label className="block text-[10px] text-slate-400 mb-1">Location</label>
            <select
              value={newLocation}
              onChange={(e) => setNewLocation(e.target.value as any)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs"
            >
              <option value="path">Path</option>
              <option value="query">Query</option>
              <option value="body">Body</option>
              <option value="header">Header</option>
            </select>
          </div>

          <div>
            <label className="block text-[10px] text-slate-400 mb-1">Category</label>
            <select
              value={newCategory}
              onChange={(e) => setNewCategory(e.target.value as any)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs"
            >
              <option value="IDOR_SEQUENTIAL">IDOR Sequential</option>
              <option value="IDOR_ROLE_SWAP">IDOR Role Swap</option>
              <option value="TYPE_CONFUSION">Type Confusion</option>
              <option value="BOUNDARY_OVERFLOW">Boundary Overflow</option>
              <option value="AUTH_STRIPPING">Auth Stripping</option>
              <option value="MASS_ASSIGNMENT">Mass Assignment</option>
            </select>
          </div>

          <div>
            <label className="block text-[10px] text-slate-400 mb-1">Mutated Value</label>
            <input
              type="text"
              value={newMutatedVal}
              onChange={(e) => setNewMutatedVal(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs"
            />
          </div>

          <div className="flex gap-2">
            <button
              type="submit"
              className="flex-1 py-1 bg-primary text-slate-950 font-bold rounded hover:bg-primary-hover text-xs"
            >
              Add Row
            </button>
            <button
              type="button"
              onClick={() => setIsAdding(false)}
              className="py-1 px-2 bg-slate-800 text-slate-400 rounded hover:bg-slate-700 text-xs"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead className="bg-[#0E1522] border-b border-border text-slate-400 select-none">
            <tr>
              <th className="py-2.5 px-3 w-10 text-center">
                <input
                  type="checkbox"
                  checked={allSelected}
                  onChange={(e) => onToggleAll(e.target.checked)}
                  className="rounded border-slate-700 text-primary focus:ring-0 cursor-pointer"
                />
              </th>
              <th className="py-2.5 px-2 w-16 text-center">Curate</th>
              <th className="py-2.5 px-3 w-64">Test Case Name</th>
              <th className="py-2.5 px-3 w-36">Category</th>
              <th className="py-2.5 px-3 w-32">Target Param</th>
              <th className="py-2.5 px-3 w-28">Baseline</th>
              <th className="py-2.5 px-3">Mutated Value</th>
              <th className="py-2.5 px-3 w-40">Execution Status</th>
              <th className="py-2.5 px-3 w-20 text-center">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/40">
            {cases.map((c) => (
              <tr
                key={c.id}
                className={`transition-colors ${
                  c.status === 'ANOMALY_DETECTED'
                    ? 'bg-rose-950/20 hover:bg-rose-950/30'
                    : 'hover:bg-slate-900/60'
                }`}
              >
                <td className="py-2.5 px-3 text-center">
                  <input
                    type="checkbox"
                    checked={c.selected}
                    onChange={() => onToggleSelected(c.id)}
                    className="rounded border-slate-700 text-primary focus:ring-0 cursor-pointer"
                  />
                </td>
                <td className="py-2.5 px-2 text-center">
                  <div className="flex items-center justify-center gap-1">
                    <button
                      type="button"
                      onClick={() => toggleStarCase(c.id)}
                      className={`p-1 rounded transition-colors ${
                        c.is_starred
                          ? 'text-yellow-400 hover:text-yellow-300 bg-yellow-500/20'
                          : 'text-slate-600 hover:text-yellow-400'
                      }`}
                      title={c.is_starred ? 'Unstar test case' : 'Star test case'}
                    >
                      <Star className={`w-3.5 h-3.5 ${c.is_starred ? 'fill-current' : ''}`} />
                    </button>
                    <button
                      type="button"
                      onClick={() => togglePinCase(c.id)}
                      className={`p-1 rounded transition-colors ${
                        c.is_pinned
                          ? 'text-cyan-400 hover:text-cyan-300 bg-cyan-500/20'
                          : 'text-slate-600 hover:text-cyan-400'
                      }`}
                      title={c.is_pinned ? 'Unpin test case' : 'Pin test case (protect from pruning)'}
                    >
                      <Pin className={`w-3.5 h-3.5 ${c.is_pinned ? 'fill-current' : ''}`} />
                    </button>
                  </div>
                </td>
                <td className="py-2.5 px-3 font-medium text-slate-200">
                  <div className="flex items-center gap-1.5">
                    {c.is_starred && <Star className="w-3 h-3 text-yellow-400 fill-current shrink-0" />}
                    {c.is_pinned && <Pin className="w-3 h-3 text-cyan-400 fill-current shrink-0" />}
                    <span className="truncate">{c.name}</span>
                  </div>
                </td>
                <td className="py-2.5 px-3">
                  <Badge variant={getCategoryBadgeVariant(c.category)} size="sm">
                    {c.category.replace('_', ' ')}
                  </Badge>
                </td>
                <td className="py-2.5 px-3 text-cyan-300 font-semibold">
                  {c.target_param_location}.{c.target_param_name}
                </td>
                <td className="py-2.5 px-3 text-slate-400 truncate max-w-[100px]">
                  {c.baseline_value === null ? '<null>' : String(c.baseline_value)}
                </td>
                <td className="py-2.5 px-3">
                  <input
                    type="text"
                    value={c.mutated_value === null ? '' : typeof c.mutated_value === 'object' ? JSON.stringify(c.mutated_value) : String(c.mutated_value)}
                    onChange={(e) => onUpdateCase(c.id, { mutated_value: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-800 rounded px-2 py-0.5 text-slate-100 text-xs font-mono focus:border-primary focus:outline-none"
                  />
                </td>
                <td className="py-2.5 px-3">
                  {getStatusBadge(c.status, c.result_summary?.anomaly_flag)}
                </td>
                <td className="py-2.5 px-3 text-center">
                  <div className="flex items-center justify-center gap-1.5">
                    {c.status === 'ANOMALY_DETECTED' && (
                      <button
                        onClick={() => handleSendToDiff(c)}
                        className="p-1 rounded text-purple-400 hover:text-purple-300 hover:bg-purple-500/20"
                        title="Diff result against baseline flow"
                      >
                        <GitCompare className="w-3.5 h-3.5" />
                      </button>
                    )}
                    <button
                      onClick={() => onDeleteCase(c.id)}
                      className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-500/20"
                      title="Delete test case"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
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

