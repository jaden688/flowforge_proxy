import React, { useState, useMemo } from 'react';
import { useFlowStore } from '../../store/flowStore';
import { CustomRule, RuleSeverity } from '../../types';
import { RuleEditor } from './RuleEditor';
import { RuleLiveTester } from './RuleLiveTester';
import { RuleTemplateGallery } from './RuleTemplateGallery';
import { Badge } from '../common/Badge';
import { 
  SlidersHorizontal, 
  Plus, 
  Trash2, 
  Copy, 
  Download, 
  Upload, 
  Search, 
  Check, 
  Zap, 
  ShieldAlert, 
  ShieldCheck, 
  FileText, 
  Sliders, 
  Layers, 
  Power,
  BarChart2,
  Tag
} from 'lucide-react';

export const RuleEngineManager: React.FC = () => {
  const rules = useFlowStore((s) => s.rules);
  const ruleOrder = useFlowStore((s) => s.ruleOrder);
  const activeRuleId = useFlowStore((s) => s.activeRuleId);
  const addRule = useFlowStore((s) => s.addRule);
  const updateRule = useFlowStore((s) => s.updateRule);
  const deleteRule = useFlowStore((s) => s.deleteRule);
  const toggleRule = useFlowStore((s) => s.toggleRule);
  const selectRule = useFlowStore((s) => s.selectRule);

  const [activeTab, setActiveTab] = useState<'editor' | 'tester' | 'overview' | 'templates'>('editor');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedSeverityFilter, setSelectedSeverityFilter] = useState<string>('ALL');

  const rulesList: CustomRule[] = useMemo(() => {
    return ruleOrder.map((id) => rules[id]).filter(Boolean);
  }, [rules, ruleOrder]);

  const filteredRules = useMemo(() => {
    return rulesList.filter((r) => {
      if (selectedSeverityFilter !== 'ALL' && r.severity !== selectedSeverityFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matches =
          r.name.toLowerCase().includes(q) ||
          r.description?.toLowerCase().includes(q) ||
          r.tags?.some((t) => t.toLowerCase().includes(q));
        if (!matches) return false;
      }
      return true;
    });
  }, [rulesList, selectedSeverityFilter, searchQuery]);

  const activeRule = useMemo(() => {
    if (activeRuleId && rules[activeRuleId]) {
      return rules[activeRuleId];
    }
    return filteredRules[0] || rulesList[0] || null;
  }, [rules, activeRuleId, filteredRules, rulesList]);

  const handleCreateNewRule = () => {
    const id = `rule-custom-${Date.now().toString(36)}`;
    const now = new Date().toISOString();
    const newRule: CustomRule = {
      id,
      name: 'New Security Heuristic Rule',
      description: 'Custom condition matcher for intercepted traffic and vulnerabilities',
      severity: 'HIGH',
      enabled: true,
      tags: ['custom', 'heuristic'],
      match_logic: 'ALL',
      conditions: [
        {
          id: `cond-${Date.now().toString(36)}`,
          field: 'path',
          operator: 'contains',
          value: '/api/v1/private',
          case_sensitive: false,
        },
      ],
      matches_count: 0,
      created_at: now,
      updated_at: now,
    };
    addRule(newRule);
    selectRule(id);
    setActiveTab('editor');
  };

  const handleUseTemplate = (rule: CustomRule) => {
    addRule(rule);
    selectRule(rule.id);
    setActiveTab('editor');
  };

  const handleDuplicateRule = (e: React.MouseEvent, r: CustomRule) => {
    e.stopPropagation();
    const id = `rule-copy-${Date.now().toString(36)}`;
    const now = new Date().toISOString();
    const cloned: CustomRule = {
      ...r,
      id,
      name: `${r.name} (Copy)`,
      matches_count: 0,
      created_at: now,
      updated_at: now,
    };
    addRule(cloned);
    selectRule(id);
  };

  const handleDeleteRule = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    if (confirm('Are you sure you want to delete this custom heuristic rule?')) {
      deleteRule(id);
    }
  };

  const handleExportRules = () => {
    const data = {
      version: '1.0.0',
      exported_at: new Date().toISOString(),
      rules: rulesList,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `flowforge_custom_rules_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleImportRules = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const json = JSON.parse(evt.target?.result as string);
        const importedList: CustomRule[] = Array.isArray(json)
          ? json
          : json.rules && Array.isArray(json.rules)
          ? json.rules
          : [];
        if (importedList.length > 0) {
          importedList.forEach((r) => {
            if (r.id && r.name) {
              addRule(r);
            }
          });
          alert(`Successfully imported ${importedList.length} custom heuristic rules!`);
        } else {
          alert('No valid rules found in JSON file.');
        }
      } catch (err: any) {
        alert(`Failed to import rules: ${err.message}`);
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const getSeverityBadgeVariant = (s: RuleSeverity) => {
    switch (s) {
      case 'CRITICAL':
        return 'danger';
      case 'HIGH':
        return 'warning';
      case 'MEDIUM':
        return 'idor';
      case 'LOW':
        return 'primary';
      default:
        return 'neutral';
    }
  };

  const enabledCount = rulesList.filter((r) => r.enabled).length;

  return (
    <div className="flex-1 flex flex-col md:flex-row h-full bg-[#080C14] text-slate-100 font-mono text-xs overflow-hidden select-none">
      {/* Left Sidebar: Rules Catalog & Controls */}
      <div className="w-full md:w-80 lg:w-96 bg-[#0B101A] border-r border-border flex flex-col h-full shrink-0">
        {/* Sidebar Header */}
        <div className="p-3.5 border-b border-border space-y-2.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                <SlidersHorizontal className="w-4 h-4" />
              </div>
              <div>
                <h3 className="font-bold text-slate-100 text-xs">Rule Engine</h3>
                <span className="text-[10px] text-slate-400">
                  {enabledCount} Active / {rulesList.length} Rules
                </span>
              </div>
            </div>

            <button
              onClick={handleCreateNewRule}
              className="px-2.5 py-1 rounded-lg bg-primary hover:bg-primary-hover text-slate-950 font-bold text-xs flex items-center gap-1 transition-colors shadow-sm shadow-primary/20"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Rule</span>
            </button>
          </div>

          {/* Search & Severity Filter */}
          <div className="space-y-1.5">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search rules, tags..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-2.5 py-1 bg-slate-950 border border-slate-700/80 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-primary"
              />
            </div>

            <div className="flex items-center justify-between gap-1 pt-1">
              <select
                value={selectedSeverityFilter}
                onChange={(e) => setSelectedSeverityFilter(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded px-2 py-0.5 text-[11px] text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

              <div className="flex items-center gap-1">
                <button
                  onClick={handleExportRules}
                  className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
                  title="Export Rules to JSON"
                >
                  <Download className="w-3.5 h-3.5 text-primary" />
                </button>
                <label className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 cursor-pointer">
                  <Upload className="w-3.5 h-3.5 text-emerald-400" />
                  <input
                    type="file"
                    accept=".json"
                    onChange={handleImportRules}
                    className="hidden"
                  />
                </label>
              </div>
            </div>
          </div>
        </div>

        {/* Rules List Cards */}
        <div className="flex-1 overflow-y-auto divide-y divide-border/40 p-1.5 space-y-1">
          {filteredRules.map((r) => {
            const isSelected = activeRule?.id === r.id;
            return (
              <div
                key={r.id}
                onClick={() => selectRule(r.id)}
                className={`p-3 rounded-xl cursor-pointer transition-all border ${
                  isSelected
                    ? 'bg-slate-900 border-primary shadow-md shadow-primary/10'
                    : 'bg-slate-950/60 border-slate-800/80 hover:bg-slate-900/60 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5 mb-1">
                      <Badge variant={getSeverityBadgeVariant(r.severity)} size="sm">
                        {r.severity}
                      </Badge>
                      <span className="font-bold text-slate-100 text-xs truncate">
                        {r.name}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-400 line-clamp-1">
                      {r.description || `${r.conditions.length} conditions defined`}
                    </p>

                    {/* Tags & Match count */}
                    <div className="flex items-center gap-2 mt-2 text-[10px] text-slate-400">
                      <span className="font-semibold text-cyan-400">
                        {r.conditions.length} cond ({r.match_logic})
                      </span>
                      <span>•</span>
                      <span className="text-slate-500">
                        Matches: <span className="font-bold text-slate-300">{r.matches_count}</span>
                      </span>
                    </div>
                  </div>

                  {/* Actions: Toggle, Duplicate, Delete */}
                  <div className="flex flex-col items-end gap-1.5 shrink-0">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleRule(r.id);
                      }}
                      className={`p-1 rounded-full transition-colors ${
                        r.enabled
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 shadow-sm shadow-emerald-500/20'
                          : 'bg-slate-800 text-slate-500 border border-slate-700'
                      }`}
                      title={r.enabled ? 'Rule Active' : 'Rule Disabled'}
                    >
                      <Power className="w-3.5 h-3.5" />
                    </button>

                    <div className="flex items-center gap-1">
                      <button
                        onClick={(e) => handleDuplicateRule(e, r)}
                        className="p-1 rounded text-slate-500 hover:text-slate-200 hover:bg-slate-800"
                        title="Duplicate rule"
                      >
                        <Copy className="w-3 h-3" />
                      </button>
                      <button
                        onClick={(e) => handleDeleteRule(e, r.id)}
                        className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-500/20"
                        title="Delete rule"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right Main Workbench: Tabs & Panes */}
      <div className="flex-1 flex flex-col h-full overflow-hidden bg-[#070B13]">
        {/* Top Tab Switcher */}
        <div className="h-12 bg-surface/90 border-b border-border px-4 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('editor')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activeTab === 'editor'
                  ? 'bg-primary text-slate-950 shadow-md shadow-primary/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>Rule Editor</span>
            </button>

            <button
              onClick={() => setActiveTab('tester')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activeTab === 'tester'
                  ? 'bg-primary text-slate-950 shadow-md shadow-primary/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Live Flow Matcher Sandbox</span>
            </button>

            <button
              onClick={() => setActiveTab('overview')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activeTab === 'overview'
                  ? 'bg-primary text-slate-950 shadow-md shadow-primary/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <BarChart2 className="w-3.5 h-3.5" />
              <span>Rules Metrics</span>
            </button>

            <button
              onClick={() => setActiveTab('templates')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activeTab === 'templates'
                  ? 'bg-primary text-slate-950 shadow-md shadow-primary/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Templates</span>
            </button>
          </div>

          {activeRule && (
            <div className="hidden sm:flex items-center gap-2 text-xs text-slate-400 font-mono">
              <span className="font-bold text-slate-200">{activeRule.name}</span>
              <Badge variant={getSeverityBadgeVariant(activeRule.severity)} size="sm">
                {activeRule.severity}
              </Badge>
            </div>
          )}
        </div>

        {/* Main Content Area */}
        <div className="flex-1 p-4 overflow-hidden">
          {activeRule ? (
            <>
              {activeTab === 'editor' && (
                <RuleEditor
                  rule={activeRule}
                  onSave={(updated) => updateRule(updated.id, updated)}
                />
              )}

              {activeTab === 'tester' && (
                <RuleLiveTester rule={activeRule} />
              )}

              {activeTab === 'overview' && (
                <div className="bg-[#0B101B] border border-border rounded-xl p-6 font-mono text-xs text-slate-200 space-y-6 overflow-y-auto h-full">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-primary/20 text-primary border border-primary/30">
                      <BarChart2 className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="font-bold text-slate-100 text-sm">
                        Heuristic Rule Engine Statistics &amp; Coverage
                      </h3>
                      <p className="text-[11px] text-slate-400">
                        Passive stream matching engine evaluating live HTTP/HTTPS flows against security assertions
                      </p>
                    </div>
                  </div>

                  {/* Metrics Tiles */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl">
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Total Rules</span>
                      <span className="text-xl font-bold text-slate-100 font-mono">{rulesList.length}</span>
                    </div>
                    <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl">
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Active / Enabled</span>
                      <span className="text-xl font-bold text-emerald-400 font-mono">{enabledCount}</span>
                    </div>
                    <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl">
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Critical Severities</span>
                      <span className="text-xl font-bold text-rose-400 font-mono">
                        {rulesList.filter((r) => r.severity === 'CRITICAL').length}
                      </span>
                    </div>
                    <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl">
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Total Triggered Matches</span>
                      <span className="text-xl font-bold text-cyan-400 font-mono">
                        {rulesList.reduce((acc, r) => acc + (r.matches_count || 0), 0)}
                      </span>
                    </div>
                  </div>

                  {/* Registered Rules Overview Table */}
                  <div className="space-y-2">
                    <h4 className="font-bold text-slate-200 uppercase tracking-wider text-xs">
                      Registered Heuristic Rules Table
                    </h4>
                    <div className="overflow-x-auto border border-slate-800 rounded-xl">
                      <table className="w-full text-left border-collapse">
                        <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[10px]">
                          <tr>
                            <th className="py-2.5 px-3">Rule Name</th>
                            <th className="py-2.5 px-3 w-28">Severity</th>
                            <th className="py-2.5 px-3 w-24">Logic</th>
                            <th className="py-2.5 px-3 w-28">Conditions</th>
                            <th className="py-2.5 px-3 w-36">Tags</th>
                            <th className="py-2.5 px-3 w-24">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
                          {rulesList.map((r) => (
                            <tr key={r.id} className="hover:bg-slate-900/60">
                              <td className="py-2.5 px-3 font-semibold text-slate-200">
                                {r.name}
                              </td>
                              <td className="py-2.5 px-3">
                                <Badge variant={getSeverityBadgeVariant(r.severity)} size="sm">
                                  {r.severity}
                                </Badge>
                              </td>
                              <td className="py-2.5 px-3 text-cyan-300 font-bold">
                                {r.match_logic}
                              </td>
                              <td className="py-2.5 px-3 text-slate-300">
                                {r.conditions.length} checks
                              </td>
                              <td className="py-2.5 px-3 text-slate-400">
                                {r.tags.join(', ')}
                              </td>
                              <td className="py-2.5 px-3">
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                    r.enabled
                                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                                      : 'bg-slate-800 text-slate-500 border border-slate-700'
                                  }`}
                                >
                                  {r.enabled ? 'ACTIVE' : 'DISABLED'}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}
              {activeTab === 'templates' && (
                <div className="bg-[#0B101B] border border-border rounded-xl p-4 font-mono text-xs text-slate-200 overflow-y-auto h-full">
                  <RuleTemplateGallery onUseTemplate={handleUseTemplate} />
                </div>
              )}
            </>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-slate-500 space-y-3">
              <SlidersHorizontal className="w-8 h-8 text-slate-600" />
              <p>No heuristic rules created yet.</p>
              <button
                onClick={handleCreateNewRule}
                className="px-4 py-2 bg-primary text-slate-950 font-bold rounded-lg text-xs"
              >
                Create First Rule
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
