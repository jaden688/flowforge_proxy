import React, { useState, useEffect } from 'react';
import { 
  CustomRule, 
  MatchCondition, 
  RuleSeverity, 
  MatchField, 
  MatchOperator 
} from '../../types';
import { 
  Plus, 
  Trash2, 
  Save, 
  Code, 
  Sliders, 
  AlertCircle, 
  Check, 
  Sparkles, 
  Tag, 
  Layers 
} from 'lucide-react';
import { Badge } from '../common/Badge';

interface RuleEditorProps {
  rule: CustomRule;
  onSave: (updatedRule: CustomRule) => void;
  onCancel?: () => void;
}

const FIELD_OPTIONS: { value: MatchField; label: string; placeholder?: string }[] = [
  { value: 'url', label: 'Full URL (url)', placeholder: 'https://api.domain.com/...' },
  { value: 'path', label: 'URL Path (path)', placeholder: '/api/v1/resource' },
  { value: 'method', label: 'HTTP Method (method)', placeholder: 'POST, GET, PUT' },
  { value: 'header', label: 'HTTP Header (header)', placeholder: 'Authorization, X-Custom-Header' },
  { value: 'query_param', label: 'Query Parameter (query_param)', placeholder: 'id, token, filter' },
  { value: 'request_body', label: 'Request Body (request_body)', placeholder: '{"username": "admin"}' },
  { value: 'response_body', label: 'Response Body (response_body)', placeholder: 'SQL syntax, token' },
  { value: 'status_code', label: 'HTTP Status Code (status_code)', placeholder: '200, 401, 500' },
  { value: 'entropy', label: 'Shannon Entropy (entropy)', placeholder: '4.5' },
  { value: 'content_type', label: 'Content-Type (content_type)', placeholder: 'application/json' },
  { value: 'latency_ms', label: 'Latency ms (latency_ms)', placeholder: '500' },
];

const OPERATOR_OPTIONS: { value: MatchOperator; label: string }[] = [
  { value: 'contains', label: 'Contains (contains)' },
  { value: 'not_contains', label: 'Does Not Contain (not_contains)' },
  { value: 'equals', label: 'Equals (equals)' },
  { value: 'not_equals', label: 'Not Equals (not_equals)' },
  { value: 'regex', label: 'Matches Regex (regex)' },
  { value: 'not_regex', label: 'Does Not Match Regex (not_regex)' },
  { value: 'starts_with', label: 'Starts With (starts_with)' },
  { value: 'ends_with', label: 'Ends With (ends_with)' },
  { value: 'gt', label: 'Greater Than > (gt)' },
  { value: 'lt', label: 'Less Than < (lt)' },
  { value: 'exists', label: 'Field Exists (exists)' },
  { value: 'not_exists', label: 'Field Does Not Exist (not_exists)' },
];

export const RuleEditor: React.FC<RuleEditorProps> = ({
  rule,
  onSave,
  onCancel,
}) => {
  const [editorMode, setEditorMode] = useState<'visual' | 'code'>('visual');
  const [name, setName] = useState(rule.name);
  const [description, setDescription] = useState(rule.description || '');
  const [severity, setSeverity] = useState<RuleSeverity>(rule.severity);
  const [enabled, setEnabled] = useState(rule.enabled);
  const [tagsStr, setTagsStr] = useState(rule.tags.join(', '));
  const [matchLogic, setMatchLogic] = useState<'ALL' | 'ANY'>(rule.match_logic);
  const [conditions, setConditions] = useState<MatchCondition[]>(rule.conditions || []);

  // Code editor JSON text
  const [jsonText, setJsonText] = useState('');
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [isSaved, setIsSaved] = useState(false);

  // Sync state when incoming rule changes
  useEffect(() => {
    setName(rule.name);
    setDescription(rule.description || '');
    setSeverity(rule.severity);
    setEnabled(rule.enabled);
    setTagsStr(rule.tags.join(', '));
    setMatchLogic(rule.match_logic);
    setConditions(rule.conditions || []);
    setJsonText(JSON.stringify(rule, null, 2));
  }, [rule]);

  // Handle mode toggle
  const handleSwitchToCode = () => {
    const currentRuleObj: CustomRule = {
      ...rule,
      name,
      description,
      severity,
      enabled,
      tags: tagsStr.split(',').map((t) => t.trim()).filter(Boolean),
      match_logic: matchLogic,
      conditions,
      updated_at: new Date().toISOString(),
    };
    setJsonText(JSON.stringify(currentRuleObj, null, 2));
    setJsonError(null);
    setEditorMode('code');
  };

  const handleSwitchToVisual = () => {
    try {
      const parsed = JSON.parse(jsonText);
      setName(parsed.name || 'Unnamed Rule');
      setDescription(parsed.description || '');
      setSeverity(parsed.severity || 'MEDIUM');
      setEnabled(parsed.enabled ?? true);
      setTagsStr(Array.isArray(parsed.tags) ? parsed.tags.join(', ') : '');
      setMatchLogic(parsed.match_logic === 'ANY' ? 'ANY' : 'ALL');
      setConditions(parsed.conditions || []);
      setJsonError(null);
      setEditorMode('visual');
    } catch (e: any) {
      setJsonError(`Invalid JSON Syntax: ${e.message}`);
    }
  };

  const handleAddCondition = () => {
    const newCond: MatchCondition = {
      id: `cond-${Date.now().toString(36)}`,
      field: 'path',
      operator: 'contains',
      value: '',
      case_sensitive: false,
    };
    setConditions([...conditions, newCond]);
  };

  const handleUpdateCondition = (index: number, updates: Partial<MatchCondition>) => {
    const updated = conditions.map((c, i) => (i === index ? { ...c, ...updates } : c));
    setConditions(updated);
  };

  const handleDeleteCondition = (index: number) => {
    setConditions(conditions.filter((_, i) => i !== index));
  };

  const handleSaveSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (editorMode === 'code') {
      try {
        const parsed = JSON.parse(jsonText);
        onSave({
          ...rule,
          ...parsed,
          updated_at: new Date().toISOString(),
        });
        setIsSaved(true);
        setTimeout(() => setIsSaved(false), 2000);
      } catch (err: any) {
        setJsonError(`Cannot save invalid JSON: ${err.message}`);
      }
    } else {
      const tags = tagsStr
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);

      const updatedRule: CustomRule = {
        ...rule,
        name: name.trim(),
        description: description.trim(),
        severity,
        enabled,
        tags,
        match_logic: matchLogic,
        conditions,
        updated_at: new Date().toISOString(),
      };
      onSave(updatedRule);
      setIsSaved(true);
      setTimeout(() => setIsSaved(false), 2000);
    }
  };

  return (
    <div className="bg-[#0B101B] border border-border rounded-xl overflow-hidden font-mono text-xs text-slate-200 flex flex-col h-full">
      {/* Editor Header Bar */}
      <div className="p-3.5 bg-surface/90 border-b border-border flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
            <Sliders className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-bold text-slate-100 text-xs flex items-center gap-2">
              Rule Definition: <span className="text-primary">{name || 'New Custom Rule'}</span>
            </h3>
            <span className="text-[10px] text-slate-400">
              YAML / JSON Heuristic Rule Specification
            </span>
          </div>
        </div>

        {/* View Mode Switcher & Save Button */}
        <div className="flex items-center gap-2">
          <div className="flex items-center bg-slate-900 p-0.5 rounded-lg border border-slate-800">
            <button
              type="button"
              onClick={() => {
                if (editorMode === 'code') handleSwitchToVisual();
                else setEditorMode('visual');
              }}
              className={`px-2.5 py-1 rounded text-xs flex items-center gap-1.5 transition-colors ${
                editorMode === 'visual'
                  ? 'bg-slate-700 text-white font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>Visual Builder</span>
            </button>
            <button
              type="button"
              onClick={() => {
                if (editorMode === 'visual') handleSwitchToCode();
                else setEditorMode('code');
              }}
              className={`px-2.5 py-1 rounded text-xs flex items-center gap-1.5 transition-colors ${
                editorMode === 'code'
                  ? 'bg-slate-700 text-white font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Code className="w-3.5 h-3.5" />
              <span>JSON Source</span>
            </button>
          </div>

          <button
            type="button"
            onClick={handleSaveSubmit}
            className="px-4 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-colors shadow-lg shadow-primary/20"
          >
            {isSaved ? (
              <>
                <Check className="w-3.5 h-3.5 text-slate-950" />
                <span>Saved!</span>
              </>
            ) : (
              <>
                <Save className="w-3.5 h-3.5" />
                <span>Save Rule</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Editor Main Body */}
      <form onSubmit={handleSaveSubmit} className="flex-1 overflow-y-auto p-4 space-y-4">
        {editorMode === 'visual' ? (
          <>
            {/* Top Metadata Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3.5 bg-slate-900/60 border border-slate-800/80 rounded-xl">
              <div className="md:col-span-2">
                <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                  Rule Name
                </label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Unauthenticated Admin Surface Access"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-primary"
                />
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                  Severity Level
                </label>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as RuleSeverity)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-primary font-bold"
                >
                  <option value="CRITICAL" className="text-rose-400">CRITICAL ⚠️</option>
                  <option value="HIGH" className="text-orange-400">HIGH</option>
                  <option value="MEDIUM" className="text-yellow-400">MEDIUM</option>
                  <option value="LOW" className="text-blue-400">LOW</option>
                  <option value="INFO" className="text-slate-400">INFO</option>
                </select>
              </div>

              <div className="md:col-span-2">
                <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                  Description / Security Rationale
                </label>
                <input
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="e.g. Detects endpoints containing /admin/ with 200 OK responses missing auth tokens"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-primary"
                />
              </div>

              <div>
                <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                  Tags (Comma separated)
                </label>
                <input
                  type="text"
                  value={tagsStr}
                  onChange={(e) => setTagsStr(e.target.value)}
                  placeholder="admin, idor, high-risk"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-primary"
                />
              </div>
            </div>

            {/* Conditions Builder Section */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-slate-200 text-xs">Match Conditions</span>
                  <div className="flex items-center bg-slate-900 border border-slate-800 rounded p-0.5 text-[10px]">
                    <button
                      type="button"
                      onClick={() => setMatchLogic('ALL')}
                      className={`px-2 py-0.5 rounded transition-colors ${
                        matchLogic === 'ALL'
                          ? 'bg-primary text-slate-950 font-bold'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      ALL (AND)
                    </button>
                    <button
                      type="button"
                      onClick={() => setMatchLogic('ANY')}
                      className={`px-2 py-0.5 rounded transition-colors ${
                        matchLogic === 'ANY'
                          ? 'bg-primary text-slate-950 font-bold'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      ANY (OR)
                    </button>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={handleAddCondition}
                  className="px-2.5 py-1 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-xs font-semibold flex items-center gap-1 transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Add Condition</span>
                </button>
              </div>

              {conditions.length === 0 ? (
                <div className="p-6 bg-slate-900/40 border border-dashed border-slate-800 rounded-xl text-center text-slate-500 space-y-2">
                  <p>No match conditions defined yet.</p>
                  <button
                    type="button"
                    onClick={handleAddCondition}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 text-cyan-400 hover:bg-slate-700 text-xs inline-flex items-center gap-1"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Add First Match Condition</span>
                  </button>
                </div>
              ) : (
                <div className="space-y-2">
                  {conditions.map((cond, idx) => {
                    const needsKey = cond.field === 'header' || cond.field === 'query_param';
                    return (
                      <div
                        key={idx}
                        className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl grid grid-cols-1 md:grid-cols-12 gap-2 items-center hover:border-slate-700 transition-colors"
                      >
                        <div className="md:col-span-1 text-slate-500 font-bold text-[10px]">
                          #{idx + 1}
                        </div>

                        {/* Field Select */}
                        <div className={needsKey ? 'md:col-span-3' : 'md:col-span-4'}>
                          <select
                            value={cond.field}
                            onChange={(e) =>
                              handleUpdateCondition(idx, { field: e.target.value as MatchField })
                            }
                            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-primary"
                          >
                            {FIELD_OPTIONS.map((f) => (
                              <option key={f.value} value={f.value}>
                                {f.label}
                              </option>
                            ))}
                          </select>
                        </div>

                        {/* Key Name Input (e.g. Header name or Param name) */}
                        {needsKey && (
                          <div className="md:col-span-2">
                            <input
                              type="text"
                              placeholder={cond.field === 'header' ? 'Header (e.g. Authorization)' : 'Param (e.g. id)'}
                              value={cond.key || ''}
                              onChange={(e) =>
                                handleUpdateCondition(idx, { key: e.target.value })
                              }
                              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-primary"
                            />
                          </div>
                        )}

                        {/* Operator Select */}
                        <div className="md:col-span-3">
                          <select
                            value={cond.operator}
                            onChange={(e) =>
                              handleUpdateCondition(idx, { operator: e.target.value as MatchOperator })
                            }
                            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-primary"
                          >
                            {OPERATOR_OPTIONS.map((op) => (
                              <option key={op.value} value={op.value}>
                                {op.label}
                              </option>
                            ))}
                          </select>
                        </div>

                        {/* Target Value Input */}
                        <div className={needsKey ? 'md:col-span-2' : 'md:col-span-3'}>
                          <input
                            type="text"
                            placeholder="Target match value..."
                            value={String(cond.value ?? '')}
                            onChange={(e) =>
                              handleUpdateCondition(idx, { value: e.target.value })
                            }
                            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-primary font-mono"
                          />
                        </div>

                        {/* Remove Action */}
                        <div className="md:col-span-1 flex justify-end">
                          <button
                            type="button"
                            onClick={() => handleDeleteCondition(idx)}
                            className="p-1.5 text-slate-500 hover:text-rose-400 hover:bg-rose-500/20 rounded-lg transition-colors"
                            title="Delete condition"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </>
        ) : (
          /* JSON / YAML Source Editor Mode */
          <div className="space-y-3 h-full flex flex-col">
            {jsonError && (
              <div className="p-3 bg-rose-950/40 border border-rose-500/50 rounded-xl text-rose-300 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                <span>{jsonError}</span>
              </div>
            )}
            <div className="flex-1 flex flex-col min-h-[360px]">
              <textarea
                value={jsonText}
                onChange={(e) => {
                  setJsonText(e.target.value);
                  setJsonError(null);
                }}
                className="w-full flex-1 bg-slate-950 border border-slate-700 rounded-xl p-4 font-mono text-xs text-cyan-300 focus:outline-none focus:border-primary leading-relaxed shadow-inner"
                rows={18}
                spellCheck={false}
              />
            </div>
          </div>
        )}
      </form>
    </div>
  );
};
