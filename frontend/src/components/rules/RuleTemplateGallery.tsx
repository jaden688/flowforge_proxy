import React, { useState, useMemo } from 'react';
import { CustomRule, RuleSeverity, MatchCondition } from '../../types';
import { Badge } from '../common/Badge';
import {
  ShieldAlert,
  ShieldCheck,
  Key,
  Bug,
  Settings,
  Globe,
  Code,
  Search,
  Zap,
  Plus,
  Tag,
  Filter,
} from 'lucide-react';

interface RuleTemplateGalleryProps {
  onUseTemplate: (rule: CustomRule) => void;
}

type TemplateCategory =
  | 'ALL'
  | 'ACCESS_CONTROL'
  | 'AUTH_BYPASS'
  | 'INJECTION'
  | 'SECRETS'
  | 'MISCONFIGURATION'
  | 'CORS'
  | 'API_SECURITY';

interface RuleTemplate {
  id: string;
  name: string;
  description: string;
  severity: RuleSeverity;
  category: TemplateCategory;
  tags: string[];
  match_logic: 'ALL' | 'ANY';
  conditions: MatchCondition[];
}

const CATEGORY_META: Record<TemplateCategory, { label: string; icon: React.ReactNode; color: string }> = {
  ALL: { label: 'All Categories', icon: <Filter className="w-3.5 h-3.5" />, color: 'text-slate-300' },
  ACCESS_CONTROL: { label: 'Access Control', icon: <ShieldAlert className="w-3.5 h-3.5" />, color: 'text-rose-400' },
  AUTH_BYPASS: { label: 'Auth Bypass', icon: <Key className="w-3.5 h-3.5" />, color: 'text-orange-400' },
  INJECTION: { label: 'Injection', icon: <Bug className="w-3.5 h-3.5" />, color: 'text-red-400' },
  SECRETS: { label: 'Secrets & Keys', icon: <Key className="w-3.5 h-3.5" />, color: 'text-cyan-400' },
  MISCONFIGURATION: { label: 'Misconfiguration', icon: <Settings className="w-3.5 h-3.5" />, color: 'text-yellow-400' },
  CORS: { label: 'CORS', icon: <Globe className="w-3.5 h-3.5" />, color: 'text-blue-400' },
  API_SECURITY: { label: 'API Security', icon: <Code className="w-3.5 h-3.5" />, color: 'text-purple-400' },
};

const SEVERITY_BADGE: Record<RuleSeverity, string> = {
  CRITICAL: 'danger',
  HIGH: 'warning',
  MEDIUM: 'idor',
  LOW: 'primary',
  INFO: 'neutral',
};

const RULE_TEMPLATES: RuleTemplate[] = [
  // ─── ACCESS_CONTROL ───────────────────────────────────────────────────────
  {
    id: 'tpl-admin-no-auth',
    name: 'Admin Endpoint Without Authentication',
    description: 'Detects successful 200 responses to /admin paths missing Authorization headers',
    severity: 'HIGH',
    category: 'ACCESS_CONTROL',
    tags: ['admin', 'auth', 'owasp_a1'],
    match_logic: 'ALL',
    conditions: [
      { id: 'c1', field: 'path', operator: 'contains', value: '/admin', case_sensitive: false },
      { id: 'c2', field: 'status_code', operator: 'equals', value: '200' },
      { id: 'c3', field: 'header', operator: 'not_exists', key: 'Authorization', value: '' },
    ],
  },
  {
    id: 'tpl-sequential-idor',
    name: 'Sequential ID Parameter (IDOR Risk)',
    description: 'Flags numeric path or query parameters that increment predictably — classic IDOR surface',
    severity: 'MEDIUM',
    category: 'ACCESS_CONTROL',
    tags: ['idor', 'bola', 'sequential'],
    match_logic: 'ALL',
    conditions: [
      { id: 'c1', field: 'query_param', operator: 'regex', key: 'id', value: '^\\d+$' },
      { id: 'c2', field: 'status_code', operator: 'equals', value: '200' },
    ],
  },
  {
    id: 'tpl-mass-assignment',
    name: 'Mass Assignment Probe',
    description: 'POST/PUT body containing privileged fields like is_admin, role, or permissions',
    severity: 'HIGH',
    category: 'ACCESS_CONTROL',
    tags: ['mass_assignment', 'privilege', 'owasp_a4'],
    match_logic: 'ANY',
    conditions: [
      { id: 'c1', field: 'request_body', operator: 'contains', value: '"is_admin"', case_sensitive: false },
      { id: 'c2', field: 'request_body', operator: 'contains', value: '"role"', case_sensitive: false },
      { id: 'c3', field: 'request_body', operator: 'contains', value: '"permissions"', case_sensitive: false },
    ],
  },

  // ─── AUTH_BYPASS ──────────────────────────────────────────────────────────
  {
    id: 'tpl-jwt-none-alg',
    name: 'JWT None Algorithm',
    description: 'Detects JWTs using the "none" algorithm — allows signature bypass',
    severity: 'CRITICAL',
    category: 'AUTH_BYPASS',
    tags: ['jwt', 'auth_bypass', 'critical'],
    match_logic: 'ALL',
    conditions: [
      { id: 'c1', field: 'header', operator: 'contains', key: 'Authorization', value: 'eyJ' },
      { id: 'c2', field: 'header', operator: 'regex', key: 'Authorization', value: 'none' },
    ],
  },
  {
    id: 'tpl-auth-header-strip',
    name: 'Auth Header Stripping Detected',
    description: 'Successful response after Authorization header is removed or empty',
    severity: 'CRITICAL',
    category: 'AUTH_BYPASS',
    tags: ['auth_strip', 'privilege', 'owasp_a7'],
    match_logic: 'ALL',
    conditions: [
      { id: 'c1', field: 'header', operator: 'equals', key: 'Authorization', value: '' },
      { id: 'c2', field: 'status_code', operator: 'equals', value: '200' },
      { id: 'c3', field: 'path', operator: 'regex', value: '/(admin|user|account|profile)' },
    ],
  },
  {
    id: 'tpl-token-in-url',
    name: 'Token or Session in Query String',
    description: 'Auth tokens exposed in URL query parameters — leaks via logs and Referer headers',
    severity: 'HIGH',
    category: 'AUTH_BYPASS',
    tags: ['token_leak', 'url_leak', 'owasp_a3'],
    match_logic: 'ANY',
    conditions: [
      { id: 'c1', field: 'query_param', operator: 'regex', key: 'token', value: '.{20,}' },
      { id: 'c2', field: 'query_param', operator: 'regex', key: 'session', value: '.{20,}' },
      { id: 'c3', field: 'query_param', operator: 'regex', key: 'api_key', value: '.{20,}' },
    ],
  },

  // ─── INJECTION ────────────────────────────────────────────────────────────
  {
    id: 'tpl-sql-error-leak',
    name: 'SQL Error Message Leak',
    description: 'Response body containing SQL syntax errors — confirms injection surface',
    severity: 'HIGH',
    category: 'INJECTION',
    tags: ['sqli', 'error_leak', 'owasp_a1'],
    match_logic: 'ANY',
    conditions: [
      { id: 'c1', field: 'response_body', operator: 'contains', value: 'SQL syntax' },
      { id: 'c2', field: 'response_body', operator: 'contains', value: 'mysql_fetch' },
      { id: 'c3', field: 'response_body', operator: 'contains', value: 'ORA-01756' },
      { id: 'c4', field: 'response_body', operator: 'contains', value: 'unclosed quotation mark' },
    ],
  },
  {
    id: 'tpl-reflected-xss',
    name: 'Reflected XSS Indicator',
    description: 'Request parameter value echoed verbatim in response body without encoding',
    severity: 'HIGH',
    category: 'INJECTION',
    tags: ['xss', 'reflection', 'owasp_a7'],
    match_logic: 'ALL',
    conditions: [
      { id: 'c1', field: 'response_body', operator: 'contains', value: '<script>' },
      { id: 'c2', field: 'status_code', operator: 'equals', value: '200' },
    ],
  },
  {
    id: 'tpl-ssti-indicator',
    name: 'Server-Side Template Injection',
    description: 'Template expression patterns reflected in response — SSTI confirmation',
    severity: 'CRITICAL',
    category: 'INJECTION',
    tags: ['ssti', 'template_injection'],
    match_logic: 'ANY',
    conditions: [
      { id: 'c1', field: 'response_body', operator: 'regex', value: '\\{\\{.*\\}\\}' },
      { id: 'c2', field: 'response_body', operator: 'contains', value: '{{7*7}}' },
      { id: 'c3', field: 'response_body', operator: 'contains', value: '${7*7}' },
    ],
  },
  {
    id: 'tpl-cmd-injection',
    name: 'OS Command Injection Leak',
    description: 'Shell command output patterns appearing in responses',
    severity: 'CRITICAL',
    category: 'INJECTION',
    tags: ['cmdi', 'rce', 'owasp_a1'],
    match_logic: 'ANY',
    conditions: [
      { id: 'c1', field: 'response_body', operator: 'regex', value: 'uid=\\d+\\(' },
      { id: 'c2', field: 'response_body', operator: 'contains', value: '/bin/sh' },
      { id: 'c3', field: 'response_body', operator: 'contains', value: 'root:x:0:0' },
    ],
  },

  // ─── SECRETS ──────────────────────────────────────────────────────────────
  {
    id: 'tpl-api-key-response',
    name: 'API Key in Response Body',
    description: 'Response leaking API keys, tokens, or secret strings (high-entropy patterns)',
    severity: 'HIGH',
    category: 'SECRETS',
    tags: ['api_key', 'secret_leak', 'owasp_a3'],
    match_logic: 'ALL',
    conditions: [
      { id: 'c1', field: 'entropy', operator: 'gt', value: '5.8' },
      { id: 'c2', field: 'response_body', operator: 'regex', value: '(key|token|secret|password)' },
      { id: 'c3', field: 'status_code', operator: 'equals', value: '200' },
    ],
  },
  {
    id: 'tpl-aws-key',
    name: 'AWS Access Key Exposure',
    description: 'AWS AKIA-prefixed keys detected in request or response',
    severity: 'CRITICAL',
    category: 'SECRETS',
    tags: ['aws', 'cloud_key', 'critical'],
    match_logic: 'ALL',
    conditions: [
      { id: 'c1', field: 'response_body', operator: 'regex', value: 'AKIA[0-9A-Z]{16}' },
    ],
  },
  {
    id: 'tpl-private-key',
    name: 'Private Key Material Leak',
    description: 'PEM-encoded private keys found in responses or request bodies',
    severity: 'CRITICAL',
    category: 'SECRETS',
    tags: ['private_key', 'pem', 'credential'],
    match_logic: 'ALL',
    conditions: [
      { id: 'c1', field: 'response_body', operator: 'contains', value: '-----BEGIN' },
      { id: 'c2', field: 'response_body', operator: 'contains', value: 'PRIVATE KEY' },
    ],
  },

  // ─── MISCONFIGURATION ─────────────────────────────────────────────────────
  {
    id: 'tpl-server-version',
    name: 'Server Version Disclosure',
    description: 'Server header revealing version info — aids attacker fingerprinting',
    severity: 'LOW',
    category: 'MISCONFIGURATION',
    tags: ['info_disclosure', 'server_header'],
    match_logic: 'ALL',
    conditions: [
      { id: 'c1', field: 'header', operator: 'regex', key: 'Server', value: '\\d+\\.\\d+' },
    ],
  },
  {
    id: 'tpl-directory-listing',
    name: 'Directory Listing Enabled',
    description: 'Directory index pages exposed — reveals file structure',
    severity: 'MEDIUM',
    category: 'MISCONFIGURATION',
    tags: ['directory_listing', 'file_exposure'],
    match_logic: 'ALL',
    conditions: [
      { id: 'c1', field: 'response_body', operator: 'contains', value: 'Index of /' },
      { id: 'c2', field: 'status_code', operator: 'equals', value: '200' },
    ],
  },
  {
    id: 'tpl-error-detail-leak',
    name: 'Verbose Error Details',
    description: 'Stack traces or error details leaked in responses',
    severity: 'MEDIUM',
    category: 'MISCONFIGURATION',
    tags: ['error_leak', 'stack_trace', 'owasp_a6'],
    match_logic: 'ANY',
    conditions: [
      { id: 'c1', field: 'response_body', operator: 'contains', value: 'Traceback (most recent call last)' },
      { id: 'c2', field: 'response_body', operator: 'contains', value: 'at com.' },
      { id: 'c3', field: 'response_body', operator: 'contains', value: 'NullPointerException' },
    ],
  },

  // ─── CORS ─────────────────────────────────────────────────────────────────
  {
    id: 'tpl-cors-wildcard',
    name: 'CORS Wildcard with Credentials',
    description: 'Access-Control-Allow-Origin: * combined with credentials — allows credential theft',
    severity: 'HIGH',
    category: 'CORS',
    tags: ['cors', 'credential_theft', 'owasp_a7'],
    match_logic: 'ALL',
    conditions: [
      { id: 'c1', field: 'header', operator: 'equals', key: 'Access-Control-Allow-Origin', value: '*' },
      { id: 'c2', field: 'header', operator: 'equals', key: 'Access-Control-Allow-Credentials', value: 'true' },
    ],
  },
  {
    id: 'tpl-cors-null-origin',
    name: 'CORS Null Origin Reflection',
    description: 'Server reflects "null" origin in Access-Control-Allow-Origin — bypasses same-origin',
    severity: 'HIGH',
    category: 'CORS',
    tags: ['cors', 'origin_reflection'],
    match_logic: 'ALL',
    conditions: [
      { id: 'c1', field: 'header', operator: 'equals', key: 'Access-Control-Allow-Origin', value: 'null' },
    ],
  },

  // ─── API_SECURITY ────────────────────────────────────────────────────────
  {
    id: 'tpl-graphql-introspection',
    name: 'GraphQL Introspection Enabled',
    description: 'Active GraphQL schema introspection — leaks full API type system',
    severity: 'MEDIUM',
    category: 'API_SECURITY',
    tags: ['graphql', 'introspection', 'owasp_api'],
    match_logic: 'ALL',
    conditions: [
      { id: 'c1', field: 'response_body', operator: 'contains', value: '__schema' },
      { id: 'c2', field: 'response_body', operator: 'contains', value: '__type' },
      { id: 'c3', field: 'status_code', operator: 'equals', value: '200' },
    ],
  },
  {
    id: 'tpl-debug-endpoint',
    name: 'Debug / Actuator Endpoint Exposed',
    description: 'Spring Boot actuator or debug paths returning sensitive system info',
    severity: 'HIGH',
    category: 'API_SECURITY',
    tags: ['debug', 'actuator', 'info_disclosure'],
    match_logic: 'ANY',
    conditions: [
      { id: 'c1', field: 'path', operator: 'contains', value: '/actuator' },
      { id: 'c2', field: 'path', operator: 'contains', value: '/debug' },
      { id: 'c3', field: 'path', operator: 'contains', value: '/env' },
    ],
  },
];

function makeTemplateRule(t: RuleTemplate): CustomRule {
  const now = new Date().toISOString();
  return {
    id: `rule-${t.id}-${Date.now().toString(36)}`,
    name: t.name,
    description: t.description,
    severity: t.severity,
    enabled: true,
    tags: [...t.tags],
    match_logic: t.match_logic,
    conditions: t.conditions.map((c) => ({ ...c, id: `cond-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}` })),
    matches_count: 0,
    created_at: now,
    updated_at: now,
  };
}

export const RuleTemplateGallery: React.FC<RuleTemplateGalleryProps> = ({ onUseTemplate }) => {
  const [selectedCategory, setSelectedCategory] = useState<TemplateCategory>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredTemplates = useMemo(() => {
    return RULE_TEMPLATES.filter((t) => {
      if (selectedCategory !== 'ALL' && t.category !== selectedCategory) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const match =
          t.name.toLowerCase().includes(q) ||
          t.description.toLowerCase().includes(q) ||
          t.tags.some((tag) => tag.toLowerCase().includes(q));
        if (!match) return false;
      }
      return true;
    });
  }, [selectedCategory, searchQuery]);

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { ALL: RULE_TEMPLATES.length };
    RULE_TEMPLATES.forEach((t) => {
      counts[t.category] = (counts[t.category] || 0) + 1;
    });
    return counts;
  }, []);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-purple-500/20 text-purple-400 border border-purple-500/30">
            <Zap className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-bold text-slate-100 text-xs">Rule Templates</h3>
            <span className="text-[10px] text-slate-400">
              {RULE_TEMPLATES.length} pre-built detection patterns across {Object.keys(CATEGORY_META).length - 1} categories
            </span>
          </div>
        </div>
      </div>

      {/* Search + Category Filter */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search templates by name, description, or tags..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-2.5 py-1.5 bg-slate-950 border border-slate-700/80 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-primary"
          />
        </div>
        <select
          value={selectedCategory}
          onChange={(e) => setSelectedCategory(e.target.value as TemplateCategory)}
          className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none shrink-0"
        >
          {Object.entries(CATEGORY_META).map(([key, meta]) => (
            <option key={key} value={key}>
              {meta.label} ({categoryCounts[key] || 0})
            </option>
          ))}
        </select>
      </div>

      {/* Category Chips */}
      <div className="flex flex-wrap gap-1.5">
        {(Object.entries(CATEGORY_META) as [TemplateCategory, typeof CATEGORY_META.ALL][]).map(([key, meta]) => {
          if (key === 'ALL') return null;
          const isActive = selectedCategory === key;
          return (
            <button
              key={key}
              onClick={() => setSelectedCategory(isActive ? 'ALL' : key)}
              className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border transition-all flex items-center gap-1 ${
                isActive
                  ? 'bg-primary/20 text-primary border-primary/40'
                  : 'bg-slate-900 text-slate-400 border-slate-800 hover:border-slate-600 hover:text-slate-300'
              }`}
            >
              {meta.icon}
              <span>{meta.label}</span>
              <span className="text-[9px] opacity-60">({categoryCounts[key] || 0})</span>
            </button>
          );
        })}
      </div>

      {/* Template Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
        {filteredTemplates.map((tpl) => {
          const catMeta = CATEGORY_META[tpl.category];
          return (
            <div
              key={tpl.id}
              className="p-3 bg-slate-900/70 border border-slate-800 rounded-xl hover:border-slate-600 transition-all group"
            >
              <div className="flex items-start justify-between gap-2 mb-1.5">
                <div className="flex items-center gap-1.5">
                  <span className={`p-1 rounded ${catMeta.color}`}>
                    {catMeta.icon}
                  </span>
                  <Badge variant={SEVERITY_BADGE[tpl.severity] as any} size="sm">
                    {tpl.severity}
                  </Badge>
                </div>
                <button
                  onClick={() => onUseTemplate(makeTemplateRule(tpl))}
                  className="px-2 py-0.5 rounded bg-primary/20 hover:bg-primary/30 text-primary text-[10px] font-bold border border-primary/30 opacity-0 group-hover:opacity-100 transition-all flex items-center gap-1"
                >
                  <Plus className="w-3 h-3" />
                  Use
                </button>
              </div>

              <h4 className="font-bold text-slate-100 text-xs mb-0.5 leading-tight">{tpl.name}</h4>
              <p className="text-[10px] text-slate-400 leading-snug mb-2">{tpl.description}</p>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1 flex-wrap">
                  {tpl.tags.slice(0, 3).map((tag) => (
                    <span key={tag} className="px-1.5 py-0 rounded bg-slate-800 text-slate-500 text-[9px] font-mono">
                      {tag}
                    </span>
                  ))}
                  {tpl.tags.length > 3 && (
                    <span className="text-[9px] text-slate-600">+{tpl.tags.length - 3}</span>
                  )}
                </div>
                <span className="text-[10px] text-slate-500 font-mono">
                  {tpl.conditions.length} cond ({tpl.match_logic})
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {filteredTemplates.length === 0 && (
        <div className="p-8 text-center text-slate-500 text-xs">
          No templates match your search criteria.
        </div>
      )}
    </div>
  );
};
