import { create } from 'zustand';
import { 
  FlowRecord, 
  TriageSummary, 
  ActiveView, 
  FilterState, 
  EndpointDossier, 
  TestMatrixJob, 
  TestMatrixCase,
  CuratedPayloadGroup,
  PruneOptions,
  CustomRule,
  TestProposal,
  ProposalExecutionResult,
  ProposalDiffSummary,
  IntruderJob,
  IntruderResult,
  IntruderResultFilters,
  TelemetryLogEntry
} from '../types';
import { api } from '../services/api';

// Live anomaly filter for streaming intruder results.
function intruderResultMatchesFilters(r: IntruderResult, f: IntruderResultFilters): boolean {
  if (f.anomaliesOnly && (!r.anomaly_reasons || r.anomaly_reasons.length === 0)) return false;
  if (f.reflectedOnly && !r.reflected) return false;
  if (f.statusCodes.length > 0 && (r.status_code == null || !f.statusCodes.includes(r.status_code))) return false;
  if (f.minSize != null && (r.response_size_bytes == null || r.response_size_bytes < f.minSize)) return false;
  if (f.maxSize != null && (r.response_size_bytes == null || r.response_size_bytes > f.maxSize)) return false;
  if (f.minTimeMs != null && (r.response_time_ms == null || r.response_time_ms < f.minTimeMs)) return false;
  if (f.maxTimeMs != null && (r.response_time_ms == null || r.response_time_ms > f.maxTimeMs)) return false;
  if (f.payloadSearch && !r.payload.toLowerCase().includes(f.payloadSearch.toLowerCase())) return false;
  return true;
}

interface FlowStoreState {
  // Flows state
  flows: Record<string, FlowRecord>;
  flowOrder: string[];
  selectedFlowId: string | null;
  
  // Navigation & Filtering
  activeView: ActiveView;
  filters: FilterState;
  
  // Real-time Connection status
  wsConnected: boolean;
  wsLatencyMs: number;
  isPaused: boolean;

  // Global Heuristic Counters
  stats: {
    totalFlows: number;
    reflectionsCount: number;
    idorCount: number;
    secretsCount: number;
    authAnomaliesCount: number;
  };

  // Target Dossiers
  dossiers: Record<string, EndpointDossier>;
  selectedDossierKey: string | null;

  // Staging / Matrix state
  activeMatrixJob: TestMatrixJob | null;

  // Active Intruder state
  activeIntruderJob: IntruderJob | null;
  intruderResults: IntruderResult[];
  intruderResultFilters: IntruderResultFilters;

  // Payload Curation State (F25-F26)
  payloadGroups: Record<string, CuratedPayloadGroup>;

  // Custom Rules Engine State (F31-F32)
  rules: Record<string, CustomRule>;
  ruleOrder: string[];
  activeRuleId: string | null;

  // Diff comparison pair
  diffFlowAId: string | null;
  diffFlowBId: string | null;

  // Automated Test Proposals State (M3-M4)
  proposals: Record<string, TestProposal>;
  proposalOrder: string[];
  isApprovalDrawerOpen: boolean;
  activeProposalFlowId: string | null;
  filterOnlyWithProposals: boolean;
  activeDiffProposal: TestProposal | null;
  telemetryLogs: TelemetryLogEntry[];

  // Actions
  addFlow: (flow: FlowRecord) => void;
  updateFlow: (id: string, partial: Partial<FlowRecord>) => void;
  setTriage: (flowId: string, triage: TriageSummary) => void;
  selectFlow: (id: string | null) => void;
  setActiveView: (view: ActiveView) => void;
  setFilters: (filters: Partial<FilterState>) => void;
  resetFilters: () => void;
  clearFlows: () => void;
  setPaused: (paused: boolean) => void;
  setWsStatus: (connected: boolean, latency?: number) => void;
  addTelemetryLog: (log: TelemetryLogEntry) => void;
  clearTelemetryLogs: () => void;
  
  // Dossier actions
  setDossiers: (dossiers: EndpointDossier[]) => void;
  updateDossier: (dossier: EndpointDossier) => void;
  selectDossier: (key: string | null) => void;

  // Matrix actions
  setMatrixJob: (job: TestMatrixJob | null) => void;
  updateMatrixCase: (caseId: string, updates: Partial<TestMatrixCase>) => void;
  toggleCaseSelected: (caseId: string) => void;
  toggleAllCasesSelected: (selected: boolean) => void;

  // Intruder actions
  setActiveIntruderJob: (job: IntruderJob | null) => void;  addIntruderResult: (result: IntruderResult) => void;
  updateIntruderJobProgress: (progress: {
    job_id: string;
    status?: string;
    completed_requests?: number;
    total_requests?: number;
  }) => void;
  setIntruderResultFilters: (filters: Partial<IntruderResultFilters>) => void;
  clearIntruderResults: () => void;
  resetEngagementState: () => void;
  clearCapturedData: (flags: {
    flows?: boolean;
    endpoints?: boolean;
    proposals?: boolean;
    intruder_jobs?: boolean;
    wordlists?: boolean;
    curated_payloads?: boolean;
  }) => Promise<{ ok: boolean; cleared: Record<string, number> }>;

  // Curation & Pruning actions (F25-F26)
  createPayloadGroup: (group: Omit<CuratedPayloadGroup, 'id' | 'created_at' | 'updated_at'>) => void;
  deletePayloadGroup: (groupId: string) => void;
  importPayloadGroups: (groups: CuratedPayloadGroup[]) => void;
  assignCasesToGroup: (caseIds: string[], groupId: string | null) => void;
  toggleStarCase: (caseId: string) => void;
  togglePinCase: (caseId: string) => void;
  pruneCases: (options: PruneOptions) => void;

  // Rule engine actions (F31-F32)
  addRule: (rule: CustomRule) => void;
  updateRule: (id: string, updates: Partial<CustomRule>) => void;
  deleteRule: (id: string) => void;
  toggleRule: (id: string) => void;
  selectRule: (id: string | null) => void;
  syncRulesFromBackend: () => Promise<void>;

  // Diff actions
  setDiffPair: (flowAId: string | null, flowBId: string | null) => void;

  // Proposal Actions (M3-M4)
  addProposal: (proposal: TestProposal) => void;
  setProposals: (proposals: TestProposal[]) => void;
  updateProposal: (id: string, updates: Partial<TestProposal>) => void;
  approveProposal: (id: string) => Promise<any>;
  dismissProposal: (id: string) => Promise<any> | void;
  dismissAllProposals: (flowId?: string) => Promise<any> | void;
  toggleApprovalDrawer: (open?: boolean, flowId?: string | null) => void;
  setFilterOnlyWithProposals: (only: boolean) => void;
  setActiveDiffProposal: (proposal: TestProposal | null) => void;
  transferProposalToMatrix: (proposalId: string) => void;
  saveProposalToCurated: (proposalId: string, groupId?: string) => void;
  transferProposalToIntruder: (proposalId: string) => Promise<void>;
  sweepProposalsToIntruder: (opts?: { min_confidence?: number; max_proposals?: number }) => Promise<any>;
}

const initialFilters: FilterState = {
  search: '',
  methods: [],
  statusGroup: 'all',
  tags: [],
  host: '',
  onlyAnomalies: false,
};

const defaultPayloadGroups: Record<string, CuratedPayloadGroup> = {
  'group-bola': {
    id: 'group-bola',
    name: 'Active BOLA Probes',
    description: 'Targeted IDOR and BOLA horizontal privilege escalation mutations',
    color: '#38BDF8',
    tags: ['idor', 'bola', 'high-risk'],
    case_ids: [],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  'group-auth': {
    id: 'group-auth',
    name: 'Privilege & Role Escalation',
    description: 'Header stripping, JWT role tampering, and admin impersonation test set',
    color: '#C084FC',
    tags: ['auth', 'privilege', 'roles'],
    case_ids: [],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  'group-refl': {
    id: 'group-refl',
    name: 'Reflected Input Probes',
    description: 'Candidate payload strings flagged for response body reflection and XSS testing',
    color: '#FACC15',
    tags: ['reflection', 'xss', 'inputs'],
    case_ids: [],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
};

const defaultRules: Record<string, CustomRule> = {};

function normalizeFlowRecord(flow: any): FlowRecord {
  if (!flow) return flow;
  
  const reqObj = flow.request || {};
  const respObj = flow.response || {};

  const reqHeaders = (reqObj.headers && Object.keys(reqObj.headers).length > 0)
    ? reqObj.headers
    : (flow.request_headers || {});

  const respHeaders = (respObj.headers && Object.keys(respObj.headers).length > 0)
    ? respObj.headers
    : (flow.response_headers || {});

  const reqBody = (reqObj.body !== undefined && reqObj.body !== null)
    ? reqObj.body
    : (flow.request_body ?? null);

  const respBody = (respObj.body !== undefined && respObj.body !== null)
    ? respObj.body
    : (flow.response_body ?? null);

  const queryParams = (reqObj.query_params && Object.keys(reqObj.query_params).length > 0)
    ? reqObj.query_params
    : (flow.query_params || {});

  const reqCookies = (reqObj.cookies && Object.keys(reqObj.cookies).length > 0)
    ? reqObj.cookies
    : (flow.request_cookies || {});

  const respCookies = (respObj.cookies && Object.keys(respObj.cookies).length > 0)
    ? respObj.cookies
    : (flow.response_cookies || {});

  const reqSize = flow.request_size 
    ?? flow.request_content_length 
    ?? reqObj.content_length 
    ?? flow.telemetry?.bandwidth?.request_body_bytes 
    ?? (reqBody ? reqBody.length : 0);

  const respSize = flow.response_size 
    ?? flow.response_content_length 
    ?? respObj.content_length 
    ?? flow.telemetry?.bandwidth?.response_body_bytes 
    ?? (respBody ? respBody.length : 0);

  const status = flow.response_status 
    ?? flow.response_status_code 
    ?? flow.status_code 
    ?? respObj.status_code 
    ?? null;

  return {
    ...flow,
    url: flow.url || reqObj.url || '',
    method: (flow.method || reqObj.method || 'GET').toUpperCase(),
    path: flow.path || reqObj.path || '/',
    host: flow.host || flow.server_host || reqObj.host || (flow.url && flow.url.startsWith('http') ? new URL(flow.url).host : ''),
    query_params: queryParams,
    request_headers: reqHeaders,
    response_headers: respHeaders,
    request_body: reqBody,
    response_body: respBody,
    request_cookies: reqCookies,
    response_cookies: respCookies,
    request_content_type: flow.request_content_type || reqObj.content_type || reqHeaders['content-type'] || null,
    response_content_type: flow.response_content_type || respObj.content_type || respHeaders['content-type'] || null,
    request_size: reqSize,
    response_size: respSize,
    response_status: status,
    response_status_code: status,
    response_status_text: flow.response_status_text || flow.response_reason || respObj.reason || null,
    latency_ms: flow.latency_ms ?? flow.duration_ms ?? 0,
    duration_ms: flow.duration_ms ?? flow.latency_ms ?? 0,
    triage: flow.triage || flow.triage_data || null,
  };
}


export const useFlowStore = create<FlowStoreState>((set, get) => ({
  flows: {},
  flowOrder: [],
  selectedFlowId: null,
  activeView: 'stream',
  filters: initialFilters,
  wsConnected: false,
  wsLatencyMs: 12,
  isPaused: false,

  stats: {
    totalFlows: 0,
    reflectionsCount: 0,
    idorCount: 0,
    secretsCount: 0,
    authAnomaliesCount: 0,
  },

  dossiers: {},
  selectedDossierKey: null,
  activeMatrixJob: null,

  activeIntruderJob: null,
  intruderResults: [],
  intruderResultFilters: {
    anomaliesOnly: false,
    reflectedOnly: false,
    minSize: null,
    maxSize: null,
    minTimeMs: null,
    maxTimeMs: null,
    statusCodes: [],
    payloadSearch: '',
  },
  payloadGroups: defaultPayloadGroups,

  rules: defaultRules,
  ruleOrder: Object.keys(defaultRules),
  activeRuleId: 'rule-admin-surface',

  diffFlowAId: null,
  diffFlowBId: null,

  proposals: {},
  proposalOrder: [],
  isApprovalDrawerOpen: false,
  activeProposalFlowId: null,
  filterOnlyWithProposals: false,
  activeDiffProposal: null,
  telemetryLogs: [],

  addFlow: (flowRaw: FlowRecord) => {
    if (get().isPaused) return;
    const flow = normalizeFlowRecord(flowRaw);

    set((state) => {
      const existing = state.flows[flow.id];
      const newFlows = {
        ...state.flows,
        [flow.id]: existing ? { ...existing, ...flow } : flow,
      };
      
      const newOrder = existing 
        ? state.flowOrder 
        : [flow.id, ...state.flowOrder.slice(0, 4999)]; // Keep up to 5000 in memory


      let reflectionsInc = 0;
      let idorInc = 0;
      let secretsInc = 0;
      let authInc = 0;

      const triage = flow.triage || (flow as any).triage_data;
      if (!existing) {
        if (triage) {
          const reflections = triage.reflections || [];
          const identifiers = triage.identifier_findings || (triage as any).identifiers || [];
          const secrets = triage.secret_findings || (triage as any).entropy || [];
          const authFindings = triage.auth_findings || ((triage as any).auth?.anomaly_flags || []);

          if (reflections.length > 0) reflectionsInc = reflections.length;
          if (identifiers.some((i: any) => (i.idor_risk_score && i.idor_risk_score >= 0.45) || i.idor_risk === 'HIGH' || i.is_sequential_integer)) idorInc += 1;
          if (secrets.length > 0) secretsInc = secrets.length;
          if (authFindings.length > 0) authInc += 1;
        } else if (flow.tags) {
          if (flow.tags.includes('reflection')) reflectionsInc += 1;
          if (flow.tags.includes('idor_candidate') || flow.tags.includes('idor')) idorInc += 1;
          if (flow.tags.includes('secrets')) secretsInc += 1;
          if (flow.tags.includes('auth_anomaly') || flow.tags.includes('auth')) authInc += 1;
        }
      }

      return {
        flows: newFlows,
        flowOrder: newOrder,
        stats: {
          totalFlows: newOrder.length,
          reflectionsCount: state.stats.reflectionsCount + reflectionsInc,
          idorCount: state.stats.idorCount + idorInc,
          secretsCount: state.stats.secretsCount + secretsInc,
          authAnomaliesCount: state.stats.authAnomaliesCount + authInc,
        },
      };
    });
  },

  updateFlow: (id: string, partial: Partial<FlowRecord>) => {
    set((state) => {
      const existing = state.flows[id];
      if (!existing) return state;
      const updated = normalizeFlowRecord({ ...existing, ...partial });
      return {
        flows: {
          ...state.flows,
          [id]: updated,
        },
      };
    });
  },


  setTriage: (flowId: string, triage: TriageSummary) => {
    set((state) => {
      const existing = state.flows[flowId];
      if (!existing) return state;

      const reflections = triage.reflections || [];
      const identifiers = (triage as any).identifier_findings || (triage as any).identifiers || [];
      const secrets = (triage as any).secret_findings || (triage as any).entropy || [];
      const authFindings = (triage as any).auth_findings || ((triage as any).auth?.anomaly_flags || []);

      const hasIdor = identifiers.some((i: any) => (i.idor_risk_score && i.idor_risk_score >= 0.45) || i.idor_risk === 'HIGH' || i.is_sequential_integer);
      const hasSecrets = secrets.length > 0;
      const hasAuthAnomaly = authFindings.length > 0;

      const updated = {
        ...existing,
        triage,
        tags: Array.from(new Set([
          ...(existing.tags || []),
          ...(reflections.length ? ['reflection'] : []),
          ...(hasIdor ? ['idor'] : []),
          ...(hasAuthAnomaly ? ['auth_anomaly'] : []),
          ...(hasSecrets ? ['secrets'] : []),
          ...(triage.endpoint_category ? [triage.endpoint_category.toLowerCase()] : []),
        ])),
      };

      return {
        flows: {
          ...state.flows,
          [flowId]: updated,
        },
        stats: {
          ...state.stats,
          reflectionsCount: state.stats.reflectionsCount + reflections.length,
          idorCount: state.stats.idorCount + (hasIdor ? 1 : 0),
          secretsCount: state.stats.secretsCount + secrets.length,
          authAnomaliesCount: state.stats.authAnomaliesCount + (hasAuthAnomaly ? 1 : 0),
        }
      };
    });
  },


  selectFlow: async (id: string | null) => {
    set({ selectedFlowId: id });
    if (id) {
      const current = get().flows[id];
      if (!current || !current.request_headers || Object.keys(current.request_headers).length === 0 || current.request_body === undefined) {
        try {
          const full = await api.getFlow(id);
          if (full) {
            get().updateFlow(id, full);
          }
        } catch (e) {
          // ignore error if flow deleted
        }
      }
    }
  },


  setActiveView: (view: ActiveView) => set({ activeView: view }),

  setFilters: (newFilters: Partial<FilterState>) => {
    set((state) => ({
      filters: { ...state.filters, ...newFilters },
    }));
  },

  resetFilters: () => set({ filters: initialFilters }),

  clearFlows: () => {
    set({
      flows: {},
      flowOrder: [],
      selectedFlowId: null,
      stats: {
        totalFlows: 0,
        reflectionsCount: 0,
        idorCount: 0,
        secretsCount: 0,
        authAnomaliesCount: 0,
      },
    });
  },

  setPaused: (paused: boolean) => set({ isPaused: paused }),

  setWsStatus: (connected: boolean, latency = 12) => {
    set({ wsConnected: connected, wsLatencyMs: latency });
  },

  addTelemetryLog: (log: TelemetryLogEntry) => {
    set((state) => ({
      telemetryLogs: [log, ...state.telemetryLogs.slice(0, 99)],
    }));
  },

  clearTelemetryLogs: () => {
    set({ telemetryLogs: [] });
  },

  setDossiers: (dossierList: EndpointDossier[]) => {
    const map: Record<string, EndpointDossier> = {};
    dossierList.forEach((d) => {
      const key = `${d.host}::${d.path_template}`;
      map[key] = d;
    });
    set({ dossiers: map });
  },

  updateDossier: (dossier: EndpointDossier) => {
    const key = `${dossier.host}::${dossier.path_template}`;
    set((state) => ({
      dossiers: { ...state.dossiers, [key]: dossier },
    }));
  },

  selectDossier: (key: string | null) => set({ selectedDossierKey: key }),

  setMatrixJob: (job: TestMatrixJob | null) => set({ activeMatrixJob: job }),

  setActiveIntruderJob: (job: IntruderJob | null) =>
    set({ activeIntruderJob: job, intruderResults: job ? [] : get().intruderResults }),

  addIntruderResult: (result: IntruderResult) => {
    const filters = get().intruderResultFilters;
    // Live anomaly filtering: drop rows that fail the operator's current filter.
    if (!intruderResultMatchesFilters(result, filters)) return;
    set((state) => ({
      intruderResults: [...state.intruderResults, result].slice(-3000),
    }));
  },

  updateIntruderJobProgress: (progress) => {
    const job = get().activeIntruderJob;
    if (!job || job.id !== progress.job_id) return;
    set({
      activeIntruderJob: {
        ...job,
        status: (progress.status as IntruderJob['status']) ?? job.status,
        completed_requests: progress.completed_requests ?? job.completed_requests,
        total_requests: progress.total_requests ?? job.total_requests,
      },
    });
  },

  setIntruderResultFilters: (filters) =>
    set((state) => ({ intruderResultFilters: { ...state.intruderResultFilters, ...filters } })),

  clearIntruderResults: () => set({ intruderResults: [] }),

  resetEngagementState: () => {
    set({
      flows: {},
      flowOrder: [],
      selectedFlowId: null,
      proposals: {},
      proposalOrder: [],
      dossiers: {},
      activeMatrixJob: null,
      activeIntruderJob: null,
      intruderResults: [],
      stats: {
        totalFlows: 0,
        reflectionsCount: 0,
        idorCount: 0,
        secretsCount: 0,
        authAnomaliesCount: 0,
      },
    });
  },

  clearCapturedData: async (flags) => {
    try {
      const result = await api.clearData(flags);
      if (result.ok) {
        // Selectively reset client-side state based on what was cleared
        if (flags.flows) {
          set({
            flows: {},
            flowOrder: [],
            selectedFlowId: null,
            stats: {
              totalFlows: 0,
              reflectionsCount: 0,
              idorCount: 0,
              secretsCount: 0,
              authAnomaliesCount: 0,
            },
          });
        }
        if (flags.proposals) {
          set({
            proposals: {},
            proposalOrder: [],
            activeProposalFlowId: null,
            activeDiffProposal: null,
          });
        }
        if (flags.intruder_jobs) {
          set({
            activeIntruderJob: null,
            intruderResults: [],
          });
        }
        if (flags.curated_payloads) {
          set({
            payloadGroups: {},
            activeMatrixJob: null,
          });
        }
      }
      return result;
    } catch (err: any) {
      console.error('Clear data failed:', err);
      throw err;
    }
  },

  updateMatrixCase: (caseId: string, updates: Partial<TestMatrixCase>) => {
    set((state) => {
      if (!state.activeMatrixJob) return state;
      const updatedCases = state.activeMatrixJob.cases.map((c) =>
        c.id === caseId ? { ...c, ...updates } : c
      );
      return {
        activeMatrixJob: {
          ...state.activeMatrixJob,
          cases: updatedCases,
        },
      };
    });
  },

  toggleCaseSelected: (caseId: string) => {
    set((state) => {
      if (!state.activeMatrixJob) return state;
      const updatedCases = state.activeMatrixJob.cases.map((c) =>
        c.id === caseId ? { ...c, selected: !c.selected } : c
      );
      return {
        activeMatrixJob: {
          ...state.activeMatrixJob,
          cases: updatedCases,
        },
      };
    });
  },

  toggleAllCasesSelected: (selected: boolean) => {
    set((state) => {
      if (!state.activeMatrixJob) return state;
      const updatedCases = state.activeMatrixJob.cases.map((c) => ({
        ...c,
        selected,
      }));
      return {
        activeMatrixJob: {
          ...state.activeMatrixJob,
          cases: updatedCases,
        },
      };
    });
  },

  // Curation & Pruning actions
  createPayloadGroup: (group) => {
    const id = `group-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;
    const now = new Date().toISOString();
    const newGroup: CuratedPayloadGroup = {
      ...group,
      id,
      created_at: now,
      updated_at: now,
      case_ids: group.case_ids || [],
    };
    set((state) => ({
      payloadGroups: {
        ...state.payloadGroups,
        [id]: newGroup,
      },
    }));
  },

  deletePayloadGroup: (groupId: string) => {
    set((state) => {
      const { [groupId]: _, ...remaining } = state.payloadGroups;
      let updatedJob = state.activeMatrixJob;
      if (updatedJob) {
        updatedJob = {
          ...updatedJob,
          cases: updatedJob.cases.map((c) =>
            c.group_id === groupId ? { ...c, group_id: undefined } : c
          ),
        };
      }
      return {
        payloadGroups: remaining,
        activeMatrixJob: updatedJob,
      };
    });
  },

  importPayloadGroups: (groups: CuratedPayloadGroup[]) => {
    set((state) => {
      const merged = { ...state.payloadGroups };
      groups.forEach((g) => {
        if (g && g.id) {
          merged[g.id] = g;
        }
      });
      return { payloadGroups: merged };
    });
  },

  assignCasesToGroup: (caseIds: string[], groupId: string | null) => {
    set((state) => {
      if (!state.activeMatrixJob) return state;
      const updatedCases = state.activeMatrixJob.cases.map((c) =>
        caseIds.includes(c.id) ? { ...c, group_id: groupId || undefined } : c
      );
      const updatedGroups = { ...state.payloadGroups };
      if (groupId && updatedGroups[groupId]) {
        const existingCaseIds = new Set(updatedGroups[groupId].case_ids || []);
        caseIds.forEach(id => existingCaseIds.add(id));
        updatedGroups[groupId] = {
          ...updatedGroups[groupId],
          case_ids: Array.from(existingCaseIds),
          updated_at: new Date().toISOString(),
        };
      }
      return {
        activeMatrixJob: {
          ...state.activeMatrixJob,
          cases: updatedCases,
        },
        payloadGroups: updatedGroups,
      };
    });
  },

  toggleStarCase: (caseId: string) => {
    set((state) => {
      if (!state.activeMatrixJob) return state;
      const updatedCases = state.activeMatrixJob.cases.map((c) =>
        c.id === caseId ? { ...c, is_starred: !c.is_starred } : c
      );
      return {
        activeMatrixJob: {
          ...state.activeMatrixJob,
          cases: updatedCases,
        },
      };
    });
  },

  togglePinCase: (caseId: string) => {
    set((state) => {
      if (!state.activeMatrixJob) return state;
      const updatedCases = state.activeMatrixJob.cases.map((c) =>
        c.id === caseId ? { ...c, is_pinned: !c.is_pinned } : c
      );
      return {
        activeMatrixJob: {
          ...state.activeMatrixJob,
          cases: updatedCases,
        },
      };
    });
  },

  pruneCases: (options: PruneOptions) => {
    set((state) => {
      if (!state.activeMatrixJob) return state;

      let regex: RegExp | null = null;
      if (options.regexPattern?.trim()) {
        try {
          regex = new RegExp(options.regexPattern.trim(), 'i');
        } catch (e) {
          regex = null;
        }
      }

      const statusCodes = (options.statusCodeFilter || '')
        .split(',')
        .map(s => parseInt(s.trim(), 10))
        .filter(n => !isNaN(n));

      const updatedCases = state.activeMatrixJob.cases.filter((c) => {
        // Protection: Pinned and Starred cases are preserved if keepPinnedAndStarred is true
        if (options.keepPinnedAndStarred && (c.is_pinned || c.is_starred)) {
          return true;
        }

        // Protection: Unselected only filter
        if (options.onlyUnselected && c.selected) {
          return true;
        }

        let matchesPrune = false;

        // Check execution status
        if (options.statuses && options.statuses.length > 0) {
          if (options.statuses.includes(c.status)) {
            matchesPrune = true;
          }
        }

        // Check status code filter
        if (statusCodes.length > 0 && c.result_summary) {
          if (statusCodes.includes(c.result_summary.status_code)) {
            matchesPrune = true;
          }
        }

        // Check length delta filter
        if (options.minLengthDelta !== undefined || options.maxLengthDelta !== undefined) {
          const delta = c.result_summary?.length_delta ?? 0;
          if (options.minLengthDelta !== undefined && delta < options.minLengthDelta) {
            matchesPrune = true;
          }
          if (options.maxLengthDelta !== undefined && delta > options.maxLengthDelta) {
            matchesPrune = true;
          }
        }

        // Check regex filter on name, target param, or mutated value
        if (regex) {
          const valStr = String(c.mutated_value ?? '');
          if (regex.test(c.name) || regex.test(c.target_param_name) || regex.test(valStr)) {
            matchesPrune = true;
          }
        }

        // If matched prune criteria, remove it
        return !matchesPrune;
      });

      return {
        activeMatrixJob: {
          ...state.activeMatrixJob,
          cases: updatedCases,
          total_count: updatedCases.length,
        },
      };
    });
  },

  // Rule engine actions
  addRule: (rule: CustomRule) => {
    set((state) => ({
      rules: { ...state.rules, [rule.id]: rule },
      ruleOrder: state.ruleOrder.includes(rule.id) ? state.ruleOrder : [rule.id, ...state.ruleOrder],
      activeRuleId: rule.id,
    }));
  },

  updateRule: (id: string, updates: Partial<CustomRule>) => {
    set((state) => {
      const existing = state.rules[id];
      if (!existing) return state;
      return {
        rules: {
          ...state.rules,
          [id]: {
            ...existing,
            ...updates,
            updated_at: new Date().toISOString(),
          },
        },
      };
    });
  },

  deleteRule: (id: string) => {
    set((state) => {
      const { [id]: _, ...remaining } = state.rules;
      return {
        rules: remaining,
        ruleOrder: state.ruleOrder.filter((rId) => rId !== id),
        activeRuleId: state.activeRuleId === id ? null : state.activeRuleId,
      };
    });
  },

  toggleRule: (id: string) => {
    set((state) => {
      const existing = state.rules[id];
      if (!existing) return state;
      return {
        rules: {
          ...state.rules,
          [id]: {
            ...existing,
            enabled: !existing.enabled,
            updated_at: new Date().toISOString(),
          },
        },
      };
    });
  },

  selectRule: (id: string | null) => set({ activeRuleId: id }),

  syncRulesFromBackend: async () => {
    try {
      const result = await api.listRules();
      if (result?.rules && Array.isArray(result.rules)) {
        const backendRules: Record<string, CustomRule> = {};
        const backendOrder: string[] = [];
        result.rules.forEach((r: any) => {
          const rule: CustomRule = {
            id: r.id,
            name: r.name,
            description: r.description || '',
            severity: r.severity || 'MEDIUM',
            enabled: r.enabled ?? true,
            tags: Array.isArray(r.tags) ? r.tags : [],
            match_logic: r.match_logic || (r.condition_combinator === 'any' ? 'ANY' : 'ALL'),
            conditions: Array.isArray(r.conditions) ? r.conditions.map((c: any, i: number) => ({
              id: c.id || `cond-${r.id}-${i}`,
              field: c.field,
              operator: c.operator,
              key: c.key,
              value: c.value ?? '',
              case_sensitive: c.case_sensitive ?? false,
            })) : [],
            matches_count: r.matches_count || 0,
            created_at: r.created_at || new Date().toISOString(),
            updated_at: r.updated_at || new Date().toISOString(),
          };
          backendRules[rule.id] = rule;
          backendOrder.push(rule.id);
        });
        set((state) => {
          // Merge: keep any user-created rules not in backend, override with backend versions
          const mergedRules = { ...backendRules };
          state.ruleOrder.forEach((id) => {
            if (!mergedRules[id] && state.rules[id]) {
              // User-created rule not in backend — keep it
              mergedRules[id] = state.rules[id];
            }
          });
          const mergedOrder = [...backendOrder, ...state.ruleOrder.filter((id) => !backendRules[id])];
          return {
            rules: mergedRules,
            ruleOrder: mergedOrder,
            activeRuleId: state.activeRuleId || mergedOrder[0] || null,
          };
        });
      }
    } catch (err) {
      // Backend unavailable — keep current rules (likely empty on first load)
    }
  },

  setDiffPair: (flowAId: string | null, flowBId: string | null) => {
    set({ diffFlowAId: flowAId, diffFlowBId: flowBId });
  },

  // Proposal Actions (M3-M4)
  addProposal: (proposal: TestProposal) => {
    set((state) => {
      const existing = state.proposals[proposal.id];
      const updatedProposals = {
        ...state.proposals,
        [proposal.id]: {
          ...proposal,
          status: proposal.status || proposal.state || 'PENDING',
        },
      };
      const updatedOrder = existing
        ? state.proposalOrder
        : [proposal.id, ...state.proposalOrder.filter((id) => id !== proposal.id)];
      return {
        proposals: updatedProposals,
        proposalOrder: updatedOrder,
      };
    });
  },

  setProposals: (proposalsList: TestProposal[]) => {
    const map: Record<string, TestProposal> = {};
    const order: string[] = [];
    proposalsList.forEach((p) => {
      map[p.id] = {
        ...p,
        status: p.status || p.state || 'PENDING',
      };
      order.push(p.id);
    });
    set({ proposals: map, proposalOrder: order });
  },

  updateProposal: (id: string, updates: Partial<TestProposal>) => {
    set((state) => {
      const existing = state.proposals[id];
      if (!existing) return state;
      return {
        proposals: {
          ...state.proposals,
          [id]: {
            ...existing,
            ...updates,
            status: updates.status || updates.state || existing.status,
          },
        },
      };
    });
  },

  approveProposal: async (id: string) => {
    const state = get();
    const proposal = state.proposals[id];
    if (!proposal) return;

    get().updateProposal(id, { status: 'EXECUTING', state: 'EXECUTING' });

    try {
      const result = await api.approveAndRunProposal(id);
      if (result) {
        const updatedProposal = result.proposal || proposal;
        const baselineFlow = state.flows[proposal.flow_id];
        const baselineStatus = baselineFlow?.response_status ?? baselineFlow?.response_status_code ?? 0;
        const execStatus = result.executed_flow?.response_status ?? result.diff?.flow_b?.response_status ?? 0;
        const execResult: ProposalExecutionResult = result.proposal?.execution_result || {
          status_code: execStatus,
          status_delta: result.diff?.status_delta ?? `${execStatus} vs ${baselineStatus}`,
          length_delta_bytes: result.diff?.length_delta_bytes ?? 0,
          latency_delta_ms: result.diff?.latency_delta_ms ?? 0,
          verdict_level: result.diff?.anomaly_verdict?.level || 'INFO_DIFF',
          verdict_description: result.diff?.anomaly_verdict?.description || '',
          executed_flow_id: result.executed_flow?.id,
        };

        const diffSummary: ProposalDiffSummary = {
          status_code: execResult.status_code ?? 0,
          length_delta: execResult.length_delta_bytes ?? 0,
          latency_ms: execResult.latency_delta_ms ?? 0,
          reflected: !!execResult.reflected,
          anomaly_flag: execResult.verdict_level || null,
          status_delta: execResult.status_delta,
          verdict_level: execResult.verdict_level,
          verdict_description: execResult.verdict_description,
        };

        const finalProposal: TestProposal = {
          ...proposal,
          ...updatedProposal,
          status: 'EXECUTED',
          state: 'EXECUTED',
          executed_flow_id: result.executed_flow?.id || updatedProposal.executed_flow_id,
          execution_result: execResult,
          diff_summary: diffSummary,
        };

        get().updateProposal(id, finalProposal);

        if (result.executed_flow) {
          get().addFlow(result.executed_flow);
        }

        set({ activeDiffProposal: finalProposal });
        return result;
      }
    } catch (err: any) {
      console.error('Failed to approve proposal:', err);
      get().updateProposal(id, { status: 'PENDING', state: 'PENDING' });
      throw err;
    }
  },

  dismissProposal: async (id: string) => {
    get().updateProposal(id, { status: 'DISMISSED', state: 'DISMISSED' });
    try {
      await api.dismissProposal(id);
    } catch (err) {
      console.warn('API dismissal error:', err);
    }
  },

  dismissAllProposals: async (flowId?: string) => {
    const state = get();
    const toDismiss = Object.values(state.proposals).filter((p) => {
      if (p.status === 'DISMISSED') return false;
      if (flowId && p.flow_id !== flowId) return false;
      return true;
    });

    const ids = toDismiss.map((p) => p.id);
    if (ids.length === 0) return;

    set((s) => {
      const updated = { ...s.proposals };
      ids.forEach((id) => {
        if (updated[id]) {
          updated[id] = { ...updated[id], status: 'DISMISSED', state: 'DISMISSED' };
        }
      });
      return { proposals: updated };
    });

    try {
      await api.batchDismissProposals(ids);
    } catch (err) {
      console.warn('API batch dismissal error:', err);
    }
  },

  toggleApprovalDrawer: (open?: boolean, flowId?: string | null) => {
    set((state) => ({
      isApprovalDrawerOpen: typeof open === 'boolean' ? open : !state.isApprovalDrawerOpen,
      activeProposalFlowId: flowId !== undefined ? flowId : (open === false ? null : state.activeProposalFlowId),
    }));
  },

  setFilterOnlyWithProposals: (only: boolean) => {
    set({ filterOnlyWithProposals: only });
  },

  setActiveDiffProposal: (proposal: TestProposal | null) => {
    set({ activeDiffProposal: proposal });
  },

  transferProposalToMatrix: (proposalId: string) => {
    const state = get();
    const proposal = state.proposals[proposalId];
    if (!proposal) return;

    const newCase: TestMatrixCase = {
      id: `case-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      name: proposal.title || `${proposal.inferred_vuln_category} [${proposal.target_param_name}]`,
      endpoint_path: proposal.endpoint_path,
      method: (proposal.method as any) || 'GET',
      category: (proposal.category as any) || 'IDOR_SEQUENTIAL',
      target_param_location: (proposal.target_param_location as any) || 'query',
      target_param_name: proposal.target_param_name,
      baseline_value: proposal.baseline_value,
      mutated_value: proposal.mutated_value,
      auth_override: proposal.auth_override as any,
      selected: true,
      status: 'READY',
      baseline_flow_id: proposal.flow_id,
      is_starred: true,
      notes: `Imported from Test Proposal ${proposal.id}: ${proposal.risk_rationale}`,
    };

    if (state.activeMatrixJob) {
      set({
        activeMatrixJob: {
          ...state.activeMatrixJob,
          cases: [newCase, ...state.activeMatrixJob.cases],
          total_count: state.activeMatrixJob.total_count + 1,
        },
        activeView: 'matrix',
        isApprovalDrawerOpen: false,
      });
    } else {
      const newJob: TestMatrixJob = {
        job_id: `job-${Date.now()}`,
        target_endpoint: proposal.endpoint_path,
        created_at: new Date().toISOString(),
        cases: [newCase],
        total_count: 1,
        completed_count: 0,
        anomalies_count: 0,
        is_running: false,
      };
      set({
        activeMatrixJob: newJob,
        activeView: 'matrix',
        isApprovalDrawerOpen: false,
      });
    }

    api.toMatrix(proposalId).catch(() => {});
  },

  saveProposalToCurated: (proposalId: string, groupId?: string) => {
    const state = get();
    const proposal = state.proposals[proposalId];
    if (!proposal) return;

    const targetGroupId = groupId || 'group-bola';
    const group = state.payloadGroups[targetGroupId] || Object.values(state.payloadGroups)[0];

    const caseId = `curated-${proposal.id}`;
    const newCase: TestMatrixCase = {
      id: caseId,
      name: proposal.title || `${proposal.inferred_vuln_category} [${proposal.target_param_name}]`,
      endpoint_path: proposal.endpoint_path,
      method: (proposal.method as any) || 'GET',
      category: (proposal.category as any) || 'IDOR_SEQUENTIAL',
      target_param_location: (proposal.target_param_location as any) || 'query',
      target_param_name: proposal.target_param_name,
      baseline_value: proposal.baseline_value,
      mutated_value: proposal.mutated_value,
      auth_override: proposal.auth_override as any,
      selected: true,
      status: proposal.status === 'EXECUTED' ? 'PASSED' : 'READY',
      baseline_flow_id: proposal.flow_id,
      is_starred: true,
      is_pinned: true,
      group_id: group ? group.id : undefined,
      notes: `Curated from Test Proposal: ${proposal.risk_rationale}`,
    };

    const existingJob = state.activeMatrixJob;
    const updatedJob: TestMatrixJob = existingJob
      ? {
          ...existingJob,
          cases: [newCase, ...existingJob.cases.filter((c) => c.id !== caseId)],
          total_count: existingJob.cases.some((c) => c.id === caseId)
            ? existingJob.total_count
            : existingJob.total_count + 1,
        }
      : {
          job_id: `job-${Date.now()}`,
          target_endpoint: proposal.endpoint_path,
          created_at: new Date().toISOString(),
          cases: [newCase],
          total_count: 1,
          completed_count: 0,
          anomalies_count: 0,
          is_running: false,
        };

    const updatedGroups = { ...state.payloadGroups };
    if (group) {
      const currentCaseIds = group.case_ids || [];
      if (!currentCaseIds.includes(caseId)) {
        updatedGroups[group.id] = {
          ...group,
          case_ids: [...currentCaseIds, caseId],
          updated_at: new Date().toISOString(),
        };
      }
    }

    set({
      activeMatrixJob: updatedJob,
      payloadGroups: updatedGroups,
    });

    api.toCurated(proposalId, { group_id: group?.id }).catch(() => {});
  },

  transferProposalToIntruder: async (proposalId: string) => {
    const state = get();
    const proposal = state.proposals[proposalId];
    if (!proposal) return;

    try {
      const result = await api.toIntruder(proposalId);
      if (result.ok) {
        // Update proposal state to EXECUTING
        set((s) => ({
          proposals: {
            ...s.proposals,
            [proposalId]: {
              ...s.proposals[proposalId],
              state: 'EXECUTING',
              status: 'EXECUTING',
              updated_at: new Date().toISOString(),
            },
          },
        }));
        // Optionally switch to intruder view
        set({ activeView: 'intruder' });
      }
    } catch (err) {
      console.error('Failed to launch intruder from proposal:', err);
    }
  },

  sweepProposalsToIntruder: async (opts?: { min_confidence?: number; max_proposals?: number }) => {
    try {
      const result = await api.sweepToIntruder({
        min_confidence: opts?.min_confidence ?? 60,
        max_proposals: opts?.max_proposals ?? 20,
      });
      if (result.ok && result.jobs_launched > 0) {
        // Mark swept proposals as EXECUTING
        const sweptIds = (result.launched || [])
          .filter((l: any) => l.intruder_job_id)
          .map((l: any) => l.proposal_id);

        if (sweptIds.length > 0) {
          set((s) => {
            const updated = { ...s.proposals };
            for (const id of sweptIds) {
              if (updated[id]) {
                updated[id] = { ...updated[id], state: 'EXECUTING', status: 'EXECUTING' };
              }
            }
            return { proposals: updated };
          });
        }
      }
      return result;
    } catch (err) {
      console.error('Sweep failed:', err);
      return { ok: false, error: String(err) };
    }
  },
}));

