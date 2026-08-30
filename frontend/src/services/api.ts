import {
  FlowRecord,
  EndpointDossier,
  TestMatrixJob,
  FlowComparisonResult,
  TestProposal,
  ProposalStats,
  CustomWordlist,
  ArsenalWordlist,
  IntruderJob,
  IntruderJobConfig,
  IntruderResult,
  IntruderResultFilters,
  IntruderSuggestions,
  AutoDecodeResult,
  EncodeResponse,
  HexdumpResponse,
  NucleiTemplate,
  NucleiStats,
  FlowReplayRequest,
  FlowReplayResponse,
} from '../types';

const API_BASE = typeof window !== 'undefined' ? '/api/v1' : 'http://127.0.0.1:8000/api/v1';

export const api = {
  /**
   * List intercepted flows with optional filtering
   */
  async getFlows(params?: {
    limit?: number;
    offset?: number;
    search?: string;
    method?: string;
    status_min?: number;
    status_max?: number;
    tag?: string;
    host?: string;
  }): Promise<{ flows: FlowRecord[]; total: number }> {
    const query = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== '') {
          query.append(k, String(v));
        }
      });
    }
    const res = await fetch(`${API_BASE}/flows?${query.toString()}`);
    if (!res.ok) {
      throw new Error(`Failed to fetch flows: ${res.statusText}`);
    }
    const data = await res.json();
    return {
      flows: data.items || data.flows || [],
      total: data.total || 0,
    };
  },


  /**
   * Get single flow detail
   */
  async getFlow(id: string): Promise<FlowRecord> {
    const res = await fetch(`${API_BASE}/flows/${id}`);
    if (!res.ok) {
      throw new Error(`Failed to fetch flow ${id}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Clear all captured flows from server database
   */
  async clearFlows(): Promise<{ status: string }> {
    const res = await fetch(`${API_BASE}/flows`, { method: 'DELETE' });
    if (!res.ok) {
      throw new Error(`Failed to clear flows: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Fetch discovered endpoint dossiers
   */
  async getDossiers(hostFilter?: string): Promise<EndpointDossier[]> {
    const query = hostFilter ? `?host=${encodeURIComponent(hostFilter)}` : '';
    const res = await fetch(`${API_BASE}/dossier${query}`);
    if (!res.ok) {
      throw new Error(`Failed to fetch dossiers: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Generate mutation test matrix for a flow or endpoint
   */
  async generateMatrix(payload: {
    flow_id?: string;
    endpoint_path?: string;
    method?: string;
    parameters?: any[];
    categories?: string[];
  }): Promise<TestMatrixJob> {
    const res = await fetch(`${API_BASE}/matrix/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to generate matrix: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Execute staged test matrix cases through proxy
   */
  async executeMatrix(payload: {
    job_id?: string;
    case_ids?: string[];
    cases?: any[];
    target_url?: string;
    concurrency?: number;
  }): Promise<{ message: string; job_id: string; cases_queued: number }> {
    const res = await fetch(`${API_BASE}/matrix/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to execute matrix: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Get matrix execution job status and progress
   */
  async getMatrixJob(jobId: string): Promise<TestMatrixJob> {
    const res = await fetch(`${API_BASE}/matrix/jobs/${jobId}`);
    if (!res.ok) {
      throw new Error(`Failed to get matrix job ${jobId}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Compute server-side delta and anomaly classification between two flows
   */
  async computeDiff(payload: {
    flow_id_a?: string;
    flow_id_b?: string;
    flow_a?: any;
    flow_b?: any;
  }): Promise<FlowComparisonResult> {
    const res = await fetch(`${API_BASE}/diff`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to compute diff: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Replay modified request
   */
  async replayRequest(payload: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string | null;
  }): Promise<any> {
    const res = await fetch(`${API_BASE}/flows/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to replay request: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Replay intercepted flow by ID with optional parameter overrides
   */
  async replayFlow(
    flowId: string,
    overrides?: FlowReplayRequest
  ): Promise<FlowReplayResponse> {
    const res = await fetch(`${API_BASE}/flows/${encodeURIComponent(flowId)}/replay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(overrides || {}),
    });
    if (!res.ok) {
      throw new Error(`Failed to replay flow ${flowId}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * System health and CA cert info
   */
  async getSystemStatus(): Promise<any> {
    const res = await fetch(`${API_BASE}/proxy/status`);
    if (!res.ok) {
      return { status: 'healthy', version: '1.0.0' };
    }
    return res.json();
  },

  /**
   * Launch isolated pre-configured browser
   */
  async launchBrowser(): Promise<{ ok: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/proxy/browser/launch`, { method: 'POST' });
    if (!res.ok) {
      throw new Error(`Failed to launch browser: ${res.statusText}`);
    }
    return res.json();
  },

  // ==========================================================================
  // Test Proposals & Operator Approval REST API (M3-M4)
  // ==========================================================================

  /**
   * Fetch test proposals with optional filters
   */
  async getProposals(params?: {
    flow_id?: string;
    state?: string;
    status?: string;
    anomaly_type?: string;
    severity?: string;
    search?: string;
    page?: number;
    page_size?: number;
  }): Promise<{ items: TestProposal[]; total: number; page?: number; page_size?: number; total_pages?: number }> {
    const query = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== '') {
          // Support both state and status parameter names
          if (k === 'status' && !params.state) {
            query.append('state', String(v));
          } else {
            query.append(k, String(v));
          }
        }
      });
    }
    const res = await fetch(`${API_BASE}/proposals?${query.toString()}`);
    if (!res.ok) {
      throw new Error(`Failed to fetch proposals: ${res.statusText}`);
    }
    const data = await res.json();
    if (Array.isArray(data)) {
      return { items: data, total: data.length };
    }
    return data;
  },

  /**
   * Fetch aggregated proposal statistics
   */
  async getProposalStats(): Promise<ProposalStats> {
    const res = await fetch(`${API_BASE}/proposals/stats`);
    if (!res.ok) {
      throw new Error(`Failed to fetch proposal stats: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Fetch single proposal by ID
   */
  async getProposal(id: string): Promise<TestProposal> {
    const res = await fetch(`${API_BASE}/proposals/${id}`);
    if (!res.ok) {
      throw new Error(`Failed to fetch proposal ${id}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Approve a proposal (mark as approved)
   */
  async approveProposal(id: string, notes?: string): Promise<TestProposal> {
    const res = await fetch(`${API_BASE}/proposals/${id}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ notes }),
    });
    if (!res.ok) {
      throw new Error(`Failed to approve proposal ${id}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * 1-Click Approve and Execute proposal through replay engine, returning executed flow and delta diff
   */
  async approveAndRunProposal(id: string): Promise<{
    proposal: TestProposal;
    executed_flow?: FlowRecord;
    diff?: FlowComparisonResult;
  }> {
    // Try execute endpoint first, fallback to approve if backend routes it
    const res = await fetch(`${API_BASE}/proposals/${id}/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) {
      // Fallback to /approve if /execute is routed under approve
      const fallbackRes = await fetch(`${API_BASE}/proposals/${id}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!fallbackRes.ok) {
        throw new Error(`Failed to execute proposal ${id}: ${res.statusText}`);
      }
      return fallbackRes.json();
    }
    return res.json();
  },

  /**
   * Dismiss single proposal
   */
  async dismissProposal(id: string, reason?: string): Promise<{ status: string }> {
    const res = await fetch(`${API_BASE}/proposals/${id}/dismiss`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason }),
    });
    if (!res.ok) {
      throw new Error(`Failed to dismiss proposal ${id}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Batch dismiss multiple proposals
   */
  async batchDismissProposals(ids: string[]): Promise<{ success_count: number; failure_count: number; updated_ids: string[] }> {
    const res = await fetch(`${API_BASE}/proposals/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proposal_ids: ids, action: 'dismiss' }),
    });
    if (!res.ok) {
      // Try alternative endpoint name /batch-dismiss
      const fallbackRes = await fetch(`${API_BASE}/proposals/batch-dismiss`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids }),
      });
      if (!fallbackRes.ok) {
        throw new Error(`Failed to batch dismiss proposals: ${res.statusText}`);
      }
      return fallbackRes.json();
    }
    return res.json();
  },

  /**
   * Batch action on proposals (approve, execute, dismiss, delete)
   */
  async batchProposalAction(
    ids: string[], 
    action: 'approve' | 'execute' | 'dismiss' | 'delete'
  ): Promise<{ success_count: number; failure_count: number; updated_ids: string[] }> {
    const res = await fetch(`${API_BASE}/proposals/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proposal_ids: ids, action }),
    });
    if (!res.ok) {
      throw new Error(`Failed to execute batch action '${action}': ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Trigger on-demand proposal synthesis for a specific flow
   */
  async generateProposals(flowId: string, payload?: { anomaly_types?: string[] }): Promise<TestProposal[]> {
    const res = await fetch(`${API_BASE}/proposals/generate/${flowId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || {}),
    });
    if (!res.ok) {
      throw new Error(`Failed to generate proposals for flow ${flowId}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Transfer proposal into Curated Collections
   */
  async toCurated(id: string, payload?: { group_id?: string; custom_name?: string; tags?: string[] }): Promise<any> {
    const res = await fetch(`${API_BASE}/proposals/${id}/to-curated`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || {}),
    });
    if (!res.ok) {
      // Optional bridge endpoint
      return { ok: true, id };
    }
    return res.json();
  },

  /**
   * Transfer proposal into Test Matrix Builder
   */
  async toMatrix(id: string, payload?: { job_id?: string; custom_name?: string }): Promise<any> {
    const res = await fetch(`${API_BASE}/proposals/${id}/to-matrix`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || {}),
    });
    if (!res.ok) {
      // Optional bridge endpoint
      return { ok: true, id };
    }
    return res.json();
  },

  /**
   * Transfer proposal directly into Intruder for active fuzzing
   */
  async toIntruder(id: string, opts?: { concurrency?: number; rate_limit?: number }): Promise<any> {
    const params = new URLSearchParams();
    if (opts?.concurrency) params.set('concurrency', String(opts.concurrency));
    if (opts?.rate_limit) params.set('rate_limit', String(opts.rate_limit));
    const qs = params.toString();
    const res = await fetch(`${API_BASE}/proposals/${id}/to-intruder${qs ? '?' + qs : ''}`, {
      method: 'POST',
    });
    if (!res.ok) return { ok: false, error: 'Failed to launch intruder job' };
    return res.json();
  },

  /**
   * Batch-sweep high-confidence pending proposals into Intruder campaigns
   */
  async sweepToIntruder(opts?: { min_confidence?: number; max_proposals?: number; concurrency?: number; severity_filter?: string }): Promise<any> {
    const params = new URLSearchParams();
    if (opts?.min_confidence) params.set('min_confidence', String(opts.min_confidence));
    if (opts?.max_proposals) params.set('max_proposals', String(opts.max_proposals));
    if (opts?.concurrency) params.set('concurrency', String(opts.concurrency));
    if (opts?.severity_filter) params.set('severity_filter', opts.severity_filter);
    const qs = params.toString();
    const res = await fetch(`${API_BASE}/proposals/sweep${qs ? '?' + qs : ''}`, {
      method: 'POST',
    });
    if (!res.ok) return { ok: false, error: 'Sweep failed' };
    return res.json();
  },

  // ========================================================================
  // Payload Management (custom wordlists)
  // ========================================================================

  async uploadCustomWordlist(payload: {
    name: string;
    description?: string;
    category?: string;
    tags?: string[];
    content: string;
  }): Promise<CustomWordlist> {
    const res = await fetch(`${API_BASE}/wordlists/custom`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Failed to upload wordlist: ${res.statusText}`);
    return res.json();
  },

  async getCustomWordlists(tag?: string): Promise<{ items: CustomWordlist[]; total: number }> {
    const query = tag ? `?tag=${encodeURIComponent(tag)}` : '';
    const res = await fetch(`${API_BASE}/wordlists/custom${query}`);
    if (!res.ok) throw new Error(`Failed to list custom wordlists: ${res.statusText}`);
    return res.json();
  },

  async updateCustomWordlist(id: string, patch: Partial<CustomWordlist> & { content?: string }): Promise<any> {
    const res = await fetch(`${API_BASE}/wordlists/custom/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    });
    if (!res.ok) throw new Error(`Failed to update wordlist: ${res.statusText}`);
    return res.json();
  },

  async deleteCustomWordlist(id: string): Promise<void> {
    const res = await fetch(`${API_BASE}/wordlists/custom/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error(`Failed to delete wordlist: ${res.statusText}`);
  },

  async getArsenalWordlists(category?: string, search?: string): Promise<{
    items: ArsenalWordlist[];
    total: number;
    categories: Record<string, number>;
  }> {
    const params = new URLSearchParams();
    if (category) params.append('category', category);
    if (search) params.append('search', search);
    const res = await fetch(`${API_BASE}/wordlists?${params.toString()}`);
    if (!res.ok) throw new Error(`Failed to list arsenal wordlists: ${res.statusText}`);
    return res.json();
  },

  async getIntruderSuggestions(): Promise<IntruderSuggestions> {
    const res = await fetch(`${API_BASE}/intruder/suggestions`);
    if (!res.ok) throw new Error(`Failed to load suggestions: ${res.statusText}`);
    return res.json();
  },

  async wipeData(includeWordlists = false): Promise<{ ok: boolean; wiped: Record<string, number> }> {
    const res = await fetch(`${API_BASE}/system/wipe?include_wordlists=${includeWordlists}`, { method: 'POST' });
    if (!res.ok) throw new Error(`Wipe failed: ${res.statusText}`);
    return res.json();
  },

  async getSystemStats(): Promise<Record<string, number>> {
    const res = await fetch(`${API_BASE}/system/stats`);
    if (!res.ok) throw new Error(`Failed to fetch system stats: ${res.statusText}`);
    return res.json();
  },

  async clearData(flags: {
    flows?: boolean;
    endpoints?: boolean;
    proposals?: boolean;
    intruder_jobs?: boolean;
    wordlists?: boolean;
    curated_payloads?: boolean;
  }): Promise<{ ok: boolean; cleared: Record<string, number> }> {
    const res = await fetch(`${API_BASE}/system/clear`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(flags),
    });
    if (!res.ok) throw new Error(`Clear failed: ${res.statusText}`);
    return res.json();
  },

  // ========================================================================
  // Active Intruder
  // ========================================================================

  async createIntruderJob(config: IntruderJobConfig): Promise<IntruderJob> {
    const res = await fetch(`${API_BASE}/intruder/jobs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config }),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`Failed to create intruder job: ${res.statusText} ${detail.slice(0, 200)}`);
    }
    const data = await res.json();
    return data.job ?? data;
  },

  async getIntruderJob(jobId: string): Promise<IntruderJob> {
    const res = await fetch(`${API_BASE}/intruder/jobs/${jobId}`);
    if (!res.ok) throw new Error(`Failed to get intruder job: ${res.statusText}`);
    return res.json();
  },

  async listIntruderJobs(): Promise<{ items: IntruderJob[]; total: number }> {
    const res = await fetch(`${API_BASE}/intruder/jobs`);
    if (!res.ok) throw new Error(`Failed to list intruder jobs: ${res.statusText}`);
    return res.json();
  },

  async abortIntruderJob(jobId: string): Promise<{ ok: boolean; job: IntruderJob | null }> {
    const res = await fetch(`${API_BASE}/intruder/jobs/${jobId}/abort`, { method: 'POST' });
    if (!res.ok) throw new Error(`Failed to abort intruder job: ${res.statusText}`);
    return res.json();
  },

  async getIntruderResults(jobId: string, filters?: Partial<IntruderResultFilters> & {
    offset?: number;
    limit?: number;
  }): Promise<{ items: IntruderResult[]; total: number; job_status: string }> {
    const params = new URLSearchParams();
    if (filters) {
      if (filters.anomaliesOnly) params.append('anomalies_only', 'true');
      if (filters.reflectedOnly) params.append('reflected_only', 'true');
      if (filters.minSize != null) params.append('min_size', String(filters.minSize));
      if (filters.maxSize != null) params.append('max_size', String(filters.maxSize));
      if (filters.minTimeMs != null) params.append('min_time_ms', String(filters.minTimeMs));
      if (filters.maxTimeMs != null) params.append('max_time_ms', String(filters.maxTimeMs));
      if (filters.payloadSearch) params.append('payload_search', filters.payloadSearch);
      if (filters.offset != null) params.append('offset', String(filters.offset));
      if (filters.limit != null) params.append('limit', String(filters.limit));
    }
    const res = await fetch(`${API_BASE}/intruder/jobs/${jobId}/results?${params.toString()}`);
    if (!res.ok) throw new Error(`Failed to get intruder results: ${res.statusText}`);
    return res.json();
  },

  // ========================================================================
  // Custom Rules Engine
  // ========================================================================

  async listRules(params?: { enabled?: boolean; severity?: string; category?: string; search?: string }): Promise<{ rules: any[]; total: number }> {
    const query = new URLSearchParams();
    if (params?.enabled !== undefined) query.set('enabled', String(params.enabled));
    if (params?.severity) query.set('severity', params.severity);
    if (params?.category) query.set('category', params.category);
    if (params?.search) query.set('search', params.search);
    const qs = query.toString();
    const res = await fetch(`${API_BASE}/rules${qs ? '?' + qs : ''}`);
    if (!res.ok) throw new Error(`Failed to list rules: ${res.statusText}`);
    return res.json();
  },

  async createRule(rule: any): Promise<{ status: string; rule: any }> {
    const res = await fetch(`${API_BASE}/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule),
    });
    if (!res.ok) throw new Error(`Failed to create rule: ${res.statusText}`);
    return res.json();
  },

  async updateRule(ruleId: string, rule: any): Promise<{ status: string; rule: any }> {
    const res = await fetch(`${API_BASE}/rules/${ruleId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule),
    });
    if (!res.ok) throw new Error(`Failed to update rule: ${res.statusText}`);
    return res.json();
  },

  async deleteRule(ruleId: string): Promise<{ status: string }> {
    const res = await fetch(`${API_BASE}/rules/${ruleId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error(`Failed to delete rule: ${res.statusText}`);
    return res.json();
  },

  async toggleRule(ruleId: string, enabled?: boolean): Promise<{ status: string; rule: any }> {
    const res = await fetch(`${API_BASE}/rules/${ruleId}/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(enabled !== undefined ? { enabled } : {}),
    });
    if (!res.ok) throw new Error(`Failed to toggle rule: ${res.statusText}`);
    return res.json();
  },

  async testRule(payload: any): Promise<any> {
    const res = await fetch(`${API_BASE}/rules/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Failed to test rule: ${res.statusText}`);
    return res.json();
  },

  async exportRules(format: string = 'yaml', enabledOnly: boolean = false): Promise<any> {
    const res = await fetch(`${API_BASE}/rules/export?format=${format}&enabled_only=${enabledOnly}`);
    if (!res.ok) throw new Error(`Failed to export rules: ${res.statusText}`);
    return res.json();
  },

  async importScopeRules(scope: {
    program_name?: string;
    in_scope_patterns: string[];
    out_of_scope_patterns?: string[];
  }): Promise<{ status: string; imported_count: number; errors: string[] }> {
    const res = await fetch(`${API_BASE}/rules/import-scope`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(scope),
    });
    if (!res.ok) throw new Error(`Failed to import scope rules: ${res.statusText}`);
    return res.json();
  },

  async importRules(content: string, format: string = 'yaml', overwrite: boolean = false): Promise<any> {
    const res = await fetch(`${API_BASE}/rules/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, format, overwrite }),
    });
    if (!res.ok) throw new Error(`Failed to import rules: ${res.statusText}`);
    return res.json();
  },

  // ========================================================================
  // Tools & Decoder REST API (Milestone 3)
  // ========================================================================

  /**
   * Decode text content using specified decoder or recursive auto-decoding pipeline
   */
  async decodeContent(
    text: string,
    operation: string = 'auto',
    options?: { multi_pass?: boolean; max_depth?: number }
  ): Promise<AutoDecodeResult> {
    const res = await fetch(`${API_BASE}/tools/decode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: text,
        decoder_type: operation || 'auto',
        multi_pass: options?.multi_pass ?? false,
        max_depth: options?.max_depth ?? 5,
      }),
    });
    if (!res.ok) {
      throw new Error(`Failed to decode content: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Encode text content into specified format (base64, url, hex, html, etc.)
   */
  async encodeContent(
    text: string,
    encoder: string = 'base64',
    options?: { hex_separator?: string }
  ): Promise<EncodeResponse> {
    const res = await fetch(`${API_BASE}/tools/encode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: text,
        encoder_type: encoder || 'base64',
        hex_separator: options?.hex_separator ?? '',
      }),
    });
    if (!res.ok) {
      throw new Error(`Failed to encode content: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Generate formatted 16-byte offset hex dump with ASCII representation
   */
  async hexdump(
    data: string,
    length: number = 16
  ): Promise<HexdumpResponse> {
    const res = await fetch(`${API_BASE}/tools/hexdump`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: data,
        bytes_per_line: length ?? 16,
      }),
    });
    if (!res.ok) {
      throw new Error(`Failed to generate hexdump: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Deeply inspect and parse a JWT token, returning claims, expiration, and security anomaly flags
   */
  async inspectJwt(token: string): Promise<any> {
    const res = await fetch(`${API_BASE}/tools/jwt/inspect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    if (!res.ok) {
      const fallbackRes = await fetch(`${API_BASE}/tools/jwt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      if (!fallbackRes.ok) {
        throw new Error(`Failed to inspect JWT: ${res.statusText}`);
      }
      return fallbackRes.json();
    }
    return res.json();
  },

  // ========================================================================
  // Nuclei Templates Engine REST API (Milestone 3)
  // ========================================================================

  /**
   * List and filter discovered Nuclei templates
   */
  async getNucleiTemplates(params?: {
    category?: string;
    severity?: string;
    tag?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ items: NucleiTemplate[]; total: number }> {
    const query = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== '') {
          query.append(k, String(v));
        }
      });
    }
    const qs = query.toString();
    const res = await fetch(`${API_BASE}/nuclei/templates${qs ? '?' + qs : ''}`);
    if (!res.ok) {
      throw new Error(`Failed to fetch Nuclei templates: ${res.statusText}`);
    }
    const data = await res.json();
    if (Array.isArray(data)) {
      return { items: data, total: data.length };
    }
    return {
      items: data.items || data.templates || [],
      total: data.total ?? (data.items || data.templates || []).length,
    };
  },

  /**
   * Get single Nuclei template by ID
   */
  async getNucleiTemplate(id: string): Promise<NucleiTemplate> {
    const res = await fetch(`${API_BASE}/nuclei/templates/${encodeURIComponent(id)}`);
    if (!res.ok) {
      throw new Error(`Failed to fetch Nuclei template '${id}': ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Fetch aggregated statistics for loaded Nuclei templates
   */
  async getNucleiStats(): Promise<NucleiStats> {
    const res = await fetch(`${API_BASE}/nuclei/stats`);
    if (!res.ok) {
      throw new Error(`Failed to fetch Nuclei stats: ${res.statusText}`);
    }
    return res.json();
  },
};



