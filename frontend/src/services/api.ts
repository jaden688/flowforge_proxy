import { 
  FlowRecord, 
  EndpointDossier, 
  TestMatrixJob, 
  FlowComparisonResult,
  TestProposal,
  ProposalStats
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
  }): Promise<FlowRecord> {
    const res = await fetch(`${API_BASE}/proxy/replay`, {
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
};


