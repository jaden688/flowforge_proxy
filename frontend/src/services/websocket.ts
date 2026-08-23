import { useFlowStore } from '../store/flowStore';
import { FlowRecord, TriageSummary, TestProposal } from '../types';

type WebSocketMessageHandler = (event: MessageEvent) => void;

class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectTimeout: number | null = null;
  private pingInterval: number | null = null;
  private lastPingTime = 0;

  constructor() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    this.url = `${protocol}//${host}/api/v1/ws/traffic`;
  }

  public connect() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        useFlowStore.getState().setWsStatus(true, 10);
        this.reconnectAttempts = 0;
        this.startHeartbeat();
      };

      this.ws.onclose = () => {
        useFlowStore.getState().setWsStatus(false);
        this.stopHeartbeat();
        this.scheduleReconnect();
      };

      this.ws.onerror = (err) => {
        useFlowStore.getState().setWsStatus(false);
      };

      this.ws.onmessage = (event) => {
        this.handleMessage(event.data);
      };
    } catch (e) {
      useFlowStore.getState().setWsStatus(false);
      this.scheduleReconnect();
    }
  }

  private handleMessage(raw: string) {
    try {
      const msg = JSON.parse(raw);
      const store = useFlowStore.getState();

      if (msg.event === 'pong') {
        const latency = Date.now() - this.lastPingTime;
        store.setWsStatus(true, Math.max(1, latency));
        return;
      }

      if (msg.event === 'flow_created') {
        const flowData: FlowRecord = msg.data;
        store.addFlow(flowData);
      } else if (msg.event === 'flow_completed') {
        const flowData: Partial<FlowRecord> & { id: string } = msg.data;
        store.updateFlow(flowData.id, flowData);
      } else if (msg.event === 'triage_annotated') {
        const { flow_id, triage }: { flow_id: string; triage: TriageSummary } = msg.data;
        store.setTriage(flow_id, triage);
      } else if (msg.event === 'matrix_progress') {
        const progress = msg.data;
        const currentJob = store.activeMatrixJob;
        if (currentJob && currentJob.job_id === progress.job_id) {
          store.setMatrixJob({
            ...currentJob,
            completed_count: progress.completed,
            total_count: progress.total,
            anomalies_count: (currentJob.anomalies_count || 0) + (progress.anomaly_detected ? 1 : 0),
          });
        }
      } else if (msg.event === 'proposal_created') {
        const payload = msg.data;
        if (payload) {
          if (Array.isArray(payload)) {
            payload.forEach((p: TestProposal) => store.addProposal(p));
          } else if (Array.isArray(payload.proposals)) {
            payload.proposals.forEach((p: TestProposal) => store.addProposal(p));
          } else if (payload.id) {
            store.addProposal(payload as TestProposal);
          }
        }
      } else if (msg.event === 'proposal_updated') {
        const payload = msg.data;
        if (payload) {
          const id = payload.id || payload.proposal_id;
          const updates = payload.updates || payload;
          if (id) {
            store.updateProposal(id, updates);
          }
        }
      } else if (msg.event === 'proposal_executed') {
        const payload = msg.data;
        if (payload) {
          const id = payload.proposal_id || payload.id || payload.proposal?.id;
          if (id) {
            const updates: Partial<TestProposal> = {
              status: 'EXECUTED',
              state: 'EXECUTED',
              executed_flow_id: payload.executed_flow_id || payload.executed_flow?.id,
              diff_summary: {
                status_code: payload.status_code || 200,
                length_delta: payload.length_delta_bytes ?? payload.length_delta ?? 0,
                latency_ms: payload.latency_ms ?? payload.latency_delta_ms ?? 0,
                reflected: !!payload.reflected,
                anomaly_flag: payload.verdict_level || null,
                status_delta: payload.status_delta,
                verdict_level: payload.verdict_level,
                verdict_description: payload.verdict_description,
              },
              execution_result: payload.execution_result || {
                status_code: payload.status_code || 200,
                status_delta: payload.status_delta,
                length_delta_bytes: payload.length_delta_bytes,
                latency_delta_ms: payload.latency_ms,
                verdict_level: payload.verdict_level,
                verdict_description: payload.verdict_description,
                executed_flow_id: payload.executed_flow_id || payload.executed_flow?.id,
              },
            };
            store.updateProposal(id, updates);
            if (payload.executed_flow) {
              store.addFlow(payload.executed_flow);
            }
          }
        }
      } else if (msg.event === 'proposal_dismissed') {
        const payload = msg.data;
        if (payload) {
          const id = payload.proposal_id || payload.id;
          if (id) {
            store.updateProposal(id, { status: 'DISMISSED', state: 'DISMISSED' });
          }
        }
      }
    } catch (e) {
      console.warn('Failed to parse WebSocket message:', e);
    }
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    this.pingInterval = window.setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.lastPingTime = Date.now();
        this.ws.send(JSON.stringify({ action: 'ping' }));
      }
    }, 5000);
  }

  private stopHeartbeat() {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  private scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      return;
    }
    const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts), 10000);
    this.reconnectAttempts++;

    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
    }

    this.reconnectTimeout = window.setTimeout(() => {
      this.connect();
    }, delay);
  }

  public send(payload: any) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(payload));
    }
  }

  public disconnect() {
    this.stopHeartbeat();
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}

export const wsClient = new WebSocketClient();
