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
        // Sync rules from backend on connect
        useFlowStore.getState().syncRulesFromBackend().catch(() => {});
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
            const statusCode = payload.status_code ?? payload.execution_result?.status_code ?? payload.executed_flow?.response_status ?? 0;
            const lengthDelta = payload.length_delta_bytes ?? payload.length_delta ?? 0;
            const latencyDelta = payload.latency_ms ?? payload.latency_delta_ms ?? 0;
            const verdictLevel = payload.verdict_level || payload.execution_result?.verdict_level;
            const verdictDesc = payload.verdict_description || payload.execution_result?.verdict_description;
            const method = payload.method || payload.proposal?.method;
            const endpointPath = payload.endpoint_path || payload.proposal?.endpoint_path;

            const updates: Partial<TestProposal> = {
              status: 'EXECUTED',
              state: 'EXECUTED',
              executed_flow_id: payload.executed_flow_id || payload.executed_flow?.id,
              diff_summary: {
                status_code: statusCode,
                length_delta: lengthDelta,
                latency_ms: latencyDelta,
                reflected: !!payload.reflected,
                anomaly_flag: verdictLevel || null,
                status_delta: payload.status_delta,
                verdict_level: verdictLevel,
                verdict_description: verdictDesc,
              },
              execution_result: payload.execution_result || {
                status_code: statusCode,
                status_delta: payload.status_delta,
                length_delta_bytes: lengthDelta,
                latency_delta_ms: latencyDelta,
                verdict_level: verdictLevel,
                verdict_description: verdictDesc,
                executed_flow_id: payload.executed_flow_id || payload.executed_flow?.id,
              },
            };
            store.updateProposal(id, updates);
            if (payload.executed_flow) {
              store.addFlow(payload.executed_flow);
            }

            store.addTelemetryLog({
              id: `ws-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
              timestamp: new Date().toLocaleTimeString(),
              type: 'AUTOPILOT',
              message: `Executed proposal ${id}`,
              method,
              endpointPath,
              proposalId: id,
              statusCode,
              statusDelta: payload.status_delta,
              lengthDeltaBytes: lengthDelta,
              latencyMs: latencyDelta,
              verdictLevel,
              verdictDescription: verdictDesc,
            });
          }
        }
      } else if (msg.event === 'intruder_result') {
        store.addIntruderResult(msg.data);
      } else if (msg.event === 'intruder_status') {
        store.updateIntruderJobProgress(msg.data);
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
