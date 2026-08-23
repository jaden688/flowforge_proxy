import React, { useState, useEffect } from 'react';
import { useFlowStore } from '../../store/flowStore';
import { api } from '../../services/api';
import { FlowRecord } from '../../types';
import { Badge } from '../common/Badge';

import { 
  Zap, 
  Sparkles, 
  ShieldCheck, 
  Key, 
  Copy, 
  Check, 
  Layers, 
  GitCompare, 
  Send,
  Binary,
  Activity,
  Code,
  Table,
  FileText,
  Clock,
  ArrowRight
} from 'lucide-react';
import { InspectorSubView } from '../../types';
import { HexDumpRenderer } from '../inspector/renderers/HexDumpRenderer';
import { FormattedContentRenderer } from '../inspector/renderers/FormattedContentRenderer';
import { FormDataRenderer } from '../inspector/renderers/FormDataRenderer';
import { TelemetryMetricsCard } from '../inspector/renderers/TelemetryMetricsCard';
import { MultiLayerDecoderModal } from '../decoder/MultiLayerDecoderModal';

export const SplitInspector: React.FC = () => {
  const selectedFlowId = useFlowStore((s) => s.selectedFlowId);
  const flows = useFlowStore((s) => s.flows);
  const updateFlow = useFlowStore((s) => s.updateFlow);
  const setActiveView = useFlowStore((s) => s.setActiveView);
  const setDiffPair = useFlowStore((s) => s.setDiffPair);

  // Main Tabs: Request, Response, Telemetry, Triage, Raw
  const [activeTab, setActiveTab] = useState<'request' | 'response' | 'telemetry' | 'triage' | 'raw'>('request');

  // Sub-views for Request and Response: Formatted, Hex, Form Data, Raw, Headers
  const [reqSubView, setReqSubView] = useState<InspectorSubView>('formatted');
  const [respSubView, setRespSubView] = useState<InspectorSubView>('formatted');

  // Decoder Modal state
  const [isDecoderOpen, setIsDecoderOpen] = useState(false);
  const [decoderInputText, setDecoderInputText] = useState('');

  const [copiedCurl, setCopiedCurl] = useState(false);

  const flow = selectedFlowId ? flows[selectedFlowId] : null;

  useEffect(() => {
    if (selectedFlowId) {
      const current = flows[selectedFlowId];
      if (!current || !current.request_headers || Object.keys(current.request_headers).length === 0 || current.request_body === undefined) {
        api.getFlow(selectedFlowId).then((fullFlow: FlowRecord) => {
          if (fullFlow) {
            updateFlow(selectedFlowId, fullFlow);
          }
        }).catch(console.error);

      }
    }
  }, [selectedFlowId]);


  if (!flow) {
    return (
      <div className="h-full flex items-center justify-center bg-[#090D15] text-slate-500 font-mono text-xs p-6 text-center">
        Select an intercepted flow from the table to inspect details and security heuristics
      </div>
    );
  }

  const handleCopyCurl = () => {
    let curl = `curl -X ${flow.method} "${flow.url}"`;
    if (flow.request_headers) {
      Object.entries(flow.request_headers).forEach(([k, v]) => {
        curl += ` \\\n  -H "${k}: ${v}"`;
      });
    }
    if (flow.request_body) {
      curl += ` \\\n  --data '${flow.request_body.replace(/'/g, "\\'")}'`;
    }
    navigator.clipboard.writeText(curl);
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  const handleStageInMatrix = () => {
    setActiveView('matrix');
  };

  const handleSendToDiff = () => {
    setDiffPair(flow.id, null);
    setActiveView('diff');
  };

  const handleOpenDecoder = (text?: string) => {
    const payload = text || flow.request_body || flow.response_body || flow.url;
    setDecoderInputText(payload);
    setIsDecoderOpen(true);
  };

  const reflections = flow.triage?.reflections || [];
  const reflectedWords = reflections.map((r) => r.value).filter(Boolean);

  const subViewButtons: { id: InspectorSubView; label: string; icon: React.ReactNode }[] = [
    { id: 'formatted', label: 'Formatted', icon: <Code className="w-3 h-3" /> },
    { id: 'hex', label: 'Hex Dump', icon: <Binary className="w-3 h-3" /> },
    { id: 'form', label: 'Form Data', icon: <Table className="w-3 h-3" /> },
    { id: 'raw', label: 'Raw Body', icon: <FileText className="w-3 h-3" /> },
    { id: 'headers', label: 'Headers', icon: <Layers className="w-3 h-3" /> },
  ];

  return (
    <div className="h-full flex flex-col bg-[#090D15] overflow-hidden">
      {/* Top Action Bar */}
      <div className="p-3 bg-surface/60 border-b border-border flex items-center justify-between gap-3 select-none">
        <div className="flex items-center gap-2 overflow-hidden">
          <Badge variant="primary" size="sm">
            {flow.method}
          </Badge>
          <span className="text-xs font-mono font-medium text-slate-200 truncate" title={flow.url}>
            {flow.url}
          </span>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          {/* Quick Decoder Action */}
          <button
            onClick={() => handleOpenDecoder()}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 hover:border-cyan-500/40 text-xs font-mono flex items-center gap-1.5 transition-colors"
            title="Open Multi-Layer Decoder Workbench"
          >
            <Binary className="w-3 h-3 text-primary" />
            <span>Decoder</span>
          </button>

          <button
            onClick={handleCopyCurl}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-mono flex items-center gap-1.5 transition-colors"
          >
            {copiedCurl ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>cURL</span>
          </button>

          <button
            onClick={handleStageInMatrix}
            className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-medium flex items-center gap-1.5 transition-colors"
            title="Stage this flow into Test Matrix"
          >
            <Zap className="w-3 h-3 text-primary" />
            <span>Stage Matrix</span>
          </button>

          <button
            onClick={handleSendToDiff}
            className="px-2.5 py-1 rounded bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/40 text-xs font-mono font-medium flex items-center gap-1.5 transition-colors"
            title="Set as baseline in Diff Viewer"
          >
            <GitCompare className="w-3 h-3 text-purple-400" />
            <span>Diff</span>
          </button>
        </div>
      </div>

      {/* Main Detail Tabs Header */}
      <div className="flex items-center px-3 bg-[#0B101A] border-b border-border gap-2 text-xs font-mono select-none">
        {(['request', 'response', 'telemetry', 'triage', 'raw'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`py-2 px-3 border-b-2 font-medium capitalize transition-colors flex items-center gap-1.5 ${
              activeTab === tab
                ? 'border-primary text-primary font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab === 'triage' && <Sparkles className="w-3 h-3 text-yellow-400" />}
            {tab === 'telemetry' && <Activity className="w-3 h-3 text-emerald-400" />}
            <span>{tab}</span>
            {tab === 'triage' && flow.triage && (
              <span className="px-1 py-0.2 rounded-full bg-yellow-500/20 text-yellow-300 text-[10px]">
                {reflections.length + (flow.triage.identifiers?.length || 0)}
              </span>
            )}
            {tab === 'telemetry' && (
              <span className="text-[10px] text-slate-400">
                {flow.duration_ms || flow.latency_ms || 45}ms
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab Panels */}
      <div className="flex-1 overflow-y-auto p-4 font-mono text-xs">
        {/* ========================================================================= */}
        {/* 1. Request Tab with Sub-View Switcher */}
        {/* ========================================================================= */}
        {/* ========================================================================= */}
        {/* 1. Request Tab: Headers + Query Params + Body */}
        {/* ========================================================================= */}
        {activeTab === 'request' && (
          <div className="space-y-4">
            {/* Request Summary Bar */}
            <div className="p-2.5 bg-[#0A0E17] border border-border rounded-lg flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-primary font-bold">{flow.method}</span>
                <span className="text-slate-300 font-mono break-all">{flow.path}</span>
              </div>
              <span className="text-[11px] text-slate-400">
                {flow.request_content_type || 'No Content-Type'} • {(flow as any).request_content_length ?? (flow as any).request?.content_length ?? flow.request_size ?? flow.request_body?.length ?? 0} bytes
              </span>
            </div>

            {/* Request Headers Table */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-slate-400 text-[11px] font-bold uppercase tracking-wider px-1">
                <span>Request Headers ({flow.request_headers ? Object.keys(flow.request_headers).length : 0})</span>
              </div>
              <div className="bg-[#0A0E17] border border-border rounded-lg overflow-hidden">
                {flow.request_headers && Object.keys(flow.request_headers).length > 0 ? (
                  <table className="w-full text-left">
                    <tbody className="divide-y divide-border/40">
                      {Object.entries(flow.request_headers).map(([k, v]) => {
                        const valStr = String(v);
                        const isDecodable = valStr.includes('eyJ') || valStr.startsWith('Bearer ') || valStr.length > 20;
                        return (
                          <tr key={k} className="hover:bg-slate-900/40 group">
                            <td className="py-1.5 px-3 text-cyan-400 w-1/3 font-semibold break-all">{k}</td>
                            <td className="py-1.5 px-3 text-slate-300 break-all flex items-center justify-between gap-2">
                              <span>{valStr}</span>
                              {isDecodable && (
                                <button
                                  onClick={() => handleOpenDecoder(valStr.replace(/^Bearer\s+/i, ''))}
                                  className="opacity-0 group-hover:opacity-100 px-1.5 py-0.5 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 text-[10px] font-mono shrink-0 transition-opacity flex items-center gap-1"
                                  title="Send to Decoder Studio"
                                >
                                  <Binary className="w-2.5 h-2.5" />
                                  <span>Decode</span>
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                ) : (
                  <div className="p-3 text-slate-500 text-center italic">No request headers recorded</div>
                )}
              </div>
            </div>

            {/* Query Parameters Section */}
            {flow.query_params && Object.keys(flow.query_params).length > 0 && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-slate-400 text-[11px] font-bold uppercase tracking-wider px-1">
                  <span>Query Parameters ({Object.keys(flow.query_params).length})</span>
                </div>
                <div className="bg-[#0A0E17] border border-border rounded-lg overflow-hidden">
                  <table className="w-full text-left">
                    <tbody className="divide-y divide-border/40">
                      {Object.entries(flow.query_params).map(([k, v]) => {
                        const valStr = typeof v === 'string' ? v : JSON.stringify(v);
                        return (
                          <tr key={k} className="hover:bg-slate-900/40 group">
                            <td className="py-1.5 px-3 text-amber-400 w-1/3 font-semibold">{k}</td>
                            <td className="py-1.5 px-3 text-slate-300 flex items-center justify-between gap-2">
                              <span>{valStr}</span>
                              <button
                                onClick={() => handleOpenDecoder(valStr)}
                                className="opacity-0 group-hover:opacity-100 px-1.5 py-0.5 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 text-[10px] font-mono shrink-0 transition-opacity flex items-center gap-1"
                                title="Send parameter to Decoder Studio"
                              >
                                <Binary className="w-2.5 h-2.5" />
                                <span>Decode</span>
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Request Body Section */}
            <div className="space-y-2 pt-2 border-t border-border/40">
              <div className="flex items-center justify-between select-none">
                <div className="flex items-center gap-1 bg-[#0A0E17] p-1 rounded-lg border border-border">
                  {subViewButtons.filter(b => b.id !== 'headers').map((btn) => (
                    <button
                      key={btn.id}
                      onClick={() => setReqSubView(btn.id)}
                      className={`px-2.5 py-1 rounded text-[11px] font-medium flex items-center gap-1.5 transition-colors ${
                        reqSubView === btn.id
                          ? 'bg-primary/20 text-primary border border-primary/40'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {btn.icon}
                      <span>{btn.label}</span>
                    </button>
                  ))}
                </div>
                <span className="text-[11px] text-slate-400">Request Body</span>
              </div>

              {/* Sub-View Panels for Request Body */}
              {reqSubView === 'formatted' && (
                <FormattedContentRenderer
                  content={flow.request_body}
                  contentType={flow.request_content_type}
                  highlightWords={reflectedWords}
                  onSendToDecoder={handleOpenDecoder}
                />
              )}

              {reqSubView === 'hex' && (
                <HexDumpRenderer
                  content={flow.request_body}
                  onSendToDecoder={handleOpenDecoder}
                />
              )}

              {reqSubView === 'form' && (
                <FormDataRenderer
                  content={flow.request_body}
                  contentType={flow.request_content_type}
                  highlightWords={reflectedWords}
                  onSendToDecoder={handleOpenDecoder}
                />
              )}

              {reqSubView === 'raw' && (
                <div className="p-3 bg-[#0A0E17] border border-border rounded-lg">
                  <pre className="text-slate-300 whitespace-pre-wrap break-all leading-relaxed">
                    {flow.request_body || '[Empty Body]'}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* 2. Response Tab: Headers + Body */}
        {/* ========================================================================= */}
        {activeTab === 'response' && (
          <div className="space-y-4">
            {/* Status Line */}
            <div className="flex flex-wrap items-center gap-3 p-2.5 bg-[#0A0E17] border border-border rounded-lg">
              <span className="text-slate-400">Status:</span>
              <span className="text-emerald-400 font-bold">
                {flow.response_status || flow.response_status_code || 200} {flow.response_status_text || flow.response_reason || 'OK'}
              </span>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400">Latency:</span>
              <span className="text-slate-200">{flow.latency_ms || flow.duration_ms || 0}ms</span>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400">Size:</span>
              <span className="text-slate-200">{(flow as any).response_content_length ?? (flow as any).response?.content_length ?? flow.response_size ?? flow.response_body?.length ?? 0} bytes</span>
            </div>

            {/* Response Headers Table */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-slate-400 text-[11px] font-bold uppercase tracking-wider px-1">
                <span>Response Headers ({flow.response_headers ? Object.keys(flow.response_headers).length : 0})</span>
              </div>
              <div className="bg-[#0A0E17] border border-border rounded-lg overflow-hidden max-h-48 overflow-y-auto">
                {flow.response_headers && Object.keys(flow.response_headers).length > 0 ? (
                  <table className="w-full text-left">
                    <tbody className="divide-y divide-border/40">
                      {Object.entries(flow.response_headers).map(([k, v]) => {
                        const valStr = String(v);
                        const isDecodable = valStr.includes('eyJ') || valStr.startsWith('Bearer ') || valStr.length > 20;
                        return (
                          <tr key={k} className="hover:bg-slate-900/40 group">
                            <td className="py-1.5 px-3 text-cyan-400 w-1/3 font-semibold break-all">{k}</td>
                            <td className="py-1.5 px-3 text-slate-300 break-all flex items-center justify-between gap-2">
                              <span>{valStr}</span>
                              {isDecodable && (
                                <button
                                  onClick={() => handleOpenDecoder(valStr)}
                                  className="opacity-0 group-hover:opacity-100 px-1.5 py-0.5 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 text-[10px] font-mono shrink-0 transition-opacity flex items-center gap-1"
                                  title="Send to Decoder Studio"
                                >
                                  <Binary className="w-2.5 h-2.5" />
                                  <span>Decode</span>
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                ) : (
                  <div className="p-3 text-slate-500 text-center italic">No response headers recorded</div>
                )}
              </div>
            </div>

            {/* Response Body Section */}
            <div className="space-y-2 pt-2 border-t border-border/40">
              <div className="flex items-center justify-between select-none">
                <div className="flex items-center gap-1 bg-[#0A0E17] p-1 rounded-lg border border-border">
                  {subViewButtons.filter(b => b.id !== 'headers').map((btn) => (
                    <button
                      key={btn.id}
                      onClick={() => setRespSubView(btn.id)}
                      className={`px-2.5 py-1 rounded text-[11px] font-medium flex items-center gap-1.5 transition-colors ${
                        respSubView === btn.id
                          ? 'bg-primary/20 text-primary border border-primary/40'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {btn.icon}
                      <span>{btn.label}</span>
                    </button>
                  ))}
                </div>

                {reflectedWords.length > 0 && (
                  <span className="text-[11px] text-yellow-300 font-bold flex items-center gap-1 bg-yellow-500/10 px-2 py-0.5 rounded border border-yellow-500/30">
                    <Sparkles className="w-3 h-3 text-yellow-400" />
                    {reflectedWords.length} Reflections Highlighted
                  </span>
                )}
              </div>

              {/* Sub-View Panels for Response Body */}
              {respSubView === 'formatted' && (
                <FormattedContentRenderer
                  content={flow.response_body}
                  contentType={flow.response_content_type}
                  highlightWords={reflectedWords}
                  onSendToDecoder={handleOpenDecoder}
                />
              )}

              {respSubView === 'hex' && (
                <HexDumpRenderer
                  content={flow.response_body}
                  onSendToDecoder={handleOpenDecoder}
                />
              )}

              {respSubView === 'form' && (
                <FormDataRenderer
                  content={flow.response_body}
                  contentType={flow.response_content_type}
                  highlightWords={reflectedWords}
                  onSendToDecoder={handleOpenDecoder}
                />
              )}

              {respSubView === 'raw' && (
                <div className="p-3 bg-[#0A0E17] border border-border rounded-lg">
                  <pre className="text-slate-300 whitespace-pre-wrap break-all leading-relaxed">
                    {flow.response_body || '[Empty Body]'}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}


        {/* ========================================================================= */}
        {/* 3. Telemetry & Timing Metrics Tab */}
        {/* ========================================================================= */}
        {activeTab === 'telemetry' && (
          <TelemetryMetricsCard flow={flow} />
        )}

        {/* ========================================================================= */}
        {/* 4. Triage Heuristics Tab */}
        {/* ========================================================================= */}
        {activeTab === 'triage' && (
          <div className="space-y-4">
            {/* Category Cluster */}
            <div className="p-3.5 bg-surface/70 border border-border rounded-lg">
              <div className="flex items-center justify-between mb-1">
                <span className="text-slate-400 text-[11px] uppercase font-bold">Endpoint Classification</span>
                <Badge variant="mutation" size="sm">
                  {flow.triage?.endpoint_category || 'DATA_READ'}
                </Badge>
              </div>
              <p className="text-slate-300 text-xs mt-1">
                Classified by HTTP method ({flow.method}) and endpoint path structure ({flow.path}).
              </p>
            </div>

            {/* Reflected Inputs Card */}
            <div className="p-3.5 bg-yellow-500/5 border border-yellow-500/20 rounded-lg">
              <h4 className="text-yellow-300 font-bold flex items-center gap-1.5 mb-2">
                <Sparkles className="w-4 h-4 text-yellow-400" />
                Input Reflections ({reflections.length})
              </h4>
              {reflections.length === 0 ? (
                <p className="text-slate-500 text-xs">No user inputs reflected in response body or headers.</p>
              ) : (
                <div className="space-y-2">
                  {reflections.map((r, i) => (
                    <div key={i} className="p-2 bg-slate-900/80 rounded border border-yellow-500/30 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-yellow-200 font-semibold">{r.source}.{r.param_name}</span>
                        <Badge variant={r.xss_indicator ? 'danger' : 'warning'} size="sm">
                          {r.context}
                        </Badge>
                      </div>
                      <div className="mt-1 text-slate-300">
                        Value: <code className="text-yellow-300 bg-yellow-500/20 px-1 py-0.5 rounded">{r.value}</code>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Identifier & IDOR Triage Card */}
            <div className="p-3.5 bg-orange-500/5 border border-orange-500/20 rounded-lg">
              <h4 className="text-orange-300 font-bold flex items-center gap-1.5 mb-2">
                <Zap className="w-4 h-4 text-orange-400" />
                Identifier & IDOR Triage
              </h4>
              {(!flow.triage?.identifiers || flow.triage.identifiers.length === 0) ? (
                <p className="text-slate-500 text-xs">No candidate object identifiers detected in parameters.</p>
              ) : (
                <div className="space-y-2">
                  {flow.triage.identifiers.map((idItem, i) => (
                    <div key={i} className="p-2 bg-slate-900/80 rounded border border-orange-500/30 text-xs flex items-center justify-between">
                      <div>
                        <div className="font-semibold text-slate-200">{idItem.param_name} = <code className="text-orange-300">{idItem.value}</code></div>
                        <div className="text-[11px] text-slate-400">Type: {idItem.id_type}</div>
                      </div>
                      <Badge variant={idItem.idor_risk === 'HIGH' ? 'idor' : 'neutral'} size="sm">
                        {idItem.idor_risk} IDOR RISK
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Auth & Session State */}
            <div className="p-3.5 bg-purple-500/5 border border-purple-500/20 rounded-lg">
              <h4 className="text-purple-300 font-bold flex items-center gap-1.5 mb-2">
                <ShieldCheck className="w-4 h-4 text-purple-400" />
                Authentication & Session Tracking
              </h4>
              <div className="text-xs space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Auth Present:</span>
                  <span className={flow.triage?.auth?.auth_present ? 'text-emerald-400 font-semibold' : 'text-slate-400'}>
                    {flow.triage?.auth?.auth_present ? `Yes (${flow.triage.auth.auth_type})` : 'Anonymous / None'}
                  </span>
                </div>
                {flow.triage?.auth?.token_preview && (
                  <div className="text-slate-400 break-all flex items-center justify-between gap-2">
                    <div>
                      Token: <code className="text-purple-300">{flow.triage.auth.token_preview}</code>
                    </div>
                    <button
                      onClick={() => handleOpenDecoder(flow.triage?.auth?.token_preview)}
                      className="px-2 py-0.5 rounded bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/40 text-[10px] flex items-center gap-1 flex-shrink-0"
                    >
                      <span>Decode JWT</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>
                )}
                {flow.triage?.auth?.anomaly_flags && flow.triage.auth.anomaly_flags.length > 0 && (
                  <div className="mt-2 p-2 bg-rose-500/10 border border-rose-500/30 rounded text-rose-300">
                    ⚠️ Anomalies: {flow.triage.auth.anomaly_flags.join(', ')}
                  </div>
                )}
              </div>
            </div>

            {/* High Entropy & Secrets */}
            {flow.triage?.entropy && flow.triage.entropy.length > 0 && (
              <div className="p-3.5 bg-rose-500/5 border border-rose-500/20 rounded-lg">
                <h4 className="text-rose-300 font-bold flex items-center gap-1.5 mb-2">
                  <Key className="w-4 h-4 text-rose-400" />
                  High-Entropy Secrets Detected ({flow.triage.entropy.length})
                </h4>
                <div className="space-y-2">
                  {flow.triage.entropy.map((e, i) => (
                    <div key={i} className="p-2 bg-slate-900/80 rounded border border-rose-500/30 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-200 font-semibold">{e.param_name}</span>
                        <Badge variant="danger" size="sm">
                          Entropy: {e.shannon_entropy.toFixed(2)}
                        </Badge>
                      </div>
                      <div className="text-[11px] text-rose-300 mt-1 flex items-center justify-between">
                        <span>Pattern: {e.secret_pattern || 'GENERIC_HIGH_ENTROPY'}</span>
                        <button
                          onClick={() => handleOpenDecoder(e.value_preview)}
                          className="text-[10px] text-cyan-400 hover:underline"
                        >
                          Send to Decoder
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ========================================================================= */}
        {/* 5. Raw Tab */}
        {/* ========================================================================= */}
        {activeTab === 'raw' && (
          <div className="space-y-4">
            <div>
              <h4 className="text-slate-400 text-[11px] font-bold uppercase tracking-wider mb-2">
                Raw Request Stream
              </h4>
              <pre className="p-3 bg-[#0A0E17] border border-border rounded-lg font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre">
                {`${flow.method} ${flow.path} HTTP/1.1\n` +
                  Object.entries(flow.request_headers || {})
                    .map(([k, v]) => `${k}: ${v}`)
                    .join('\n') +
                  (flow.request_body ? `\n\n${flow.request_body}` : '')}
              </pre>
            </div>

            <div>
              <h4 className="text-slate-400 text-[11px] font-bold uppercase tracking-wider mb-2">
                Raw Response Stream
              </h4>
              <pre className="p-3 bg-[#0A0E17] border border-border rounded-lg font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre">
                {`HTTP/1.1 ${flow.response_status || 200} ${flow.response_status_text || 'OK'}\n` +
                  Object.entries(flow.response_headers || {})
                    .map(([k, v]) => `${k}: ${v}`)
                    .join('\n') +
                  (flow.response_body ? `\n\n${flow.response_body}` : '')}
              </pre>
            </div>
          </div>
        )}
      </div>

      {/* Multi-Layer Decoder Modal / Drawer */}
      <MultiLayerDecoderModal
        isOpen={isDecoderOpen}
        onClose={() => setIsDecoderOpen(false)}
        initialInput={decoderInputText}
      />
    </div>
  );
};
