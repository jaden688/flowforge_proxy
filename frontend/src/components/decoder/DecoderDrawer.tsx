import React, { useState, useEffect, useMemo } from 'react';
import { 
  Binary, 
  X, 
  Sparkles, 
  Plus, 
  Trash2, 
  ArrowRight, 
  Copy, 
  Check, 
  RefreshCw, 
  ShieldCheck, 
  Code, 
  Sliders, 
  FileText, 
  Layers, 
  Zap,
  RotateCcw
} from 'lucide-react';
import { 
  DecoderOperationType, 
  DecoderStep, 
  DetectedFormatType 
} from '../../types';
import { 
  detectFormat, 
  executeChain, 
  parseJwt, 
  calculateEntropy 
} from '../../utils/decoder';
import { JwtClaimsViewer } from './JwtClaimsViewer';

export interface DecoderDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  initialInput?: string;
  className?: string;
}

const SAMPLE_PAYLOADS: { label: string; value: string; desc: string }[] = [
  {
    label: 'JWT Token (HS256)',
    desc: 'Sample auth bearer token with role and expiration',
    value: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIEhhY2tlciIsImFkbWluIjp0cnVlLCJyb2xlIjoiYWRtaW4iLCJlbWFpbCI6ImFsaWNlQHRhcmdldC5jb20iLCJpYXQiOjE3MDgwMDAwMDAsImV4cCI6MTgwMDAwMDAwMH0.3e1j3G95f-9kYp28jK5Vp4M902xXk1aK_8b3Z1z4k2w',
  },
  {
    label: 'Nested Base64 in URL',
    desc: 'URL-encoded base64 payload',
    value: '%65%79%4a%68%62%47%63%69%4f%69%4a%49%55%7a%49%31%4e%69%49%73%49%6e%52%35%63%43%49%36%49%6b%70%58%56%43%4a%39',
  },
  {
    label: 'Hex Stream String',
    desc: 'Raw hexadecimal byte sequence',
    value: '466c6f77466f7267652053656375726974792054657374696e6720576f726b62656e6368',
  },
  {
    label: 'HTML Entities & Special Chars',
    desc: 'XSS & HTML entity escaped string',
    value: '&lt;script&gt;alert(&quot;FlowForge&quot;)&lt;/script&gt;&amp;user=&#x61;&#x64;&#x6d;&#x69;&#x6e;',
  },
];

const AVAILABLE_OPERATIONS: { op: DecoderOperationType; label: string; category: string }[] = [
  { op: 'base64_decode', label: 'Base64 Decode', category: 'Encoding' },
  { op: 'base64_encode', label: 'Base64 Encode', category: 'Encoding' },
  { op: 'base64url_decode', label: 'Base64URL Decode', category: 'Encoding' },
  { op: 'base64url_encode', label: 'Base64URL Encode', category: 'Encoding' },
  { op: 'url_decode', label: 'URL Percent Decode', category: 'Web' },
  { op: 'url_encode', label: 'URL Percent Encode', category: 'Web' },
  { op: 'html_decode', label: 'HTML Entity Decode', category: 'Web' },
  { op: 'html_encode', label: 'HTML Entity Encode', category: 'Web' },
  { op: 'hex_decode', label: 'Hex String to Text', category: 'Binary' },
  { op: 'hex_encode', label: 'Text to Hex Stream', category: 'Binary' },
  { op: 'hex_dump', label: 'Format as Hex Dump', category: 'Binary' },
  { op: 'json_prettify', label: 'JSON Prettify (2-spaces)', category: 'Formatting' },
  { op: 'json_minify', label: 'JSON Minify', category: 'Formatting' },
  { op: 'rot13', label: 'ROT13 Caesar Cipher', category: 'Cipher' },
  { op: 'jwt_decode', label: 'JWT Parse & Audit', category: 'Security' },
];

export const DecoderDrawer: React.FC<DecoderDrawerProps> = ({
  isOpen,
  onClose,
  initialInput = '',
  className = '',
}) => {
  const [input, setInput] = useState(initialInput);
  const [pipeline, setPipeline] = useState<DecoderOperationType[]>([]);
  const [activeTab, setActiveTab] = useState<'pipeline' | 'jwt'>('pipeline');
  const [copied, setCopied] = useState(false);

  // Sync initial input
  useEffect(() => {
    if (initialInput) {
      setInput(initialInput);
      const detection = detectFormat(initialInput);
      if (detection.suggestedOperations.length > 0) {
        setPipeline(detection.suggestedOperations.slice(0, 2));
      }
      if (detection.format === 'JWT') {
        setActiveTab('jwt');
      }
    }
  }, [initialInput]);

  // Real-time format auto-detection
  const detection = useMemo(() => detectFormat(input), [input]);
  const inputEntropy = useMemo(() => calculateEntropy(input), [input]);

  // Execute pipeline chain
  const chainResult = useMemo(() => {
    return executeChain(input, pipeline);
  }, [input, pipeline]);

  // JWT parsed data if available
  const jwtData = useMemo(() => {
    return parseJwt(input) || (chainResult.final_output ? parseJwt(chainResult.final_output) : null);
  }, [input, chainResult.final_output]);

  if (!isOpen) return null;

  const handleApplyAutoDetection = () => {
    if (detection.suggestedOperations.length > 0) {
      setPipeline(detection.suggestedOperations);
      if (detection.format === 'JWT') {
        setActiveTab('jwt');
      }
    }
  };

  const handleAddStep = (op: DecoderOperationType) => {
    setPipeline(prev => [...prev, op]);
  };

  const handleRemoveStep = (index: number) => {
    setPipeline(prev => prev.filter((_, i) => i !== index));
  };

  const handleResetPipeline = () => {
    setPipeline([]);
  };

  const handleCopyOutput = () => {
    navigator.clipboard.writeText(chainResult.final_output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`fixed inset-y-0 right-0 w-full max-w-2xl bg-[#0B0F17] border-l border-border shadow-2xl z-50 flex flex-col font-mono text-xs ${className}`}>
      {/* Top Drawer Header */}
      <div className="h-14 px-4 bg-surface border-b border-border flex items-center justify-between select-none">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-300">
            <Binary className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-bold text-white text-sm flex items-center gap-2">
              Multi-Layer Decoder Workbench
            </h3>
            <p className="text-[10px] text-slate-400">
              One-click multi-pass transformation and token auditing
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Tab Switcher */}
          <div className="flex items-center bg-slate-900 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => setActiveTab('pipeline')}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                activeTab === 'pipeline' ? 'bg-primary text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Pipeline ({pipeline.length})
            </button>
            <button
              onClick={() => setActiveTab('jwt')}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors flex items-center gap-1 ${
                activeTab === 'jwt' ? 'bg-primary text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <ShieldCheck className="w-3 h-3" />
              <span>JWT Audit</span>
              {jwtData && (
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              )}
            </button>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Drawer Body Viewport */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Input Section */}
        <div className="space-y-2">
          <div className="flex items-center justify-between select-none">
            <label className="text-[11px] text-slate-300 font-bold uppercase tracking-wider flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5 text-primary" />
              <span>Input Data ({input.length} chars • Entropy: {inputEntropy.toFixed(2)})</span>
            </label>

            {/* Sample Presets Dropdown */}
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-slate-500">Presets:</span>
              {SAMPLE_PAYLOADS.map((sample, i) => (
                <button
                  key={i}
                  onClick={() => setInput(sample.value)}
                  className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] border border-slate-700"
                  title={sample.desc}
                >
                  {sample.label.split(' ')[0]}
                </button>
              ))}
              <button
                onClick={() => setInput('')}
                className="px-2 py-0.5 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 text-[10px] border border-rose-500/30"
              >
                Clear
              </button>
            </div>
          </div>

          <textarea
            rows={4}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Paste Base64, JWT token, URL-encoded string, or raw Hex stream here..."
            className="w-full bg-[#0A0E17] border border-border rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-primary leading-relaxed"
          />

          {/* Real-time Format Auto-Detection Banner */}
          {input.trim() && (
            <div className="p-2.5 bg-slate-900/80 border border-slate-800 rounded-lg flex items-center justify-between select-none">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-yellow-400" />
                <span className="text-slate-400 text-[11px]">Detected:</span>
                <span className="text-cyan-300 font-bold text-[11px] bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/30">
                  {detection.label}
                </span>
                <span className="text-[10px] text-slate-500">
                  ({(detection.confidence * 100).toFixed(0)}% match)
                </span>
              </div>

              <button
                onClick={handleApplyAutoDetection}
                className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[11px] font-semibold flex items-center gap-1"
              >
                <Zap className="w-3 h-3" />
                <span>Auto-Decode</span>
              </button>
            </div>
          )}
        </div>

        {/* Tab 1: Multi-Step Transformation Pipeline */}
        {activeTab === 'pipeline' && (
          <div className="space-y-4">
            {/* Pipeline Controls & Add Step */}
            <div className="p-3 bg-[#0A0E17] border border-border rounded-lg space-y-3">
              <div className="flex items-center justify-between select-none">
                <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                  <Sliders className="w-3.5 h-3.5 text-primary" />
                  <span>Pipeline Operations ({pipeline.length} steps)</span>
                </span>
                {pipeline.length > 0 && (
                  <button
                    onClick={handleResetPipeline}
                    className="text-[10px] text-slate-400 hover:text-rose-300 flex items-center gap-1"
                  >
                    <RotateCcw className="w-3 h-3" />
                    <span>Reset Chain</span>
                  </button>
                )}
              </div>

              {/* Quick Add Operation Chips */}
              <div className="flex flex-wrap gap-1.5 select-none">
                {AVAILABLE_OPERATIONS.map((item) => (
                  <button
                    key={item.op}
                    onClick={() => handleAddStep(item.op)}
                    className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 hover:border-slate-700 text-[10px] flex items-center gap-1 transition-colors"
                  >
                    <Plus className="w-2.5 h-2.5 text-primary" />
                    <span>{item.label}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Pipeline Steps List & Intermediate Previews */}
            {chainResult.steps.length === 0 ? (
              <div className="p-6 bg-slate-950/40 border border-dashed border-slate-800 rounded-lg text-center text-slate-500 text-xs">
                No transformation operations added. Click any operation chip above to build a multi-pass pipeline.
              </div>
            ) : (
              <div className="space-y-3">
                {chainResult.steps.map((step, idx) => (
                  <div
                    key={step.id}
                    className={`p-3 rounded-lg border ${
                      step.error
                        ? 'bg-rose-500/10 border-rose-500/30'
                        : 'bg-[#0A0E17] border-border'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5 select-none">
                      <div className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center text-[10px] font-bold">
                          {idx + 1}
                        </span>
                        <span className="font-bold text-white text-xs">
                          {AVAILABLE_OPERATIONS.find(o => o.op === step.operation)?.label || step.operation}
                        </span>
                        <span className="text-[10px] text-slate-500">
                          {step.duration_ms}ms • Δ Entropy: {step.entropy_delta > 0 ? `+${step.entropy_delta}` : step.entropy_delta}
                        </span>
                      </div>

                      <button
                        onClick={() => handleRemoveStep(idx)}
                        className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-500/10"
                        title="Remove step"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    {step.error ? (
                      <div className="text-rose-400 text-xs mt-1 p-2 bg-rose-950/40 rounded border border-rose-800/40">
                        ⚠️ Error: {step.error}
                      </div>
                    ) : (
                      <pre className="p-2 bg-slate-950 rounded border border-slate-800/60 text-slate-300 font-mono text-[11px] max-h-28 overflow-y-auto whitespace-pre-wrap break-all">
                        {step.output}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Final Output Section */}
            <div className="space-y-2 pt-2 border-t border-border">
              <div className="flex items-center justify-between select-none">
                <label className="text-[11px] text-emerald-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Final Decoded Output ({chainResult.final_output.length} chars)</span>
                </label>

                <button
                  onClick={handleCopyOutput}
                  className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] font-medium flex items-center gap-1.5 transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy Output</span>
                </button>
              </div>

              <textarea
                readOnly
                rows={6}
                value={chainResult.final_output}
                className="w-full bg-[#0A0E17] border border-border rounded-lg p-3 text-xs font-mono text-emerald-300 leading-relaxed select-all"
              />
            </div>
          </div>
        )}

        {/* Tab 2: JWT Claims Viewer */}
        {activeTab === 'jwt' && (
          <div>
            {jwtData ? (
              <JwtClaimsViewer jwtData={jwtData} />
            ) : (
              <div className="p-8 bg-slate-950/40 border border-dashed border-slate-800 rounded-lg text-center text-slate-500 text-xs">
                <ShieldCheck className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                <p>No valid JWT Token detected in input or decoded output.</p>
                <button
                  onClick={() => setInput(SAMPLE_PAYLOADS[0].value)}
                  className="mt-3 px-3 py-1.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-xs font-semibold"
                >
                  Load Sample JWT
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
