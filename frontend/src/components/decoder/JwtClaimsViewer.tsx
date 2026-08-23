import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Clock, 
  AlertTriangle, 
  Copy, 
  Check, 
  Key, 
  Lock, 
  User, 
  Shield, 
  ExternalLink,
  Code
} from 'lucide-react';
import { JwtDecoded } from '../../types';

export interface JwtClaimsViewerProps {
  jwtData: JwtDecoded;
  className?: string;
}

export const JwtClaimsViewer: React.FC<JwtClaimsViewerProps> = ({
  jwtData,
  className = '',
}) => {
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const copyText = (section: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(section);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const { header, payload, expiry, security_flags, sensitive_claims } = jwtData;

  return (
    <div className={`space-y-4 font-mono text-xs ${className}`}>
      {/* 1. Color-Coded Token Raw Representation */}
      <div className="p-3 bg-[#0A0E17] border border-border rounded-lg">
        <div className="flex items-center justify-between mb-2 select-none">
          <span className="text-[11px] text-slate-400 font-bold uppercase tracking-wider">
            Token Structure (Base64URL)
          </span>
          <button
            onClick={() => copyText('raw', jwtData.raw)}
            className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] flex items-center gap-1"
          >
            {copiedSection === 'raw' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>Copy Token</span>
          </button>
        </div>

        <div className="p-2.5 bg-slate-950 rounded border border-slate-800 break-all leading-relaxed font-mono select-all">
          <span className="text-rose-400 font-semibold" title="Header (Algorithm & Token Type)">
            {jwtData.header_raw}
          </span>
          <span className="text-slate-500 select-none">.</span>
          <span className="text-purple-400 font-semibold" title="Payload (Claims & User Data)">
            {jwtData.payload_raw}
          </span>
          <span className="text-slate-500 select-none">.</span>
          <span className="text-cyan-400 font-semibold" title="Signature">
            {jwtData.signature_raw || <span className="text-rose-500 italic">[UNSIGNED / NONE]</span>}
          </span>
        </div>

        <div className="flex items-center gap-4 mt-2 text-[11px] select-none">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
            <span className="text-rose-300">Header</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-500" />
            <span className="text-purple-300">Payload</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
            <span className="text-cyan-300">Signature</span>
          </div>
        </div>
      </div>

      {/* 2. Security Flags & Expiry Audit Banner */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Expiry Status Widget */}
        <div className="p-3.5 bg-[#0A0E17] border border-border rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-amber-400" />
              <h4 className="text-slate-200 font-bold text-[11px] uppercase">
                Expiration Status
              </h4>
            </div>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                expiry.status_badge === 'ACTIVE'
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                  : expiry.status_badge === 'EXPIRED'
                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                  : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
              }`}
            >
              {expiry.status_badge}
            </span>
          </div>

          <div className="text-slate-300 text-xs mb-2">
            <strong>{expiry.relative_expiry}</strong>
          </div>

          <div className="space-y-1 text-[11px] text-slate-400">
            {expiry.expires_at && (
              <div>
                <span>Expires: </span>
                <span className="text-slate-200">{expiry.expires_at.toUTCString()}</span>
              </div>
            )}
            {expiry.issued_at && (
              <div>
                <span>Issued At (iat): </span>
                <span className="text-slate-200">{expiry.issued_at.toUTCString()}</span>
              </div>
            )}
            {expiry.not_before && (
              <div>
                <span>Not Before (nbf): </span>
                <span className="text-slate-200">{expiry.not_before.toUTCString()}</span>
              </div>
            )}
          </div>
        </div>

        {/* Security Vulnerability Audit */}
        <div className="p-3.5 bg-[#0A0E17] border border-border rounded-lg">
          <div className="flex items-center gap-2 mb-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <h4 className="text-slate-200 font-bold text-[11px] uppercase">
              Security Audit ({security_flags.length})
            </h4>
          </div>

          {security_flags.length === 0 ? (
            <div className="flex items-center gap-2 text-emerald-400 text-xs p-2 bg-emerald-500/10 rounded border border-emerald-500/20">
              <ShieldCheck className="w-4 h-4" />
              <span>No critical configuration flaws detected.</span>
            </div>
          ) : (
            <div className="space-y-2 max-h-36 overflow-y-auto">
              {security_flags.map((flag, idx) => (
                <div
                  key={idx}
                  className={`p-2 rounded border text-[11px] ${
                    flag.level === 'CRITICAL'
                      ? 'bg-rose-500/15 border-rose-500/40 text-rose-200'
                      : flag.level === 'HIGH'
                      ? 'bg-orange-500/15 border-orange-500/40 text-orange-200'
                      : 'bg-amber-500/15 border-amber-500/40 text-amber-200'
                  }`}
                >
                  <div className="font-bold flex items-center justify-between">
                    <span>{flag.title}</span>
                    <span className="text-[9px] uppercase px-1 rounded bg-black/40">
                      {flag.level}
                    </span>
                  </div>
                  <div className="text-[10px] mt-0.5 opacity-90">
                    {flag.description}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* 3. Parsed Header & Payload Side-by-Side */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Header Block (Red theme) */}
        <div className="p-3 bg-[#0A0E17] border border-rose-500/30 rounded-lg">
          <div className="flex items-center justify-between mb-2 select-none">
            <div className="flex items-center gap-1.5 text-rose-400 font-bold">
              <Code className="w-3.5 h-3.5" />
              <span>HEADER: Algorithm & Type</span>
            </div>
            <button
              onClick={() => copyText('header', JSON.stringify(header, null, 2))}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px]"
              title="Copy Header JSON"
            >
              {copiedSection === 'header' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>
          <pre className="p-2.5 bg-slate-950 rounded border border-rose-500/20 text-rose-300 overflow-x-auto whitespace-pre-wrap">
            {JSON.stringify(header, null, 2)}
          </pre>
        </div>

        {/* Payload Block (Purple theme) */}
        <div className="p-3 bg-[#0A0E17] border border-purple-500/30 rounded-lg">
          <div className="flex items-center justify-between mb-2 select-none">
            <div className="flex items-center gap-1.5 text-purple-400 font-bold">
              <User className="w-3.5 h-3.5" />
              <span>PAYLOAD: Claims & Data</span>
            </div>
            <button
              onClick={() => copyText('payload', JSON.stringify(payload, null, 2))}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px]"
              title="Copy Payload JSON"
            >
              {copiedSection === 'payload' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>
          <pre className="p-2.5 bg-slate-950 rounded border border-purple-500/20 text-purple-300 overflow-x-auto whitespace-pre-wrap max-h-72">
            {JSON.stringify(payload, null, 2)}
          </pre>
        </div>
      </div>

      {/* 4. Sensitive & Privilege Claims Spotlight */}
      {sensitive_claims.length > 0 && (
        <div className="p-3.5 bg-purple-500/5 border border-purple-500/20 rounded-lg">
          <h4 className="text-purple-300 font-bold text-[11px] uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-purple-400" />
            Privilege & Identity Claims ({sensitive_claims.length})
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
            {sensitive_claims.map((claim, idx) => (
              <div key={idx} className="p-2 bg-slate-900 rounded border border-slate-800">
                <div className="text-[10px] text-slate-400">{claim.label}</div>
                <div className="font-semibold text-white truncate" title={claim.key}>
                  {claim.key}
                </div>
                <div className="text-cyan-300 font-mono text-[11px] truncate mt-0.5" title={JSON.stringify(claim.value)}>
                  {JSON.stringify(claim.value)}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
