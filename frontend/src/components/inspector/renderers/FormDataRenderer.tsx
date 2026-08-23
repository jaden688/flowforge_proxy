import React, { useState, useMemo } from 'react';
import { 
  Table, 
  Copy, 
  Check, 
  Search, 
  FileText, 
  Upload, 
  Sparkles, 
  ArrowRight, 
  Code,
  FileCode,
  Layers
} from 'lucide-react';
import { urlDecode } from '../../../utils/decoder';
import { Badge } from '../../common/Badge';

export interface FormDataRendererProps {
  content: string | null | undefined;
  contentType?: string | null;
  highlightWords?: string[];
  onSendToDecoder?: (text: string) => void;
  className?: string;
}

interface ParsedFormField {
  key: string;
  value: string;
  type: 'text' | 'file' | 'json' | 'binary';
  filename?: string;
  contentType?: string;
  sizeBytes: number;
  isReflected?: boolean;
}

export const FormDataRenderer: React.FC<FormDataRendererProps> = ({
  content,
  contentType = '',
  highlightWords = [],
  onSendToDecoder,
  className = '',
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showRaw, setShowRaw] = useState(false);

  // Parse Form Data (URL-Encoded or Multipart)
  const { isMultipart, fields, boundary } = useMemo(() => {
    if (!content) {
      return { isMultipart: false, fields: [], boundary: undefined };
    }

    const ct = (contentType || '').toLowerCase();
    const isMulti = ct.includes('multipart') || content.trim().startsWith('--');

    if (isMulti) {
      // Multipart Parser
      let extractedBoundary = '';
      const match = ct.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
      if (match) {
        extractedBoundary = match[1] || match[2];
      } else {
        // Infer from first line
        const firstLine = content.trim().split('\n')[0];
        if (firstLine.startsWith('--')) {
          extractedBoundary = firstLine.substring(2).trim();
        }
      }

      const boundaryMarker = `--${extractedBoundary}`;
      const rawParts = content.split(boundaryMarker);
      const parsedFields: ParsedFormField[] = [];

      rawParts.forEach((part) => {
        const cleanPart = part.trim();
        if (!cleanPart || cleanPart === '--') return;

        // Split headers from body (separated by \r\n\r\n or \n\n)
        const headerEndIdx = cleanPart.search(/\r?\n\r?\n/);
        if (headerEndIdx === -1) return;

        const headerBlock = cleanPart.substring(0, headerEndIdx);
        const bodyBlock = cleanPart.substring(headerEndIdx).replace(/^\r?\n\r?\n/, '');

        let name = 'unnamed';
        let filename: string | undefined;
        let partContentType = 'text/plain';

        const dispMatch = headerBlock.match(/Content-Disposition:\s*form-data;\s*name="([^"]+)"/i);
        if (dispMatch) name = dispMatch[1];

        const fileMatch = headerBlock.match(/filename="([^"]+)"/i);
        if (fileMatch) filename = fileMatch[1];

        const typeMatch = headerBlock.match(/Content-Type:\s*([^\r\n;]+)/i);
        if (typeMatch) partContentType = typeMatch[1].trim();

        let type: 'text' | 'file' | 'json' | 'binary' = 'text';
        if (filename) {
          type = 'file';
        } else if (partContentType.includes('json') || (bodyBlock.startsWith('{') && bodyBlock.endsWith('}'))) {
          type = 'json';
        } else if (partContentType.includes('octet-stream') || partContentType.includes('image') || partContentType.includes('pdf')) {
          type = 'binary';
        }

        const isReflected = highlightWords.some(w => w.toLowerCase() === name.toLowerCase() || w.toLowerCase() === bodyBlock.toLowerCase());

        parsedFields.push({
          key: name,
          value: bodyBlock,
          type,
          filename,
          contentType: partContentType,
          sizeBytes: new TextEncoder().encode(bodyBlock).length,
          isReflected,
        });
      });

      return { isMultipart: true, fields: parsedFields, boundary: extractedBoundary };
    }

    // URL-Encoded Form Data Parser
    const parsedFields: ParsedFormField[] = [];
    const pairs = content.trim().split('&');

    pairs.forEach((pair) => {
      if (!pair) return;
      const eqIdx = pair.indexOf('=');
      let rawKey = eqIdx !== -1 ? pair.substring(0, eqIdx) : pair;
      let rawVal = eqIdx !== -1 ? pair.substring(eqIdx + 1) : '';

      const key = urlDecode(rawKey);
      const val = urlDecode(rawVal);

      let type: 'text' | 'file' | 'json' | 'binary' = 'text';
      if ((val.startsWith('{') && val.endsWith('}')) || (val.startsWith('[') && val.endsWith(']'))) {
        type = 'json';
      }

      const isReflected = highlightWords.some(w => w.toLowerCase() === key.toLowerCase() || (val && w.toLowerCase() === val.toLowerCase()));

      parsedFields.push({
        key,
        value: val,
        type,
        sizeBytes: new TextEncoder().encode(val).length,
        isReflected,
      });
    });

    return { isMultipart: false, fields: parsedFields, boundary: undefined };
  }, [content, contentType, highlightWords]);

  const filteredFields = useMemo(() => {
    if (!searchQuery.trim()) return fields;
    const q = searchQuery.toLowerCase();
    return fields.filter(f => 
      f.key.toLowerCase().includes(q) || 
      f.value.toLowerCase().includes(q) ||
      (f.filename && f.filename.toLowerCase().includes(q))
    );
  }, [fields, searchQuery]);

  if (!content || fields.length === 0) {
    return (
      <div className={`p-6 text-xs font-mono text-slate-500 italic bg-[#0A0E17] rounded-lg border border-border text-center ${className}`}>
        [No Form-Encoded or Multipart Key-Value Pairs Detected]
      </div>
    );
  }

  const handleCopyValue = (k: string, v: string) => {
    navigator.clipboard.writeText(v);
    setCopiedKey(k);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className={`flex flex-col bg-[#0A0E17] border border-border rounded-lg overflow-hidden font-mono text-xs ${className}`}>
      {/* Header Toolbar */}
      <div className="p-2.5 bg-surface/80 border-b border-border flex flex-wrap items-center justify-between gap-2 select-none">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[11px] font-semibold">
            {isMultipart ? <Upload className="w-3.5 h-3.5" /> : <Table className="w-3.5 h-3.5" />}
            <span>{isMultipart ? 'Multipart Form Data' : 'URL-Encoded Form Data'}</span>
          </div>
          <span className="text-slate-400 text-[11px]">
            {fields.length} Parameters {boundary && `(Boundary: ${boundary})`}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter parameters..."
              className="pl-7 pr-2 py-1 bg-slate-900 border border-slate-700/80 rounded text-[11px] text-slate-200 placeholder-slate-500 focus:outline-none focus:border-primary w-40"
            />
          </div>

          <button
            onClick={() => setShowRaw(!showRaw)}
            className={`px-2.5 py-1 rounded border text-[11px] font-medium transition-colors ${
              showRaw ? 'bg-primary/20 text-primary border-primary/40' : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}
          >
            {showRaw ? 'Table View' : 'Raw Stream'}
          </button>
        </div>
      </div>

      {/* Main Content: Table or Raw */}
      {showRaw ? (
        <div className="p-3 overflow-x-auto max-h-[500px]">
          <pre className="text-slate-300 whitespace-pre-wrap break-all leading-relaxed">
            {content}
          </pre>
        </div>
      ) : (
        <div className="p-3 overflow-x-auto max-h-[500px]">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="text-[11px] text-slate-400 border-b border-border/80 pb-2 select-none">
                <th className="pb-2 font-semibold w-1/4">FIELD NAME</th>
                <th className="pb-2 font-semibold w-24">TYPE</th>
                <th className="pb-2 font-semibold">VALUE / METADATA</th>
                <th className="pb-2 font-semibold w-20 text-right">SIZE</th>
                <th className="pb-2 font-semibold w-24 text-right">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30">
              {filteredFields.map((field, idx) => (
                <tr key={idx} className="hover:bg-slate-900/50 transition-colors group">
                  {/* Field Name */}
                  <td className="py-2.5 pr-3 font-semibold text-cyan-400 align-top">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span>{field.key}</span>
                      {field.isReflected && (
                        <span className="flex items-center gap-0.5 text-[10px] text-yellow-300 bg-yellow-500/20 px-1.5 py-0.2 rounded border border-yellow-500/40">
                          <Sparkles className="w-2.5 h-2.5 text-yellow-400" />
                          Reflected
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Field Type Badge */}
                  <td className="py-2.5 pr-3 align-top select-none">
                    {field.type === 'file' ? (
                      <span className="px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 text-[10px] flex items-center gap-1 w-fit">
                        <FileCode className="w-2.5 h-2.5" />
                        File
                      </span>
                    ) : field.type === 'json' ? (
                      <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px] flex items-center gap-1 w-fit">
                        <Code className="w-2.5 h-2.5" />
                        JSON
                      </span>
                    ) : field.type === 'binary' ? (
                      <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 text-[10px] flex items-center gap-1 w-fit">
                        <Layers className="w-2.5 h-2.5" />
                        Binary
                      </span>
                    ) : (
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px] flex items-center gap-1 w-fit">
                        <FileText className="w-2.5 h-2.5 text-slate-400" />
                        Text
                      </span>
                    )}
                  </td>

                  {/* Value / File Metadata */}
                  <td className="py-2.5 pr-3 text-slate-200 break-all align-top">
                    {field.filename ? (
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="text-slate-400 text-[11px]">Filename:</span>
                          <span className="text-white font-semibold">{field.filename}</span>
                        </div>
                        {field.contentType && (
                          <div className="flex items-center gap-2 text-[11px] text-slate-400">
                            <span>MIME:</span>
                            <span className="text-purple-300 font-mono">{field.contentType}</span>
                          </div>
                        )}
                        <div className="mt-1 text-slate-400 text-[11px] bg-slate-900/80 p-2 rounded border border-slate-800 max-h-24 overflow-y-auto">
                          {field.value.length > 200 ? field.value.substring(0, 200) + '...' : field.value}
                        </div>
                      </div>
                    ) : (
                      <div className="font-mono">
                        {field.value || <span className="text-slate-600 italic">[Empty Value]</span>}
                      </div>
                    )}
                  </td>

                  {/* Size */}
                  <td className="py-2.5 pr-3 text-slate-400 text-right align-top text-[11px]">
                    {field.sizeBytes} B
                  </td>

                  {/* Row Actions */}
                  <td className="py-2.5 text-right align-top select-none">
                    <div className="flex items-center justify-end gap-1 opacity-80 group-hover:opacity-100 transition-opacity">
                      <button
                        onClick={() => handleCopyValue(field.key, field.value)}
                        className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                        title="Copy Parameter Value"
                      >
                        {copiedKey === field.key ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>

                      {onSendToDecoder && (
                        <button
                          onClick={() => onSendToDecoder(field.value)}
                          className="p-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40"
                          title="Send to Decoder"
                        >
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
