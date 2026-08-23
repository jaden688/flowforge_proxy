import React, { useState, useMemo } from 'react';
import { generateHexDump, HexDumpRow } from '../../../utils/decoder';
import { Copy, Check, Search, ChevronLeft, ChevronRight, Binary, ArrowRight } from 'lucide-react';

export interface HexDumpRendererProps {
  content: string | null | undefined;
  pageSize?: number;
  onSendToDecoder?: (text: string) => void;
  className?: string;
}

export const HexDumpRenderer: React.FC<HexDumpRendererProps> = ({
  content,
  pageSize = 32, // 32 rows * 16 bytes = 512 bytes per page
  onSendToDecoder,
  className = '',
}) => {
  const [currentPage, setCurrentPage] = useState(0);
  const [hoveredByteIndex, setHoveredByteIndex] = useState<number | null>(null);
  const [selectedRange, setSelectedRange] = useState<[number, number] | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedType, setCopiedType] = useState<string | null>(null);

  const rawBytes = useMemo(() => {
    if (!content) return new Uint8Array(0);
    return new TextEncoder().encode(content);
  }, [content]);

  const allRows: HexDumpRow[] = useMemo(() => {
    if (rawBytes.length === 0) return [];
    return generateHexDump(rawBytes, 16);
  }, [rawBytes]);

  const totalPages = Math.max(1, Math.ceil(allRows.length / pageSize));
  const visibleRows = useMemo(() => {
    const start = currentPage * pageSize;
    return allRows.slice(start, start + pageSize);
  }, [allRows, currentPage, pageSize]);

  // Search match offsets
  const searchMatches = useMemo(() => {
    if (!searchQuery.trim() || rawBytes.length === 0) return new Set<number>();
    const matches = new Set<number>();
    const q = searchQuery.toLowerCase();

    // 1. Text search
    const text = new TextDecoder('utf-8').decode(rawBytes).toLowerCase();
    let idx = text.indexOf(q);
    while (idx !== -1) {
      for (let i = 0; i < q.length; i++) {
        matches.add(idx + i);
      }
      idx = text.indexOf(q, idx + 1);
    }

    // 2. Hex search (e.g. "48 65" or "4865")
    const cleanHexQuery = q.replace(/[\s0x]/g, '');
    if (/^[0-9a-f]+$/.test(cleanHexQuery) && cleanHexQuery.length % 2 === 0) {
      const targetBytes: number[] = [];
      for (let i = 0; i < cleanHexQuery.length; i += 2) {
        targetBytes.push(parseInt(cleanHexQuery.substring(i, i + 2), 16));
      }
      for (let i = 0; i <= rawBytes.length - targetBytes.length; i++) {
        let match = true;
        for (let j = 0; j < targetBytes.length; j++) {
          if (rawBytes[i + j] !== targetBytes[j]) {
            match = false;
            break;
          }
        }
        if (match) {
          for (let j = 0; j < targetBytes.length; j++) {
            matches.add(i + j);
          }
        }
      }
    }

    return matches;
  }, [searchQuery, rawBytes]);

  if (!content || rawBytes.length === 0) {
    return (
      <div className={`p-6 text-xs font-mono text-slate-500 italic bg-[#0A0E17] rounded-lg border border-border text-center ${className}`}>
        [Empty Payload — 0 Bytes]
      </div>
    );
  }

  const copyToClipboard = (type: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  const handleCopyRaw = () => {
    copyToClipboard('raw', content);
  };

  const handleCopyHexStream = () => {
    let hex = '';
    for (let i = 0; i < rawBytes.length; i++) {
      hex += rawBytes[i].toString(16).padStart(2, '0');
    }
    copyToClipboard('hex', hex);
  };

  const handleCopyCArray = () => {
    const arrayStr = `const unsigned char payload[${rawBytes.length}] = {\n  ` +
      Array.from(rawBytes).map(b => `0x${b.toString(16).padStart(2, '0')}`).join(', ') +
      '\n};';
    copyToClipboard('carray', arrayStr);
  };

  const handleCopyFullDump = () => {
    const dumpText = allRows.map(r => {
      const hexLeft = r.bytesHex.slice(0, 8).map(b => b || '  ').join(' ');
      const hexRight = r.bytesHex.slice(8, 16).map(b => b || '  ').join(' ');
      return `${r.offsetHex}  ${hexLeft}  ${hexRight}  |${r.ascii.join('')}|`;
    }).join('\n');
    copyToClipboard('dump', dumpText);
  };

  // Hovered byte info
  const hoveredByteVal = hoveredByteIndex !== null && hoveredByteIndex < rawBytes.length
    ? rawBytes[hoveredByteIndex]
    : null;

  return (
    <div className={`flex flex-col bg-[#0A0E17] border border-border rounded-lg overflow-hidden font-mono text-xs ${className}`}>
      {/* Header Toolbar */}
      <div className="p-2.5 bg-surface/80 border-b border-border flex flex-wrap items-center justify-between gap-2 select-none">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-[11px] font-semibold">
            <Binary className="w-3 h-3 text-primary" />
            <span>Hex Dump</span>
          </div>
          <span className="text-slate-400 text-[11px]">
            {rawBytes.length} bytes ({allRows.length} lines)
          </span>
        </div>

        {/* Search & Actions */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(0);
              }}
              placeholder="Search text or hex..."
              className="pl-7 pr-2 py-1 bg-slate-900 border border-slate-700/80 rounded text-[11px] text-slate-200 placeholder-slate-500 focus:outline-none focus:border-primary w-40"
            />
          </div>

          <div className="flex items-center gap-1 border-l border-slate-700 pl-2">
            <button
              onClick={handleCopyRaw}
              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] flex items-center gap-1"
              title="Copy Raw String"
            >
              {copiedType === 'raw' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>Raw</span>
            </button>

            <button
              onClick={handleCopyHexStream}
              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] flex items-center gap-1"
              title="Copy Continuous Hex Stream"
            >
              {copiedType === 'hex' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>Hex</span>
            </button>

            <button
              onClick={handleCopyCArray}
              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] flex items-center gap-1"
              title="Copy C Array definition"
            >
              {copiedType === 'carray' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>C Array</span>
            </button>

            <button
              onClick={handleCopyFullDump}
              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] flex items-center gap-1"
              title="Copy Full Formatted Hex Dump"
            >
              {copiedType === 'dump' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>Dump</span>
            </button>

            {onSendToDecoder && (
              <button
                onClick={() => onSendToDecoder(content)}
                className="px-2 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[10px] font-semibold flex items-center gap-1 transition-colors"
                title="Send body to Multi-Layer Decoder"
              >
                <span>Decoder</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Hex Table Viewport */}
      <div className="p-3 overflow-x-auto select-text max-h-[520px]">
        <table className="w-full border-collapse leading-relaxed">
          <thead>
            <tr className="text-[10px] text-slate-500 border-b border-border/60 select-none pb-1">
              <th className="text-left font-mono font-normal pr-4 w-20">OFFSET</th>
              <th className="text-left font-mono font-normal px-2" colSpan={8}>
                00 01 02 03 04 05 06 07
              </th>
              <th className="w-2"></th>
              <th className="text-left font-mono font-normal px-2" colSpan={8}>
                08 09 0A 0B 0C 0D 0E 0F
              </th>
              <th className="text-left font-mono font-normal pl-4">ASCII DECODED</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/20">
            {visibleRows.map((row) => (
              <tr key={row.offset} className="hover:bg-slate-900/50 transition-colors">
                {/* Offset Column */}
                <td className="text-cyan-500/80 select-none font-bold pr-4 align-top">
                  {row.offsetHex}
                </td>

                {/* Left 8 Hex Bytes */}
                {row.bytesHex.slice(0, 8).map((hex, j) => {
                  const byteIdx = row.offset + j;
                  const isHovered = hoveredByteIndex === byteIdx;
                  const isMatch = searchMatches.has(byteIdx);
                  const isNull = hex === null;

                  return (
                    <td
                      key={j}
                      onMouseEnter={() => !isNull && setHoveredByteIndex(byteIdx)}
                      onMouseLeave={() => setHoveredByteIndex(null)}
                      className={`text-center px-1 font-mono transition-colors ${
                        isNull
                          ? 'text-transparent'
                          : isMatch
                          ? 'bg-yellow-500/30 text-yellow-300 font-bold rounded'
                          : isHovered
                          ? 'bg-cyan-500/30 text-white font-bold rounded'
                          : hex === '00'
                          ? 'text-slate-600'
                          : hex === 'ff'
                          ? 'text-rose-400'
                          : 'text-slate-300'
                      }`}
                    >
                      {hex || '  '}
                    </td>
                  );
                })}

                {/* Center Spacer */}
                <td className="w-2 text-slate-700 select-none text-center"> </td>

                {/* Right 8 Hex Bytes */}
                {row.bytesHex.slice(8, 16).map((hex, j) => {
                  const byteIdx = row.offset + 8 + j;
                  const isHovered = hoveredByteIndex === byteIdx;
                  const isMatch = searchMatches.has(byteIdx);
                  const isNull = hex === null;

                  return (
                    <td
                      key={j}
                      onMouseEnter={() => !isNull && setHoveredByteIndex(byteIdx)}
                      onMouseLeave={() => setHoveredByteIndex(null)}
                      className={`text-center px-1 font-mono transition-colors ${
                        isNull
                          ? 'text-transparent'
                          : isMatch
                          ? 'bg-yellow-500/30 text-yellow-300 font-bold rounded'
                          : isHovered
                          ? 'bg-cyan-500/30 text-white font-bold rounded'
                          : hex === '00'
                          ? 'text-slate-600'
                          : hex === 'ff'
                          ? 'text-rose-400'
                          : 'text-slate-300'
                      }`}
                    >
                      {hex || '  '}
                    </td>
                  );
                })}

                {/* ASCII Column */}
                <td className="pl-4 font-mono text-slate-300 border-l border-slate-800/80 whitespace-pre">
                  {row.ascii.map((char, j) => {
                    const byteIdx = row.offset + j;
                    const isHovered = hoveredByteIndex === byteIdx;
                    const isMatch = searchMatches.has(byteIdx);
                    const isNonPrintable = char === '.';

                    return (
                      <span
                        key={j}
                        onMouseEnter={() => byteIdx < rawBytes.length && setHoveredByteIndex(byteIdx)}
                        onMouseLeave={() => setHoveredByteIndex(null)}
                        className={`inline-block px-[1px] transition-colors ${
                          isMatch
                            ? 'bg-yellow-500/30 text-yellow-300 font-bold rounded'
                            : isHovered
                            ? 'bg-cyan-500/30 text-white font-bold rounded'
                            : isNonPrintable
                            ? 'text-slate-600'
                            : 'text-emerald-400 font-medium'
                        }`}
                      >
                        {char}
                      </span>
                    );
                  })}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Footer Info & Pagination */}
      <div className="p-2 bg-[#080B12] border-t border-border flex items-center justify-between text-[11px] text-slate-400 select-none">
        {/* Byte Inspector Status */}
        <div className="flex items-center gap-3">
          {hoveredByteVal !== null && hoveredByteIndex !== null ? (
            <div className="flex items-center gap-3 text-cyan-300">
              <span>Offset: <strong className="text-white">0x{hoveredByteIndex.toString(16).padStart(4, '0')}</strong> ({hoveredByteIndex})</span>
              <span>Hex: <strong className="text-white">0x{hoveredByteVal.toString(16).padStart(2, '0').toUpperCase()}</strong></span>
              <span>Dec: <strong className="text-white">{hoveredByteVal}</strong></span>
              <span>Bin: <strong className="text-white">{hoveredByteVal.toString(2).padStart(8, '0')}</strong></span>
              <span>Char: <strong className="text-emerald-400">{hoveredByteVal >= 32 && hoveredByteVal <= 126 ? `'${String.fromCharCode(hoveredByteVal)}'` : 'Non-printable'}</strong></span>
            </div>
          ) : (
            <span className="text-slate-500">Hover over any byte or ASCII character for real-time numerical and binary inspection</span>
          )}
        </div>

        {/* Pagination Controls */}
        {totalPages > 1 && (
          <div className="flex items-center gap-2">
            <span>
              Page {currentPage + 1} of {totalPages}
            </span>
            <div className="flex items-center gap-1">
              <button
                disabled={currentPage === 0}
                onClick={() => setCurrentPage(p => Math.max(0, p - 1))}
                className="p-1 rounded bg-slate-800 disabled:opacity-30 hover:bg-slate-700 text-slate-300"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <button
                disabled={currentPage >= totalPages - 1}
                onClick={() => setCurrentPage(p => Math.min(totalPages - 1, p + 1))}
                className="p-1 rounded bg-slate-800 disabled:opacity-30 hover:bg-slate-700 text-slate-300"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
