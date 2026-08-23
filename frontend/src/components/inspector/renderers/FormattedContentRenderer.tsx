import React, { useState, useMemo } from 'react';
import { 
  Copy, 
  Check, 
  Search, 
  ChevronDown, 
  ChevronRight, 
  Sparkles, 
  ArrowRight, 
  WrapText, 
  ListOrdered,
  Maximize2,
  Minimize2
} from 'lucide-react';
import { jsonPrettify } from '../../../utils/decoder';

export interface FormattedContentRendererProps {
  content: string | null | undefined;
  contentType?: string | null;
  highlightWords?: string[];
  onSendToDecoder?: (text: string) => void;
  className?: string;
}

export const FormattedContentRenderer: React.FC<FormattedContentRendererProps> = ({
  content,
  contentType,
  highlightWords = [],
  onSendToDecoder,
  className = '',
}) => {
  const [copied, setCopied] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [wordWrap, setWordWrap] = useState(true);
  const [showLineNumbers, setShowLineNumbers] = useState(true);
  const [collapsedLines, setCollapsedLines] = useState<Set<number>>(new Set());

  // Determine detected format
  const formatType = useMemo(() => {
    if (!content) return 'text';
    const ct = (contentType || '').toLowerCase();
    if (ct.includes('json') || content.trim().startsWith('{') || content.trim().startsWith('[')) {
      return 'json';
    }
    if (ct.includes('xml') || ct.includes('html') || content.trim().startsWith('<')) {
      return 'xml';
    }
    return 'text';
  }, [content, contentType]);

  // Format content nicely
  const formattedText = useMemo(() => {
    if (!content) return '';
    if (formatType === 'json') {
      try {
        return jsonPrettify(content);
      } catch {
        return content;
      }
    }
    return content;
  }, [content, formatType]);

  const rawLines = useMemo(() => formattedText.split('\n'), [formattedText]);

  if (!content) {
    return (
      <div className={`p-6 text-xs font-mono text-slate-500 italic bg-[#0A0E17] rounded-lg border border-border text-center ${className}`}>
        [Empty Body]
      </div>
    );
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(formattedText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const toggleCollapseLine = (lineIdx: number) => {
    setCollapsedLines(prev => {
      const next = new Set(prev);
      if (next.has(lineIdx)) {
        next.delete(lineIdx);
      } else {
        next.add(lineIdx);
      }
      return next;
    });
  };

  const collapseAll = () => {
    const next = new Set<number>();
    rawLines.forEach((line, idx) => {
      if (line.includes('{') || line.includes('[')) {
        next.add(idx);
      }
    });
    setCollapsedLines(next);
  };

  const expandAll = () => {
    setCollapsedLines(new Set());
  };

  // Syntax colorizer with search & reflection highlighting
  const renderTokenizedLine = (line: string, lineIdx: number) => {
    // 1. Check for search query highlighting
    if (searchQuery.trim()) {
      const escapedSearch = searchQuery.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const parts = line.split(new RegExp(`(${escapedSearch})`, 'gi'));
      return (
        <span>
          {parts.map((part, i) => {
            if (part.toLowerCase() === searchQuery.toLowerCase()) {
              return (
                <mark key={i} className="bg-yellow-400 text-slate-950 font-bold px-0.5 rounded">
                  {part}
                </mark>
              );
            }
            return renderSyntaxTokens(part);
          })}
        </span>
      );
    }

    return renderSyntaxTokens(line);
  };

  const renderSyntaxTokens = (line: string) => {
    // Check reflection keywords first
    if (highlightWords.length > 0) {
      const escapedWords = highlightWords.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
      const parts = line.split(new RegExp(`(${escapedWords})`, 'gi'));
      if (parts.length > 1) {
        return (
          <span>
            {parts.map((part, i) => {
              const isReflection = highlightWords.some(w => w.toLowerCase() === part.toLowerCase());
              if (isReflection) {
                return (
                  <span
                    key={i}
                    className="reflection-highlight inline-flex items-center gap-0.5 shadow-sm shadow-yellow-500/20"
                    title={`Reflected Input Parameter: "${part}"`}
                  >
                    <Sparkles className="w-2.5 h-2.5 inline text-yellow-300 mr-0.5" />
                    {part}
                  </span>
                );
              }
              return colorizeLine(part);
            })}
          </span>
        );
      }
    }

    return colorizeLine(line);
  };

  const colorizeLine = (line: string) => {
    if (formatType === 'json') {
      // Colorize JSON Keys, Strings, Numbers, Booleans, Null
      const jsonRegex = /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|[{}[\],:])/g;
      const elements: React.ReactNode[] = [];
      let lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = jsonRegex.exec(line)) !== null) {
        if (match.index > lastIndex) {
          elements.push(line.substring(lastIndex, match.index));
        }
        const token = match[0];
        if (token.endsWith(':')) {
          // JSON Object Key
          elements.push(
            <span key={match.index} className="text-cyan-400 font-semibold">
              {token.slice(0, -1)}
            </span>
          );
          elements.push(<span key={`${match.index}-colon`} className="text-slate-500">:</span>);
        } else if (token.startsWith('"')) {
          // JSON String Value
          elements.push(
            <span key={match.index} className="text-emerald-300">
              {token}
            </span>
          );
        } else if (token === 'true' || token === 'false') {
          // Boolean
          elements.push(
            <span key={match.index} className="text-amber-400 font-bold">
              {token}
            </span>
          );
        } else if (token === 'null') {
          // Null
          elements.push(
            <span key={match.index} className="text-rose-400 italic">
              {token}
            </span>
          );
        } else if (/^-?\d+/.test(token)) {
          // Number
          elements.push(
            <span key={match.index} className="text-purple-400">
              {token}
            </span>
          );
        } else {
          // Brackets and punctuation
          elements.push(
            <span key={match.index} className="text-slate-400 font-bold">
              {token}
            </span>
          );
        }
        lastIndex = match.index + token.length;
      }

      if (lastIndex < line.length) {
        elements.push(line.substring(lastIndex));
      }

      return <span>{elements}</span>;
    }

    if (formatType === 'xml') {
      // Colorize XML Tags, Attributes, Values
      const xmlRegex = /(<\/?[a-zA-Z0-9_:-]+)(\s+[^>]*)?(\/?>)|([^<]+)/g;
      const elements: React.ReactNode[] = [];
      let lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = xmlRegex.exec(line)) !== null) {
        if (match[1]) {
          // Opening or closing tag
          elements.push(
            <span key={match.index} className="text-sky-400 font-semibold">
              {match[1]}
            </span>
          );
          if (match[2]) {
            // Attributes
            elements.push(
              <span key={`${match.index}-attr`} className="text-amber-300">
                {match[2]}
              </span>
            );
          }
          if (match[3]) {
            elements.push(
              <span key={`${match.index}-close`} className="text-sky-400 font-semibold">
                {match[3]}
              </span>
            );
          }
        } else if (match[4]) {
          // Text content
          elements.push(
            <span key={match.index} className="text-slate-200">
              {match[4]}
            </span>
          );
        }
        lastIndex = match.index + match[0].length;
      }
      if (lastIndex < line.length) {
        elements.push(line.substring(lastIndex));
      }
      return <span>{elements}</span>;
    }

    return <span className="text-slate-200">{line}</span>;
  };

  return (
    <div className={`flex flex-col bg-[#0A0E17] border border-border rounded-lg overflow-hidden font-mono text-xs ${className}`}>
      {/* Top Toolbar */}
      <div className="p-2.5 bg-surface/80 border-b border-border flex flex-wrap items-center justify-between gap-2 select-none">
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 text-[11px] font-semibold uppercase">
            {formatType}
          </span>
          <span className="text-slate-400 text-[11px]">
            {rawLines.length} lines • {content.length} chars
          </span>
          {highlightWords.length > 0 && (
            <span className="flex items-center gap-1 text-[11px] text-yellow-300 bg-yellow-500/10 px-2 py-0.5 rounded border border-yellow-500/30">
              <Sparkles className="w-3 h-3 text-yellow-400" />
              {highlightWords.length} Reflections
            </span>
          )}
        </div>

        {/* Toolbar Controls */}
        <div className="flex items-center gap-1.5">
          {/* Search Input */}
          <div className="relative">
            <Search className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Find in body..."
              className="pl-7 pr-2 py-1 bg-slate-900 border border-slate-700/80 rounded text-[11px] text-slate-200 placeholder-slate-500 focus:outline-none focus:border-primary w-36"
            />
          </div>

          {/* Line Number Toggle */}
          <button
            onClick={() => setShowLineNumbers(!showLineNumbers)}
            className={`p-1.5 rounded border text-[11px] transition-colors ${
              showLineNumbers ? 'bg-primary/20 text-primary border-primary/40' : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}
            title="Toggle Line Numbers"
          >
            <ListOrdered className="w-3.5 h-3.5" />
          </button>

          {/* Word Wrap Toggle */}
          <button
            onClick={() => setWordWrap(!wordWrap)}
            className={`p-1.5 rounded border text-[11px] transition-colors ${
              wordWrap ? 'bg-primary/20 text-primary border-primary/40' : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}
            title="Toggle Word Wrap"
          >
            <WrapText className="w-3.5 h-3.5" />
          </button>

          {/* Fold/Unfold Controls for JSON */}
          {formatType === 'json' && (
            <div className="flex items-center gap-1 border-l border-slate-700 pl-1.5">
              <button
                onClick={collapseAll}
                className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] flex items-center gap-1"
                title="Collapse all objects"
              >
                <Minimize2 className="w-3 h-3" />
                <span>Fold</span>
              </button>
              <button
                onClick={expandAll}
                className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] flex items-center gap-1"
                title="Expand all"
              >
                <Maximize2 className="w-3 h-3" />
                <span>Expand</span>
              </button>
            </div>
          )}

          {/* Copy Button */}
          <button
            onClick={handleCopy}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-[11px] flex items-center gap-1 transition-colors"
            title="Copy Formatted Content"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy</span>
          </button>

          {/* Send to Decoder */}
          {onSendToDecoder && (
            <button
              onClick={() => onSendToDecoder(content)}
              className="px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-[11px] font-semibold flex items-center gap-1 transition-colors"
              title="Open content in Multi-Layer Decoder"
            >
              <span>Decoder</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* Code Table Viewport */}
      <div className="p-3 overflow-x-auto max-h-[520px]">
        <table className="border-collapse w-full">
          <tbody>
            {rawLines.map((line, idx) => {
              const isCollapsible = (line.includes('{') || line.includes('[')) && !line.includes('}') && !line.includes(']');
              const isCollapsed = collapsedLines.has(idx);

              return (
                <tr key={idx} className="hover:bg-slate-900/40 leading-5">
                  {/* Line Numbers */}
                  {showLineNumbers && (
                    <td className="pr-3 text-right text-slate-600 select-none w-10 align-top font-mono text-[11px]">
                      {idx + 1}
                    </td>
                  )}

                  {/* Fold Indicator */}
                  {formatType === 'json' && (
                    <td className="w-4 select-none align-top text-slate-500 cursor-pointer">
                      {isCollapsible && (
                        <button
                          onClick={() => toggleCollapseLine(idx)}
                          className="hover:text-cyan-400 p-0.5"
                        >
                          {isCollapsed ? <ChevronRight className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                        </button>
                      )}
                    </td>
                  )}

                  {/* Code Line Content */}
                  <td className={`font-mono text-xs ${wordWrap ? 'whitespace-pre-wrap break-all' : 'whitespace-pre'}`}>
                    {renderTokenizedLine(line, idx)}
                    {isCollapsed && (
                      <span className="text-slate-500 italic ml-2 cursor-pointer" onClick={() => toggleCollapseLine(idx)}>
                        {line.includes('{') ? '{ ... }' : '[ ... ]'}
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
