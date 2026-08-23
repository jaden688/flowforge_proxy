import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

export interface SyntaxHighlighterProps {
  content: string | null | undefined;
  language?: 'json' | 'html' | 'http' | 'text';
  highlightOffsets?: [number, number][]; // Offsets in original text to highlight
  highlightWords?: string[]; // Specific words (e.g. reflected params) to highlight
  showLineNumbers?: boolean;
  className?: string;
}

export const SyntaxHighlighter: React.FC<SyntaxHighlighterProps> = ({
  content,
  language = 'text',
  highlightOffsets,
  highlightWords,
  showLineNumbers = true,
  className = '',
}) => {
  const [copied, setCopied] = useState(false);

  if (!content) {
    return (
      <div className={`p-4 text-xs font-mono text-slate-500 italic bg-slate-950/60 rounded border border-slate-800 ${className}`}>
        [Empty Body]
      </div>
    );
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Attempt formatting JSON nicely
  let formattedContent = content;
  if (language === 'json') {
    try {
      const parsed = JSON.parse(content);
      formattedContent = JSON.stringify(parsed, null, 2);
    } catch {
      // Keep original if not valid JSON
    }
  }

  const lines = formattedContent.split('\n');

  const renderLineContent = (line: string) => {
    if (!highlightWords?.length) {
      return <span>{line}</span>;
    }

    // Highlight specific keywords / reflected tokens
    const regex = new RegExp(`(${highlightWords.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`, 'gi');
    const parts = line.split(regex);

    return (
      <span>
        {parts.map((part, i) => {
          const isMatch = highlightWords.some(w => w.toLowerCase() === part.toLowerCase());
          if (isMatch) {
            return (
              <span key={i} className="reflection-highlight" title="Reflected Input Token">
                {part}
              </span>
            );
          }
          return <span key={i}>{part}</span>;
        })}
      </span>
    );
  };

  return (
    <div className={`relative group bg-[#0A0E17] border border-slate-800/80 rounded-lg overflow-hidden font-mono text-xs ${className}`}>
      {/* Copy button */}
      <button
        onClick={handleCopy}
        className="absolute top-2 right-2 p-1.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700/60 opacity-0 group-hover:opacity-100 transition-opacity z-10"
        title="Copy to clipboard"
      >
        {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
      </button>

      {/* Code viewport */}
      <div className="p-3 overflow-x-auto max-h-[500px]">
        <table className="border-collapse w-full">
          <tbody>
            {lines.map((line, idx) => (
              <tr key={idx} className="hover:bg-slate-900/60 leading-5">
                {showLineNumbers && (
                  <td className="pr-4 text-right text-slate-600 select-none w-8 align-top font-mono text-[11px]">
                    {idx + 1}
                  </td>
                )}
                <td className="text-slate-300 font-mono whitespace-pre break-all">
                  {renderLineContent(line)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
