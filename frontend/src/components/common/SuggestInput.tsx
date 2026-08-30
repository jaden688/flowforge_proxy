import React, { useEffect, useMemo, useRef, useState } from 'react';

export interface SuggestInputProps {
  value: string;
  onChange: (value: string) => void;
  suggestions?: string[];
  placeholder?: string;
  className?: string;
  title?: string;
  onSelectExtra?: (value: string) => void; // fired when user picks a suggestion
  align?: 'left' | 'right';
}

/**
 * Auto-suggesting text input: shows dynamically assembled suggestions on
 * focus, filters as you type, click (or Enter) to accept. Falls back to
 * free-text entry — suggestions never block manual input.
 */
export const SuggestInput: React.FC<SuggestInputProps> = ({
  value,
  onChange,
  suggestions = [],
  placeholder,
  className = '',
  title,
  onSelectExtra,
  align = 'left',
}) => {
  const [open, setOpen] = useState(false);
  const [highlighted, setHighlighted] = useState(-1);
  const wrapRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const needle = value.trim().toLowerCase();
    const base = needle
      ? suggestions.filter((s) => s.toLowerCase().includes(needle) && s.toLowerCase() !== needle)
      : suggestions;
    return base.slice(0, 12);
  }, [value, suggestions]);

  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, []);

  const pick = (s: string) => {
    onChange(s);
    onSelectExtra?.(s);
    setOpen(false);
    inputRef.current?.blur();
  };

  return (
    <div ref={wrapRef} className={`relative ${className}`}>
      <input
        ref={inputRef}
        type="text"
        value={value}
        title={title}
        placeholder={placeholder}
        onFocus={() => { setOpen(true); setHighlighted(-1); }}
        onChange={(e) => { onChange(e.target.value); setOpen(true); }}
        onKeyDown={(e) => {
          if (!open || filtered.length === 0) return;
          if (e.key === 'ArrowDown') {
            e.preventDefault();
            setHighlighted((h) => Math.min(h + 1, filtered.length - 1));
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setHighlighted((h) => Math.max(h - 1, -1));
          } else if (e.key === 'Enter' && highlighted >= 0) {
            e.preventDefault();
            pick(filtered[highlighted]);
          } else if (e.key === 'Escape') {
            setOpen(false);
          }
        }}
        className={className.includes('w-full') ? className : `${className} w-full`}
      />
      {open && filtered.length > 0 && (
        <div
          className={`absolute z-50 mt-1 max-h-56 overflow-y-auto rounded-lg border border-slate-700 bg-slate-900 shadow-xl shadow-black/50 py-1 ${
            align === 'right' ? 'right-0' : 'left-0'
          } min-w-full w-max max-w-[320px]`}
        >
          {filtered.map((s, i) => (
            <button
              key={s}
              type="button"
              onMouseDown={(e) => { e.preventDefault(); pick(s); }}
              onMouseEnter={() => setHighlighted(i)}
              className={`block w-full text-left px-2.5 py-1 text-[11px] font-mono truncate transition-colors ${
                i === highlighted ? 'bg-primary/20 text-primary' : 'text-slate-300 hover:bg-slate-800'
              }`}
              title={s}
            >
              {s}
            </button>
          ))}
        </div>
      )}
    </div>
  );
};
