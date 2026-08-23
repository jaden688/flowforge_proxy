import React from 'react';

export interface BadgeProps {
  children: React.ReactNode;
  variant?: 'primary' | 'success' | 'warning' | 'danger' | 'mutation' | 'idor' | 'reflection' | 'neutral' | 'outline';
  size?: 'sm' | 'md';
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'neutral',
  size = 'sm',
  className = '',
}) => {
  const sizeClasses = size === 'sm' ? 'px-1.5 py-0.5 text-xs' : 'px-2 py-1 text-sm';

  const variantClasses = {
    primary: 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30',
    success: 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30',
    warning: 'bg-amber-500/20 text-amber-300 border border-amber-500/30',
    danger: 'bg-rose-500/20 text-rose-300 border border-rose-500/30',
    mutation: 'bg-purple-500/20 text-purple-300 border border-purple-500/30',
    idor: 'bg-orange-500/20 text-orange-300 border border-orange-500/30 font-semibold',
    reflection: 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30',
    neutral: 'bg-slate-800 text-slate-300 border border-slate-700',
    outline: 'bg-transparent text-slate-400 border border-slate-700 hover:border-slate-500',
  }[variant];

  return (
    <span
      className={`inline-flex items-center gap-1 rounded font-mono font-medium tracking-tight whitespace-nowrap ${sizeClasses} ${variantClasses} ${className}`}
    >
      {children}
    </span>
  );
};
