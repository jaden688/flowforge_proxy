import React, { useState, useRef, useEffect } from 'react';
import { MutationCategory, StrategyRecommendation, FlowRecord, EndpointDossier } from '../../types';
import { getStrategyRecommendations, formatRankLabel } from '../../utils/recommendations';
import { 
  Sparkles, 
  ChevronDown, 
  Check, 
  ShieldAlert, 
  Zap, 
  Info,
  Layers,
  Search
} from 'lucide-react';
import { Badge } from '../common/Badge';

interface StrategySelectDropdownProps {
  selectedCategory: string; // 'ALL' or a specific MutationCategory
  onSelectCategory: (category: string) => void;
  flow?: FlowRecord | null;
  dossier?: EndpointDossier | null;
  className?: string;
}

export const StrategySelectDropdown: React.FC<StrategySelectDropdownProps> = ({
  selectedCategory,
  onSelectCategory,
  flow,
  dossier,
  className = '',
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const dropdownRef = useRef<HTMLDivElement>(null);

  const recommendations = getStrategyRecommendations(flow, dossier);

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const selectedRec = recommendations.find(r => r.category === selectedCategory);
  
  const filteredRecs = recommendations.filter(rec => 
    rec.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    rec.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
    rec.matchReason.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const getSeverityBadgeColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40';
      default:
        return 'bg-slate-700/40 text-slate-300 border-slate-600/40';
    }
  };

  const getRankBadge = (rec: StrategyRecommendation) => {
    if (rec.rank === 1) {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-gradient-to-r from-yellow-500/20 to-amber-500/20 text-yellow-300 border border-yellow-500/40 flex items-center gap-1 shadow-sm shadow-yellow-500/10 animate-pulse">
          <Sparkles className="w-2.5 h-2.5 text-yellow-400" />
          <span>#1 Recommended</span>
        </span>
      );
    }
    if (rec.isRecommended) {
      return (
        <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
          #{rec.rank} High Fit ({rec.score}%)
        </span>
      );
    }
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] text-slate-400 bg-slate-800/80 border border-slate-700">
        #{rec.rank}
      </span>
    );
  };

  return (
    <div className={`relative inline-block font-mono text-xs ${className}`} ref={dropdownRef}>
      {/* Trigger Button */}
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="w-full min-w-[280px] bg-slate-900 border border-slate-700 hover:border-cyan-500/60 rounded-lg px-3 py-1.5 text-slate-200 flex items-center justify-between gap-2 transition-colors focus:outline-none focus:ring-1 focus:ring-primary shadow-sm"
      >
        <div className="flex items-center gap-2 truncate">
          {selectedCategory === 'ALL' ? (
            <>
              <Layers className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span className="font-semibold text-slate-100">All Categories (Full Suite)</span>
            </>
          ) : selectedRec ? (
            <>
              <Zap className="w-3.5 h-3.5 text-primary shrink-0" />
              <span className="font-semibold text-slate-100 truncate">{selectedRec.name}</span>
              {getRankBadge(selectedRec)}
            </>
          ) : (
            <span className="text-slate-300 truncate">{selectedCategory}</span>
          )}
        </div>
        <ChevronDown className={`w-3.5 h-3.5 text-slate-400 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div className="absolute left-0 mt-1 w-[460px] max-w-[90vw] bg-[#0E1524] border border-slate-700/90 rounded-xl shadow-2xl z-50 overflow-hidden animate-in fade-in zoom-in-95 duration-100">
          {/* Header & Quick Search */}
          <div className="p-2.5 bg-slate-900/90 border-b border-slate-800 flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter mutation strategies by name or heuristic..."
              className="w-full bg-transparent text-slate-200 placeholder-slate-500 text-xs focus:outline-none"
              autoFocus
            />
            {searchQuery && (
              <button 
                onClick={() => setSearchQuery('')}
                className="text-[10px] text-slate-400 hover:text-slate-200"
              >
                Clear
              </button>
            )}
          </div>

          <div className="max-h-[360px] overflow-y-auto divide-y divide-slate-800/60 p-1">
            {/* "All Categories" Option */}
            <div
              onClick={() => {
                onSelectCategory('ALL');
                setIsOpen(false);
              }}
              className={`p-2.5 rounded-lg cursor-pointer transition-colors flex items-start justify-between gap-2 ${
                selectedCategory === 'ALL'
                  ? 'bg-cyan-950/40 border border-cyan-500/30'
                  : 'hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-start gap-2.5">
                <div className="p-1.5 rounded bg-cyan-500/20 text-cyan-400 mt-0.5">
                  <Layers className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-100">All Categories (Full Suite)</span>
                    <span className="px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                      Standard
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Generate cases across IDOR, Auth, Boundaries, Schema and Reflection surfaces simultaneously.
                  </p>
                </div>
              </div>
              {selectedCategory === 'ALL' && <Check className="w-4 h-4 text-primary shrink-0 mt-1" />}
            </div>

            {/* Ranked Strategy Options */}
            {filteredRecs.map((rec) => {
              const isSelected = selectedCategory === rec.category;
              return (
                <div
                  key={rec.category}
                  onClick={() => {
                    onSelectCategory(rec.category);
                    setIsOpen(false);
                  }}
                  className={`p-2.5 rounded-lg cursor-pointer transition-colors flex items-start justify-between gap-2 ${
                    isSelected
                      ? 'bg-cyan-950/40 border border-cyan-500/30'
                      : rec.rank === 1
                      ? 'bg-yellow-950/10 hover:bg-yellow-950/20'
                      : 'hover:bg-slate-800/60'
                  }`}
                >
                  <div className="flex items-start gap-2.5 flex-1 min-w-0">
                    <div className={`p-1.5 rounded mt-0.5 ${rec.rank === 1 ? 'bg-yellow-500/20 text-yellow-400' : 'bg-slate-800 text-slate-300'}`}>
                      <Zap className="w-4 h-4" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="font-bold text-slate-100 truncate">{rec.name}</span>
                        {getRankBadge(rec)}
                        <span className={`px-1.5 py-0.2 rounded text-[9px] font-mono border ${getSeverityBadgeColor(rec.severityLikelihood)}`}>
                          {rec.severityLikelihood}
                        </span>
                      </div>
                      
                      <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-2">
                        {rec.description}
                      </p>

                      {/* Recommendation Rationale Indicator */}
                      <div className="mt-1.5 p-1.5 rounded bg-slate-900/80 border border-slate-800 text-[10px] text-cyan-300 flex items-start gap-1.5">
                        <Info className="w-3 h-3 text-cyan-400 shrink-0 mt-0.5" />
                        <span className="leading-tight">{rec.matchReason}</span>
                      </div>
                    </div>
                  </div>

                  {isSelected && <Check className="w-4 h-4 text-primary shrink-0 mt-1" />}
                </div>
              );
            })}
          </div>

          {/* Footer summary */}
          <div className="p-2 bg-slate-900 border-t border-slate-800 text-[10px] text-slate-400 flex items-center justify-between">
            <span>Context-Aware Best-Fit Ranking Active</span>
            <span className="text-primary font-semibold">{recommendations.length} Strategies Evaluated</span>
          </div>
        </div>
      )}
    </div>
  );
};
