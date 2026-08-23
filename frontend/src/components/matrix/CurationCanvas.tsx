import React, { useState } from 'react';
import { 
  CuratedPayloadGroup, 
  TestMatrixCase, 
  MutationCategory 
} from '../../types';
import { useFlowStore } from '../../store/flowStore';
import { 
  FolderPlus, 
  Star, 
  Pin, 
  Download, 
  Upload, 
  Trash2, 
  Edit3, 
  Tag, 
  Check, 
  Plus, 
  Sparkles,
  Layers,
  ChevronRight,
  Folder
} from 'lucide-react';
import { Badge } from '../common/Badge';
import { Modal } from '../common/Modal';

interface CurationCanvasProps {
  cases: TestMatrixCase[];
  selectedGroupId: string | null;
  onSelectGroup: (groupId: string | null) => void;
  onToggleStar: (caseId: string) => void;
  onTogglePin: (caseId: string) => void;
  onAssignToGroup: (caseIds: string[], groupId: string | null) => void;
}

export const CurationCanvas: React.FC<CurationCanvasProps> = ({
  cases,
  selectedGroupId,
  onSelectGroup,
  onToggleStar,
  onTogglePin,
  onAssignToGroup,
}) => {
  const payloadGroups = useFlowStore((s) => s.payloadGroups);
  const createPayloadGroup = useFlowStore((s) => s.createPayloadGroup);
  const deletePayloadGroup = useFlowStore((s) => s.deletePayloadGroup);
  const importPayloadGroups = useFlowStore((s) => s.importPayloadGroups);

  const [isCreatingGroup, setIsCreatingGroup] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [newGroupDesc, setNewGroupDesc] = useState('');
  const [newGroupColor, setNewGroupColor] = useState('#38BDF8');
  const [newGroupTags, setNewGroupTags] = useState('idor, critical');

  const groupsList = Object.values(payloadGroups);
  const starredCasesCount = cases.filter(c => c.is_starred).length;
  const pinnedCasesCount = cases.filter(c => c.is_pinned).length;

  const handleCreateGroupSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newGroupName.trim()) return;

    const tags = newGroupTags
      .split(',')
      .map(t => t.trim())
      .filter(Boolean);

    createPayloadGroup({
      name: newGroupName.trim(),
      description: newGroupDesc.trim() || undefined,
      color: newGroupColor,
      tags,
      case_ids: [],
    });

    setNewGroupName('');
    setNewGroupDesc('');
    setIsCreatingGroup(false);
  };

  const handleExportAllGroups = () => {
    const data = {
      version: '1.0.0',
      exported_at: new Date().toISOString(),
      groups: groupsList,
      cases: cases.filter(c => c.is_pinned || c.is_starred || c.group_id),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `curated_payload_collections_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleImportFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const json = JSON.parse(evt.target?.result as string);
        if (json && json.groups && Array.isArray(json.groups)) {
          importPayloadGroups(json.groups);
          alert(`Successfully imported ${json.groups.length} payload collections!`);
        } else if (Array.isArray(json)) {
          importPayloadGroups(json);
          alert(`Successfully imported ${json.length} payload collections!`);
        } else {
          alert('Invalid payload group JSON format.');
        }
      } catch (err: any) {
        alert(`Failed to import JSON: ${err.message}`);
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  return (
    <div className="bg-surface/90 border border-border rounded-xl p-3 font-mono text-xs space-y-3">
      {/* Top Bar: Title, Import, Export, Create Group */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-2.5">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/20 text-cyan-400">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-bold text-slate-100 text-xs flex items-center gap-2">
              Payload Curation & Collections
            </h3>
            <span className="text-[10px] text-slate-400">
              Organize, pin, and persist high-value probes across test sessions
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setIsCreatingGroup(true)}
            className="px-2.5 py-1 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-[11px] font-semibold flex items-center gap-1 transition-colors"
          >
            <FolderPlus className="w-3.5 h-3.5" />
            <span>New Collection</span>
          </button>

          <button
            onClick={handleExportAllGroups}
            className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-[11px] font-semibold flex items-center gap-1 transition-colors"
            title="Export collections to JSON"
          >
            <Download className="w-3.5 h-3.5 text-primary" />
            <span>Export</span>
          </button>

          <label className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-[11px] font-semibold flex items-center gap-1 cursor-pointer transition-colors">
            <Upload className="w-3.5 h-3.5 text-emerald-400" />
            <span>Import</span>
            <input
              type="file"
              accept=".json"
              onChange={handleImportFile}
              className="hidden"
            />
          </label>
        </div>
      </div>

      {/* Collection Filter Pills */}
      <div className="flex flex-wrap items-center gap-1.5 pt-1">
        {/* All Cases Pill */}
        <button
          onClick={() => onSelectGroup(null)}
          className={`px-2.5 py-1 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
            selectedGroupId === null
              ? 'bg-primary text-slate-950 shadow-md shadow-primary/20'
              : 'bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-800'
          }`}
        >
          <Folder className="w-3 h-3" />
          <span>All Staged Cases ({cases.length})</span>
        </button>

        {/* Starred Filter Pill */}
        <button
          onClick={() => onSelectGroup('__STARRED__')}
          className={`px-2.5 py-1 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
            selectedGroupId === '__STARRED__'
              ? 'bg-yellow-500 text-slate-950 shadow-md shadow-yellow-500/20 font-bold'
              : 'bg-yellow-500/10 text-yellow-300 hover:bg-yellow-500/20 border border-yellow-500/30'
          }`}
        >
          <Star className="w-3 h-3 fill-current" />
          <span>Starred ({starredCasesCount})</span>
        </button>

        {/* Pinned Filter Pill */}
        <button
          onClick={() => onSelectGroup('__PINNED__')}
          className={`px-2.5 py-1 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all ${
            selectedGroupId === '__PINNED__'
              ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20 font-bold'
              : 'bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20 border border-cyan-500/30'
          }`}
        >
          <Pin className="w-3 h-3 fill-current" />
          <span>Pinned ({pinnedCasesCount})</span>
        </button>

        {/* Custom Named Groups */}
        {groupsList.map((group) => {
          const isSelected = selectedGroupId === group.id;
          const groupCount = cases.filter(c => c.group_id === group.id || group.case_ids?.includes(c.id)).length;
          return (
            <div
              key={group.id}
              className={`group relative flex items-center rounded-lg border transition-all ${
                isSelected
                  ? 'bg-slate-800 text-white border-primary shadow-md'
                  : 'bg-slate-900/80 text-slate-300 border-slate-800 hover:border-slate-700'
              }`}
            >
              <button
                onClick={() => onSelectGroup(group.id)}
                className="px-2.5 py-1 flex items-center gap-1.5 text-xs font-medium"
              >
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: group.color || '#38BDF8' }}
                />
                <span>{group.name}</span>
                <span className="px-1.5 py-0.2 rounded bg-slate-950 text-[10px] font-bold text-slate-400">
                  {groupCount}
                </span>
              </button>

              <button
                onClick={() => deletePayloadGroup(group.id)}
                className="opacity-0 group-hover:opacity-100 p-1 text-slate-500 hover:text-rose-400 transition-opacity pr-1.5"
                title="Delete group"
              >
                <Trash2 className="w-3 h-3" />
              </button>
            </div>
          );
        })}
      </div>

      {/* New Collection Modal */}
      <Modal
        isOpen={isCreatingGroup}
        onClose={() => setIsCreatingGroup(false)}
        title="Create Curated Payload Collection"
      >
        <form onSubmit={handleCreateGroupSubmit} className="space-y-3 font-mono text-xs text-slate-200">
          <div>
            <label className="block text-[11px] text-slate-400 mb-1">Collection Name</label>
            <input
              type="text"
              required
              placeholder="e.g. Active BOLA Probes, Reflected XSS Candidates"
              value={newGroupName}
              onChange={(e) => setNewGroupName(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-slate-100 focus:outline-none focus:border-primary"
            />
          </div>

          <div>
            <label className="block text-[11px] text-slate-400 mb-1">Description (Optional)</label>
            <textarea
              rows={2}
              placeholder="Context notes regarding this curated payload test set..."
              value={newGroupDesc}
              onChange={(e) => setNewGroupDesc(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 focus:outline-none focus:border-primary"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Accent Color</label>
              <div className="flex items-center gap-2">
                <input
                  type="color"
                  value={newGroupColor}
                  onChange={(e) => setNewGroupColor(e.target.value)}
                  className="w-8 h-8 rounded border border-slate-700 bg-transparent cursor-pointer"
                />
                <input
                  type="text"
                  value={newGroupColor}
                  onChange={(e) => setNewGroupColor(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-300"
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Tags (Comma-separated)</label>
              <input
                type="text"
                placeholder="idor, high-risk, auth"
                value={newGroupTags}
                onChange={(e) => setNewGroupTags(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-slate-100 focus:outline-none focus:border-primary"
              />
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsCreatingGroup(false)}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-slate-950 font-bold"
            >
              Create Collection
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
