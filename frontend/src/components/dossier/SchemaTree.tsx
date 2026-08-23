import React from 'react';
import { SyntaxHighlighter } from '../common/SyntaxHighlighter';
import { Download, Code2 } from 'lucide-react';

interface SchemaTreeProps {
  schema?: Record<string, unknown>;
  endpointPath: string;
}

export const SchemaTree: React.FC<SchemaTreeProps> = ({ schema, endpointPath }) => {
  const fallbackSchema = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    title: `InferredSchema_${endpointPath.replace(/[^a-zA-Z0-9]/g, '_')}`,
    type: 'object',
    properties: {
      id: { type: 'integer', format: 'int64', description: 'Observed primary identifier' },
      status: { type: 'string', enum: ['active', 'pending', 'cancelled'] },
      created_at: { type: 'string', format: 'date-time' },
    },
    required: ['id'],
  };

  const activeSchema = schema || fallbackSchema;
  const jsonString = JSON.stringify(activeSchema, null, 2);

  const handleDownloadSchema = () => {
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `schema_${endpointPath.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-[#0A0E17] border border-border rounded-lg overflow-hidden font-mono text-xs">
      <div className="p-3 bg-surface/60 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Code2 className="w-4 h-4 text-primary" />
          <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">
            Inferred JSON Schema & Contracts
          </h4>
        </div>
        <button
          onClick={handleDownloadSchema}
          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1.5 transition-colors text-[11px]"
        >
          <Download className="w-3 h-3 text-cyan-400" />
          <span>Export Schema JSON</span>
        </button>
      </div>

      <div className="p-3">
        <SyntaxHighlighter content={jsonString} language="json" />
      </div>
    </div>
  );
};
