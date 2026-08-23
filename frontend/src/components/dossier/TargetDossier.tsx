import React, { useEffect, useState } from 'react';
import { useFlowStore } from '../../store/flowStore';
import { api } from '../../services/api';
import { EndpointTree } from './EndpointTree';
import { ParameterGrid } from './ParameterGrid';
import { SchemaTree } from './SchemaTree';
import { Badge } from '../common/Badge';
import { 
  Zap, 
  Sparkles, 
  ShieldAlert, 
  Layers, 
  Download, 
  CheckCircle2, 
  AlertTriangle 
} from 'lucide-react';
import { EndpointDossier } from '../../types';

export const TargetDossier: React.FC = () => {
  const dossiersMap = useFlowStore((s) => s.dossiers);
  const setDossiers = useFlowStore((s) => s.setDossiers);
  const selectedDossierKey = useFlowStore((s) => s.selectedDossierKey);
  const selectDossier = useFlowStore((s) => s.selectDossier);
  const setActiveView = useFlowStore((s) => s.setActiveView);
  const flows = useFlowStore((s) => s.flows);
  const flowOrder = useFlowStore((s) => s.flowOrder);

  const [isLoading, setIsLoading] = useState(false);

  // Synthesize dossiers from captured flows if server dossier is empty
  useEffect(() => {
    const loadDossiers = async () => {
      setIsLoading(true);
      try {
        const fetched = await api.getDossiers();
        if (fetched && fetched.length > 0) {
          setDossiers(fetched);
          if (!selectedDossierKey) {
            selectDossier(`${fetched[0].host}::${fetched[0].path_template}`);
          }
          return;
        }
      } catch {
        // Fallback to local synthesis
      }

      // Local synthesis from flows in store
      const synthesized: Record<string, EndpointDossier> = {};
      flowOrder.forEach((id) => {
        const f = flows[id];
        if (!f) return;

        // Path template normalization (e.g. /orders/1001 -> /orders/{id})
        const pathTemplate = f.path.replace(/\/\d+/g, '/{id}');
        const key = `${f.host}::${pathTemplate}`;

        if (!synthesized[key]) {
          synthesized[key] = {
            host: f.host,
            path_template: pathTemplate,
            methods: [f.method],
            primary_category: f.triage?.endpoint_category || 'DATA_READ',
            auth_types_observed: f.triage?.auth?.auth_present ? [f.triage.auth.auth_type] : ['NONE'],
            parameters: [],
            total_calls_observed: 1,
            sample_flow_ids: [f.id],
            anomalies_detected: f.triage?.auth?.anomaly_flags || [],
          };
        } else {
          synthesized[key].total_calls_observed += 1;
          if (!synthesized[key].methods.includes(f.method)) {
            synthesized[key].methods.push(f.method);
          }
        }

        // Add query parameters
        if (f.query_params) {
          Object.entries(f.query_params).forEach(([k, v]) => {
            const exists = synthesized[key].parameters.find((p) => p.name === k && p.location === 'query');
            if (!exists) {
              const isDigit = strDigits(v);
              synthesized[key].parameters.push({
                name: k,
                location: 'query',
                inferred_type: isDigit ? 'integer' : 'string',
                id_type: isDigit ? 'SEQUENTIAL_INT' : undefined,
                idor_risk: isDigit ? 'HIGH' : 'NONE',
                required: false,
                nullable: false,
                sample_values: [String(v)],
                reflections_count: f.triage?.reflections?.filter(r => r.param_name === k).length || 0,
                last_seen: f.timestamp,
              });
            }
          });
        }

        // Add path parameters
        if (pathTemplate.includes('{id}')) {
          const exists = synthesized[key].parameters.find((p) => p.name === 'id' && p.location === 'path');
          if (!exists) {
            synthesized[key].parameters.push({
              name: 'id',
              location: 'path',
              inferred_type: 'integer',
              id_type: 'SEQUENTIAL_INT',
              idor_risk: 'HIGH',
              required: true,
              nullable: false,
              sample_values: ['1001', '1002'],
              reflections_count: 0,
              last_seen: f.timestamp,
            });
          }
        }
      });

      const dossierList = Object.values(synthesized);
      if (dossierList.length > 0) {
        setDossiers(dossierList);
        if (!selectedDossierKey) {
          selectDossier(`${dossierList[0].host}::${dossierList[0].path_template}`);
        }
      }
      setIsLoading(false);
    };

    loadDossiers();
  }, [flowOrder, flows, selectedDossierKey, selectDossier, setDossiers]);

  const strDigits = (val: any) => {
    return val !== undefined && val !== null && String(val).trim().length > 0 && !isNaN(Number(val));
  };

  const dossierList = Object.values(dossiersMap);
  const activeDossier = selectedDossierKey ? dossiersMap[selectedDossierKey] : dossierList[0] || null;

  const handleStageInMatrix = () => {
    setActiveView('matrix');
  };

  const handleExportOpenApi = () => {
    if (!activeDossier) return;
    const openApiSpec = {
      openapi: '3.1.0',
      info: {
        title: `FlowForge Discovered API — ${activeDossier.host}`,
        version: '1.0.0',
      },
      paths: {
        [activeDossier.path_template]: {
          [activeDossier.methods[0]?.toLowerCase() || 'get']: {
            summary: `Automated Dossier for ${activeDossier.path_template}`,
            parameters: activeDossier.parameters.map((p) => ({
              name: p.name,
              in: p.location,
              required: p.required,
              schema: { type: p.inferred_type },
            })),
            responses: {
              '200': { description: 'Observed Successful Response' },
            },
          },
        },
      },
    };

    const blob = new Blob([JSON.stringify(openApiSpec, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `openapi_${activeDossier.host}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex-1 flex flex-col md:flex-row h-full overflow-hidden font-mono text-xs">
      {/* Left Sidebar: Host & Endpoint Hierarchy Tree */}
      <div className="w-full md:w-80 lg:w-96 flex-shrink-0 h-48 md:h-full">
        <EndpointTree
          dossiers={dossierList}
          selectedKey={selectedDossierKey}
          onSelect={(key) => selectDossier(key)}
        />
      </div>

      {/* Right Canvas: Selected Endpoint Target Dossier */}
      <div className="flex-1 overflow-y-auto p-4 bg-[#090D15] space-y-4">
        {!activeDossier ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 p-8 text-center">
            <Layers className="w-10 h-10 mb-2 opacity-30 animate-pulse" />
            <span className="font-bold">No Target Endpoint Selected</span>
            <span className="text-slate-600 text-[11px] mt-1">
              Select an endpoint from the left hierarchy to inspect its aggregated parameters and schemas
            </span>
          </div>
        ) : (
          <>
            {/* Header Canvas Banner */}
            <div className="p-4 bg-surface/80 border border-border rounded-xl shadow-lg space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Badge variant="primary" size="md">
                    {activeDossier.methods.join(' / ')}
                  </Badge>
                  <span className="text-sm font-bold text-slate-100 truncate">
                    {activeDossier.host}{activeDossier.path_template}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleExportOpenApi}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-colors text-xs font-semibold"
                  >
                    <Download className="w-3.5 h-3.5 text-primary" />
                    <span>Export OpenAPI 3.1</span>
                  </button>

                  <button
                    onClick={handleStageInMatrix}
                    className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 flex items-center gap-1.5 transition-colors text-xs font-semibold"
                  >
                    <Zap className="w-3.5 h-3.5 text-primary" />
                    <span>Stage in Test Matrix</span>
                  </button>
                </div>
              </div>

              {/* Endpoint Stats and Categories */}
              <div className="flex flex-wrap items-center gap-4 text-xs pt-2 border-t border-border/60">
                <div>
                  <span className="text-slate-500 mr-1.5">Classification:</span>
                  <Badge variant="mutation" size="sm">
                    {activeDossier.primary_category}
                  </Badge>
                </div>

                <div>
                  <span className="text-slate-500 mr-1.5">Observed Calls:</span>
                  <span className="text-slate-200 font-semibold">{activeDossier.total_calls_observed}</span>
                </div>

                <div>
                  <span className="text-slate-500 mr-1.5">Auth Observed:</span>
                  <span className="text-purple-300 font-semibold">
                    {activeDossier.auth_types_observed.join(', ')}
                  </span>
                </div>

                {activeDossier.parameters.some(p => p.idor_risk === 'HIGH') && (
                  <div className="flex items-center gap-1 text-orange-400 font-bold">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>High IDOR Surface Detected</span>
                  </div>
                )}
              </div>
            </div>

            {/* Aggregated Parameter Grid */}
            <ParameterGrid parameters={activeDossier.parameters} />

            {/* Inferred JSON Schema */}
            <SchemaTree
              schema={activeDossier.inferred_json_schema}
              endpointPath={activeDossier.path_template}
            />
          </>
        )}
      </div>
    </div>
  );
};
