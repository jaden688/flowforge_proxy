import React, { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import { useFlowStore } from '../../store/flowStore';
import { 
  GraphNodeData, 
  GraphEdgeData, 
  LineageEdgeType, 
  EndpointCategory, 
  IdorRiskLevel, 
  HttpMethod, 
  ActiveView 
} from '../../types';
import { EndpointNode } from './EndpointNode';
import { LineageEdge } from './LineageEdge';
import { Badge } from '../common/Badge';
import { 
  Network, 
  ZoomIn, 
  ZoomOut, 
  RotateCcw, 
  Maximize2, 
  Filter, 
  Sparkles, 
  ShieldAlert, 
  Lock, 
  Activity, 
  Search, 
  ExternalLink, 
  Zap, 
  ArrowRight, 
  Layers, 
  SlidersHorizontal,
  X
} from 'lucide-react';

export const ApiFlowGraph: React.FC = () => {
  const flows = useFlowStore((s) => s.flows);
  const flowOrder = useFlowStore((s) => s.flowOrder);
  const dossiers = useFlowStore((s) => s.dossiers);
  const stats = useFlowStore((s) => s.stats);
  const selectDossier = useFlowStore((s) => s.selectDossier);
  const setActiveView = useFlowStore((s) => s.setActiveView);
  const setFilters = useFlowStore((s) => s.setFilters);

  // Viewport State (Pan & Zoom)
  const [zoom, setZoom] = useState<number>(0.95);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 80, y: 60 });
  const [isPanning, setIsPanning] = useState(false);
  const [startPanPos, setStartPanPos] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  // Node Dragging State
  const [draggedNodeId, setDraggedNodeId] = useState<string | null>(null);
  const [dragStartPos, setDragStartPos] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [customNodePositions, setCustomNodePositions] = useState<Record<string, { x: number; y: number }>>({});

  // Selection & Filter State
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedHostFilter, setSelectedHostFilter] = useState<string>('ALL');
  const [minRiskFilter, setMinRiskFilter] = useState<number>(0);
  const [onlyAnomalies, setOnlyAnomalies] = useState<boolean>(false);

  const containerRef = useRef<HTMLDivElement>(null);

  // --------------------------------------------------------------------------
  // Build Graph Nodes & Directed Lineage Edges from Intercepted Flows & Dossiers
  // --------------------------------------------------------------------------
  const { nodes, edges, hostList } = useMemo(() => {
    const rawNodesMap: Record<string, GraphNodeData> = {};
    const hostsSet = new Set<string>();

    // 1. Process discovered dossiers
    Object.values(dossiers).forEach((dossier) => {
      const host = dossier.host || 'api.target.com';
      hostsSet.add(host);
      const path = dossier.path_template || '/';
      const nodeId = `node-${host}-${path}`;
      const method = (dossier.methods?.[0] || 'GET') as HttpMethod;
      const dossierKey = `${host}::${path}`;

      // Calculate risk score from dossier anomalies
      let riskScore = 20;
      const anomalies: string[] = [];
      let reflectionsCount = 0;
      let idorRisk: IdorRiskLevel = 'NONE';
      let authPresent = false;

      // Extract from dossier parameters
      dossier.parameters?.forEach((p) => {
        if ((p as any).is_reflected || (p.reflections_count && p.reflections_count > 0)) {
          reflectionsCount += 1;
          riskScore += 25;
          if (!anomalies.includes('Input Reflection')) anomalies.push('Input Reflection');
        }
        if (p.idor_risk === 'HIGH') {
          idorRisk = 'HIGH';
          riskScore += 35;
          if (!anomalies.includes('High-Risk IDOR')) anomalies.push('High-Risk IDOR');
        }
      });

      const dossierCat = dossier.primary_category || (dossier as any).category;
      if (dossierCat === 'ADMIN') {
        riskScore += 30;
        anomalies.push('Admin Surface');
      } else if (dossierCat === 'AUTH') {
        authPresent = true;
      }

      rawNodesMap[nodeId] = {
        id: nodeId,
        label: `${method} ${path}`,
        host,
        path,
        method,
        category: dossierCat || 'DATA_READ',
        riskScore: Math.min(100, riskScore),
        anomalies,
        reflectionsCount,
        idorRisk,
        authPresent,
        dossierKey,
        callCount: dossier.sample_flow_ids?.length || 1,
      };
    });

    // 2. Process intercepted flows to enrich or add nodes
    const flowList = flowOrder.map((id) => flows[id]).filter(Boolean);
    flowList.forEach((flow) => {
      const host = flow.host || 'api.target.com';
      hostsSet.add(host);
      const path = flow.path.split('?')[0] || '/';
      const nodeId = `node-${host}-${path}`;
      const dossierKey = `${host}::${path}`;

      let reflectionsCount = flow.triage?.reflections?.length || 0;
      let idorRisk: IdorRiskLevel = flow.triage?.identifiers?.some((i) => i.idor_risk === 'HIGH') ? 'HIGH' : 'NONE';
      let authPresent = !!flow.triage?.auth?.auth_present;
      let category: EndpointCategory = flow.triage?.endpoint_category || 'DATA_READ';

      let riskScore = 15;
      const anomalies: string[] = [];
      if (reflectionsCount > 0) {
        riskScore += 30;
        anomalies.push('Input Reflection');
      }
      if (idorRisk === 'HIGH') {
        riskScore += 35;
        anomalies.push('High-Risk IDOR');
      }
      if (flow.triage?.auth?.anomaly_flags?.length) {
        riskScore += 25;
        anomalies.push('Auth Deviation');
      }
      if (category === 'ADMIN') {
        riskScore += 30;
        anomalies.push('Admin Surface');
      }

      const flowStatusCode = flow.response_status_code ?? flow.response_status ?? (flow as any).status_code;

      if (rawNodesMap[nodeId]) {
        rawNodesMap[nodeId].callCount += 1;
        rawNodesMap[nodeId].reflectionsCount = Math.max(rawNodesMap[nodeId].reflectionsCount, reflectionsCount);
        if (idorRisk === 'HIGH') rawNodesMap[nodeId].idorRisk = 'HIGH';
        if (authPresent) rawNodesMap[nodeId].authPresent = true;
        rawNodesMap[nodeId].riskScore = Math.min(100, Math.max(rawNodesMap[nodeId].riskScore, riskScore));
        rawNodesMap[nodeId].lastStatusCode = flowStatusCode;
      } else {
        rawNodesMap[nodeId] = {
          id: nodeId,
          label: `${flow.method} ${path}`,
          host,
          path,
          method: flow.method,
          category,
          riskScore: Math.min(100, riskScore),
          anomalies,
          reflectionsCount,
          idorRisk,
          authPresent,
          dossierKey,
          callCount: 1,
          lastStatusCode: flowStatusCode,
        };
      }
    });

    // Fallback: If no flows or dossiers captured yet, provide sample realistic target topology
    if (Object.keys(rawNodesMap).length === 0) {
      const defaultHost = 'api.forge-target.io';
      hostsSet.add(defaultHost);
      const sampleNodes: GraphNodeData[] = [
        {
          id: `node-${defaultHost}-/api/v1/auth/login`,
          label: 'POST /api/v1/auth/login',
          host: defaultHost,
          path: '/api/v1/auth/login',
          method: 'POST',
          category: 'AUTH',
          riskScore: 35,
          anomalies: ['Auth Handshake'],
          reflectionsCount: 0,
          idorRisk: 'NONE',
          authPresent: true,
          dossierKey: `${defaultHost}::/api/v1/auth/login`,
          callCount: 6,
          lastStatusCode: 200,
        },
        {
          id: `node-${defaultHost}-/api/v1/users/{id}`,
          label: 'GET /api/v1/users/{id}',
          host: defaultHost,
          path: '/api/v1/users/{id}',
          method: 'GET',
          category: 'DATA_READ',
          riskScore: 85,
          anomalies: ['High-Risk IDOR', 'Input Reflection'],
          reflectionsCount: 2,
          idorRisk: 'HIGH',
          authPresent: true,
          dossierKey: `${defaultHost}::/api/v1/users/{id}`,
          callCount: 14,
          lastStatusCode: 200,
        },
        {
          id: `node-${defaultHost}-/api/v1/orders`,
          label: 'GET /api/v1/orders',
          host: defaultHost,
          path: '/api/v1/orders',
          method: 'GET',
          category: 'DATA_READ',
          riskScore: 45,
          anomalies: ['Numeric Identifier'],
          reflectionsCount: 0,
          idorRisk: 'LOW',
          authPresent: true,
          dossierKey: `${defaultHost}::/api/v1/orders`,
          callCount: 8,
          lastStatusCode: 200,
        },
        {
          id: `node-${defaultHost}-/api/v1/orders/checkout`,
          label: 'POST /api/v1/orders/checkout',
          host: defaultHost,
          path: '/api/v1/orders/checkout',
          method: 'POST',
          category: 'MUTATION_ACTION',
          riskScore: 70,
          anomalies: ['State Mutation', 'Token Reflection'],
          reflectionsCount: 1,
          idorRisk: 'LOW',
          authPresent: true,
          dossierKey: `${defaultHost}::/api/v1/orders/checkout`,
          callCount: 4,
          lastStatusCode: 201,
        },
        {
          id: `node-${defaultHost}-/api/v1/admin/tenants`,
          label: 'GET /api/v1/admin/tenants',
          host: defaultHost,
          path: '/api/v1/admin/tenants',
          method: 'GET',
          category: 'ADMIN',
          riskScore: 95,
          anomalies: ['Admin Surface', 'Auth Deviation'],
          reflectionsCount: 0,
          idorRisk: 'HIGH',
          authPresent: false,
          dossierKey: `${defaultHost}::/api/v1/admin/tenants`,
          callCount: 2,
          lastStatusCode: 403,
        },
      ];
      sampleNodes.forEach((n) => (rawNodesMap[n.id] = n));
    }

    // 3. Compute DAG Layer Positions (Layered Columns: Auth -> Data Read -> Mutation -> Admin)
    const layerCategories: EndpointCategory[] = ['AUTH', 'DATA_READ', 'MUTATION_ACTION', 'ADMIN'];
    const layerBuckets: Record<EndpointCategory, GraphNodeData[]> = {
      AUTH: [],
      DATA_READ: [],
      MUTATION_ACTION: [],
      ADMIN: [],
      TELEMETRY: [],
      UNKNOWN: [],
    };

    Object.values(rawNodesMap).forEach((node) => {
      const cat = node.category || 'DATA_READ';
      if (layerBuckets[cat]) {
        layerBuckets[cat].push(node);
      } else {
        layerBuckets['DATA_READ'].push(node);
      }
    });

    const positionedNodes: GraphNodeData[] = [];
    const layerXSpacing = 340;
    const nodeYSpacing = 160;
    const initialYOffset = 60;

    layerCategories.forEach((cat, colIdx) => {
      const bucket = layerBuckets[cat];
      bucket.forEach((node, rowIdx) => {
        const defaultX = 60 + colIdx * layerXSpacing;
        const defaultY = initialYOffset + rowIdx * nodeYSpacing;
        const savedPos = customNodePositions[node.id];

        positionedNodes.push({
          ...node,
          x: savedPos ? savedPos.x : defaultX,
          y: savedPos ? savedPos.y : defaultY,
        });
      });
    });

    // 4. Construct Directed Lineage Edges between Connected Endpoints
    const computedEdges: GraphEdgeData[] = [];
    const nodeIds = positionedNodes.map((n) => n.id);

    for (let i = 0; i < positionedNodes.length; i++) {
      const source = positionedNodes[i];
      for (let j = 0; j < positionedNodes.length; j++) {
        if (i === j) continue;
        const target = positionedNodes[j];

        // Edge Rule 1: Auth node -> Other authenticated nodes
        if (source.category === 'AUTH' && target.authPresent && target.category !== 'AUTH') {
          computedEdges.push({
            id: `edge-${source.id}-${target.id}-auth`,
            sourceNodeId: source.id,
            targetNodeId: target.id,
            lineageType: 'AUTH_TOKEN',
            carriedKey: 'Authorization: Bearer <jwt>',
            carriedValueSample: 'eyJhbGciOiJIUzI1Ni...',
            confidence: 0.95,
            active: true,
          });
        }

        // Edge Rule 2: User/Resource Read -> Mutation Checkout / Specific details
        if (
          source.category === 'DATA_READ' &&
          (target.category === 'MUTATION_ACTION' || target.category === 'ADMIN') &&
          source.host === target.host
        ) {
          computedEdges.push({
            id: `edge-${source.id}-${target.id}-param`,
            sourceNodeId: source.id,
            targetNodeId: target.id,
            lineageType: 'PARAM_ID',
            carriedKey: 'user_id / order_id',
            carriedValueSample: '10042',
            confidence: 0.88,
            active: true,
          });
        }

        // Edge Rule 3: High IDOR Risk link
        if (source.idorRisk === 'HIGH' && target.category === 'ADMIN') {
          computedEdges.push({
            id: `edge-${source.id}-${target.id}-idor`,
            sourceNodeId: source.id,
            targetNodeId: target.id,
            lineageType: 'STATE_SEQUENCE',
            carriedKey: 'Privilege Escalation Vector',
            confidence: 0.9,
            active: true,
          });
        }
      }
    }

    return {
      nodes: positionedNodes,
      edges: computedEdges,
      hostList: Array.from(hostsSet),
    };
  }, [flows, flowOrder, dossiers, customNodePositions]);

  // --------------------------------------------------------------------------
  // Apply Search & Risk Filtering to Graph Nodes & Edges
  // --------------------------------------------------------------------------
  const filteredNodes = useMemo(() => {
    return nodes.filter((node) => {
      // Host Filter
      if (selectedHostFilter !== 'ALL' && node.host !== selectedHostFilter) {
        return false;
      }
      // Min Risk Score Filter
      if (node.riskScore < minRiskFilter) {
        return false;
      }
      // Anomalies Only Filter
      if (onlyAnomalies && node.anomalies.length === 0 && node.riskScore < 50) {
        return false;
      }
      // Text Search Query Filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matches =
          node.path.toLowerCase().includes(query) ||
          node.method.toLowerCase().includes(query) ||
          node.host.toLowerCase().includes(query) ||
          node.anomalies.some((a) => a.toLowerCase().includes(query));
        if (!matches) return false;
      }
      return true;
    });
  }, [nodes, selectedHostFilter, minRiskFilter, onlyAnomalies, searchQuery]);

  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map((n) => n.id)), [filteredNodes]);

  const filteredEdges = useMemo(() => {
    return edges.filter(
      (edge) => filteredNodeIds.has(edge.sourceNodeId) && filteredNodeIds.has(edge.targetNodeId)
    );
  }, [edges, filteredNodeIds]);

  const selectedNode = useMemo(() => {
    return nodes.find((n) => n.id === selectedNodeId) || null;
  }, [nodes, selectedNodeId]);

  // --------------------------------------------------------------------------
  // Pan & Zoom Event Handlers
  // --------------------------------------------------------------------------
  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
    setZoom((prev) => Math.min(2.2, Math.max(0.35, prev * zoomFactor)));
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.target === containerRef.current || (e.target as HTMLElement).tagName === 'svg') {
      setIsPanning(true);
      setStartPanPos({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isPanning) {
      setPan({
        x: e.clientX - startPanPos.x,
        y: e.clientY - startPanPos.y,
      });
    } else if (draggedNodeId) {
      const deltaX = (e.clientX - dragStartPos.x) / zoom;
      const deltaY = (e.clientY - dragStartPos.y) / zoom;
      setCustomNodePositions((prev) => {
        const current = prev[draggedNodeId] || {
          x: nodes.find((n) => n.id === draggedNodeId)?.x || 0,
          y: nodes.find((n) => n.id === draggedNodeId)?.y || 0,
        };
        return {
          ...prev,
          [draggedNodeId]: {
            x: current.x + deltaX,
            y: current.y + deltaY,
          },
        };
      });
      setDragStartPos({ x: e.clientX, y: e.clientY });
    }
  };

  const handleMouseUp = () => {
    setIsPanning(false);
    setDraggedNodeId(null);
  };

  const handleNodeDragStart = (e: React.MouseEvent, node: GraphNodeData) => {
    setDraggedNodeId(node.id);
    setDragStartPos({ x: e.clientX, y: e.clientY });
  };

  const resetViewport = () => {
    setZoom(0.95);
    setPan({ x: 80, y: 60 });
  };

  const zoomIn = () => setZoom((z) => Math.min(2.2, z * 1.2));
  const zoomOut = () => setZoom((z) => Math.max(0.35, z * 0.8));

  const handleNavigateDossier = (dossierKey: string) => {
    selectDossier(dossierKey);
    setActiveView('dossier');
  };

  const handleStageInMatrix = (node: GraphNodeData) => {
    const flow = Object.values(flows).find(
      (f) => f.host === node.host && f.path.startsWith(node.path.split('{')[0])
    );
    if (flow) {
      useFlowStore.getState().selectFlow(flow.id);
    }
    setActiveView('matrix');
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-[#070B12] text-slate-100 font-mono text-xs overflow-hidden relative select-none">
      {/* Top Header & Interactive Filter Bar */}
      <div className="p-3 bg-surface/90 border-b border-border/80 flex flex-wrap items-center justify-between gap-3 z-20 backdrop-blur-md">
        {/* Title & Stats */}
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gradient-to-tr from-cyan-600 to-sky-500 text-white shadow-md shadow-cyan-500/20">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <h2 className="font-bold text-slate-100 text-sm flex items-center gap-2">
              API Topology & Data Flow Lineage Visualizer
            </h2>
            <div className="flex items-center gap-3 text-[11px] text-slate-400">
              <span>{filteredNodes.length} Endpoints</span>
              <span>•</span>
              <span className="text-cyan-400 font-semibold">{filteredEdges.length} Active Lineages</span>
              <span>•</span>
              <span className="text-rose-400 font-semibold">
                {filteredNodes.filter((n) => n.riskScore >= 80).length} High Risk
              </span>
            </div>
          </div>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Quick Search */}
          <div className="relative w-48 sm:w-60">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search endpoint or anomaly..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-2.5 py-1 bg-slate-900 border border-slate-700/80 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-primary"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Host Filter */}
          {hostList.length > 1 && (
            <select
              value={selectedHostFilter}
              onChange={(e) => setSelectedHostFilter(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1 text-slate-200 text-xs focus:outline-none focus:border-primary"
            >
              <option value="ALL">All Hosts ({hostList.length})</option>
              {hostList.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
            </select>
          )}

          {/* Risk Level Filter Pill */}
          <div className="flex items-center bg-slate-900 p-0.5 rounded-lg border border-slate-800">
            <button
              onClick={() => setMinRiskFilter(0)}
              className={`px-2 py-0.5 rounded text-[11px] transition-colors ${
                minRiskFilter === 0 ? 'bg-slate-700 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All Risk
            </button>
            <button
              onClick={() => setMinRiskFilter(40)}
              className={`px-2 py-0.5 rounded text-[11px] transition-colors ${
                minRiskFilter === 40 ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40 font-bold' : 'text-slate-400 hover:text-yellow-300'
              }`}
            >
              Med &gt; 40
            </button>
            <button
              onClick={() => setMinRiskFilter(80)}
              className={`px-2 py-0.5 rounded text-[11px] transition-colors ${
                minRiskFilter === 80 ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold' : 'text-slate-400 hover:text-rose-300'
              }`}
            >
              High &gt; 80
            </button>
          </div>

          {/* Anomalies Only Toggle */}
          <button
            onClick={() => setOnlyAnomalies(!onlyAnomalies)}
            className={`px-2.5 py-1 rounded-lg border text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              onlyAnomalies
                ? 'bg-yellow-500/20 border-yellow-500/40 text-yellow-300 shadow-sm shadow-yellow-500/10'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-yellow-400" />
            <span>Anomalies Only</span>
          </button>
        </div>
      </div>

      {/* Main Interactive Graph Canvas Viewport */}
      <div
        ref={containerRef}
        onWheel={handleWheel}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        className="flex-1 w-full h-full relative overflow-hidden cursor-grab active:cursor-grabbing bg-[#05080E]"
      >
        {/* Layer Background Headers */}
        <div 
          className="absolute top-4 left-0 flex pointer-events-none transition-transform duration-75"
          style={{
            transform: `translate(${pan.x}px, ${pan.y - 30}px) scale(${zoom})`,
            transformOrigin: '0 0',
          }}
        >
          <div className="w-[340px] px-4 font-bold text-slate-500 text-xs tracking-wider uppercase flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-purple-400" />
            <span>Tier 1: Auth &amp; Handshake</span>
          </div>
          <div className="w-[340px] px-4 font-bold text-slate-500 text-xs tracking-wider uppercase flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-sky-400" />
            <span>Tier 2: Data Read &amp; Entities</span>
          </div>
          <div className="w-[340px] px-4 font-bold text-slate-500 text-xs tracking-wider uppercase flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-yellow-400" />
            <span>Tier 3: State Mutations</span>
          </div>
          <div className="w-[340px] px-4 font-bold text-slate-500 text-xs tracking-wider uppercase flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>Tier 4: Administrative Surface</span>
          </div>
        </div>

        {/* SVG Canvas for Grid & Directed Lineage Edges */}
        <svg
          className="absolute inset-0 w-full h-full pointer-events-none"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: '0 0',
          }}
        >
          <defs>
            <pattern id="flowgrid" width="40" height="40" patternUnits="userSpaceOnUse">
              <circle cx="2" cy="2" r="1.2" fill="#1E293B" opacity="0.6" />
            </pattern>
          </defs>

          {/* Grid Background */}
          <rect width="5000" height="5000" x="-1000" y="-1000" fill="url(#flowgrid)" />

          {/* Directed Lineage Edges */}
          {filteredEdges.map((edge) => {
            const sourceNode = filteredNodes.find((n) => n.id === edge.sourceNodeId);
            const targetNode = filteredNodes.find((n) => n.id === edge.targetNodeId);
            if (!sourceNode || !targetNode) return null;
            return (
              <LineageEdge
                key={edge.id}
                edge={edge}
                sourceNode={sourceNode}
                targetNode={targetNode}
                isSelected={selectedEdgeId === edge.id}
              />
            );
          })}
        </svg>

        {/* DOM Layer for Interactive Endpoint Nodes */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: '0 0',
          }}
        >
          {filteredNodes.map((node) => (
            <div key={node.id} className="pointer-events-auto">
              <EndpointNode
                node={node}
                isSelected={selectedNodeId === node.id}
                onSelect={(n) => {
                  setSelectedNodeId(n.id);
                  setSelectedEdgeId(null);
                }}
                onNavigateDossier={handleNavigateDossier}
                onDragStart={handleNodeDragStart}
              />
            </div>
          ))}
        </div>

        {/* Floating Viewport Controls */}
        <div className="absolute bottom-4 left-4 flex items-center gap-1.5 p-1.5 bg-slate-900/90 border border-slate-700/80 rounded-xl shadow-2xl backdrop-blur-md z-30">
          <button
            onClick={zoomIn}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
            title="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={zoomOut}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
            title="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <div className="px-2 py-1 text-[11px] font-mono text-slate-400 select-none">
            {Math.round(zoom * 100)}%
          </div>
          <button
            onClick={resetViewport}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
            title="Reset Viewport (100%)"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>

        {/* Node Inspector Detail Panel (Drawer when a node is clicked) */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-80 max-w-[90vw] bg-[#0E1524] border border-slate-700/90 rounded-xl shadow-2xl p-4 z-40 animate-in fade-in slide-in-from-right-4 duration-150 font-mono text-xs space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <div className="flex items-center gap-2">
                <Badge variant={selectedNode.method === 'GET' ? 'primary' : selectedNode.method === 'POST' ? 'success' : 'warning'} size="sm">
                  {selectedNode.method}
                </Badge>
                <span className="font-bold text-slate-200 truncate max-w-[150px]">
                  {selectedNode.path}
                </span>
              </div>
              <button
                onClick={() => setSelectedNodeId(null)}
                className="p-1 text-slate-400 hover:text-slate-200 rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Risk Score Meter */}
            <div className="p-2.5 bg-slate-900/80 rounded-lg border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-slate-400 text-[11px]">Triage Risk Score</span>
                <span className={`font-bold font-mono ${selectedNode.riskScore >= 80 ? 'text-rose-400' : selectedNode.riskScore >= 40 ? 'text-yellow-400' : 'text-emerald-400'}`}>
                  {selectedNode.riskScore} / 100
                </span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-300 ${
                    selectedNode.riskScore >= 80 ? 'bg-rose-500' : selectedNode.riskScore >= 40 ? 'bg-yellow-500' : 'bg-emerald-500'
                  }`}
                  style={{ width: `${selectedNode.riskScore}%` }}
                />
              </div>
            </div>

            {/* Node Metadata & Findings */}
            <div className="space-y-2">
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Target Host</span>
                <span className="text-slate-300 break-all">{selectedNode.host}</span>
              </div>

              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Category</span>
                <span className="text-cyan-300 font-semibold">{selectedNode.category}</span>
              </div>

              {selectedNode.anomalies.length > 0 && (
                <div>
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Detected Anomalies</span>
                  <div className="flex flex-wrap gap-1">
                    {selectedNode.anomalies.map((anom, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded text-[10px] bg-rose-500/10 border border-rose-500/30 text-rose-300 font-semibold"
                      >
                        {anom}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="pt-2 border-t border-slate-800 space-y-2">
              <button
                onClick={() => handleNavigateDossier(selectedNode.dossierKey)}
                className="w-full py-1.5 px-3 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors shadow-sm"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Open Target Dossier</span>
              </button>

              <button
                onClick={() => handleStageInMatrix(selectedNode)}
                className="w-full py-1.5 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors"
              >
                <Zap className="w-3.5 h-3.5 text-primary" />
                <span>Stage in Test Matrix</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
