import React from 'react';
import { GraphEdgeData, GraphNodeData } from '../../types';

interface LineageEdgeProps {
  edge: GraphEdgeData;
  sourceNode: GraphNodeData;
  targetNode: GraphNodeData;
  isSelected?: boolean;
}

export const LineageEdge: React.FC<LineageEdgeProps> = ({
  edge,
  sourceNode,
  targetNode,
  isSelected = false,
}) => {
  const nodeWidth = 256;
  const nodeHeight = 100;

  const sx = (sourceNode.x || 0) + nodeWidth / 2;
  const sy = (sourceNode.y || 0) + nodeHeight / 2;
  const tx = (targetNode.x || 0) + nodeWidth / 2;
  const ty = (targetNode.y || 0) + nodeHeight / 2;

  // Compute bezier control points
  const dx = tx - sx;
  const dy = ty - sy;
  const cx1 = sx + dx * 0.5;
  const cy1 = sy;
  const cx2 = sx + dx * 0.5;
  const cy2 = ty;

  const pathData = `M ${sx} ${sy} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${tx} ${ty}`;

  const getEdgeColor = (type: string) => {
    switch (type) {
      case 'AUTH_TOKEN': return '#C084FC'; // Purple
      case 'PARAM_ID': return '#38BDF8'; // Cyan
      case 'SESSION_COOKIE': return '#34D399'; // Emerald
      case 'STATE_SEQUENCE': return '#FBBF24'; // Amber
      default: return '#94A3B8'; // Slate
    }
  };

  const edgeColor = getEdgeColor(edge.lineageType);
  const midX = (sx + tx) / 2;
  const midY = (sy + ty) / 2;

  return (
    <g className="select-none pointer-events-none">
      {/* Background shadow path */}
      <path
        d={pathData}
        fill="none"
        stroke={edgeColor}
        strokeWidth={isSelected ? 3.5 : 2}
        strokeOpacity={isSelected ? 0.9 : 0.45}
        strokeDasharray="6,4"
        className="transition-all"
      />

      {/* Animated flow pulse line */}
      <path
        d={pathData}
        fill="none"
        stroke={edgeColor}
        strokeWidth={isSelected ? 3 : 1.5}
        strokeDasharray="4,8"
        strokeLinecap="round"
        className="animate-pulse"
      />

      {/* Arrowhead marker at destination */}
      <circle
        cx={tx}
        cy={ty}
        r={4}
        fill={edgeColor}
        className="shadow-sm"
      />

      {/* Lineage parameter label pill */}
      <foreignObject
        x={midX - 70}
        y={midY - 12}
        width={140}
        height={24}
        className="overflow-visible pointer-events-auto"
      >
        <div 
          className="px-2 py-0.5 rounded-full border text-[9px] font-mono font-bold text-center truncate shadow-lg flex items-center justify-center gap-1 backdrop-blur-md"
          style={{
            backgroundColor: '#090D16EE',
            borderColor: edgeColor,
            color: edgeColor,
          }}
          title={`${edge.lineageType}: ${edge.carriedKey}`}
        >
          <span>→ {edge.carriedKey}</span>
        </div>
      </foreignObject>
    </g>
  );
};
