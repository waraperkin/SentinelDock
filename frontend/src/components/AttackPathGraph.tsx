'use client';

import { useState } from 'react';
import type { AttackPathGraph } from '@/types/models';

const SEVERITY_COLOR: Record<string, string> = {
  low: '#64748b',
  medium: '#d97706',
  high: '#ea580c',
  critical: '#dc2626',
};

/** Simple circular layout SVG graph — no external charting dependency. */
export function AttackPathGraphView({ graph }: { graph: AttackPathGraph }) {
  const [hovered, setHovered] = useState<string | null>(null);
  const width = 700;
  const height = 500;
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(cx, cy) - 60;

  const positions = new Map<string, { x: number; y: number }>();
  graph.nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / Math.max(graph.nodes.length, 1);
    positions.set(node.id, { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) });
  });

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-[500px] bg-slate-900 border border-slate-800 rounded-lg">
      {graph.edges.map((edge, i) => {
        const source = positions.get(edge.source);
        const target = positions.get(edge.target);
        if (!source || !target) return null;
        return (
          <line
            key={i}
            x1={source.x}
            y1={source.y}
            x2={target.x}
            y2={target.y}
            stroke={SEVERITY_COLOR[edge.severity] ?? '#64748b'}
            strokeWidth={hovered === edge.path_id ? 3 : 1.5}
            opacity={hovered && hovered !== edge.path_id ? 0.2 : 0.8}
          />
        );
      })}
      {graph.nodes.map((node) => {
        const pos = positions.get(node.id);
        if (!pos) return null;
        return (
          <g key={node.id} onMouseEnter={() => setHovered(node.id)} onMouseLeave={() => setHovered(null)}>
            <circle cx={pos.x} cy={pos.y} r={10} fill={node.type === 'service' ? '#0ea5e9' : node.type === 'host' ? '#a78bfa' : '#34d399'} />
            <text x={pos.x} y={pos.y - 14} fontSize={10} fill="#cbd5e1" textAnchor="middle">
              {node.id}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
