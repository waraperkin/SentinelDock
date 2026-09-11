'use client';

import { useState } from 'react';
import type { AttackPathGraph } from '@/types/models';

const SEVERITY_COLOR: Record<string, string> = {
  low: '#64748b',
  medium: '#d9a441',
  high: '#e8823a',
  critical: '#ef4a5f',
};

// Colored by *layer* (network/container/service/ics/cloud/devops/it), not
// raw asset type — this is what makes the graph read as multi-domain
// rather than just "here are some dots".
const LAYER_COLOR: Record<string, string> = {
  network: '#5b6b85',
  container: '#34d399',
  service: '#22d3c8',
  it: '#a78bfa',
  ics: '#ef4a5f',
  cloud: '#5eead4',
  devops: '#d9a441',
};

const LAYER_LABEL: Record<string, string> = {
  network: 'Network',
  container: 'Container',
  service: 'Service',
  it: 'Host (IT)',
  ics: 'ICS/OT',
  cloud: 'Cloud',
  devops: 'DevOps',
};

/** Simple circular layout SVG graph — no external charting dependency. */
export function AttackPathGraphView({ graph }: { graph: AttackPathGraph }) {
  const [hovered, setHovered] = useState<string | null>(null);
  const width = 700;
  const height = 480;
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(cx, cy) - 64;

  const positions = new Map<string, { x: number; y: number }>();
  graph.nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / Math.max(graph.nodes.length, 1) - Math.PI / 2;
    positions.set(node.id, { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) });
  });

  const usedLayers = Array.from(new Set(graph.nodes.map((n) => n.layer)));

  return (
    <div className="sd-panel p-4">
      {graph.nodes.length === 0 ? (
        <div className="h-[220px] flex items-center justify-center text-sm text-[var(--sd-text-muted)]">
          No attack path graph data yet — it fills in once a risk is detected on an exposed asset.
        </div>
      ) : (
        <>
          <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-[440px]">
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
                  strokeWidth={hovered === edge.path_id ? 2.5 : 1.3}
                  opacity={hovered && hovered !== edge.path_id ? 0.15 : 0.7}
                />
              );
            })}
            {graph.nodes.map((node) => {
              const pos = positions.get(node.id);
              if (!pos) return null;
              const color = LAYER_COLOR[node.layer] ?? '#64748b';
              return (
                <g key={node.id} onMouseEnter={() => setHovered(node.id)} onMouseLeave={() => setHovered(null)} className="cursor-pointer">
                  <circle cx={pos.x} cy={pos.y} r={12} fill={color} opacity={0.18} />
                  <circle cx={pos.x} cy={pos.y} r={6} fill={color} />
                  <text x={pos.x} y={pos.y - 18} fontSize={10} fill="#94a3b8" textAnchor="middle" fontFamily="var(--font-mono, monospace)">
                    {node.id.length > 22 ? `${node.id.slice(0, 20)}…` : node.id}
                  </text>
                </g>
              );
            })}
          </svg>
          <div className="flex flex-wrap items-center gap-5 px-2 pt-2 border-t border-[var(--sd-border)] mt-1">
            {usedLayers.map((layer) => (
              <div key={layer} className="flex items-center gap-1.5 text-xs text-[var(--sd-text-muted)]">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: LAYER_COLOR[layer] ?? '#64748b' }} />
                {LAYER_LABEL[layer] ?? layer}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
