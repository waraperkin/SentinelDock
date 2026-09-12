import { apiGet } from '@/lib/api';
import type { WorkerNode } from '@/types/models';

function timeAgo(iso: string): string {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

/**
 * last_cycle_summary is whatever the evaluation pipeline returned that
 * cycle (see runDownstreamPipeline/evaluatePoliciesBySegment in the
 * backend) — a flat map of counts for a plain evaluation, or including
 * a `per_segment` array when the distributed engine ran. React cannot
 * render an object/array directly as a child, so anything beyond a
 * primitive is summarized instead of crashing the page.
 */
function summaryValueLabel(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? '' : 's'}`;
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

export default async function WorkersPage() {
  const nodes = await apiGet<WorkerNode[]>('/workers');

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-[26px] font-display font-semibold text-[var(--sd-text-primary)]">Worker Nodes</h1>
        <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">
          Every worker replica that has ever heartbeated, coordinated via a Redis distributed lock so only one runs a given collection cycle.
        </p>
      </div>
      <div className="space-y-3">
        {nodes.map((node) => (
          <div key={node.id} className="sd-panel p-5">
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: node.online ? '#4ade80' : 'var(--sd-text-muted)' }} />
                <span className="font-medium sd-mono text-sm text-[var(--sd-text-primary)]">{node.hostname}</span>
                {node.is_leader && (
                  <span className="inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide text-[var(--sd-accent-strong)] bg-[var(--sd-accent-soft)]">
                    Leader
                  </span>
                )}
              </div>
              <span className="text-xs text-[var(--sd-text-muted)]">{node.online ? 'online' : 'offline'} — last heartbeat {timeAgo(node.last_heartbeat_at)}</span>
            </div>
            <div className="mt-2 text-xs text-[var(--sd-text-muted)] sd-mono">worker_id: {node.worker_id}</div>
            {node.last_cycle_summary && (
              <>
                <div className="mt-3 pt-3 border-t border-[var(--sd-border)] flex flex-wrap gap-x-5 gap-y-1 text-xs text-[var(--sd-text-secondary)]">
                  {Object.entries(node.last_cycle_summary)
                    .filter(([, value]) => !Array.isArray(value))
                    .map(([key, value]) => (
                      <span key={key}>
                        {key}: <span className="sd-mono text-[var(--sd-text-primary)]">{summaryValueLabel(value)}</span>
                      </span>
                    ))}
                </div>
                {Array.isArray(node.last_cycle_summary.per_segment) && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {(node.last_cycle_summary.per_segment as Array<{ segment_name: string; host_count: number; violations: number }>).map((seg) => (
                      <span
                        key={seg.segment_name}
                        className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] sd-mono bg-[var(--sd-surface-hover)] text-[var(--sd-text-secondary)]"
                        title={`${seg.host_count} host(s)`}
                      >
                        {seg.segment_name}
                        {seg.violations > 0 && <span className="text-[var(--sd-critical)] font-semibold">·{seg.violations}</span>}
                      </span>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        ))}
        {nodes.length === 0 && <p className="text-[var(--sd-text-muted)] text-sm">No worker nodes have heartbeated yet.</p>}
      </div>
    </div>
  );
}
