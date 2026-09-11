import { apiGet } from '@/lib/api';
import type { SegmentZeroTrustScore } from '@/types/models';

function scoreColor(score: number): string {
  if (score >= 70) return '#ef4a5f';
  if (score >= 40) return '#e8823a';
  if (score >= 20) return '#d9a441';
  return '#4ade80';
}

export default async function ZeroTrustPage() {
  const segments = await apiGet<SegmentZeroTrustScore[]>('/zero-trust/segments');
  const sorted = [...segments].sort((a, b) => b.score - a.score);

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-[26px] font-display font-semibold text-[var(--sd-text-primary)]">Zero Trust Posture</h1>
        <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">
          A heuristic 0-100 segmentation maturity score per network segment — higher is worse. Derived from zone exposure, device-class
          mixing, ICS/OT placement, and attached critical risks. Not a certification against a formal Zero Trust framework.
        </p>
      </div>
      <div className="space-y-3">
        {sorted.map((segment) => (
          <div key={segment.segment_id} className="sd-panel p-5">
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <span className="font-medium text-sm text-[var(--sd-text-primary)]">{segment.segment_name}</span>
                <span className="inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide text-[var(--sd-text-secondary)] bg-[var(--sd-surface-hover)]">
                  {segment.zone}
                </span>
                <span className="text-xs text-[var(--sd-text-muted)]">{segment.host_count} host(s) — {segment.device_classes.join(', ') || 'no hosts'}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="sd-mono text-lg font-semibold" style={{ color: scoreColor(segment.score) }}>
                  {segment.score}
                </span>
                <div className="h-2 w-24 rounded-full bg-[var(--sd-surface-hover)] overflow-hidden">
                  <div className="h-full rounded-full" style={{ width: `${segment.score}%`, backgroundColor: scoreColor(segment.score) }} />
                </div>
              </div>
            </div>
            {segment.reasons.length > 0 && (
              <ul className="mt-3 pt-3 border-t border-[var(--sd-border)] space-y-1 text-xs text-[var(--sd-text-secondary)] list-disc list-inside">
                {segment.reasons.map((reason, i) => (
                  <li key={i}>{reason}</li>
                ))}
              </ul>
            )}
          </div>
        ))}
        {sorted.length === 0 && <p className="text-[var(--sd-text-muted)] text-sm">No network segments defined yet.</p>}
      </div>
    </div>
  );
}
