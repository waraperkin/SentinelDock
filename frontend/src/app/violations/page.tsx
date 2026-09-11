import { apiGet } from '@/lib/api';
import type { Policy, PolicyViolation } from '@/types/models';
import { SeverityBadge } from '@/components/SeverityBadge';
import { ActionableList } from '@/components/ActionableList';

const VIOLATION_STATUS_OPTIONS = [
  { value: 'acknowledged', label: 'Acknowledge' },
  { value: 'resolved', label: 'Resolve' },
];

function timeAgo(iso: string): string {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default async function ViolationsPage() {
  const [violations, policies] = await Promise.all([
    apiGet<PolicyViolation[]>('/violations?status=open'),
    apiGet<Policy[]>('/policies'),
  ]);

  const policyById = new Map(policies.map((p) => [p.id, p]));

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-[26px] font-display font-semibold text-[var(--sd-text-primary)]">Violations</h1>
        <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">
          Every open policy violation, one row per asset — the same detections the Policies page counts, with the underlying asset
          and detail visible directly. Acknowledging or resolving here is a manual override; the next evaluation cycle re-detects
          the condition and reopens it if it&apos;s still true.
        </p>
      </div>
      <div className="sd-panel divide-y divide-[var(--sd-border)]">
        <ActionableList
          pathPrefix="/violations"
          options={VIOLATION_STATUS_OPTIONS}
          hideWhenStatusLeaves="open"
          emptyMessage="No open violations — every evaluated policy currently passes."
          initial={violations.map((v) => {
            const policy = policyById.get(v.policy_id);
            return {
              id: v.id,
              status: v.status,
              content: (
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={v.severity} />
                      <span className="text-sm font-medium text-[var(--sd-text-primary)]">{policy?.name ?? 'Unknown policy'}</span>
                    </div>
                    <p className="text-xs text-[var(--sd-text-muted)] sd-mono truncate">
                      {v.asset_type}:{v.asset_id}
                    </p>
                    {Object.keys(v.details).length > 0 && (
                      <p className="text-xs text-[var(--sd-text-muted)] mt-1 sd-mono truncate">{JSON.stringify(v.details)}</p>
                    )}
                  </div>
                  <span className="text-xs text-[var(--sd-text-muted)] shrink-0">{timeAgo(v.detected_at)}</span>
                </div>
              ),
            };
          })}
        />
      </div>
    </div>
  );
}
