import { apiGet } from '@/lib/api';
import type { Policy, PolicyViolation } from '@/types/models';
import { SeverityBadge } from '@/components/SeverityBadge';

export default async function PoliciesPage() {
  const [policies, violations] = await Promise.all([
    apiGet<Policy[]>('/policies'),
    apiGet<PolicyViolation[]>('/violations?status=open'),
  ]);

  const violationsByPolicy = new Map<string, PolicyViolation[]>();
  for (const v of violations) {
    violationsByPolicy.set(v.policy_id, [...(violationsByPolicy.get(v.policy_id) ?? []), v]);
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-[26px] font-display font-semibold text-[var(--sd-text-primary)]">Policies</h1>
        <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">
          {policies.length} rule{policies.length === 1 ? '' : 's'} evaluated against every discovered asset on each collection cycle.
        </p>
      </div>
      <div className="space-y-3">
        {policies.map((policy) => {
          const policyViolations = violationsByPolicy.get(policy.id) ?? [];
          const ok = policyViolations.length === 0;
          return (
            <div key={policy.id} className="sd-panel p-5">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="font-medium text-[var(--sd-text-primary)]">{policy.name}</div>
                  <div className="text-sm text-[var(--sd-text-secondary)] mt-0.5">{policy.description}</div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <SeverityBadge severity={policy.severity} />
                  <span
                    className="inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide"
                    style={
                      ok
                        ? { color: '#4ade80', backgroundColor: 'rgba(74,222,128,0.12)' }
                        : { color: 'var(--sd-critical)', backgroundColor: 'rgba(239,74,95,0.16)' }
                    }
                  >
                    {ok ? 'OK' : `${policyViolations.length} violation${policyViolations.length === 1 ? '' : 's'}`}
                  </span>
                </div>
              </div>
              {!ok && (
                <ul className="mt-3 text-sm text-[var(--sd-text-secondary)] space-y-1 border-t border-[var(--sd-border)] pt-3">
                  {policyViolations.map((v) => (
                    <li key={v.id} className="sd-mono text-xs">
                      {v.asset_type}:{v.asset_id} — {JSON.stringify(v.details)}
                    </li>
                  ))}
                </ul>
              )}
              {policy.recommendation && <p className="mt-3 text-xs text-[var(--sd-text-muted)]">Recommendation: {policy.recommendation}</p>}
            </div>
          );
        })}
        {policies.length === 0 && <p className="text-[var(--sd-text-muted)] text-sm">No policies loaded.</p>}
      </div>
    </div>
  );
}
