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
      <h1 className="text-2xl font-bold mb-6">Policies</h1>
      <div className="space-y-4">
        {policies.map((policy) => {
          const policyViolations = violationsByPolicy.get(policy.id) ?? [];
          const ok = policyViolations.length === 0;
          return (
            <div key={policy.id} className="border border-slate-800 rounded-lg p-4 bg-slate-900">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-semibold">{policy.name}</div>
                  <div className="text-slate-400 text-sm">{policy.description}</div>
                </div>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={policy.severity} />
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${ok ? 'bg-emerald-700' : 'bg-red-700'}`}>
                    {ok ? 'OK' : `${policyViolations.length} violation(s)`}
                  </span>
                </div>
              </div>
              {!ok && (
                <ul className="mt-3 text-sm text-slate-300 space-y-1">
                  {policyViolations.map((v) => (
                    <li key={v.id}>
                      {v.asset_type}:{v.asset_id} — {JSON.stringify(v.details)}
                    </li>
                  ))}
                </ul>
              )}
              {policy.recommendation && <p className="mt-2 text-xs text-slate-500">Recommendation: {policy.recommendation}</p>}
            </div>
          );
        })}
        {policies.length === 0 && <p className="text-slate-500">No policies loaded.</p>}
      </div>
    </div>
  );
}
