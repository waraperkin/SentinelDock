import { apiGet } from '@/lib/api';
import { SeverityBadge } from '@/components/SeverityBadge';
import { SandboxSimulator } from '@/components/SandboxSimulator';
import { SimulationCampaignRunner } from '@/components/SimulationCampaignRunner';
import { ActionableList } from '@/components/ActionableList';
import type { AttackPath, CloudPosture, IcsPosture, XdrDetection, RemediationPlan, SimulationCampaign, QuantumTrend, QuantumOutlier } from '@/types/models';

const REMEDIATION_STATUS_OPTIONS = [
  { value: 'in_progress', label: 'Start' },
  { value: 'done', label: 'Mark done' },
  { value: 'dismissed', label: 'Dismiss' },
];

function scoreColor(score: number): string {
  if (score >= 70) return '#ef4a5f';
  if (score >= 40) return '#e8823a';
  if (score >= 20) return '#d9a441';
  return '#4ade80';
}

export default async function GodmodePage() {
  const [paths, cloudPosture, icsPosture, xdr, remediation, campaigns, trend, outliers] = await Promise.all([
    apiGet<AttackPath[]>('/attack-paths'),
    apiGet<CloudPosture[]>('/cloud/posture'),
    apiGet<IcsPosture[]>('/ics/posture'),
    apiGet<XdrDetection[]>('/xdr/detections'),
    apiGet<RemediationPlan[]>('/remediation/plans?status=open'),
    apiGet<SimulationCampaign[]>('/simulation/campaigns'),
    apiGet<QuantumTrend>('/quantum/trend'),
    apiGet<QuantumOutlier[]>('/quantum/outliers'),
  ]);

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-[26px] font-display font-semibold text-[var(--sd-text-primary)]">GODMODE Operations</h1>
        <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">
          Non-destructive attack simulation, CLOUDMASTER/ICSMASTER posture aggregation, XDR-lite multi-source correlation, and
          prioritized auto-remediation plans — recommendations only, nothing here auto-applies.
        </p>
      </div>

      <section className="mb-10">
        <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Network Sandbox Engine</h2>
        {paths.length > 0 ? (
          <SandboxSimulator paths={paths} />
        ) : (
          <div className="sd-panel p-5 text-sm text-[var(--sd-text-muted)]">No attack paths yet to simulate against.</div>
        )}
      </section>

      <section className="mb-10">
        <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Attack Simulation Engine — full-fleet campaign</h2>
        <SimulationCampaignRunner initial={campaigns} />
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-10">
        <section>
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">CLOUDMASTER — cloud posture</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            {cloudPosture.map((p) => (
              <div key={p.id} className="px-5 py-3">
                <div className="flex items-center justify-between gap-3 mb-1">
                  <span className="text-sm font-medium text-[var(--sd-text-primary)] capitalize">{p.provider}</span>
                  <span className="sd-mono text-sm font-semibold" style={{ color: scoreColor(p.score) }}>{p.score}</span>
                </div>
                <p className="text-xs text-[var(--sd-text-muted)]">
                  {p.host_count} host(s) · {p.overprivileged_role_count} overprivileged role(s) · {p.metadata_reachable_count} metadata-reachable · {p.mixed_segment_count} mixed-segment
                </p>
              </div>
            ))}
            {cloudPosture.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No cloud-classified hosts yet.</p>}
          </div>
        </section>

        <section>
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">ICSMASTER — ICS/OT posture</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            {icsPosture.map((p) => (
              <div key={p.id} className="px-5 py-3">
                <div className="flex items-center justify-between gap-3 mb-1">
                  <span className="text-sm font-medium text-[var(--sd-text-primary)]">{p.segment_name}</span>
                  <span className="sd-mono text-sm font-semibold" style={{ color: scoreColor(p.score) }}>{p.score}</span>
                </div>
                <p className="text-xs text-[var(--sd-text-muted)]">
                  {p.device_count} device(s) · {p.write_risk_count} write-risk · {p.gateway_count} gateway(s)
                  {p.outside_management_zone && ' · outside management zone'}
                </p>
              </div>
            ))}
            {icsPosture.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No ICS/OT hosts yet.</p>}
          </div>
        </section>

        <section>
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">XDR-lite — correlated detections</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            {xdr.map((d) => (
              <div key={d.id} className="px-5 py-3">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={d.severity} />
                  <span className="text-xs text-[var(--sd-text-muted)]">score {d.composite_score}</span>
                </div>
                <p className="text-sm text-[var(--sd-text-primary)]">{d.summary}</p>
              </div>
            ))}
            {xdr.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No multi-source correlated detections.</p>}
          </div>
        </section>

        <section>
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Auto-Remediation — prioritized plans</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            <ActionableList
              pathPrefix="/remediation/plans"
              options={REMEDIATION_STATUS_OPTIONS}
              hideWhenStatusLeaves="open"
              emptyMessage="No open remediation plans."
              initial={remediation.slice(0, 10).map((r) => ({
                id: r.id,
                status: r.status,
                content: (
                  <>
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={r.severity} />
                      <span className="text-xs text-[var(--sd-text-muted)]">priority {r.priority}</span>
                    </div>
                    <p className="text-sm text-[var(--sd-text-primary)]">{r.title}</p>
                    <ol className="mt-1.5 space-y-0.5">
                      {r.steps.map((step, i) => (
                        <li key={i} className="text-xs text-[var(--sd-text-muted)]">
                          {i + 1}. {step}
                        </li>
                      ))}
                    </ol>
                  </>
                ),
              }))}
            />
          </div>
        </section>
      </div>

      <section>
        <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">
          QUANTUM Engine — local statistical analysis
          <span className="ml-2 text-xs font-normal text-[var(--sd-text-muted)]">(classical statistics, not quantum computing)</span>
        </h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="sd-panel p-5">
            <h3 className="text-xs font-semibold text-[var(--sd-text-muted)] uppercase tracking-wide mb-3">Risk score trend</h3>
            {trend.message ? (
              <p className="text-sm text-[var(--sd-text-muted)]">{trend.message}</p>
            ) : (
              <div>
                <div className="flex items-baseline gap-2 mb-1">
                  <span className="text-2xl font-semibold sd-mono text-[var(--sd-text-primary)]">{trend.current_score}</span>
                  <span className="text-xs text-[var(--sd-text-muted)] uppercase tracking-wide">{trend.direction}</span>
                </div>
                <p className="text-xs text-[var(--sd-text-muted)]">
                  Forecast next sample: {trend.forecast_next} · slope {trend.slope} over {trend.samples} sample(s)
                </p>
              </div>
            )}
          </div>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            <h3 className="text-xs font-semibold text-[var(--sd-text-muted)] uppercase tracking-wide px-5 py-3">Statistical outliers (z-score)</h3>
            {outliers.slice(0, 6).map((o) => (
              <div key={o.id} className="px-5 py-3 flex items-center justify-between text-sm">
                <span className="text-[var(--sd-text-primary)] sd-mono text-xs truncate">
                  {o.asset_type}:{o.asset_id}
                </span>
                <span className="text-xs text-[var(--sd-text-muted)]">z={o.z_score} (score {o.score}, fleet mean {o.mean})</span>
              </div>
            ))}
            {outliers.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No statistical outliers in the current risk distribution.</p>}
          </div>
        </div>
      </section>
    </div>
  );
}
