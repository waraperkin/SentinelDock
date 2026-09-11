import { apiGet } from '@/lib/api';
import { SeverityBadge } from '@/components/SeverityBadge';
import type { TimelineEvent, TiMatch, UebaAnomaly, EdrDetection, SegmentationRecommendation, HardeningRecommendation } from '@/types/models';

const SOURCE_LABEL: Record<string, string> = {
  risk: 'Risk',
  violation: 'Policy violation',
  secret: 'Secret',
  ti: 'Threat intel',
  ueba: 'UEBA anomaly',
  edr: 'EDR detection',
};

function timeAgo(iso: string): string {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default async function TitanPage() {
  const [timeline, ti, ueba, edr, segReco, hardenReco] = await Promise.all([
    apiGet<TimelineEvent[]>('/siem/timeline?limit=50'),
    apiGet<TiMatch[]>('/ti/matches'),
    apiGet<UebaAnomaly[]>('/ueba/anomalies?hours=24'),
    apiGet<EdrDetection[]>('/edr/detections'),
    apiGet<SegmentationRecommendation[]>('/segmentation/recommendations?status=open'),
    apiGet<HardeningRecommendation[]>('/hardening/recommendations?status=open'),
  ]);

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-[26px] font-display font-semibold text-[var(--sd-text-primary)]">TITAN Operations</h1>
        <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">
          Threat intelligence (local curated dataset), UEBA-lite behavioral baselines, agentless EDR-lite detections, a correlated
          SIEM-lite timeline, and auto-generated segmentation/hardening recommendations — all reviewed by a human before acting.
        </p>
      </div>

      <section className="mb-10">
        <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Correlated timeline (SIEM-lite)</h2>
        <div className="sd-panel divide-y divide-[var(--sd-border)]">
          {timeline.map((event) => (
            <div key={event.id} className="flex items-center justify-between gap-4 px-5 py-3">
              <div className="flex items-center gap-3 min-w-0">
                <SeverityBadge severity={event.severity} />
                <span className="text-xs font-semibold text-[var(--sd-text-muted)] uppercase tracking-wide shrink-0">
                  {SOURCE_LABEL[event.source] ?? event.source}
                </span>
                <span className="text-sm text-[var(--sd-text-primary)] truncate">{event.summary}</span>
              </div>
              <span className="text-xs text-[var(--sd-text-muted)] shrink-0">{timeAgo(event.occurred_at)}</span>
            </div>
          ))}
          {timeline.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No correlated events yet — run an evaluation.</p>}
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-10">
        <section>
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Threat intelligence matches</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            {ti.map((m) => (
              <div key={m.id} className="px-5 py-3">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={m.severity} />
                  <span className="text-xs text-[var(--sd-text-muted)] uppercase tracking-wide">{m.indicator_kind.replace('_', ' ')}</span>
                </div>
                <p className="text-sm text-[var(--sd-text-primary)]">{m.label}</p>
              </div>
            ))}
            {ti.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No TI matches against current inventory.</p>}
          </div>
        </section>

        <section>
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">EDR-lite detections (agentless)</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            {edr.map((d) => (
              <div key={d.id} className="px-5 py-3">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={d.severity} />
                  <span className="text-xs text-[var(--sd-text-muted)] uppercase tracking-wide">{d.kind.replace(/-/g, ' ')}</span>
                </div>
              </div>
            ))}
            {edr.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No behavioral detections.</p>}
          </div>
        </section>

        <section>
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">UEBA-lite anomalies (24h)</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            {ueba.map((a) => (
              <div key={a.id} className="px-5 py-3">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={a.severity} />
                  <span className="text-xs text-[var(--sd-text-muted)] uppercase tracking-wide">{a.kind.replace(/-/g, ' ')}</span>
                </div>
              </div>
            ))}
            {ueba.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No baseline deviations in the last 24 hours.</p>}
          </div>
        </section>

        <section>
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Auto-segmentation recommendations</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            {segReco.map((r) => (
              <div key={r.id} className="px-5 py-3">
                <p className="text-sm text-[var(--sd-text-primary)]">{r.recommendation}</p>
                <p className="text-xs text-[var(--sd-text-muted)] mt-1">{r.rationale}</p>
              </div>
            ))}
            {segReco.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No open segmentation recommendations.</p>}
          </div>
        </section>
      </div>

      <section>
        <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Auto-hardening recommendations</h2>
        <div className="sd-panel divide-y divide-[var(--sd-border)]">
          {hardenReco.map((r) => (
            <div key={r.id} className="px-5 py-3">
              <div className="flex items-center gap-2 mb-1">
                <SeverityBadge severity={r.severity} />
              </div>
              <p className="text-sm text-[var(--sd-text-primary)]">{r.action}</p>
              <p className="text-xs text-[var(--sd-text-muted)] mt-1">{r.rationale}</p>
            </div>
          ))}
          {hardenReco.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No open hardening recommendations.</p>}
        </div>
      </section>
    </div>
  );
}
