import Link from 'next/link';
import { notFound } from 'next/navigation';
import { apiGet } from '@/lib/api';
import { SeverityBadge } from '@/components/SeverityBadge';
import type { Host, Container, ServiceRecord, Risk, PolicyViolation, SecretFinding, ConfigSnapshot, NetworkSegment } from '@/types/models';

const DEVICE_CLASS_LABEL: Record<string, string> = { it: 'IT', ics: 'ICS/OT', cloud: 'Cloud' };

function timeAgo(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

// Known Next.js 14 App Router quirk in self-hosted (`next start`) mode: a
// notFound() call from a dynamic route with no-store data fetching still
// renders the not-found.tsx UI correctly, but the HTTP status code stays
// 200 instead of 404. Cosmetic only (irrelevant for an internal tool with
// no public search indexing) — the content and navigation are correct.

async function fetchHost(id: string): Promise<Host | null> {
  try {
    return await apiGet<Host>(`/assets/hosts/${id}`);
  } catch {
    return null;
  }
}

/**
 * Host detail / drill-down page — clicking a host anywhere in the app
 * (Inventory table, TITAN/GODMODE asset references, etc.) should land
 * here to see everything known about that one asset in one place,
 * instead of only ever seeing it as a row in a big table.
 */
export default async function HostDetailPage({ params }: { params: { id: string } }) {
  const host = await fetchHost(params.id);
  if (!host) notFound();

  // Risks and violations mostly attach to the service/container that
  // actually triggered them (e.g. an exposed SSH port), not to the host
  // itself — so a host detail page that only queried `asset_type=host`
  // would look empty for almost every real finding. Instead, all risks/
  // violations are fetched once and matched against this host directly
  // AND every container/service running on it.
  const [containers, services, risks, violations, secrets, configs, segments] = await Promise.all([
    apiGet<Container[]>('/assets/containers'),
    apiGet<ServiceRecord[]>('/assets/services'),
    apiGet<Risk[]>('/risks'),
    apiGet<PolicyViolation[]>('/violations?status=open'),
    apiGet<SecretFinding[]>(`/secrets?asset_type=host&asset_id=${host.id}`),
    apiGet<ConfigSnapshot[]>(`/configs?asset_type=host&asset_id=${host.id}`),
    apiGet<NetworkSegment[]>('/assets/network'),
  ]);

  const hostContainers = containers.filter((c) => c.host_id === host.id);
  const containerIds = new Set(hostContainers.map((c) => c.id));
  const hostServices = services.filter((s) => s.host_id === host.id || (s.container_id && containerIds.has(s.container_id)));
  const serviceIds = new Set(hostServices.map((s) => s.id));

  const belongsToThisHost = (assetType: string, assetId: string) =>
    (assetType === 'host' && assetId === host.id) || (assetType === 'container' && containerIds.has(assetId)) || (assetType === 'service' && serviceIds.has(assetId));
  const hostRisks = risks.filter((r) => belongsToThisHost(r.asset_type, r.asset_id));
  const hostViolations = violations.filter((v) => belongsToThisHost(v.asset_type, v.asset_id));

  const segment = segments.find((s) => s.id === host.network_segment_id);
  const latestSnapshotByKind = new Map<string, ConfigSnapshot>();
  for (const snapshot of configs) {
    const existing = latestSnapshotByKind.get(snapshot.kind);
    if (!existing || new Date(snapshot.collected_at) > new Date(existing.collected_at)) latestSnapshotByKind.set(snapshot.kind, snapshot);
  }

  return (
    <div>
      <div className="mb-6">
        <Link href="/inventory" className="text-xs text-[var(--sd-text-muted)] hover:text-[var(--sd-accent)]">
          ← Inventory
        </Link>
      </div>

      <div className="sd-panel p-6 mb-8">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-[24px] font-display font-semibold text-[var(--sd-text-primary)] sd-mono">{host.hostname}</h1>
            <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">
              {host.role} · {DEVICE_CLASS_LABEL[host.device_class] ?? host.device_class}
              {segment && (
                <>
                  {' '}
                  ·{' '}
                  <Link href="/inventory" className="text-[var(--sd-accent)] hover:underline">
                    {segment.name}
                  </Link>
                </>
              )}
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <SeverityBadge severity={host.criticality} />
          </div>
        </div>
        <div className="mt-5 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <div className="text-[11px] uppercase tracking-wide text-[var(--sd-text-muted)]">IP Address</div>
            <div className="sd-mono text-[var(--sd-text-primary)] mt-0.5">{host.ip_address ?? '—'}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wide text-[var(--sd-text-muted)]">OS</div>
            <div className="text-[var(--sd-text-primary)] mt-0.5 truncate" title={host.os ?? undefined}>
              {host.os ?? '—'}
            </div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wide text-[var(--sd-text-muted)]">Last Seen</div>
            <div className="text-[var(--sd-text-primary)] mt-0.5">{timeAgo(host.last_seen)}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wide text-[var(--sd-text-muted)]">Host ID</div>
            <div className="sd-mono text-[var(--sd-text-muted)] mt-0.5 truncate" title={host.id}>
              {host.id}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <section>
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Risks ({hostRisks.length})</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            {hostRisks.map((r) => (
              <div key={r.id} className="px-5 py-3">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={r.severity} />
                  <span className="text-xs text-[var(--sd-text-muted)] uppercase tracking-wide">{r.category}</span>
                  {r.asset_type !== 'host' && <span className="text-xs text-[var(--sd-text-muted)] sd-mono">via {r.asset_type}</span>}
                  <span className="text-xs text-[var(--sd-text-muted)] ml-auto">score {r.score}</span>
                </div>
                <p className="text-sm text-[var(--sd-text-primary)]">{r.summary}</p>
              </div>
            ))}
            {hostRisks.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No risks recorded for this host or anything running on it.</p>}
          </div>
        </section>

        <section>
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Open violations ({hostViolations.length})</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            {hostViolations.map((v) => (
              <div key={v.id} className="px-5 py-3">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={v.severity} />
                  <span className="text-xs text-[var(--sd-text-muted)] sd-mono">{v.asset_type}</span>
                </div>
                <p className="text-xs text-[var(--sd-text-muted)] sd-mono truncate">{JSON.stringify(v.details)}</p>
              </div>
            ))}
            {hostViolations.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No open violations for this host or anything running on it.</p>}
          </div>
        </section>

        <section>
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Containers ({hostContainers.length})</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            {hostContainers.map((c) => (
              <div key={c.id} className="px-5 py-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm text-[var(--sd-text-primary)]">{c.name}</span>
                  {c.privileged && <span className="text-xs text-[var(--sd-critical)] font-medium">privileged</span>}
                </div>
                <p className="text-xs text-[var(--sd-text-muted)] sd-mono mt-0.5">
                  {c.image} · {c.status}
                </p>
              </div>
            ))}
            {hostContainers.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No containers on this host.</p>}
          </div>
        </section>

        <section>
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Services ({hostServices.length})</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            {hostServices.map((s) => (
              <div key={s.id} className="px-5 py-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm text-[var(--sd-text-primary)] sd-mono">
                    {s.name}:{s.port}
                  </span>
                  {s.exposed_publicly && <span className="text-xs text-[var(--sd-high)] font-medium">public</span>}
                </div>
                {s.cve_ids.length > 0 && <p className="text-xs text-[var(--sd-critical)] sd-mono mt-0.5">{s.cve_ids.join(', ')}</p>}
              </div>
            ))}
            {hostServices.length === 0 && <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">No services discovered on this host.</p>}
          </div>
        </section>
      </div>

      {secrets.length > 0 && (
        <section className="mb-8">
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Secrets detected ({secrets.length})</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            {secrets.map((s) => (
              <div key={s.id} className="px-5 py-3">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={s.severity} />
                  <span className="text-xs text-[var(--sd-text-muted)] uppercase tracking-wide">{s.kind}</span>
                </div>
                <p className="text-xs text-[var(--sd-text-muted)] sd-mono">{s.match_preview} — {s.source}</p>
              </div>
            ))}
          </div>
        </section>
      )}

      {latestSnapshotByKind.size > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Collected snapshots</h2>
          <div className="sd-panel divide-y divide-[var(--sd-border)]">
            {Array.from(latestSnapshotByKind.values()).map((snap) => (
              <div key={snap.id} className="px-5 py-3">
                <div className="flex items-center justify-between gap-3 mb-1">
                  <span className="text-xs font-semibold text-[var(--sd-text-muted)] uppercase tracking-wide">{snap.kind}</span>
                  <span className="text-xs text-[var(--sd-text-muted)]">{timeAgo(snap.collected_at)}</span>
                </div>
                <pre className="text-xs text-[var(--sd-text-secondary)] sd-mono whitespace-pre-wrap break-all">{JSON.stringify(snap.data, null, 2)}</pre>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
