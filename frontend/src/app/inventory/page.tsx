import { apiGet } from '@/lib/api';
import type { Host, Container, ServiceRecord, NetworkSegment } from '@/types/models';
import { DataTable } from '@/components/DataTable';

const CRITICALITY_COLOR: Record<string, string> = {
  low: 'text-[var(--sd-low)]',
  medium: 'text-[var(--sd-medium)]',
  high: 'text-[var(--sd-high)]',
  critical: 'text-[var(--sd-critical)]',
};

const DEVICE_CLASS_STYLE: Record<string, { label: string; color: string; bg: string }> = {
  it: { label: 'IT', color: 'var(--sd-text-secondary)', bg: 'transparent' },
  ics: { label: 'ICS/OT', color: 'var(--sd-critical)', bg: 'rgba(239,74,95,0.14)' },
  cloud: { label: 'Cloud', color: 'var(--sd-accent-strong)', bg: 'var(--sd-accent-soft)' },
};

export default async function InventoryPage() {
  const [hosts, containers, services, segments] = await Promise.all([
    apiGet<Host[]>('/assets/hosts'),
    apiGet<Container[]>('/assets/containers'),
    apiGet<ServiceRecord[]>('/assets/services'),
    apiGet<NetworkSegment[]>('/assets/network'),
  ]);

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-[26px] font-display font-semibold text-[var(--sd-text-primary)]">Inventory</h1>
        <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">Hosts, containers, services, and network segments discovered across your environment.</p>
      </div>
      <DataTable
        title={`Hosts (${hosts.length})`}
        headers={['Hostname', 'Class', 'OS', 'Role', 'Criticality', 'IP']}
        rows={hosts.map((h) => {
          const dc = DEVICE_CLASS_STYLE[h.device_class] ?? DEVICE_CLASS_STYLE.it;
          return [
            <span key="h" className="sd-mono">
              {h.hostname}
            </span>,
            <span key="dc" className="inline-flex rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide" style={{ color: dc.color, backgroundColor: dc.bg }}>
              {dc.label}
            </span>,
            h.os ?? '—',
            h.role,
            <span key="c" className={`font-medium ${CRITICALITY_COLOR[h.criticality] ?? ''}`}>
              {h.criticality}
            </span>,
            <span key="ip" className="sd-mono text-[var(--sd-text-secondary)]">
              {h.ip_address ?? '—'}
            </span>,
          ];
        })}
      />
      <DataTable
        title={`Containers (${containers.length})`}
        headers={['Name', 'Image', 'Status', 'Privileged']}
        rows={containers.map((c) => [
          c.name,
          <span key="i" className="sd-mono text-[var(--sd-text-secondary)]">
            {c.image}
          </span>,
          c.status,
          c.privileged ? <span className="text-[var(--sd-critical)] font-medium">yes</span> : 'no',
        ])}
      />
      <DataTable
        title={`Services (${services.length})`}
        headers={['Name', 'Port', 'Version', 'Bind Address', 'Exposed Publicly', 'Known CVEs']}
        rows={services.map((s) => [
          s.name,
          <span key="p" className="sd-mono">
            {s.port}
          </span>,
          s.version ?? '—',
          <span key="b" className="sd-mono text-[var(--sd-text-secondary)]">
            {s.bind_address}
          </span>,
          s.exposed_publicly ? <span className="text-[var(--sd-high)] font-medium">yes</span> : 'no',
          s.cve_ids.length > 0 ? (
            <span key="cve" className="sd-mono text-[var(--sd-critical)]">
              {s.cve_ids.join(', ')}
            </span>
          ) : (
            '—'
          ),
        ])}
      />
      <DataTable
        title={`Network Segments (${segments.length})`}
        headers={['Name', 'CIDR', 'Zone']}
        rows={segments.map((s) => [
          s.name,
          <span key="c" className="sd-mono">
            {s.cidr}
          </span>,
          s.zone,
        ])}
      />
    </div>
  );
}
