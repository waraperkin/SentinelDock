import { apiGet } from '@/lib/api';
import type { Host, Container, ServiceRecord, NetworkSegment } from '@/types/models';

function Table({ title, headers, rows }: { title: string; headers: string[]; rows: (string | number)[][] }) {
  return (
    <div className="mb-8">
      <h2 className="text-lg font-semibold mb-2">{title}</h2>
      <div className="overflow-x-auto border border-slate-800 rounded-lg">
        <table className="w-full text-sm">
          <thead className="bg-slate-900">
            <tr>
              {headers.map((h) => (
                <th key={h} className="text-left px-3 py-2 text-slate-400 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={headers.length} className="px-3 py-3 text-slate-500">
                  No records
                </td>
              </tr>
            )}
            {rows.map((row, i) => (
              <tr key={i} className="border-t border-slate-800">
                {row.map((cell, j) => (
                  <td key={j} className="px-3 py-2">
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default async function InventoryPage() {
  const [hosts, containers, services, segments] = await Promise.all([
    apiGet<Host[]>('/assets/hosts'),
    apiGet<Container[]>('/assets/containers'),
    apiGet<ServiceRecord[]>('/assets/services'),
    apiGet<NetworkSegment[]>('/assets/network'),
  ]);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Inventory</h1>
      <Table
        title={`Hosts (${hosts.length})`}
        headers={['Hostname', 'OS', 'Role', 'Criticality', 'IP']}
        rows={hosts.map((h) => [h.hostname, h.os ?? '-', h.role, h.criticality, h.ip_address ?? '-'])}
      />
      <Table
        title={`Containers (${containers.length})`}
        headers={['Name', 'Image', 'Status', 'Privileged']}
        rows={containers.map((c) => [c.name, c.image, c.status, c.privileged ? 'yes' : 'no'])}
      />
      <Table
        title={`Services (${services.length})`}
        headers={['Name', 'Port', 'Version', 'Bind Address', 'Exposed Publicly', 'Known CVEs']}
        rows={services.map((s) => [
          s.name,
          s.port,
          s.version ?? '-',
          s.bind_address,
          s.exposed_publicly ? 'yes' : 'no',
          s.cve_ids.length > 0 ? s.cve_ids.join(', ') : '-',
        ])}
      />
      <Table
        title={`Network Segments (${segments.length})`}
        headers={['Name', 'CIDR', 'Zone']}
        rows={segments.map((s) => [s.name, s.cidr, s.zone])}
      />
    </div>
  );
}
