import { apiGet } from '@/lib/api';
import type { DashboardSummary } from '@/types/models';

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
      <div className="text-slate-400 text-sm">{label}</div>
      <div className="text-3xl font-bold mt-1">{value}</div>
    </div>
  );
}

export default async function DashboardPage() {
  let summary: DashboardSummary | null = null;
  let error: string | null = null;
  try {
    summary = await apiGet<DashboardSummary>('/dashboard/summary');
  } catch (e) {
    error = e instanceof Error ? e.message : 'Failed to load dashboard';
  }

  if (error || !summary) {
    return <p className="text-red-400">Unable to load dashboard: {error}</p>;
  }

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Control Plane Overview</h1>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Assets" value={summary.asset_count} />
        <StatCard label="Global Risk Score" value={summary.global_risk_score} />
        <StatCard label="Open Violations" value={summary.open_violations} />
        <StatCard label="Incident Scenarios" value={summary.incident_scenarios} />
        <StatCard label="Hosts" value={summary.hosts} />
        <StatCard label="Containers" value={summary.containers} />
        <StatCard label="Services" value={summary.services} />
      </div>
    </div>
  );
}
