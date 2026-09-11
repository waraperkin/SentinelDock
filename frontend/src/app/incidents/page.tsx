import { apiGet } from '@/lib/api';
import type { IncidentScenario } from '@/types/models';
import { SeverityBadge } from '@/components/SeverityBadge';
import ReactMarkdown from 'react-markdown';

export default async function IncidentsPage() {
  const scenarios = await apiGet<IncidentScenario[]>('/incident-scenarios');

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Incident Scenarios</h1>
      <div className="space-y-6">
        {scenarios.map((scenario) => (
          <div key={scenario.id} className="border border-slate-800 rounded-lg p-4 bg-slate-900">
            <div className="flex items-center justify-between">
              <div className="font-semibold">{scenario.title}</div>
              <SeverityBadge severity={scenario.severity} />
            </div>
            <p className="text-sm text-slate-400 mt-1">{scenario.summary}</p>
            <details className="mt-3">
              <summary className="cursor-pointer text-sm text-sky-400">View playbook</summary>
              <div className="mt-3 max-w-none whitespace-pre-wrap text-sm text-slate-300">
                <ReactMarkdown>{scenario.playbook}</ReactMarkdown>
              </div>
            </details>
          </div>
        ))}
        {scenarios.length === 0 && <p className="text-slate-500">No incident scenarios generated yet.</p>}
      </div>
    </div>
  );
}
