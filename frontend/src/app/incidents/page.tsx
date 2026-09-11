import { apiGet } from '@/lib/api';
import type { IncidentScenario, Severity } from '@/types/models';
import { SeverityBadge } from '@/components/SeverityBadge';
import ReactMarkdown from 'react-markdown';

const SEVERITY_LINE: Record<Severity, string> = {
  low: 'var(--sd-low)',
  medium: 'var(--sd-medium)',
  high: 'var(--sd-high)',
  critical: 'var(--sd-critical)',
};

const markdownComponents = {
  h1: (props: React.ComponentProps<'h1'>) => <h1 className="text-base font-display font-semibold text-[var(--sd-text-primary)] mt-4 mb-2" {...props} />,
  h2: (props: React.ComponentProps<'h2'>) => (
    <h2 className="text-[13px] font-semibold uppercase tracking-wide text-[var(--sd-accent-strong)] mt-5 mb-2 first:mt-0" {...props} />
  ),
  p: (props: React.ComponentProps<'p'>) => <p className="text-sm text-[var(--sd-text-secondary)] leading-relaxed mb-2" {...props} />,
  strong: (props: React.ComponentProps<'strong'>) => <strong className="text-[var(--sd-text-primary)] font-semibold" {...props} />,
  ul: (props: React.ComponentProps<'ul'>) => <ul className="space-y-1.5 mb-2" {...props} />,
  li: (props: React.ComponentProps<'li'>) => (
    <li className="text-sm text-[var(--sd-text-secondary)] flex gap-2">
      <span className="text-[var(--sd-accent)] mt-1.5 h-1 w-1 rounded-full bg-current shrink-0" />
      <span>{props.children}</span>
    </li>
  ),
  code: (props: React.ComponentProps<'code'>) => <code className="sd-mono text-xs text-[var(--sd-accent-strong)] bg-[var(--sd-accent-soft)] px-1 py-0.5 rounded" {...props} />,
};

export default async function IncidentsPage() {
  const scenarios = await apiGet<IncidentScenario[]>('/incident-scenarios');

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-[26px] font-display font-semibold text-[var(--sd-text-primary)]">Incident Scenarios</h1>
        <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">Generated playbooks for every high or critical risk currently on the board.</p>
      </div>
      <div className="relative space-y-5 before:content-[''] before:absolute before:left-[7px] before:top-2 before:bottom-2 before:w-px before:bg-[var(--sd-border)]">
        {scenarios.map((scenario) => (
          <div key={scenario.id} className="relative pl-8">
            <span
              className="absolute left-0 top-1.5 h-3.5 w-3.5 rounded-full border-2 border-[var(--sd-bg)]"
              style={{ backgroundColor: SEVERITY_LINE[scenario.severity] }}
            />
            <div className="sd-panel p-5" style={{ borderLeftColor: SEVERITY_LINE[scenario.severity], borderLeftWidth: 3 }}>
              <div className="flex items-start justify-between gap-4">
                <div className="font-medium text-[var(--sd-text-primary)]">{scenario.title}</div>
                <SeverityBadge severity={scenario.severity} />
              </div>
              <p className="text-sm text-[var(--sd-text-secondary)] mt-2">{scenario.summary}</p>
              <details className="mt-3 group">
                <summary className="cursor-pointer text-sm font-medium text-[var(--sd-accent-strong)] hover:text-[var(--sd-accent)] select-none">
                  View playbook
                </summary>
                <div className="mt-3 pt-3 border-t border-[var(--sd-border)]">
                  <ReactMarkdown components={markdownComponents}>{scenario.playbook}</ReactMarkdown>
                </div>
              </details>
            </div>
          </div>
        ))}
        {scenarios.length === 0 && <p className="text-[var(--sd-text-muted)] text-sm pl-8">No incident scenarios generated yet.</p>}
      </div>
    </div>
  );
}
