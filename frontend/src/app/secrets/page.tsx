import { apiGet } from '@/lib/api';
import type { SecretFinding } from '@/types/models';
import { SeverityBadge } from '@/components/SeverityBadge';

const KIND_LABEL: Record<string, string> = {
  aws_access_key: 'AWS access key',
  private_key: 'Private key',
  generic_api_key: 'API key',
  generic_password: 'Password',
};

export default async function SecretsPage() {
  const findings = await apiGet<SecretFinding[]>('/secrets');

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-[26px] font-display font-semibold text-[var(--sd-text-primary)]">Secrets</h1>
        <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">
          Local, offline pattern matches against container environment variables — never the full secret value, only a redacted preview.
        </p>
      </div>
      <div className="space-y-3">
        {findings.map((finding) => (
          <div key={finding.id} className="sd-panel p-5">
            <div className="flex items-center justify-between gap-4">
              <div className="font-medium text-[var(--sd-text-primary)]">{KIND_LABEL[finding.kind] ?? finding.kind}</div>
              <SeverityBadge severity={finding.severity} />
            </div>
            <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-xs text-[var(--sd-text-muted)] sd-mono">
              <span>
                {finding.asset_type}:{finding.asset_id}
              </span>
              <span>source: {finding.source}</span>
              <span className="text-[var(--sd-critical)]">preview: {finding.match_preview}</span>
            </div>
          </div>
        ))}
        {findings.length === 0 && <p className="text-[var(--sd-text-muted)] text-sm">No secrets detected.</p>}
      </div>
    </div>
  );
}
