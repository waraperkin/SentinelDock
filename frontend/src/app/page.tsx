import Link from 'next/link';
import { apiGet } from '@/lib/api';
import type { DashboardSummary } from '@/types/models';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: JSX.Element;
  accent?: 'default' | 'critical';
  hint?: string;
  href?: string;
}

function StatCard({ label, value, icon, accent = 'default', hint, href }: StatCardProps) {
  const isCritical = accent === 'critical' && Number(value) > 0;
  const content = (
    <div
      className="sd-panel relative overflow-hidden p-5 h-full"
      style={isCritical ? { boxShadow: '0 0 0 1px rgba(239,74,95,0.35), 0 0 32px -8px var(--sd-critical-glow)' } : undefined}
    >
      <div className="flex items-start justify-between">
        <span className="text-[11px] font-medium uppercase tracking-[0.12em] text-[var(--sd-text-muted)]">{label}</span>
        <span className={isCritical ? 'text-[var(--sd-critical)]' : 'text-[var(--sd-text-muted)]'}>{icon}</span>
      </div>
      <div className={`mt-3 font-display text-[34px] leading-none font-semibold sd-mono ${isCritical ? 'text-[var(--sd-critical)]' : 'text-[var(--sd-text-primary)]'}`}>
        {value}
      </div>
      {hint && <div className="mt-2 text-xs text-[var(--sd-text-muted)]">{hint}</div>}
    </div>
  );
  return href ? (
    <Link href={href} className="block transition-opacity hover:opacity-90">
      {content}
    </Link>
  ) : (
    content
  );
}

interface QuickLink {
  href: string;
  label: string;
  description: string;
}

const QUICK_LINKS: QuickLink[] = [
  { href: '/violations', label: 'Violations', description: 'Open policy violations awaiting review' },
  { href: '/attack-paths', label: 'Attack Paths', description: 'Multi-layer traversal graph' },
  { href: '/zero-trust', label: 'Zero Trust', description: 'Per-segment segmentation score' },
  { href: '/titan', label: 'TITAN', description: 'Threat intel, UEBA, EDR, SIEM timeline' },
  { href: '/godmode', label: 'GODMODE', description: 'Simulation, posture, XDR, remediation' },
  { href: '/sovereign', label: 'SOVEREIGN', description: 'RBAC tokens & tenants' },
];

function QuickLinks() {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
      {QUICK_LINKS.map((link) => (
        <Link key={link.href} href={link.href} className="sd-panel p-4 block transition-colors hover:border-[var(--sd-accent)]">
          <div className="text-sm font-medium text-[var(--sd-text-primary)]">{link.label}</div>
          <div className="text-xs text-[var(--sd-text-muted)] mt-1">{link.description}</div>
        </Link>
      ))}
    </div>
  );
}

function IconGrid() {
  return (
    <svg viewBox="0 0 20 20" fill="none" className="h-4 w-4">
      <rect x="2.5" y="2.5" width="6" height="6" rx="1.2" stroke="currentColor" strokeWidth="1.4" />
      <rect x="11.5" y="2.5" width="6" height="6" rx="1.2" stroke="currentColor" strokeWidth="1.4" />
      <rect x="2.5" y="11.5" width="6" height="6" rx="1.2" stroke="currentColor" strokeWidth="1.4" />
      <rect x="11.5" y="11.5" width="6" height="6" rx="1.2" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  );
}
function IconGauge() {
  return (
    <svg viewBox="0 0 20 20" fill="none" className="h-4 w-4">
      <path d="M3 14a7 7 0 1 1 14 0" stroke="currentColor" strokeWidth="1.4" />
      <path d="M10 14 13.5 8.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}
function IconShieldAlert() {
  return (
    <svg viewBox="0 0 20 20" fill="none" className="h-4 w-4">
      <path d="M10 2.5 16 5v5c0 4-2.7 6.6-6 7.5-3.3-.9-6-3.5-6-7.5V5l6-2.5Z" stroke="currentColor" strokeWidth="1.4" />
      <path d="M10 7v4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      <circle cx="10" cy="13.2" r="0.8" fill="currentColor" />
    </svg>
  );
}
function IconFlame() {
  return (
    <svg viewBox="0 0 20 20" fill="none" className="h-4 w-4">
      <path
        d="M10 2.5c1 1.7 2.2 3 3.6 4.4 1.9 1.9 2.9 3.6 2.9 5.6a6.5 6.5 0 1 1-13 0c0-1.5.7-2.8 1.6-4 .4 1 1.2 1.6 2 1.6.2-2.3 1.3-4.3 2.9-7.6Z"
        stroke="currentColor"
        strokeWidth="1.4"
      />
    </svg>
  );
}
function IconServer() {
  return (
    <svg viewBox="0 0 20 20" fill="none" className="h-4 w-4">
      <rect x="3" y="3.5" width="14" height="4.5" rx="1" stroke="currentColor" strokeWidth="1.4" />
      <rect x="3" y="12" width="14" height="4.5" rx="1" stroke="currentColor" strokeWidth="1.4" />
      <circle cx="6" cy="5.75" r="0.7" fill="currentColor" />
      <circle cx="6" cy="14.25" r="0.7" fill="currentColor" />
    </svg>
  );
}
function IconBox() {
  return (
    <svg viewBox="0 0 20 20" fill="none" className="h-4 w-4">
      <path d="M3 6.5 10 3l7 3.5-7 3.5-7-3.5Z" stroke="currentColor" strokeWidth="1.4" />
      <path d="M3 10.5 10 14l7-3.5M3 6.5v8M17 6.5v8" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  );
}
function IconPlug() {
  return (
    <svg viewBox="0 0 20 20" fill="none" className="h-4 w-4">
      <path d="M7 3v5M13 3v5M5 8h10v2a5 5 0 0 1-10 0V8Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <path d="M10 15v2.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}

function riskBand(score: number): { label: string; color: string } {
  if (score >= 70) return { label: 'Critical exposure', color: 'var(--sd-critical)' };
  if (score >= 40) return { label: 'Elevated exposure', color: 'var(--sd-high)' };
  if (score > 0) return { label: 'Moderate exposure', color: 'var(--sd-medium)' };
  return { label: 'No active risk signal', color: 'var(--sd-low)' };
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
    return (
      <div className="sd-panel p-6 text-[var(--sd-critical)] text-sm">
        Unable to reach the control plane API: {error}
      </div>
    );
  }

  const band = riskBand(summary.global_risk_score);

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-[26px] font-display font-semibold text-[var(--sd-text-primary)]">Control Plane Overview</h1>
        <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">Live posture across every discovered asset, service, and network segment.</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
        <StatCard label="Total Assets" value={summary.asset_count} icon={<IconGrid />} href="/inventory" />
        <StatCard label="Global Risk Score" value={summary.global_risk_score} icon={<IconGauge />} hint={band.label} href="/risks" />
        <StatCard label="Open Violations" value={summary.open_violations} icon={<IconShieldAlert />} accent="critical" href="/violations" />
        <StatCard label="Incident Scenarios" value={summary.incident_scenarios} icon={<IconFlame />} accent="critical" href="/incidents" />
      </div>
      <div className="grid grid-cols-3 gap-4 mb-8">
        <StatCard label="Hosts" value={summary.hosts} icon={<IconServer />} href="/inventory" />
        <StatCard label="Containers" value={summary.containers} icon={<IconBox />} href="/inventory" />
        <StatCard label="Services" value={summary.services} icon={<IconPlug />} href="/inventory" />
      </div>

      <h2 className="text-sm font-semibold text-[var(--sd-text-primary)] mb-3">Explore</h2>
      <QuickLinks />
    </div>
  );
}
