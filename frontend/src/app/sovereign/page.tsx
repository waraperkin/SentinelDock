import { SovereignAdmin } from '@/components/SovereignAdmin';

export default function SovereignPage() {
  return (
    <div>
      <div className="mb-8">
        <h1 className="text-[26px] font-display font-semibold text-[var(--sd-text-primary)]">SOVEREIGN — RBAC &amp; Tenants</h1>
        <p className="mt-1 text-sm text-[var(--sd-text-secondary)]">
          DB-backed, revocable, role-aware API tokens (admin / analyst / readonly) and optional tenant scoping, layered on top of the
          existing opt-in API_TOKENS env-var auth. Every action below requires an admin-role token — nothing here is open by default.
        </p>
      </div>
      <SovereignAdmin />
    </div>
  );
}
