'use client';

import { useState } from 'react';
import type { Tenant, AuthToken, Role } from '@/types/models';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

/**
 * GODMODE+ tier: SOVEREIGN Engine admin console. Every action here calls
 * a /sovereign/* route that requires an admin-role bearer token (see
 * backend/src/services/rbac.ts's requireRole, which is strict — unlike
 * the rest of this platform's opt-in auth). The token is kept only in
 * this component's in-memory state for the current browser session — it
 * is never persisted (no localStorage/cookie) and is sent solely as the
 * Authorization header on these calls.
 */
export function SovereignAdmin() {
  const [adminToken, setAdminToken] = useState('');
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tokens, setTokens] = useState<AuthToken[]>([]);
  const [newestToken, setNewestToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tenantName, setTenantName] = useState('');
  const [tenantSlug, setTenantSlug] = useState('');
  const [tokenName, setTokenName] = useState('');
  const [tokenRole, setTokenRole] = useState<Role>('readonly');
  const [tokenTenantId, setTokenTenantId] = useState('');

  async function authedFetch(path: string, init?: RequestInit) {
    const res = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: { ...(init?.headers ?? {}), authorization: `Bearer ${adminToken}` },
    });
    if (!res.ok) throw new Error(`${path} -> ${res.status}`);
    return res.status === 204 ? null : res.json();
  }

  async function refresh() {
    setError(null);
    try {
      setTenants(await authedFetch('/sovereign/tenants'));
      setTokens(await authedFetch('/sovereign/tokens'));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load — check the admin token');
    }
  }

  async function createTenant() {
    if (!tenantName || !tenantSlug) return;
    setError(null);
    try {
      await authedFetch('/sovereign/tenants', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: tenantName, slug: tenantSlug }) });
      setTenantName('');
      setTenantSlug('');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create tenant');
    }
  }

  async function createToken() {
    if (!tokenName) return;
    setError(null);
    try {
      const created = await authedFetch('/sovereign/tokens', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: tokenName, role: tokenRole, tenant_id: tokenTenantId || null }),
      });
      setNewestToken(created.token);
      setTokenName('');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create token');
    }
  }

  async function revokeToken(id: string) {
    setError(null);
    try {
      await authedFetch(`/sovereign/tokens/${id}`, { method: 'DELETE' });
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke token');
    }
  }

  return (
    <div className="space-y-6">
      <div className="sd-panel p-5">
        <label className="block text-xs font-semibold text-[var(--sd-text-muted)] uppercase tracking-wide mb-2">Admin bearer token</label>
        <div className="flex items-center gap-3">
          <input
            type="password"
            value={adminToken}
            onChange={(e) => setAdminToken(e.target.value)}
            placeholder="Env-var API_TOKENS admin token, or an existing SOVEREIGN admin token"
            className="flex-1 bg-[var(--sd-bg-elevated)] border border-[var(--sd-border)] rounded-lg px-3 py-2 text-sm text-[var(--sd-text-primary)]"
          />
          <button onClick={refresh} disabled={!adminToken} className="rounded-lg px-4 py-2 text-sm font-medium bg-[var(--sd-accent)] text-[var(--sd-bg-base,#0a0e14)] disabled:opacity-50">
            Load
          </button>
        </div>
        <p className="mt-2 text-xs text-[var(--sd-text-muted)]">Kept only in this browser tab&apos;s memory — never stored or sent anywhere else.</p>
        {error && <p className="mt-2 text-sm text-[var(--sd-critical,#ef4a5f)]">{error}</p>}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="sd-panel p-5">
          <h3 className="text-xs font-semibold text-[var(--sd-text-muted)] uppercase tracking-wide mb-3">Tenants</h3>
          <div className="flex items-center gap-2 mb-3">
            <input value={tenantName} onChange={(e) => setTenantName(e.target.value)} placeholder="Name" className="flex-1 bg-[var(--sd-bg-elevated)] border border-[var(--sd-border)] rounded-lg px-2 py-1.5 text-sm text-[var(--sd-text-primary)]" />
            <input value={tenantSlug} onChange={(e) => setTenantSlug(e.target.value)} placeholder="slug" className="w-28 bg-[var(--sd-bg-elevated)] border border-[var(--sd-border)] rounded-lg px-2 py-1.5 text-sm text-[var(--sd-text-primary)]" />
            <button onClick={createTenant} className="rounded-lg px-3 py-1.5 text-xs font-medium bg-[var(--sd-accent)] text-[var(--sd-bg-base,#0a0e14)]">Create</button>
          </div>
          <div className="space-y-1.5">
            {tenants.map((t) => (
              <div key={t.id} className="text-sm text-[var(--sd-text-secondary)] flex items-center justify-between">
                <span>{t.name}</span>
                <span className="text-xs text-[var(--sd-text-muted)] sd-mono">{t.slug}</span>
              </div>
            ))}
            {tenants.length === 0 && <p className="text-xs text-[var(--sd-text-muted)]">No tenants loaded.</p>}
          </div>
        </div>

        <div className="sd-panel p-5">
          <h3 className="text-xs font-semibold text-[var(--sd-text-muted)] uppercase tracking-wide mb-3">RBAC tokens</h3>
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <input value={tokenName} onChange={(e) => setTokenName(e.target.value)} placeholder="Token name" className="flex-1 bg-[var(--sd-bg-elevated)] border border-[var(--sd-border)] rounded-lg px-2 py-1.5 text-sm text-[var(--sd-text-primary)]" />
            <select value={tokenRole} onChange={(e) => setTokenRole(e.target.value as Role)} className="bg-[var(--sd-bg-elevated)] border border-[var(--sd-border)] rounded-lg px-2 py-1.5 text-sm text-[var(--sd-text-primary)]">
              <option value="readonly">readonly</option>
              <option value="analyst">analyst</option>
              <option value="admin">admin</option>
            </select>
            <select value={tokenTenantId} onChange={(e) => setTokenTenantId(e.target.value)} className="bg-[var(--sd-bg-elevated)] border border-[var(--sd-border)] rounded-lg px-2 py-1.5 text-sm text-[var(--sd-text-primary)]">
              <option value="">no tenant (global)</option>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
            <button onClick={createToken} className="rounded-lg px-3 py-1.5 text-xs font-medium bg-[var(--sd-accent)] text-[var(--sd-bg-base,#0a0e14)]">Create</button>
          </div>
          {newestToken && (
            <p className="text-xs text-[var(--sd-accent-strong,#22d3c8)] mb-3 break-all">
              New token (shown once): <span className="sd-mono">{newestToken}</span>
            </p>
          )}
          <div className="space-y-1.5">
            {tokens.map((t) => (
              <div key={t.id} className="text-sm text-[var(--sd-text-secondary)] flex items-center justify-between gap-2">
                <span className="truncate">{t.name} <span className="text-xs text-[var(--sd-text-muted)]">({t.role})</span></span>
                {t.revoked_at ? (
                  <span className="text-xs text-[var(--sd-text-muted)]">revoked</span>
                ) : (
                  <button onClick={() => revokeToken(t.id)} className="text-xs text-[var(--sd-critical,#ef4a5f)]">Revoke</button>
                )}
              </div>
            ))}
            {tokens.length === 0 && <p className="text-xs text-[var(--sd-text-muted)]">No tokens loaded.</p>}
          </div>
        </div>
      </div>
    </div>
  );
}
