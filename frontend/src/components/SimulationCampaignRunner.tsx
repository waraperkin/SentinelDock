'use client';

import { useState } from 'react';
import type { SimulationCampaign } from '@/types/models';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

/**
 * GODMODE+ tier: Attack Simulation Engine trigger — batches the
 * non-destructive Network Sandbox Engine across every current attack
 * path (see backend/src/services/attackSimulationEngine.ts). Same
 * "never touches the real network" guarantee as the single-path
 * simulator.
 */
export function SimulationCampaignRunner({ initial }: { initial: SimulationCampaign[] }) {
  const [campaigns, setCampaigns] = useState(initial);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function runCampaign() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_URL}/simulation/campaigns/run`, { method: 'POST' });
      if (!res.ok) throw new Error(`Campaign run failed: ${res.status}`);
      const body = await res.json();
      if (body?.id) setCampaigns((prev) => [body, ...prev]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Campaign run failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="sd-panel p-5">
      <div className="flex items-center gap-3 flex-wrap mb-4">
        <button
          onClick={runCampaign}
          disabled={loading}
          className="rounded-lg px-4 py-2 text-sm font-medium bg-[var(--sd-accent)] text-[var(--sd-bg-base,#0a0e14)] disabled:opacity-50"
        >
          {loading ? 'Running campaign…' : 'Run full-fleet simulation campaign'}
        </button>
        <span className="text-xs text-[var(--sd-text-muted)]">Simulates every current attack path — still pure computation, never touches the real network.</span>
      </div>
      {error && <p className="text-sm text-[var(--sd-critical,#ef4a5f)] mb-3">{error}</p>}
      <div className="space-y-2">
        {campaigns.slice(0, 5).map((c) => (
          <div key={c.id} className="flex items-center justify-between text-xs border-t border-[var(--sd-border)] pt-2 first:border-0 first:pt-0">
            <span className="text-[var(--sd-text-secondary)]">{c.path_count} path(s) simulated</span>
            <span className="text-[var(--sd-text-muted)]">
              avg {(c.avg_success_probability * 100).toFixed(1)}% · worst-case {(c.max_success_probability * 100).toFixed(1)}%
            </span>
          </div>
        ))}
        {campaigns.length === 0 && <p className="text-xs text-[var(--sd-text-muted)]">No campaigns run yet.</p>}
      </div>
    </div>
  );
}
