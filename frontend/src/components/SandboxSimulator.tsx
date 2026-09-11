'use client';

import { useState } from 'react';
import type { AttackPath, SandboxSimulation } from '@/types/models';
import { SeverityBadge } from './SeverityBadge';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

/**
 * Client-side trigger for the Network Sandbox Engine — calls
 * POST /sandbox/simulate/:attackPathId, which is pure computation over an
 * already-persisted attack path (see backend/src/services/sandboxEngine.ts).
 * Never sends a real network packet.
 */
export function SandboxSimulator({ paths }: { paths: AttackPath[] }) {
  const [selectedId, setSelectedId] = useState(paths[0]?.id ?? '');
  const [result, setResult] = useState<SandboxSimulation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function runSimulation() {
    if (!selectedId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_URL}/sandbox/simulate/${selectedId}`, { method: 'POST' });
      if (!res.ok) throw new Error(`Simulation failed: ${res.status}`);
      setResult(await res.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Simulation failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="sd-panel p-5">
      <div className="flex items-center gap-3 flex-wrap">
        <select
          value={selectedId}
          onChange={(e) => setSelectedId(e.target.value)}
          className="bg-[var(--sd-bg-elevated)] border border-[var(--sd-border)] rounded-lg px-3 py-2 text-sm text-[var(--sd-text-primary)]"
        >
          {paths.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        <button
          onClick={runSimulation}
          disabled={loading || !selectedId}
          className="rounded-lg px-4 py-2 text-sm font-medium bg-[var(--sd-accent)] text-[var(--sd-bg-base,#0a0e14)] disabled:opacity-50"
        >
          {loading ? 'Simulating…' : 'Run non-destructive simulation'}
        </button>
        <span className="text-xs text-[var(--sd-text-muted)]">Pure computation over stored data — never touches the real network.</span>
      </div>

      {error && <p className="mt-4 text-sm text-[var(--sd-critical,#ef4a5f)]">{error}</p>}

      {result && (
        <div className="mt-5 pt-5 border-t border-[var(--sd-border)]">
          <div className="flex items-center gap-3 mb-3">
            <span className="text-sm font-semibold text-[var(--sd-text-primary)]">
              Overall success probability: {(result.overall_success_probability * 100).toFixed(1)}%
            </span>
            <span className="text-xs text-[var(--sd-text-muted)]">{result.hops_compromised} hop(s) modeled as compromised</span>
          </div>
          <ol className="space-y-2">
            {result.steps.map((step) => (
              <li key={step.hop_index} className="flex items-center gap-3 text-xs">
                <span className="text-[var(--sd-accent)] shrink-0">{step.hop_index + 1}.</span>
                <span className="sd-mono text-[var(--sd-text-secondary)] truncate">
                  {step.via} → {step.asset_type}:{step.asset_id}
                </span>
                <span className="text-[var(--sd-text-muted)] shrink-0">
                  step {(step.success_probability * 100).toFixed(0)}% · cumulative {(step.cumulative_probability * 100).toFixed(1)}%
                </span>
                {step.compromised ? <SeverityBadge severity="high" /> : <SeverityBadge severity="low" />}
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}
