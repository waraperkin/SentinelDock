'use client';

import { useState, useTransition } from 'react';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

interface StatusActionsProps {
  /** API path to PATCH, e.g. `/hardening/recommendations/${id}`. */
  path: string;
  /** Each option becomes a button; clicking it PATCHes `{ status: value }`. */
  options: Array<{ value: string; label: string }>;
  currentStatus: string;
  /** Called with the new status after a successful PATCH, so the parent list can remove/update the row without a full page reload. */
  onChanged?: (newStatus: string) => void;
}

/**
 * Generic status-action button row for the recommendation-style resources
 * across the platform (segmentation/hardening recommendations, remediation
 * plans, policy violations) — they all share the same shape (a `status`
 * field, mutated via `PATCH { status }`), so this one component drives all
 * of them instead of duplicating the same fetch-and-refresh logic per page.
 */
export function StatusActions({ path, options, currentStatus, onChanged }: StatusActionsProps) {
  const [status, setStatus] = useState(currentStatus);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  function apply(value: string) {
    setError(null);
    startTransition(async () => {
      try {
        const res = await fetch(`${API_URL}${path}`, {
          method: 'PATCH',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ status: value }),
        });
        if (!res.ok) throw new Error(`${res.status}`);
        setStatus(value);
        onChanged?.(value);
      } catch {
        setError('Failed to update — check auth if API_TOKENS is configured.');
      }
    });
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      {options
        .filter((o) => o.value !== status)
        .map((o) => (
          <button
            key={o.value}
            onClick={() => apply(o.value)}
            disabled={isPending}
            className="rounded-md px-2.5 py-1 text-[11px] font-medium border border-[var(--sd-border)] text-[var(--sd-text-secondary)] hover:text-[var(--sd-text-primary)] hover:border-[var(--sd-accent)] disabled:opacity-50 transition-colors"
          >
            {isPending ? '…' : o.label}
          </button>
        ))}
      {error && <span className="text-[11px] text-[var(--sd-critical,#ef4a5f)]">{error}</span>}
    </div>
  );
}
