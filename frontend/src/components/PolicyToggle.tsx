'use client';

import { useState, useTransition } from 'react';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

/** Enable/disable toggle for one policy — PATCH /policies/:id { enabled }. Used both for reviewing an auto-generated draft policy and for turning any existing policy on/off without leaving the page. */
export function PolicyToggle({ id, initialEnabled }: { id: string; initialEnabled: boolean }) {
  const [enabled, setEnabled] = useState(initialEnabled);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  function toggle() {
    const next = !enabled;
    setError(null);
    startTransition(async () => {
      try {
        const res = await fetch(`${API_URL}/policies/${id}`, {
          method: 'PATCH',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ enabled: next }),
        });
        if (!res.ok) throw new Error(`${res.status}`);
        setEnabled(next);
      } catch {
        setError('Failed to update — check auth if API_TOKENS is configured.');
      }
    });
  }

  return (
    <div className="flex items-center gap-2">
      <button
        onClick={toggle}
        disabled={isPending}
        role="switch"
        aria-checked={enabled}
        className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors disabled:opacity-50"
        style={{ backgroundColor: enabled ? 'var(--sd-accent)' : 'var(--sd-border)' }}
      >
        <span className="inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform" style={{ transform: enabled ? 'translateX(18px)' : 'translateX(3px)' }} />
      </button>
      <span className="text-xs text-[var(--sd-text-muted)]">{isPending ? 'saving…' : enabled ? 'enabled' : 'disabled'}</span>
      {error && <span className="text-[11px] text-[var(--sd-critical,#ef4a5f)]">{error}</span>}
    </div>
  );
}
