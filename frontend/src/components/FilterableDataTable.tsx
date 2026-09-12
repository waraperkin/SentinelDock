'use client';

import { useMemo, useState } from 'react';
import { DataTable } from './DataTable';

interface FilterableRow {
  /** Plain-text representation of the row, precomputed by the server caller, used only for matching against the search box — the actual rendered cells can be arbitrary ReactNode. */
  searchText: string;
  cells: React.ReactNode[];
}

/**
 * DataTable with a client-side search box. Row content is often rendered
 * ReactNode (badges, links), which can't be searched by reading React
 * state directly, so the caller precomputes one plain-text `searchText`
 * string per row (server-side, before this client component ever
 * mounts) and this just filters against it.
 */
export function FilterableDataTable({ title, headers, rows, placeholder }: { title: string; headers: string[]; rows: FilterableRow[]; placeholder?: string }) {
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    if (!query.trim()) return rows;
    const needle = query.trim().toLowerCase();
    return rows.filter((r) => r.searchText.toLowerCase().includes(needle));
  }, [rows, query]);

  return (
    <div className="mb-8">
      <div className="flex items-center justify-between gap-4 mb-3">
        <h2 className="text-[13px] font-semibold uppercase tracking-[0.1em] text-[var(--sd-text-secondary)]">
          {title} {query.trim() && <span className="text-[var(--sd-text-muted)] normal-case font-normal">({filtered.length} matching)</span>}
        </h2>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={placeholder ?? 'Filter…'}
          className="w-64 max-w-full bg-[var(--sd-bg-elevated)] border border-[var(--sd-border)] rounded-lg px-3 py-1.5 text-sm text-[var(--sd-text-primary)] placeholder:text-[var(--sd-text-muted)] outline-none focus:border-[var(--sd-accent)]"
        />
      </div>
      <DataTable title="" headers={headers} rows={filtered.map((r) => r.cells)} hideTitle />
    </div>
  );
}
