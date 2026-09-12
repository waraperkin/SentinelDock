'use client';

import { useMemo, useState, type ReactNode } from 'react';

interface SearchableItem {
  id: string;
  severity: string;
  searchText: string;
  content: ReactNode;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low'];

/**
 * Client-side search + severity filter over a list of pre-rendered cards.
 * Like ActionableList/FilterableDataTable, content is rendered server-side
 * and passed in as ReactNode (functions can't cross the server/client
 * boundary) — this component only manages the filtering.
 */
export function SearchableList({
  items,
  placeholder,
  emptyMessage,
  resultsClassName,
}: {
  items: SearchableItem[];
  placeholder?: string;
  emptyMessage: string;
  /** Applied to the results container — e.g. the timeline-line pseudo-element classes on Incidents, which need to wrap every visible item together. */
  resultsClassName?: string;
}) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');

  const filtered = useMemo(() => {
    return items.filter((item) => {
      if (severity && item.severity !== severity) return false;
      if (query.trim() && !item.searchText.toLowerCase().includes(query.trim().toLowerCase())) return false;
      return true;
    });
  }, [items, query, severity]);

  return (
    <div>
      <div className="flex items-center gap-3 mb-5 flex-wrap">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={placeholder ?? 'Search…'}
          className="w-72 max-w-full bg-[var(--sd-bg-elevated)] border border-[var(--sd-border)] rounded-lg px-3 py-2 text-sm text-[var(--sd-text-primary)] placeholder:text-[var(--sd-text-muted)] outline-none focus:border-[var(--sd-accent)]"
        />
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="bg-[var(--sd-bg-elevated)] border border-[var(--sd-border)] rounded-lg px-3 py-2 text-sm text-[var(--sd-text-primary)] outline-none focus:border-[var(--sd-accent)]"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        {(query.trim() || severity) && (
          <span className="text-xs text-[var(--sd-text-muted)]">
            {filtered.length} of {items.length}
          </span>
        )}
      </div>
      {filtered.length === 0 ? (
        <p className="text-[var(--sd-text-muted)] text-sm">{emptyMessage}</p>
      ) : (
        <div className={resultsClassName}>
          {filtered.map((item) => (
            <div key={item.id}>{item.content}</div>
          ))}
        </div>
      )}
    </div>
  );
}
