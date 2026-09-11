'use client';

import { useState, type ReactNode } from 'react';
import { StatusActions } from './StatusActions';

export interface ActionableItem {
  id: string;
  status: string;
  /** Pre-rendered by the server component caller — everything except the action row. Passing a function to render this per-item would cross the server/client boundary illegally, so the caller renders it up front instead. */
  content: ReactNode;
}

interface ActionableListProps {
  initial: ActionableItem[];
  /** Each item's PATCH path is `${pathPrefix}/${item.id}` — a plain string instead of a function, since functions cannot be passed from a Server Component to a Client Component. */
  pathPrefix: string;
  options: Array<{ value: string; label: string }>;
  emptyMessage: string;
  /** When set, an item is removed from view once its status changes away from this value (e.g. "open") rather than merely re-rendered with its new status. */
  hideWhenStatusLeaves?: string;
}

/**
 * Client-side wrapper for any list of "recommendation"-shaped resources
 * (segmentation/hardening recommendations, remediation plans, policy
 * violations) that lets each row's status be changed via StatusActions and
 * reflects the change immediately — removing it from an "open"-filtered
 * list, or just updating its badge otherwise — without a full page
 * reload. The initial data (and each item's rendered content) still comes
 * from the server component that renders this, so the first paint is
 * server-rendered with no client-side data fetch on load.
 */
export function ActionableList({ initial, pathPrefix, options, emptyMessage, hideWhenStatusLeaves }: ActionableListProps) {
  const [items, setItems] = useState(initial);

  function handleChanged(id: string, newStatus: string) {
    if (hideWhenStatusLeaves && newStatus !== hideWhenStatusLeaves) {
      setItems((prev) => prev.filter((i) => i.id !== id));
    } else {
      setItems((prev) => prev.map((i) => (i.id === id ? { ...i, status: newStatus } : i)));
    }
  }

  if (items.length === 0) return <p className="px-5 py-6 text-sm text-[var(--sd-text-muted)]">{emptyMessage}</p>;

  return (
    <>
      {items.map((item) => (
        <div key={item.id} className="px-5 py-3">
          {item.content}
          <div className="mt-2">
            <StatusActions path={`${pathPrefix}/${item.id}`} options={options} currentStatus={item.status} onChanged={(s) => handleChanged(item.id, s)} />
          </div>
        </div>
      ))}
    </>
  );
}
