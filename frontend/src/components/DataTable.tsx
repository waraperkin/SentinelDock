export function DataTable({ title, headers, rows }: { title: string; headers: string[]; rows: React.ReactNode[][] }) {
  return (
    <div className="mb-8">
      <h2 className="text-[13px] font-semibold uppercase tracking-[0.1em] text-[var(--sd-text-secondary)] mb-3">{title}</h2>
      <div className="sd-panel sd-scrollbar overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--sd-border)]">
              {headers.map((h) => (
                <th key={h} className="text-left px-4 py-3 text-[11px] font-semibold uppercase tracking-wide text-[var(--sd-text-muted)]">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={headers.length} className="px-4 py-5 text-[var(--sd-text-muted)] text-sm">
                  No records
                </td>
              </tr>
            )}
            {rows.map((row, i) => (
              <tr key={i} className="border-t border-[var(--sd-border)] hover:bg-[var(--sd-surface-hover)] transition-colors">
                {row.map((cell, j) => (
                  <td key={j} className="px-4 py-2.5 text-[var(--sd-text-primary)]">
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
