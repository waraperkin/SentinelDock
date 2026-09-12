/** Shown by Next.js while a page's server-side data fetches (most pages await several Promise.all'd apiGet calls) are in flight, instead of a blank white flash between navigations. */
export default function Loading() {
  return (
    <div>
      <div className="mb-8">
        <div className="h-7 w-56 rounded-md bg-[var(--sd-surface-hover)] animate-pulse" />
        <div className="mt-2 h-4 w-96 max-w-full rounded-md bg-[var(--sd-surface-hover)] animate-pulse" />
      </div>
      <div className="space-y-3">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="sd-panel p-5">
            <div className="h-4 w-1/3 rounded bg-[var(--sd-surface-hover)] animate-pulse" />
            <div className="mt-3 h-3 w-2/3 rounded bg-[var(--sd-surface-hover)] animate-pulse" />
          </div>
        ))}
      </div>
    </div>
  );
}
