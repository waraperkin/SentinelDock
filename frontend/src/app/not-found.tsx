import Link from 'next/link';

/** Styled 404 — replaces Next.js's default unstyled not-found page. Renders inside the Sidebar/Topbar layout, so navigation stays available (e.g. after clicking `notFound()` on a deleted host in /inventory/hosts/[id]). */
export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <div className="sd-panel p-8 max-w-md">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-[var(--sd-accent-soft)]">
          <svg viewBox="0 0 20 20" fill="none" className="h-6 w-6 text-[var(--sd-accent)]">
            <circle cx="8.5" cy="8.5" r="5.5" stroke="currentColor" strokeWidth="1.4" />
            <path d="m16 16-3.2-3.2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
          </svg>
        </div>
        <h1 className="text-lg font-display font-semibold text-[var(--sd-text-primary)]">Not found</h1>
        <p className="mt-2 text-sm text-[var(--sd-text-secondary)]">
          This asset or page doesn&apos;t exist — it may have been removed, or the link is stale.
        </p>
        <Link
          href="/"
          className="mt-5 inline-block rounded-lg px-4 py-2 text-sm font-medium bg-[var(--sd-accent)] text-[var(--sd-bg,#06090f)] hover:brightness-110 transition"
        >
          Back to Dashboard
        </Link>
      </div>
    </div>
  );
}
