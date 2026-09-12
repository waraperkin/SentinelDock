'use client';

/**
 * Global error boundary for the app router. Without this, any uncaught
 * exception in a page (like the RSC serialization crash on /violations,
 * /titan, /godmode found earlier, or the /workers render crash) falls
 * through to Next.js's raw unstyled "Application error" page — jarring
 * and looks like the whole app is broken rather than one page hitting a
 * real bug. This renders inside the existing Sidebar/Topbar layout, so
 * navigation still works, and offers a retry.
 */
export default function GlobalError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <div className="sd-panel p-8 max-w-lg">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full" style={{ backgroundColor: 'rgba(239,74,95,0.14)' }}>
          <svg viewBox="0 0 20 20" fill="none" className="h-6 w-6 text-[var(--sd-critical)]">
            <path d="M10 2.5 17.5 16h-15L10 2.5Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
            <path d="M10 8v3.2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
            <circle cx="10" cy="13.6" r="0.9" fill="currentColor" />
          </svg>
        </div>
        <h1 className="text-lg font-display font-semibold text-[var(--sd-text-primary)]">This page hit an error</h1>
        <p className="mt-2 text-sm text-[var(--sd-text-secondary)]">
          Something went wrong rendering this view. The rest of the app is unaffected — try again, or navigate elsewhere from the sidebar.
        </p>
        {error.message && (
          <pre className="mt-4 text-left text-xs text-[var(--sd-text-muted)] sd-mono whitespace-pre-wrap break-all bg-[var(--sd-bg-elevated)] rounded-lg p-3 border border-[var(--sd-border)]">
            {error.message}
          </pre>
        )}
        <button
          onClick={reset}
          className="mt-5 rounded-lg px-4 py-2 text-sm font-medium bg-[var(--sd-accent)] text-[var(--sd-bg,#06090f)] hover:brightness-110 transition"
        >
          Try again
        </button>
      </div>
    </div>
  );
}
