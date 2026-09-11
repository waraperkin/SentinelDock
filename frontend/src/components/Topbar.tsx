export function Topbar() {
  return (
    <header className="h-16 shrink-0 border-b border-[var(--sd-border)] bg-[var(--sd-bg)]/80 backdrop-blur-sm flex items-center justify-between px-8">
      <div className="text-xs font-medium tracking-[0.14em] uppercase text-[var(--sd-text-muted)]">Unified Infra &amp; Security Control Plane</div>
      <div className="flex items-center gap-4">
        <span className="text-xs text-[var(--sd-text-muted)] sd-mono">v0.1.0</span>
        <div className="h-8 w-8 rounded-full bg-gradient-to-br from-[var(--sd-accent)] to-[var(--sd-critical)] opacity-90" />
      </div>
    </header>
  );
}
