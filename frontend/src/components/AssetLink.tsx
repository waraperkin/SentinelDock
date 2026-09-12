import Link from 'next/link';

/**
 * Renders an `asset_type:asset_id` reference — the shape risks,
 * violations, TI matches, etc. all use to point at an asset. Hosts get a
 * real link to their detail page; other asset types (service, container,
 * network) don't have a dedicated detail page yet, so they render as
 * plain text rather than a dead link.
 */
export function AssetLink({ assetType, assetId, className }: { assetType: string; assetId: string; className?: string }) {
  if (assetType === 'host') {
    return (
      <Link href={`/inventory/hosts/${assetId}`} className={className ?? 'sd-mono text-[var(--sd-accent)] hover:underline'}>
        {assetType}:{assetId}
      </Link>
    );
  }
  // Strip color/hover cues from a passed className for the non-link case
  // (nothing here is clickable), while still honoring layout utilities
  // (margins, text size) the caller included alongside them.
  const layoutOnly = className
    ?.split(' ')
    .filter((cls) => !/^(text-\[|hover:|text-accent)/.test(cls))
    .join(' ');
  return (
    <span className={`sd-mono text-[var(--sd-text-muted)] ${layoutOnly ?? ''}`}>
      {assetType}:{assetId}
    </span>
  );
}
