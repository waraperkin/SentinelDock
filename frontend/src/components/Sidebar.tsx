'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

interface NavItem {
  href: string;
  label: string;
  icon: JSX.Element;
}

function Icon({ children }: { children: React.ReactNode }) {
  return (
    <svg viewBox="0 0 20 20" fill="none" className="h-[18px] w-[18px] shrink-0" xmlns="http://www.w3.org/2000/svg">
      {children}
    </svg>
  );
}

const NAV_ITEMS: NavItem[] = [
  {
    href: '/',
    label: 'Dashboard',
    icon: (
      <Icon>
        <rect x="2.5" y="2.5" width="6.5" height="6.5" rx="1.3" stroke="currentColor" strokeWidth="1.4" />
        <rect x="11" y="2.5" width="6.5" height="6.5" rx="1.3" stroke="currentColor" strokeWidth="1.4" />
        <rect x="2.5" y="11" width="6.5" height="6.5" rx="1.3" stroke="currentColor" strokeWidth="1.4" />
        <rect x="11" y="11" width="6.5" height="6.5" rx="1.3" stroke="currentColor" strokeWidth="1.4" />
      </Icon>
    ),
  },
  {
    href: '/inventory',
    label: 'Inventory',
    icon: (
      <Icon>
        <path d="M3 6.5 10 3l7 3.5-7 3.5-7-3.5Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
        <path d="M3 10.5 10 14l7-3.5M3 6.5v8M17 6.5v8" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      </Icon>
    ),
  },
  {
    href: '/policies',
    label: 'Policies',
    icon: (
      <Icon>
        <path d="M10 2.5 16 5v5c0 4-2.7 6.6-6 7.5-3.3-.9-6-3.5-6-7.5V5l6-2.5Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
        <path d="M7.3 10 9.2 11.8 12.8 8.2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
      </Icon>
    ),
  },
  {
    href: '/violations',
    label: 'Violations',
    icon: (
      <Icon>
        <circle cx="10" cy="10" r="7" stroke="currentColor" strokeWidth="1.4" />
        <path d="M10 6.5v4M10 13v.01" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      </Icon>
    ),
  },
  {
    href: '/risks',
    label: 'Risks',
    icon: (
      <Icon>
        <path d="M10 2.5 17.5 16h-15L10 2.5Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
        <path d="M10 8v3.2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
        <circle cx="10" cy="13.6" r="0.9" fill="currentColor" />
      </Icon>
    ),
  },
  {
    href: '/attack-paths',
    label: 'Attack Paths',
    icon: (
      <Icon>
        <circle cx="4" cy="5" r="1.8" stroke="currentColor" strokeWidth="1.4" />
        <circle cx="16" cy="5" r="1.8" stroke="currentColor" strokeWidth="1.4" />
        <circle cx="10" cy="15" r="1.8" stroke="currentColor" strokeWidth="1.4" />
        <path d="M5.5 6.3 8.7 13.3M14.5 6.3 11.3 13.3M5.8 5h8.4" stroke="currentColor" strokeWidth="1.4" />
      </Icon>
    ),
  },
  {
    href: '/incidents',
    label: 'Incidents',
    icon: (
      <Icon>
        <path
          d="M10 2.5c1 1.7 2.2 3 3.6 4.4 1.9 1.9 2.9 3.6 2.9 5.6a6.5 6.5 0 1 1-13 0c0-1.5.7-2.8 1.6-4 .4 1 1.2 1.6 2 1.6.2-2.3 1.3-4.3 2.9-7.6Z"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinejoin="round"
        />
      </Icon>
    ),
  },
  {
    href: '/secrets',
    label: 'Secrets',
    icon: (
      <Icon>
        <circle cx="7.5" cy="12.5" r="3.2" stroke="currentColor" strokeWidth="1.4" />
        <path d="M9.8 10.2 17 3M14.3 5.7l2 2M16.3 3.7l2 2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      </Icon>
    ),
  },
  {
    href: '/workers',
    label: 'Workers',
    icon: (
      <Icon>
        <rect x="3" y="4" width="14" height="9" rx="1.3" stroke="currentColor" strokeWidth="1.4" />
        <path d="M7 17h6M10 13v4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
        <circle cx="6.5" cy="8.5" r="1" fill="currentColor" />
      </Icon>
    ),
  },
  {
    href: '/zero-trust',
    label: 'Zero Trust',
    icon: (
      <Icon>
        <path d="M10 2.5 16 5v5c0 4-2.7 6.6-6 7.5-3.3-.9-6-3.5-6-7.5V5l6-2.5Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
        <rect x="7.4" y="9" width="5.2" height="4" rx="0.8" stroke="currentColor" strokeWidth="1.3" />
        <path d="M8.4 9V7.6a1.6 1.6 0 0 1 3.2 0V9" stroke="currentColor" strokeWidth="1.3" />
      </Icon>
    ),
  },
  {
    href: '/titan',
    label: 'TITAN',
    icon: (
      <Icon>
        <path d="M10 2.5 3 6.5v5.2c0 3.6 3 6.9 7 8.3 4-1.4 7-4.7 7-8.3V6.5l-7-4Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
        <path d="M7 10.2 9.2 12.4 13.2 8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
      </Icon>
    ),
  },
  {
    href: '/godmode',
    label: 'GODMODE',
    icon: (
      <Icon>
        <circle cx="10" cy="10" r="7" stroke="currentColor" strokeWidth="1.4" />
        <path d="M10 6v4l3 2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="10" cy="10" r="1" fill="currentColor" />
      </Icon>
    ),
  },
  {
    href: '/sovereign',
    label: 'SOVEREIGN',
    icon: (
      <Icon>
        <path d="M10 2.5 3.5 5.5v4.3c0 4 2.8 6.9 6.5 7.7 3.7-.8 6.5-3.7 6.5-7.7V5.5L10 2.5Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
        <path d="M10 6.5v4M10 13v.01" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      </Icon>
    ),
  },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-[232px] shrink-0 border-r border-[var(--sd-border)] bg-[var(--sd-bg-elevated)] flex flex-col">
      <div className="h-16 flex items-center gap-2.5 px-6 border-b border-[var(--sd-border)]">
        <div className="relative h-7 w-7 shrink-0">
          <div className="absolute inset-0 rounded-md bg-[var(--sd-accent)] opacity-20 blur-md" />
          <svg viewBox="0 0 24 24" className="relative h-7 w-7" fill="none">
            <path
              d="M12 2.5 20 6v6c0 5.2-3.5 8.6-8 9.5-4.5-.9-8-4.3-8-9.5V6l8-3.5Z"
              stroke="var(--sd-accent)"
              strokeWidth="1.6"
              strokeLinejoin="round"
            />
            <path d="M8.5 12 11 14.5 15.5 9" stroke="var(--sd-accent)" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
        <span className="font-display font-semibold text-[15px] tracking-tight text-[var(--sd-text-primary)]">SentinelDock</span>
      </div>

      <nav className="flex-1 px-3 py-5 space-y-1">
        {NAV_ITEMS.map((item) => {
          const active = item.href === '/' ? pathname === '/' : pathname?.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                active
                  ? 'bg-[var(--sd-accent-soft)] text-[var(--sd-accent-strong)]'
                  : 'text-[var(--sd-text-secondary)] hover:bg-[var(--sd-surface-hover)] hover:text-[var(--sd-text-primary)]'
              }`}
            >
              <span className={active ? 'text-[var(--sd-accent-strong)]' : 'text-[var(--sd-text-muted)] group-hover:text-[var(--sd-text-secondary)]'}>
                {item.icon}
              </span>
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div className="px-6 py-4 border-t border-[var(--sd-border)]">
        <div className="flex items-center gap-2 text-xs text-[var(--sd-text-muted)]">
          <span className="h-1.5 w-1.5 rounded-full bg-[var(--sd-accent)] sd-live-dot" />
          Control plane online
        </div>
      </div>
    </aside>
  );
}
