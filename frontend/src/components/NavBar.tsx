import Link from 'next/link';

const LINKS = [
  { href: '/', label: 'Dashboard' },
  { href: '/inventory', label: 'Inventory' },
  { href: '/policies', label: 'Policies' },
  { href: '/risks', label: 'Risks' },
  { href: '/attack-paths', label: 'Attack Paths' },
  { href: '/incidents', label: 'Incidents' },
];

export function NavBar() {
  return (
    <nav className="border-b border-slate-800 bg-slate-950 px-6 py-3 flex items-center gap-6">
      <span className="font-bold text-lg text-white">SentinelDock</span>
      {LINKS.map((link) => (
        <Link key={link.href} href={link.href} className="text-slate-300 hover:text-white text-sm">
          {link.label}
        </Link>
      ))}
    </nav>
  );
}
