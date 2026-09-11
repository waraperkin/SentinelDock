// Server Components run inside the Docker network and must reach the
// backend by its service name; the browser reaches it via the published
// port through NEXT_PUBLIC_API_URL. API_INTERNAL_URL is server-only (not
// prefixed with NEXT_PUBLIC_) and takes precedence when set.
const BASE_URL = (typeof window === 'undefined' ? process.env.API_INTERNAL_URL : undefined) ?? process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`);
  return (await res.json()) as T;
}
