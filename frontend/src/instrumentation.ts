// Forces IPv4-only connections for server-side fetch() calls. Without this,
// undici's Happy Eyeballs dual-stack connector races IPv4/IPv6 against the
// Docker Compose bridge network and reliably reports ECONNREFUSED for
// internal service-name lookups (e.g. http://backend:4000), even though a
// plain IPv4 connection succeeds. Node's --dns-result-order/
// --no-network-family-autoselection CLI flags do not affect this because
// undici configures socket family selection itself rather than deferring to
// Node's net module defaults.
export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const { setGlobalDispatcher, Agent } = await import('undici');
    // `family` is a valid Node net.connect option at runtime; undici's type
    // for `connect` just doesn't model the partial-options case cleanly.
    setGlobalDispatcher(new Agent({ connect: { family: 4 } as any }));
  }
}
