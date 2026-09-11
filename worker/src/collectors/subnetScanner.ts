import net from 'node:net';
import dns from 'node:dns/promises';

export interface DiscoveredDevice {
  ip: string;
  hostname: string | null;
  openPorts: number[];
}

const PROBE_PORTS = [22, 80, 443, 445, 3389, 8080, 8443, 9100, 62078, 502, 102, 4840, 47808];
const CONNECT_TIMEOUT_MS = 400;
const MAX_CONCURRENCY = 32;
/** Hard cap on addresses swept per cycle so a /16 or larger CIDR can't stall the worker. */
const MAX_HOSTS_PER_SWEEP = 254;

interface ProbeResult {
  open: boolean;
  /** true if the OS actively refused the connection (ECONNREFUSED) — proves a device answered even with the port closed. */
  hostAlive: boolean;
}

function probePort(ip: string, port: number, timeoutMs = CONNECT_TIMEOUT_MS): Promise<ProbeResult> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (result: ProbeResult) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish({ open: true, hostAlive: true }));
    socket.once('timeout', () => finish({ open: false, hostAlive: false }));
    socket.once('error', (err: NodeJS.ErrnoException) => {
      // ECONNREFUSED means the OS at that IP actively rejected the connection,
      // which only happens if something is listening on the network stack —
      // i.e. the host itself is alive even though this specific port is closed.
      finish({ open: false, hostAlive: err.code === 'ECONNREFUSED' });
    });
    socket.connect(port, ip);
  });
}

export function expandCidrHosts(cidr: string): string[] {
  const [base, prefixStr] = cidr.split('/');
  const prefix = Number(prefixStr ?? 24);
  const octets = base.split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => Number.isNaN(o))) return [];

  const hostBits = 32 - prefix;
  const hostCount = Math.min(2 ** hostBits, MAX_HOSTS_PER_SWEEP + 2);
  if (hostBits > 16 || hostCount <= 2) return []; // refuse to sweep anything larger than a /16-ish range

  const baseInt = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const addresses: string[] = [];
  // Skip network (.0) and broadcast (last) addresses of the range.
  for (let i = 1; i < hostCount - 1 && addresses.length < MAX_HOSTS_PER_SWEEP; i++) {
    const ipInt = (baseInt & (0xffffffff << hostBits)) + i;
    addresses.push([(ipInt >>> 24) & 255, (ipInt >>> 16) & 255, (ipInt >>> 8) & 255, ipInt & 255].join('.'));
  }
  return addresses;
}

async function runWithConcurrency<T, R>(items: T[], limit: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  async function next(): Promise<void> {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await worker(items[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, next));
  return results;
}

/**
 * Real subnet device discovery: TCP-connect sweeps every host address in the
 * given CIDR across a curated port list, bounded to MAX_HOSTS_PER_SWEEP and
 * MAX_CONCURRENCY concurrent probes. A device counts as discovered if any
 * port is open OR the OS actively refused a connection (proving the host
 * itself answered even with every probed port closed).
 *
 * This requires the worker container to actually see the target subnet —
 * on the default Docker bridge network it only reaches other containers.
 * To scan your real LAN, run the worker with `network_mode: host` (see
 * docker-compose.yml and the README for platform caveats).
 */
export async function scanSubnet(cidr: string): Promise<DiscoveredDevice[]> {
  const addresses = expandCidrHosts(cidr);
  if (addresses.length === 0) return [];

  const perHostResults = await runWithConcurrency(addresses, MAX_CONCURRENCY, async (ip) => {
    const probes = await Promise.all(PROBE_PORTS.map((port) => probePort(ip, port).then((r) => ({ port, ...r }))));
    const openPorts = probes.filter((p) => p.open).map((p) => p.port);
    const alive = openPorts.length > 0 || probes.some((p) => p.hostAlive);
    return { ip, alive, openPorts };
  });

  const alive = perHostResults.filter((r) => r.alive);
  const devices = await runWithConcurrency(alive, MAX_CONCURRENCY, async ({ ip, openPorts }) => {
    let hostname: string | null = null;
    try {
      const names = await dns.reverse(ip);
      hostname = names[0] ?? null;
    } catch {
      hostname = null;
    }
    return { ip, hostname, openPorts };
  });

  return devices;
}
