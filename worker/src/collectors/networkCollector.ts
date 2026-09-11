import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface CollectedNetworkInterface {
  name: string;
  address: string;
  family: string;
  mac: string;
  internal: boolean;
}

export interface CollectedRoute {
  destination: string;
  gateway: string | null;
  interface: string | null;
  raw: string;
}

export function collectNetworkInterfaces(): CollectedNetworkInterface[] {
  const result: CollectedNetworkInterface[] = [];
  const interfaces = os.networkInterfaces();
  for (const [name, entries] of Object.entries(interfaces)) {
    for (const entry of entries ?? []) {
      result.push({ name, address: entry.address, family: entry.family, mac: entry.mac, internal: entry.internal });
    }
  }
  return result;
}

/**
 * Real route table discovery via `ip route` (iproute2, present in the
 * worker's Alpine image). Falls back to an empty list if the binary is
 * unavailable rather than failing the collection cycle.
 */
export async function collectRoutes(): Promise<CollectedRoute[]> {
  try {
    const { stdout } = await execFileAsync('ip', ['route']);
    return stdout
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const destination = line.split(' ')[0];
        const gateway = line.match(/via (\S+)/)?.[1] ?? null;
        const iface = line.match(/dev (\S+)/)?.[1] ?? null;
        return { destination, gateway, interface: iface, raw: line };
      });
  } catch {
    return [];
  }
}

/**
 * Derives the local subnets this host participates in from its non-internal
 * IPv4 interfaces + CIDR prefix, for use as NetworkSegment discovery input.
 */
export function deriveSubnets(interfaces: CollectedNetworkInterface[]): string[] {
  const subnets = new Set<string>();
  for (const iface of interfaces) {
    if (iface.internal || iface.family !== 'IPv4') continue;
    const octets = iface.address.split('.');
    if (octets.length === 4) subnets.add(`${octets[0]}.${octets[1]}.${octets[2]}.0/24`);
  }
  return Array.from(subnets);
}
