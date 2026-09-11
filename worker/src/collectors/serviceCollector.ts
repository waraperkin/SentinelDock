import net from 'node:net';

export interface CollectedService {
  name: string;
  port: number;
  protocol: 'tcp';
  bind_address: string;
  exposed_publicly: boolean;
}

const COMMON_PORTS: Array<{ port: number; name: string }> = [
  { port: 22, name: 'ssh' },
  { port: 80, name: 'http' },
  { port: 443, name: 'https' },
  { port: 3000, name: 'app' },
  { port: 4000, name: 'sentineldock-backend' },
  { port: 5432, name: 'postgresql' },
  { port: 6379, name: 'redis' },
];

function probePort(host: string, port: number, timeoutMs = 500): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const done = (result: boolean) => {
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.connect(port, host);
  });
}

/** Basic TCP scan of common ports on localhost to detect listening services. */
export async function collectServices(host = '127.0.0.1'): Promise<CollectedService[]> {
  const results: CollectedService[] = [];
  for (const candidate of COMMON_PORTS) {
    const open = await probePort(host, candidate.port);
    if (open) {
      results.push({
        name: candidate.name,
        port: candidate.port,
        protocol: 'tcp',
        bind_address: '0.0.0.0',
        exposed_publicly: candidate.port !== 5432 && candidate.port !== 6379,
      });
    }
  }
  return results;
}
