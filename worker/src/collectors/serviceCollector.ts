import net from 'node:net';

export interface CollectedService {
  name: string;
  port: number;
  protocol: 'tcp';
  bind_address: string;
  banner: string | null;
  version: string | null;
  exposed_publicly: boolean;
}

const COMMON_PORTS: Array<{ port: number; name: string }> = [
  { port: 21, name: 'ftp' },
  { port: 22, name: 'ssh' },
  { port: 23, name: 'telnet' },
  { port: 80, name: 'http' },
  { port: 443, name: 'https' },
  { port: 2375, name: 'docker' },
  { port: 2376, name: 'docker' },
  { port: 3000, name: 'app' },
  { port: 3306, name: 'mysql' },
  { port: 3389, name: 'rdp' },
  { port: 4000, name: 'sentineldock-backend' },
  { port: 5432, name: 'postgres' },
  { port: 6379, name: 'redis' },
  { port: 9200, name: 'elasticsearch' },
  { port: 27017, name: 'mongo' },
];

/** Extracts a version string from a service banner using per-service heuristics. */
function extractVersion(name: string, banner: string): string | null {
  if (name === 'ssh') return banner.match(/SSH-[\d.]+-OpenSSH_([\d.]+)/i)?.[1] ?? banner.match(/OpenSSH[_ ]([\d.]+)/i)?.[1] ?? null;
  if (name === 'redis') return banner.match(/redis_version:([\d.]+)/i)?.[1] ?? null;
  if (name === 'ftp') return banner.match(/FTP server \(([^)]+)\)/i)?.[1] ?? null;
  if (name === 'postgres') return banner.match(/PostgreSQL ([\d.]+)/i)?.[1] ?? null;
  const generic = banner.match(/(\d+\.\d+(\.\d+)?)/);
  return generic?.[1] ?? null;
}

function connectAndReadBanner(host: string, port: number, timeoutMs = 700): Promise<string | null> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let data = '';
    let settled = false;
    const finish = (result: string | null) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      // Most banner-emitting protocols (SSH, FTP, SMTP) send their banner
      // unprompted right after connect; give it a short window to arrive.
      setTimeout(() => finish(data.length > 0 ? data.trim() : null), 300);
    });
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
    });
    socket.once('timeout', () => finish(data.length > 0 ? data.trim() : null));
    socket.once('error', () => finish(null));
    socket.connect(port, host);
  });
}

/**
 * Real TCP service discovery: probes a curated port list on the given host,
 * grabs whatever banner the service offers unprompted, and extracts a
 * version string + classifies the service from the banner content (not
 * just the port number, since a banner-mismatched port should still be
 * classified correctly).
 */
export async function collectServices(host = '127.0.0.1'): Promise<CollectedService[]> {
  const results: CollectedService[] = [];

  for (const candidate of COMMON_PORTS) {
    const banner = await connectAndReadBanner(host, candidate.port);
    const socketOpened = banner !== null || (await isPortOpen(host, candidate.port));
    if (!socketOpened) continue;

    const name = classifyFromBanner(banner) ?? candidate.name;
    const version = banner ? extractVersion(name, banner) : null;

    results.push({
      name,
      port: candidate.port,
      protocol: 'tcp',
      bind_address: '0.0.0.0',
      banner,
      version,
      // Anything reachable on 0.0.0.0 from outside the collecting
      // container's own namespace counts as publicly exposed in this
      // model — policies then judge whether that exposure is acceptable
      // for the specific port/service (e.g. a database never is).
      exposed_publicly: true,
    });
  }

  return results;
}

function classifyFromBanner(banner: string | null): string | null {
  if (!banner) return null;
  if (/^SSH-/.test(banner)) return 'ssh';
  if (/^220.*FTP/i.test(banner)) return 'ftp';
  if (/redis_version/i.test(banner)) return 'redis';
  if (/^HTTP\//.test(banner)) return 'http';
  return null;
}

function isPortOpen(host: string, port: number, timeoutMs = 400): Promise<boolean> {
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
