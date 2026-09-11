import http from 'node:http';

export interface CollectedContainer {
  id: string;
  name: string;
  image: string;
  status: 'running' | 'stopped' | 'paused';
  ports: Array<{ container: number; host: number; protocol: 'tcp' | 'udp' }>;
  privileged: boolean;
}

const DOCKER_SOCKET = process.env.DOCKER_SOCKET_PATH ?? '/var/run/docker.sock';

function dockerRequest<T>(path: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const req = http.request({ socketPath: DOCKER_SOCKET, path, method: 'GET' }, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        if ((res.statusCode ?? 500) >= 400) return reject(new Error(`Docker API ${path} -> ${res.statusCode}`));
        try {
          resolve(JSON.parse(body) as T);
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

interface DockerApiContainer {
  Id: string;
  Names: string[];
  Image: string;
  State: string;
  HostConfig?: { Privileged?: boolean };
  Ports: Array<{ PrivatePort: number; PublicPort?: number; Type: string }>;
}

/**
 * Collects running containers via the Docker Engine API over the unix
 * socket. Falls back to an empty list (mock mode) if the socket is not
 * reachable, e.g. when the worker runs without Docker access.
 */
export async function collectContainers(): Promise<CollectedContainer[]> {
  try {
    const containers = await dockerRequest<DockerApiContainer[]>('/containers/json?all=true');
    return containers.map((c) => ({
      id: c.Id,
      name: (c.Names[0] ?? c.Id).replace(/^\//, ''),
      image: c.Image,
      status: c.State === 'running' ? 'running' : c.State === 'paused' ? 'paused' : 'stopped',
      ports: (c.Ports ?? [])
        .filter((p) => p.PublicPort)
        .map((p) => ({ container: p.PrivatePort, host: p.PublicPort as number, protocol: (p.Type as 'tcp' | 'udp') ?? 'tcp' })),
      privileged: Boolean(c.HostConfig?.Privileged),
    }));
  } catch {
    return [];
  }
}
