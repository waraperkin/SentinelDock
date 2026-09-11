import http from 'node:http';

export interface HttpReconResult {
  finding: 'jenkins' | 'git-exposed';
  detail: string;
}

function httpGet(ip: string, port: number, path: string, timeoutMs = 600): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string } | null> {
  return new Promise((resolve) => {
    const req = http.request({ host: ip, port, path, method: 'GET', timeout: timeoutMs }, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        if (body.length < 4096) body += chunk;
      });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    req.on('error', () => resolve(null));
    req.end();
  });
}

/**
 * Real HTTP-layer recon against a discovered web port: identifies Jenkins
 * by its distinctive `X-Jenkins` response header (present on virtually
 * every Jenkins HTTP response, including 403s, so it doesn't require
 * authentication to detect), and checks for an exposed `.git/HEAD` — a
 * classic, extremely common misconfiguration that leaks full source
 * repository history when a web root is a git checkout.
 */
export async function httpRecon(ip: string, port: number): Promise<HttpReconResult[]> {
  const results: HttpReconResult[] = [];

  const root = await httpGet(ip, port, '/');
  if (root?.headers['x-jenkins']) {
    results.push({ finding: 'jenkins', detail: `X-Jenkins: ${root.headers['x-jenkins']}` });
  }

  const gitHead = await httpGet(ip, port, '/.git/HEAD');
  if (gitHead && gitHead.status === 200 && gitHead.body.trim().startsWith('ref:')) {
    results.push({ finding: 'git-exposed', detail: gitHead.body.trim() });
  }

  return results;
}
