import http from 'node:http';

export interface CloudMetadataResult {
  provider: 'aws' | 'gcp' | 'azure';
  reachable: boolean;
  detail: string;
}

function httpGet(host: string, path: string, headers: Record<string, string>, timeoutMs = 500): Promise<{ status: number; body: string } | null> {
  return new Promise((resolve) => {
    const req = http.request({ host, path, method: 'GET', headers, timeout: timeoutMs }, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
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
 * Checks whether the well-known cloud instance metadata endpoints are
 * reachable from this container/host. This matters for security posture
 * because an application with SSRF (server-side request forgery) can pivot
 * through it to steal instance credentials — a very common real-world
 * cloud attack path (see the 2019 Capital One breach). Reachability alone
 * is the signal that matters here, not the metadata content.
 */
export async function scanCloudMetadata(): Promise<CloudMetadataResult[]> {
  const results: CloudMetadataResult[] = [];

  const aws = await httpGet('169.254.169.254', '/latest/meta-data/', { 'X-aws-ec2-metadata-token-ttl-seconds': '1' });
  if (aws && aws.status > 0) results.push({ provider: 'aws', reachable: true, detail: `HTTP ${aws.status}` });

  const azure = await httpGet('169.254.169.254', '/metadata/instance?api-version=2021-02-01', { Metadata: 'true' });
  if (azure && azure.status > 0 && azure.body.includes('compute')) results.push({ provider: 'azure', reachable: true, detail: `HTTP ${azure.status}` });

  const gcp = await httpGet('metadata.google.internal', '/computeMetadata/v1/', { 'Metadata-Flavor': 'Google' });
  if (gcp && gcp.status > 0) results.push({ provider: 'gcp', reachable: true, detail: `HTTP ${gcp.status}` });

  return results;
}
