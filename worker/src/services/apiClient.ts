const BASE_URL = process.env.BACKEND_API_URL ?? 'http://localhost:4000';
// Only needed when the backend has API_TOKENS configured (auth is opt-in
// and off by default — see backend/src/middleware/auth.ts).
const API_TOKEN = process.env.WORKER_API_TOKEN;

async function request<T>(path: string, method: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (API_TOKEN) headers.authorization = `Bearer ${API_TOKEN}`;

  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: Object.keys(headers).length > 0 ? headers : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${method} ${path} -> ${res.status}: ${text}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const backendApi = {
  upsertHost: (host: Record<string, unknown>) => request('/assets/hosts', 'POST', host),
  patchHost: (id: string, patch: Record<string, unknown>) => request(`/assets/hosts/${id}`, 'PATCH', patch),
  upsertContainer: (container: Record<string, unknown>) => request('/assets/containers', 'POST', container),
  upsertService: (service: Record<string, unknown>) => request('/assets/services', 'POST', service),
  upsertNetworkSegment: (segment: Record<string, unknown>) => request('/assets/network', 'POST', segment),
  submitConfigSnapshot: (snapshot: Record<string, unknown>) => request('/configs', 'POST', snapshot),
  submitSecretFindings: (findings: Array<Record<string, unknown>>) => request('/secrets', 'POST', { findings }),
  heartbeat: (payload: Record<string, unknown>) => request('/workers/heartbeat', 'POST', payload),
  listWorkers: () => request<Array<{ worker_id: string; online: boolean }>>('/workers', 'GET'),
  triggerEvaluation: () => request('/policies/evaluate', 'POST'),
  triggerDistributedEvaluation: () => request('/policies/evaluate/distributed', 'POST'),
  autoGeneratePolicies: () => request('/policies/auto-generate', 'POST'),
};
