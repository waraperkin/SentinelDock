const BASE_URL = process.env.BACKEND_API_URL ?? 'http://localhost:4000';

async function request<T>(path: string, method: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
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
  upsertContainer: (container: Record<string, unknown>) => request('/assets/containers', 'POST', container),
  upsertService: (service: Record<string, unknown>) => request('/assets/services', 'POST', service),
  submitConfigSnapshot: (snapshot: Record<string, unknown>) => request('/configs', 'POST', snapshot),
  triggerEvaluation: () => request('/policies/evaluate', 'POST'),
};
