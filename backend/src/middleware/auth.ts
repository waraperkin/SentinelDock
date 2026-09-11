import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

declare module 'fastify' {
  interface FastifyRequest {
    actor?: string;
  }
}

/**
 * Minimal API token auth: opt-in via the API_TOKENS env var
 * (comma-separated bearer tokens, optionally "name:token" pairs to give
 * each token an identity for the audit log). When unset (the default),
 * no enforcement happens — this keeps the default docker-compose flow
 * working without requiring every internal caller (the worker) to be
 * configured with a token out of the box.
 *
 * This is a real, testable auth primitive — not a full multi-tenant RBAC
 * system. There is no per-resource authorization, only "does this request
 * carry a known token". Full RBAC (roles, tenants, scoped permissions)
 * would need a much larger identity/session model and is out of scope
 * for this iteration.
 */
const MUTATING_METHODS = new Set(['POST', 'PATCH', 'PUT', 'DELETE']);

function parseTokens(raw: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const entry of raw.split(',').map((s) => s.trim()).filter(Boolean)) {
    const [maybeName, maybeToken] = entry.split(':');
    if (maybeToken) map.set(maybeToken, maybeName);
    else map.set(maybeName, 'api-token');
  }
  return map;
}

export function registerAuth(app: FastifyInstance): void {
  const rawTokens = process.env.API_TOKENS ?? '';
  if (!rawTokens.trim()) {
    app.log.info('API_TOKENS not set — running without API authentication (default local-dev mode)');
    return;
  }
  const tokens = parseTokens(rawTokens);

  app.addHook('onRequest', async (req: FastifyRequest, reply: FastifyReply) => {
    if (!MUTATING_METHODS.has(req.method)) return;
    const header = req.headers.authorization ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    const actor = token ? tokens.get(token) : undefined;
    if (!token || !actor) {
      reply.code(401).send({ error: 'unauthorized', message: 'Missing or invalid API token' });
      return;
    }
    req.actor = actor;
  });
}
