import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import type { Role } from '../types/models.js';
import { findActiveTokenByRawValue } from '../services/rbac.js';

declare module 'fastify' {
  interface FastifyRequest {
    actor?: string;
    /** SOVEREIGN tier: set only when the request authenticated via a DB-backed auth_tokens row (see rbac.ts). Undefined for env-var API_TOKENS callers and for any request when no auth is configured at all — requireRole() treats "undefined" as "unenforced", matching this platform's established opt-in-auth default. */
    role?: Role;
    /** SOVEREIGN tier: set only when the authenticating DB token has a non-null tenant_id. */
    tenantId?: string;
  }
}

/**
 * API token auth: opt-in via the API_TOKENS env var (comma-separated
 * bearer tokens, optionally "name:token" pairs to give each token an
 * identity for the audit log) — unchanged, original OMEGA-tier behavior.
 * When unset AND no SOVEREIGN DB tokens exist either (the default), no
 * enforcement happens — this keeps the default docker-compose flow
 * working without requiring every internal caller (the worker) to be
 * configured with a token out of the box.
 *
 * GODMODE+ tier (SOVEREIGN) layers a second, independent token source on
 * top: DB-backed tokens (`auth_tokens`, managed via /sovereign/tokens),
 * each carrying an explicit role (admin/analyst/readonly) and optional
 * tenant scope, checked on EVERY request (not just mutating ones) so
 * `req.role`/`req.tenantId` are available for read-side tenant filtering
 * too. A request with no matching token (env-var or DB) simply leaves
 * `req.role` unset. That is harmless for every pre-existing route (they
 * never look at `req.role`), but the new /sovereign/tenants and
 * /sovereign/tokens management routes gate themselves with
 * `requireRole()` (rbac.ts), which — unlike this file's own mutating-
 * method check — rejects unconditionally when `req.role` is unset, since
 * they are a brand-new privileged surface with no legacy default-open
 * behavior to preserve. Env-var tokens are treated as full "admin",
 * matching their pre-existing unrestricted behavior, so they can bootstrap
 * the first DB-backed SOVEREIGN token.
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
  const envTokens = rawTokens.trim() ? parseTokens(rawTokens) : null;
  if (!envTokens) {
    app.log.info('API_TOKENS not set — running without env-var API authentication (SOVEREIGN DB tokens, if any, still apply)');
  }

  app.addHook('onRequest', async (req: FastifyRequest, reply: FastifyReply) => {
    const header = req.headers.authorization ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;

    // Try the env-var mechanism first (cheap, no DB round-trip).
    const envActor = token && envTokens ? envTokens.get(token) : undefined;
    if (envActor) {
      req.actor = envActor;
      req.role = 'admin'; // unchanged pre-SOVEREIGN behavior: an env token could always do anything
      return;
    }

    // SOVEREIGN: fall back to a DB-backed token, checked on every request
    // (not just mutating ones) so GET handlers can also read req.tenantId.
    if (token) {
      const dbToken = await findActiveTokenByRawValue(token);
      if (dbToken) {
        req.actor = dbToken.name;
        req.role = dbToken.role;
        if (dbToken.tenant_id) req.tenantId = dbToken.tenant_id;
        return;
      }
    }

    // No token matched either mechanism. Only mutating requests are
    // rejected outright when env-var auth is configured — this preserves
    // the exact pre-SOVEREIGN default: GET is always open, and when
    // API_TOKENS is unset entirely, nothing is rejected here at all
    // (SOVEREIGN's own routes still gate specific actions via
    // requireRole(), which no-ops when req.role is unset).
    if (envTokens && MUTATING_METHODS.has(req.method)) {
      reply.code(401).send({ error: 'unauthorized', message: 'Missing or invalid API token' });
    }
  });
}
