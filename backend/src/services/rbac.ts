import { createHash, randomBytes } from 'node:crypto';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { query, queryOne } from '../db/pool.js';
import type { Role, AuthToken } from '../types/models.js';

/**
 * GODMODE+ tier: SOVEREIGN Engine — DB-backed, revocable, role-aware API
 * tokens layered on top of the existing opt-in API_TOKENS env-var
 * mechanism (backend/src/middleware/auth.ts), which is untouched and
 * still works standalone with implicit admin-equivalent access (its
 * documented, unchanged behavior). This adds a second, independent token
 * source: tokens minted via POST /sovereign/tokens, stored only as a
 * sha256 hash (the raw token is returned once, at creation, and never
 * persisted), each carrying an explicit role and optional tenant scope.
 */

const ROLE_RANK: Record<Role, number> = { readonly: 0, analyst: 1, admin: 2 };

export function hashToken(rawToken: string): string {
  return createHash('sha256').update(rawToken).digest('hex');
}

/** Generates a new random bearer token — 32 bytes of CSPRNG output, hex-encoded. */
export function generateToken(): string {
  return randomBytes(32).toString('hex');
}

export interface AuthTokenRecord extends AuthToken {
  token_hash: string;
}

export async function findActiveTokenByRawValue(rawToken: string): Promise<AuthTokenRecord | null> {
  const hash = hashToken(rawToken);
  return queryOne<AuthTokenRecord>('SELECT * FROM auth_tokens WHERE token_hash = $1 AND revoked_at IS NULL', [hash]);
}

export async function createAuthToken(name: string, role: Role, tenantId: string | null): Promise<{ token: string; record: AuthToken }> {
  const rawToken = generateToken();
  const [record] = await query<AuthToken>(
    `INSERT INTO auth_tokens (token_hash, name, role, tenant_id) VALUES ($1, $2, $3, $4)
     RETURNING id, name, role, tenant_id, created_at, revoked_at`,
    [hashToken(rawToken), name, role, tenantId],
  );
  return { token: rawToken, record };
}

export async function revokeAuthToken(id: string): Promise<AuthToken | null> {
  return queryOne<AuthToken>('UPDATE auth_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL RETURNING id, name, role, tenant_id, created_at, revoked_at', [id]);
}

/**
 * Fastify preHandler factory: STRICTLY requires `req.role` (set by the
 * auth middleware) to meet or exceed `minimumRole` — rejects with 401 if
 * no token authenticated at all, 403 if it authenticated but its role is
 * too low. Unlike the rest of this platform's auth, this is deliberately
 * NOT skipped when unconfigured: it exists only to gate the new
 * SOVEREIGN management routes (/sovereign/tenants, /sovereign/tokens),
 * which are a brand-new privileged surface with no prior behavior to
 * preserve, so there is no backward-compatibility reason to leave them
 * open by default. To use them at all, an operator must first present
 * either an env-var API_TOKENS admin token (bootstrapping) or an existing
 * DB-backed admin token. Every other pre-existing route in this codebase
 * is untouched by requireRole() and keeps its original opt-in-auth
 * behavior.
 */
export function requireRole(minimumRole: Role) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    if (!req.role || ROLE_RANK[req.role] < ROLE_RANK[minimumRole]) {
      reply.code(req.role ? 403 : 401).send({
        error: req.role ? 'forbidden' : 'unauthorized',
        message: req.role ? `Requires role >= ${minimumRole}, this token has role ${req.role}` : 'Missing or invalid admin/analyst token',
      });
    }
  };
}
