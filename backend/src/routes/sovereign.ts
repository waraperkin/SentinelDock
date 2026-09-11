import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';
import type { Tenant, Role } from '../types/models.js';
import { requireRole, createAuthToken, revokeAuthToken } from '../services/rbac.js';
import { recordAudit } from '../services/audit.js';

const VALID_ROLES = new Set<Role>(['admin', 'analyst', 'readonly']);

/** GODMODE+ tier: SOVEREIGN Engine routes — tenant and DB-backed RBAC token management. Every route here requires an authenticated admin (see rbac.ts's requireRole, which is strict — unlike the rest of this platform's opt-in auth). */
export async function sovereignRoutes(app: FastifyInstance) {
  app.get('/sovereign/tenants', { preHandler: requireRole('admin') }, async () => query<Tenant>('SELECT * FROM tenants ORDER BY name'));

  app.post('/sovereign/tenants', { preHandler: requireRole('admin') }, async (req, reply) => {
    const b = req.body as { name?: string; slug?: string };
    if (!b.name || !b.slug) return reply.code(400).send({ error: 'invalid_request', message: 'name and slug are required' });
    const row = await queryOne<Tenant>('INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING *', [b.name, b.slug]);
    await recordAudit('sovereign.tenant.create', req.actor ?? 'admin', { tenant: row });
    return reply.code(201).send(row);
  });

  app.delete('/sovereign/tenants/:id', { preHandler: requireRole('admin') }, async (req, reply) => {
    const { id } = req.params as { id: string };
    await query('DELETE FROM tenants WHERE id = $1', [id]);
    await recordAudit('sovereign.tenant.delete', req.actor ?? 'admin', { tenant_id: id });
    return reply.code(204).send();
  });

  // Tokens are returned in full (the raw bearer value) ONLY at creation,
  // in this one response — never again. The DB only ever stores a sha256
  // hash (see rbac.ts).
  app.post('/sovereign/tokens', { preHandler: requireRole('admin') }, async (req, reply) => {
    const b = req.body as { name?: string; role?: string; tenant_id?: string | null };
    if (!b.name || !b.role || !VALID_ROLES.has(b.role as Role)) {
      return reply.code(400).send({ error: 'invalid_request', message: 'name is required; role must be admin, analyst, or readonly' });
    }
    const { token, record } = await createAuthToken(b.name, b.role as Role, b.tenant_id ?? null);
    await recordAudit('sovereign.token.create', req.actor ?? 'admin', { token_id: record.id, name: record.name, role: record.role });
    return reply.code(201).send({ token, ...record });
  });

  app.get('/sovereign/tokens', { preHandler: requireRole('admin') }, async () =>
    query('SELECT id, name, role, tenant_id, created_at, revoked_at FROM auth_tokens ORDER BY created_at DESC'),
  );

  app.delete('/sovereign/tokens/:id', { preHandler: requireRole('admin') }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const revoked = await revokeAuthToken(id);
    if (!revoked) return reply.code(404).send({ error: 'not_found' });
    await recordAudit('sovereign.token.revoke', req.actor ?? 'admin', { token_id: id });
    return revoked;
  });
}
