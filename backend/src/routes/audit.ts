import type { FastifyInstance } from 'fastify';
import { query } from '../db/pool.js';

export async function auditRoutes(app: FastifyInstance) {
  app.get('/audit-log', async (req) => {
    const { action, limit } = req.query as Record<string, string | undefined>;
    const params: unknown[] = [];
    let where = '';
    if (action) {
      params.push(action);
      where = `WHERE action = $${params.length}`;
    }
    params.push(Math.min(Number(limit ?? 100), 500));
    return query(`SELECT * FROM audit_log ${where} ORDER BY created_at DESC LIMIT $${params.length}`, params);
  });
}
