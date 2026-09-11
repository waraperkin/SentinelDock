import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';

export async function configRoutes(app: FastifyInstance) {
  app.get('/configs', async (req) => {
    const { asset_type, asset_id, kind } = req.query as Record<string, string | undefined>;
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (asset_type) { params.push(asset_type); clauses.push(`asset_type = $${params.length}`); }
    if (asset_id) { params.push(asset_id); clauses.push(`asset_id = $${params.length}`); }
    if (kind) { params.push(kind); clauses.push(`kind = $${params.length}`); }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    return query(`SELECT * FROM config_snapshots ${where} ORDER BY collected_at DESC LIMIT 200`, params);
  });

  app.get('/configs/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = await queryOne('SELECT * FROM config_snapshots WHERE id = $1', [id]);
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });

  // Ingest a new immutable config snapshot for an asset.
  app.post('/configs', async (req, reply) => {
    const b = req.body as Record<string, unknown>;
    const row = await queryOne(
      `INSERT INTO config_snapshots (asset_type, asset_id, kind, data, collected_at)
       VALUES ($1,$2,$3,$4, COALESCE($5, now())) RETURNING *`,
      [b.asset_type, b.asset_id, b.kind, JSON.stringify(b.data ?? {}), b.collected_at ?? null],
    );
    return reply.code(201).send(row);
  });
}
