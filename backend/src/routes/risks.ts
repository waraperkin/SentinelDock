import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';
import { globalRiskScore } from '../services/riskEngine.js';

export async function riskRoutes(app: FastifyInstance) {
  app.get('/risks', async (req) => {
    const { severity, category, asset_type, asset_id } = req.query as Record<string, string | undefined>;
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (severity) { params.push(severity); clauses.push(`severity = $${params.length}`); }
    if (category) { params.push(category); clauses.push(`category = $${params.length}`); }
    if (asset_type) { params.push(asset_type); clauses.push(`asset_type = $${params.length}`); }
    if (asset_id) { params.push(asset_id); clauses.push(`asset_id = $${params.length}`); }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    return query(`SELECT * FROM risks ${where} ORDER BY score DESC`, params);
  });

  app.get('/risks/global-score', async () => ({ score: await globalRiskScore() }));

  app.get('/risks/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = await queryOne('SELECT * FROM risks WHERE id = $1', [id]);
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });
}
