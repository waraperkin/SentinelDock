import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';

export async function incidentRoutes(app: FastifyInstance) {
  app.get('/incident-scenarios', async (req) => {
    const { severity } = req.query as Record<string, string | undefined>;
    if (severity) return query('SELECT * FROM incident_scenarios WHERE severity = $1 ORDER BY created_at DESC', [severity]);
    return query('SELECT * FROM incident_scenarios ORDER BY created_at DESC');
  });

  app.get('/incident-scenarios/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = await queryOne('SELECT * FROM incident_scenarios WHERE id = $1', [id]);
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });
}
