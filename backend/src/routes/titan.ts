import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';
import { getCorrelatedTimeline } from '../services/siemEngine.js';

/** TITAN tier read/action routes: TI matches, UEBA anomalies, EDR detections, segmentation/hardening recommendations, SIEM-lite timeline. */
export async function titanRoutes(app: FastifyInstance) {
  app.get('/ti/matches', async () => query('SELECT * FROM ti_matches ORDER BY detected_at DESC'));

  app.get('/ueba/anomalies', async (req) => {
    const { hours } = req.query as Record<string, string | undefined>;
    const hoursBack = hours ? Number(hours) : 24;
    return query('SELECT * FROM ueba_anomalies WHERE detected_at > now() - ($1 || \' hours\')::interval ORDER BY detected_at DESC', [hoursBack]);
  });

  app.get('/edr/detections', async () => query('SELECT * FROM edr_detections ORDER BY detected_at DESC'));

  app.get('/segmentation/recommendations', async (req) => {
    const { status } = req.query as Record<string, string | undefined>;
    if (status) return query('SELECT * FROM segmentation_recommendations WHERE status = $1 ORDER BY created_at DESC', [status]);
    return query('SELECT * FROM segmentation_recommendations ORDER BY created_at DESC');
  });

  app.patch('/segmentation/recommendations/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const b = req.body as { status?: string };
    const row = await queryOne('UPDATE segmentation_recommendations SET status = COALESCE($1, status) WHERE id = $2 RETURNING *', [b.status ?? null, id]);
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });

  app.get('/hardening/recommendations', async (req) => {
    const { status } = req.query as Record<string, string | undefined>;
    if (status) return query('SELECT * FROM hardening_recommendations WHERE status = $1 ORDER BY created_at DESC', [status]);
    return query('SELECT * FROM hardening_recommendations ORDER BY created_at DESC');
  });

  app.patch('/hardening/recommendations/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const b = req.body as { status?: string };
    const row = await queryOne('UPDATE hardening_recommendations SET status = COALESCE($1, status) WHERE id = $2 RETURNING *', [b.status ?? null, id]);
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });

  app.get('/siem/timeline', async (req) => {
    const { limit } = req.query as Record<string, string | undefined>;
    return getCorrelatedTimeline(limit ? Number(limit) : 200);
  });
}
