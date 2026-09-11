import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';
import { simulateAttackPath, listSandboxSimulations } from '../services/sandboxEngine.js';
import { recordAudit } from '../services/audit.js';

/** GODMODE tier routes: Network Sandbox, CLOUDMASTER posture, ICSMASTER posture, XDR-lite detections, Auto-Remediation plans. */
export async function godmodeRoutes(app: FastifyInstance) {
  // Network Sandbox Engine — non-destructive: pure computation over an
  // already-persisted attack path, never a real network action.
  app.post('/sandbox/simulate/:attackPathId', async (req, reply) => {
    const { attackPathId } = req.params as { attackPathId: string };
    const simulation = await simulateAttackPath(attackPathId);
    if (!simulation) return reply.code(404).send({ error: 'attack_path_not_found' });
    await recordAudit('sandbox.simulate', req.actor ?? 'api-token', { attack_path_id: attackPathId, overall_success_probability: simulation.overall_success_probability });
    return reply.code(201).send(simulation);
  });

  app.get('/sandbox/simulations', async (req) => {
    const { attack_path_id } = req.query as Record<string, string | undefined>;
    return listSandboxSimulations(attack_path_id);
  });

  app.get('/sandbox/simulations/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = await queryOne('SELECT * FROM sandbox_simulations WHERE id = $1', [id]);
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });

  // CLOUDMASTER — read the latest per-provider posture computed during the evaluation pipeline.
  app.get('/cloud/posture', async () => query('SELECT * FROM cloud_posture ORDER BY score DESC'));

  // ICSMASTER — read the latest per-segment ICS/OT posture.
  app.get('/ics/posture', async () => query('SELECT * FROM ics_posture ORDER BY score DESC'));

  // XDR-lite — multi-source correlated detections.
  app.get('/xdr/detections', async () => query('SELECT * FROM xdr_detections ORDER BY composite_score DESC'));

  // Auto-Remediation Engine — prioritized plans.
  app.get('/remediation/plans', async (req) => {
    const { status } = req.query as Record<string, string | undefined>;
    if (status) return query('SELECT * FROM remediation_plans WHERE status = $1 ORDER BY priority DESC', [status]);
    return query('SELECT * FROM remediation_plans ORDER BY priority DESC');
  });

  app.patch('/remediation/plans/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const b = req.body as { status?: string };
    const row = await queryOne('UPDATE remediation_plans SET status = COALESCE($1, status) WHERE id = $2 RETURNING *', [b.status ?? null, id]);
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });
}
