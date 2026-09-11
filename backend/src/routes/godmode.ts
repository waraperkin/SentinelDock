import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';
import { simulateAttackPath, listSandboxSimulations } from '../services/sandboxEngine.js';
import { runSimulationCampaign, listSimulationCampaigns } from '../services/attackSimulationEngine.js';
import { computeRiskTrend } from '../services/quantumEngine.js';
import { recordAudit } from '../services/audit.js';

/** GODMODE / GODMODE+ tier routes: Network Sandbox + Attack Simulation, CLOUDMASTER posture, ICSMASTER posture, XDR-lite detections, Auto-Remediation plans, QUANTUM trend/outliers. */
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

  // GODMODE+: Attack Simulation Engine — batches the (non-destructive)
  // Network Sandbox Engine across every current attack path.
  app.post('/simulation/campaigns/run', async (req, reply) => {
    const campaign = await runSimulationCampaign();
    if (!campaign) return reply.code(200).send({ message: 'no attack paths to simulate' });
    await recordAudit('simulation.campaign.run', req.actor ?? 'api-token', { campaign_id: campaign.id, path_count: campaign.path_count, max_success_probability: campaign.max_success_probability });
    return reply.code(201).send(campaign);
  });

  app.get('/simulation/campaigns', async () => listSimulationCampaigns());

  // GODMODE+: QUANTUM Engine — local statistical trend/outlier analysis (see quantumEngine.ts; not literal quantum computing).
  app.get('/quantum/trend', async (req, reply) => {
    const { samples } = req.query as Record<string, string | undefined>;
    const trend = await computeRiskTrend(samples ? Number(samples) : undefined);
    if (!trend) return reply.code(200).send({ message: 'not enough risk-score history yet (need at least 2 evaluation cycles)' });
    return trend;
  });

  app.get('/quantum/outliers', async () => query('SELECT * FROM quantum_outliers ORDER BY ABS(z_score) DESC'));
}
