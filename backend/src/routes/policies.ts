import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';
import { evaluatePolicies } from '../services/policyEngine.js';
import { recomputeRisks } from '../services/riskEngine.js';
import { rebuildAttackPaths } from '../services/attackPathEngine.js';
import { generateIncidentScenarios } from '../services/incidentEngine.js';
import { scanVulnerabilities } from '../services/vulnerabilityScanner.js';
import { recordAudit } from '../services/audit.js';
import { autoGeneratePolicies } from '../services/autoPolicyGenerator.js';
import { scanThreatIntel } from '../services/threatIntelEngine.js';
import { computeUebaAnomalies } from '../services/uebaEngine.js';
import { scanEdrSignals } from '../services/edrEngine.js';
import { generateSegmentationRecommendations } from '../services/segmentationEngine.js';
import { generateHardeningRecommendations } from '../services/hardeningEngine.js';
import { evaluatePoliciesBySegment } from '../services/distributedEvaluationEngine.js';

/**
 * The shared downstream pipeline that must run after policy violations are
 * up to date, regardless of whether violation detection itself ran
 * globally (`evaluatePolicies()`) or partitioned by segment
 * (`evaluatePoliciesBySegment()`, see distributedEvaluationEngine.ts).
 * These stages inherently need a whole-graph view (CVE chaining across a
 * host's services, cross-segment attack paths), so they always run
 * centralized — see the "reduce" side of the map/reduce framing in
 * distributedEvaluationEngine.ts.
 */
async function runDownstreamPipeline() {
  const vulnerabilities = await scanVulnerabilities();
  const tiMatches = await scanThreatIntel();
  const uebaAnomalies = await computeUebaAnomalies();
  const edrDetections = await scanEdrSignals();
  const risks = await recomputeRisks();
  const attackPaths = await rebuildAttackPaths();
  const incidents = await generateIncidentScenarios();
  const segmentationRecommendations = await generateSegmentationRecommendations();
  const hardeningRecommendations = await generateHardeningRecommendations();
  return {
    vulnerabilities: vulnerabilities.length,
    ti_matches: tiMatches.length,
    ueba_anomalies: uebaAnomalies.length,
    edr_detections: edrDetections.length,
    risks: risks.length,
    attack_paths: attackPaths.length,
    incident_scenarios: incidents.length,
    segmentation_recommendations: segmentationRecommendations.length,
    hardening_recommendations: hardeningRecommendations.length,
  };
}

export async function policyRoutes(app: FastifyInstance) {
  app.get('/policies', async () => query('SELECT * FROM policies ORDER BY severity DESC, key'));

  app.get('/policies/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = await queryOne('SELECT * FROM policies WHERE id = $1', [id]);
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });

  app.post('/policies', async (req, reply) => {
    const b = req.body as Record<string, unknown>;
    const row = await queryOne(
      `INSERT INTO policies (key, name, description, severity, recommendation, conditions, enabled)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [b.key, b.name, b.description ?? null, b.severity ?? 'medium', b.recommendation ?? null, JSON.stringify(b.conditions), b.enabled ?? true],
    );
    return reply.code(201).send(row);
  });

  app.patch('/policies/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const b = req.body as Record<string, unknown>;
    const row = await queryOne(
      `UPDATE policies SET name = COALESCE($1, name), description = COALESCE($2, description),
        severity = COALESCE($3, severity), recommendation = COALESCE($4, recommendation),
        conditions = COALESCE($5, conditions), enabled = COALESCE($6, enabled), updated_at = now()
       WHERE id = $7 RETURNING *`,
      [b.name ?? null, b.description ?? null, b.severity ?? null, b.recommendation ?? null, b.conditions ? JSON.stringify(b.conditions) : null, b.enabled ?? null, id],
    );
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });

  app.delete('/policies/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    await query('DELETE FROM policies WHERE id = $1', [id]);
    return reply.code(204).send();
  });

  // Runs the full evaluation pipeline: violations -> vulnerabilities -> TI
  // -> UEBA -> EDR -> risks -> attack paths -> incidents -> segmentation ->
  // hardening. Violation detection runs globally in one pass.
  app.post('/policies/evaluate', async (req) => {
    const violations = await evaluatePolicies();
    const downstream = await runDownstreamPipeline();
    const summary = { violations: violations.length, ...downstream };
    await recordAudit('policies.evaluate', req.actor ?? 'api-token', summary);
    return summary;
  });

  // TITAN: Distributed Evaluation Engine — same downstream pipeline, but
  // violation detection is partitioned per network segment first (see
  // distributedEvaluationEngine.ts for why this is an honest "map" step
  // rather than a real multi-node claim).
  app.post('/policies/evaluate/distributed', async (req) => {
    const segmentResult = await evaluatePoliciesBySegment();
    const downstream = await runDownstreamPipeline();
    const summary = { ...segmentResult, ...downstream };
    await recordAudit('policies.evaluate.distributed', req.actor ?? 'api-token', summary);
    return summary;
  });

  // Scans inventory for protocol_family/device_class combinations with no
  // existing policy and creates disabled draft policies for human review.
  app.post('/policies/auto-generate', async (req) => {
    const proposed = await autoGeneratePolicies();
    if (proposed.length > 0) await recordAudit('policies.auto-generate', req.actor ?? 'worker', { proposed: proposed.map((p) => p.key) });
    return proposed;
  });

  // ---- Violations ----
  app.get('/violations', async (req) => {
    const { status, severity, asset_type } = req.query as Record<string, string | undefined>;
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (status) { params.push(status); clauses.push(`status = $${params.length}`); }
    if (severity) { params.push(severity); clauses.push(`severity = $${params.length}`); }
    if (asset_type) { params.push(asset_type); clauses.push(`asset_type = $${params.length}`); }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    return query(`SELECT * FROM policy_violations ${where} ORDER BY detected_at DESC`, params);
  });

  app.get('/violations/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = await queryOne('SELECT * FROM policy_violations WHERE id = $1', [id]);
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });

  app.patch('/violations/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const b = req.body as Record<string, unknown>;
    const resolvedAt = b.status === 'resolved' ? 'now()' : 'resolved_at';
    const row = await queryOne(
      `UPDATE policy_violations SET status = COALESCE($1, status), resolved_at = ${resolvedAt} WHERE id = $2 RETURNING *`,
      [b.status ?? null, id],
    );
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });
}
