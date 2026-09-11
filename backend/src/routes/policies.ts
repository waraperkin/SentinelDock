import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';
import { evaluatePolicies } from '../services/policyEngine.js';
import { recomputeRisks } from '../services/riskEngine.js';
import { rebuildAttackPaths } from '../services/attackPathEngine.js';
import { generateIncidentScenarios } from '../services/incidentEngine.js';
import { scanVulnerabilities } from '../services/vulnerabilityScanner.js';
import { recordAudit } from '../services/audit.js';

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

  // Runs the full evaluation pipeline: violations -> vulnerabilities -> risks -> attack paths -> incidents.
  app.post('/policies/evaluate', async (req) => {
    const violations = await evaluatePolicies();
    const vulnerabilities = await scanVulnerabilities();
    const risks = await recomputeRisks();
    const attackPaths = await rebuildAttackPaths();
    const incidents = await generateIncidentScenarios();
    const summary = {
      violations: violations.length,
      vulnerabilities: vulnerabilities.length,
      risks: risks.length,
      attack_paths: attackPaths.length,
      incident_scenarios: incidents.length,
    };
    await recordAudit('policies.evaluate', req.actor ?? 'api-token', summary);
    return summary;
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
