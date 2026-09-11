import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';
import { globalRiskScore } from '../services/riskEngine.js';

export async function dashboardRoutes(app: FastifyInstance) {
  app.get('/dashboard/summary', async () => {
    const [hosts, containers, services, violations, incidents, score] = await Promise.all([
      queryOne<{ count: string }>('SELECT count(*) FROM hosts'),
      queryOne<{ count: string }>('SELECT count(*) FROM containers'),
      queryOne<{ count: string }>('SELECT count(*) FROM services'),
      queryOne<{ count: string }>("SELECT count(*) FROM policy_violations WHERE status = 'open'"),
      queryOne<{ count: string }>('SELECT count(*) FROM incident_scenarios'),
      globalRiskScore(),
    ]);
    return {
      asset_count: Number(hosts?.count ?? 0) + Number(containers?.count ?? 0) + Number(services?.count ?? 0),
      hosts: Number(hosts?.count ?? 0),
      containers: Number(containers?.count ?? 0),
      services: Number(services?.count ?? 0),
      global_risk_score: score,
      open_violations: Number(violations?.count ?? 0),
      incident_scenarios: Number(incidents?.count ?? 0),
    };
  });
}
