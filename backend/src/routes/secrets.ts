import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';
import { recordAudit } from '../services/audit.js';

export async function secretRoutes(app: FastifyInstance) {
  app.get('/secrets', async (req) => {
    const { asset_type, asset_id } = req.query as Record<string, string | undefined>;
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (asset_type) {
      params.push(asset_type);
      clauses.push(`asset_type = $${params.length}`);
    }
    if (asset_id) {
      params.push(asset_id);
      clauses.push(`asset_id = $${params.length}`);
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    return query(`SELECT * FROM secrets_findings ${where} ORDER BY detected_at DESC`, params);
  });

  // Ingests a batch of secret findings from the worker's local scan. Findings
  // are append-only (never store the full secret — only a redacted preview,
  // produced client-side before this ever reaches the network).
  app.post('/secrets', async (req, reply) => {
    const body = req.body as { findings: Array<Record<string, unknown>> };
    const inserted = [];
    for (const f of body.findings ?? []) {
      const row = await queryOne(
        `INSERT INTO secrets_findings (asset_type, asset_id, kind, match_preview, source, severity)
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
        [f.asset_type, f.asset_id, f.kind, f.match_preview, f.source, f.severity ?? 'high'],
      );
      inserted.push(row);
    }
    if (inserted.length > 0) {
      await recordAudit('secrets.ingest', req.actor ?? 'api-token', { count: inserted.length, kinds: inserted.map((r: any) => r.kind) });
    }
    return reply.code(201).send(inserted);
  });
}
