import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';

/** How long without a heartbeat before a worker node is considered offline. */
const STALE_AFTER_SECONDS = 180;

export async function workerRoutes(app: FastifyInstance) {
  // Lists all known worker nodes with a derived online/offline status —
  // the real substrate for "distributed worker" visibility: every replica
  // that has ever heartbeated shows up here, whether or not it currently
  // holds the collection-cycle leader lock.
  app.get('/workers', async () => {
    const nodes = await query<Record<string, unknown>>(`SELECT *, (now() - last_heartbeat_at) < interval '${STALE_AFTER_SECONDS} seconds' AS online FROM worker_nodes ORDER BY last_heartbeat_at DESC`);
    return nodes;
  });

  // Upserts by worker_id (the stable per-process UUID from
  // distributedLock.workerId()) so a replica's row updates in place across
  // heartbeats instead of accumulating duplicates.
  app.post('/workers/heartbeat', async (req, reply) => {
    const b = req.body as Record<string, unknown>;
    const existing = await queryOne<{ id: string }>('SELECT id FROM worker_nodes WHERE worker_id = $1', [b.worker_id]);
    if (existing) {
      const row = await queryOne(
        `UPDATE worker_nodes SET hostname = $1, is_leader = $2, last_cycle_summary = $3, last_heartbeat_at = now() WHERE id = $4 RETURNING *`,
        [b.hostname, b.is_leader ?? false, JSON.stringify(b.last_cycle_summary ?? null), existing.id],
      );
      return reply.code(200).send(row);
    }
    const row = await queryOne(
      `INSERT INTO worker_nodes (worker_id, hostname, is_leader, last_cycle_summary) VALUES ($1,$2,$3,$4) RETURNING *`,
      [b.worker_id, b.hostname, b.is_leader ?? false, JSON.stringify(b.last_cycle_summary ?? null)],
    );
    return reply.code(201).send(row);
  });
}
