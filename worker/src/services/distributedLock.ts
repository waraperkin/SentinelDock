import { Redis } from 'ioredis';
import { randomUUID } from 'node:crypto';

const REDIS_URL = process.env.REDIS_URL;
const WORKER_ID = randomUUID();

let client: Redis | null = null;
function getClient(): Redis | null {
  if (!REDIS_URL) return null;
  if (!client) {
    client = new Redis(REDIS_URL, { maxRetriesPerRequest: 1, retryStrategy: () => null, lazyConnect: true });
    client.on('error', () => {
      /* logged at call sites; avoid crashing the process on transient Redis errors */
    });
  }
  return client;
}

/**
 * Distributed leader coordination for horizontally-scaled worker replicas
 * (`docker compose up --scale worker=N`). Only one replica should run a
 * given collection cycle at a time — without this, N replicas would each
 * run the full subnet sweep + Docker/service discovery concurrently,
 * multiplying load and racing writes with no benefit. Uses Redis SET NX PX
 * as a simple TTL'd mutex; if Redis is unreachable, every replica falls
 * back to running independently (fail-open) rather than blocking entirely.
 *
 * This does NOT yet split work across replicas (e.g. one subnet per
 * replica) — it only prevents duplicate concurrent runs. Splitting the
 * subnet list across replicas is a natural next step but adds
 * coordination complexity (dynamic replica membership) out of scope here.
 */
export async function withCollectionCycleLock<T>(ttlMs: number, fn: () => Promise<T>): Promise<T | 'skipped-not-leader'> {
  const redis = getClient();
  if (!redis) return fn(); // no Redis configured — run standalone

  try {
    const acquired = await redis.set('sentineldock:worker:cycle-lock', WORKER_ID, 'PX', ttlMs, 'NX');
    if (acquired !== 'OK') {
      console.log('[worker] another replica is running this cycle — skipping');
      return 'skipped-not-leader';
    }
  } catch (err) {
    console.warn('[worker] distributed lock unavailable (Redis unreachable), running standalone', (err as Error).message);
    return fn();
  }

  try {
    return await fn();
  } finally {
    try {
      // Only release if we still hold it (avoid releasing a lock another
      // replica acquired after ours expired mid-run).
      const holder = await redis.get('sentineldock:worker:cycle-lock');
      if (holder === WORKER_ID) await redis.del('sentineldock:worker:cycle-lock');
    } catch {
      /* lock will simply expire via its TTL */
    }
  }
}

export function workerId(): string {
  return WORKER_ID;
}

/** Deterministic string hash (djb2) — stable across processes, used to shard work items without central coordination beyond knowing the fleet size. */
function stringHash(text: string): number {
  let hash = 5381;
  for (let i = 0; i < text.length; i++) hash = (hash * 33) ^ text.charCodeAt(i);
  return hash >>> 0;
}

/**
 * Real distributed work-splitting: given the full list of work items (e.g.
 * subnet CIDRs) and the set of currently-online worker replica IDs (from
 * the `/workers` heartbeat registry), returns only the subset this replica
 * is responsible for — each item's hash mod the fleet size determines its
 * owner, so every replica computes the same partition independently with
 * no additional coordination round-trip. If this replica isn't in the
 * online set yet (e.g. its first heartbeat hasn't landed), it falls back
 * to claiming everything (fail-open, so a brand-new replica doesn't sweep
 * nothing while it warms up).
 */
export function shardWorkItems<T>(items: T[], keyOf: (item: T) => string, onlineWorkerIds: string[]): T[] {
  const fleet = Array.from(new Set(onlineWorkerIds)).sort();
  if (fleet.length === 0 || !fleet.includes(WORKER_ID)) return items;
  const myIndex = fleet.indexOf(WORKER_ID);
  return items.filter((item) => stringHash(keyOf(item)) % fleet.length === myIndex);
}
