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
