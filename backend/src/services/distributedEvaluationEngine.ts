import { query, queryOne } from '../db/pool.js';
import type { Host, NetworkSegment } from '../types/models.js';
import { evaluatePolicies } from './policyEngine.js';

/** Deterministic string hash (djb2) — same algorithm the worker fleet uses (see worker/src/services/distributedLock.ts) to shard work items without central coordination beyond knowing the shard count. */
function stringHash(text: string): number {
  let hash = 5381;
  for (let i = 0; i < text.length; i++) hash = (hash * 33) ^ text.charCodeAt(i);
  return hash >>> 0;
}

const UNASSIGNED_SHARD_KEY = 'unassigned-hosts';

/** GODMODE v2: which shard (of `shardCount`) a given segment id (or the fixed unassigned-hosts bucket) is assigned to. */
export function shardFor(key: string, shardCount: number): number {
  return stringHash(key) % shardCount;
}

/** Counts currently-open violations whose owning host falls within the given host id set, across all three asset types. */
async function countOpenViolationsForHosts(hostIds: string[]): Promise<number> {
  if (hostIds.length === 0) return 0;
  const row = await queryOne<{ count: string }>(
    `SELECT count(*) FROM policy_violations pv
     LEFT JOIN services s ON pv.asset_type = 'service' AND pv.asset_id = s.id
     LEFT JOIN containers c ON pv.asset_type = 'container' AND pv.asset_id = c.id
     LEFT JOIN containers sc ON s.container_id = sc.id
     WHERE pv.status = 'open' AND (
       (pv.asset_type = 'host' AND pv.asset_id = ANY($1::uuid[]))
       OR (pv.asset_type = 'container' AND c.host_id = ANY($1::uuid[]))
       OR (pv.asset_type = 'service' AND COALESCE(s.host_id, sc.host_id) = ANY($1::uuid[]))
     )`,
    [hostIds],
  );
  return Number(row?.count ?? 0);
}

export interface DistributedEvaluationResult {
  per_segment: Array<{ segment_id: string; segment_name: string; host_count: number; violations: number }>;
  unassigned_hosts: number;
  shard_index?: number;
  shard_count?: number;
  segments_skipped_other_shards?: number;
}

/**
 * TITAN tier: Distributed Evaluation Engine (v1: single-shard).
 * GODMODE tier: Distributed Evaluation Engine v2 — adds optional
 * horizontal-scaling shard parameters (`shardIndex`/`shardCount`).
 *
 * Honest framing: this backend runs as a single process by default, so
 * "distributed" means the *evaluation work is partitioned by network
 * segment* (map), which is the same partitioning primitive a real
 * multi-instance deployment would use to spread evaluation load across
 * processes/nodes — each segment's policy-violation detection is
 * independent and safe to run in any order, or in parallel, or on a
 * separate process entirely (see `evaluatePolicies(scopeHostIds)` in
 * policyEngine.ts, which never touches violations outside its scope).
 *
 * v2 makes that partitioning addressable from the outside: when
 * `shardCount` > 1, this call only processes the segments whose
 * `shardFor(segment.id, shardCount) === shardIndex` (same djb2-hash
 * partitioning the worker fleet already uses in
 * worker/src/services/distributedLock.ts), skipping the rest. A real
 * horizontally-scaled deployment runs `shardCount` backend instances (or
 * `shardCount` scheduled calls) each with its own `shardIndex`, so no two
 * of them ever touch the same segment's violations concurrently — this is
 * genuinely safe to parallelize, not just a label. Downstream aggregation
 * (risk scoring, attack-path/incident rebuilding, TI/UEBA/EDR/
 * segmentation/hardening/CLOUDMASTER/ICSMASTER/XDR/remediation)
 * inherently needs a whole-graph view — a CVE-chaining risk or a
 * cross-segment attack path cannot be computed from one segment alone —
 * so that stays centralized (reduce) regardless of shard count.
 */
export async function evaluatePoliciesBySegment(shardIndex?: number, shardCount?: number): Promise<DistributedEvaluationResult> {
  const sharded = typeof shardCount === 'number' && shardCount > 1 && typeof shardIndex === 'number';

  const segments = await query<NetworkSegment>('SELECT * FROM network_segments');
  const hosts = await query<Host>('SELECT * FROM hosts');

  const hostIdsBySegment = new Map<string, Set<string>>();
  for (const host of hosts) {
    if (!host.network_segment_id) continue;
    const set = hostIdsBySegment.get(host.network_segment_id) ?? new Set<string>();
    set.add(host.id);
    hostIdsBySegment.set(host.network_segment_id, set);
  }

  const perSegment: Array<{ segment_id: string; segment_name: string; host_count: number; violations: number }> = [];
  let skippedOtherShards = 0;

  // Sequential here (not Promise.all) because each call shares the same
  // Postgres connection pool and mutates overlapping tables (policy
  // violations) — running them concurrently would not be a safe
  // demonstration of "distributed" work even though the scoping itself
  // makes it correct to run out of order. A real distributed deployment
  // would instead dispatch each segment's evaluation to a separate
  // process; this loop stands in for that dispatch boundary within one
  // process's shard of the work.
  for (const segment of segments) {
    if (sharded && shardFor(segment.id, shardCount!) !== shardIndex) {
      skippedOtherShards++;
      continue;
    }
    const scopeHostIds = hostIdsBySegment.get(segment.id) ?? new Set<string>();
    if (scopeHostIds.size === 0) {
      perSegment.push({ segment_id: segment.id, segment_name: segment.name, host_count: 0, violations: 0 });
      continue;
    }
    await evaluatePolicies(scopeHostIds);
    const scopedOpenCount = await countOpenViolationsForHosts(Array.from(scopeHostIds));
    perSegment.push({ segment_id: segment.id, segment_name: segment.name, host_count: scopeHostIds.size, violations: scopedOpenCount });
  }

  const assignedHostIds = new Set(hosts.filter((h) => h.network_segment_id).map((h) => h.id));
  const unassignedHosts = hosts.filter((h) => !assignedHostIds.has(h.id));
  const unassignedOwnedByThisShard = !sharded || shardFor(UNASSIGNED_SHARD_KEY, shardCount!) === shardIndex;
  if (unassignedHosts.length > 0 && unassignedOwnedByThisShard) {
    await evaluatePolicies(new Set(unassignedHosts.map((h) => h.id)));
  }

  return {
    per_segment: perSegment,
    unassigned_hosts: unassignedOwnedByThisShard ? unassignedHosts.length : 0,
    ...(sharded ? { shard_index: shardIndex, shard_count: shardCount, segments_skipped_other_shards: skippedOtherShards } : {}),
  };
}

/**
 * GODMODE v2: returns the segment -> shard assignment for a given shard
 * count without evaluating anything — lets an external orchestrator (N
 * scheduled calls, or N backend instances each configured with a distinct
 * shard index) know its workload in advance.
 */
export async function planEvaluationShards(shardCount: number): Promise<{ shard_count: number; assignments: Array<{ segment_id: string; segment_name: string; shard_index: number }>; unassigned_hosts_shard_index: number }> {
  const segments = await query<NetworkSegment>('SELECT * FROM network_segments');
  return {
    shard_count: shardCount,
    assignments: segments.map((s) => ({ segment_id: s.id, segment_name: s.name, shard_index: shardFor(s.id, shardCount) })),
    unassigned_hosts_shard_index: shardFor(UNASSIGNED_SHARD_KEY, shardCount),
  };
}
