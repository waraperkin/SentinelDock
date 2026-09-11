import { query } from '../db/pool.js';
import type { Host, Container, ServiceRecord, Policy, PolicyCondition, PolicyViolation, NetworkSegment } from '../types/models.js';

type Evaluatable = Record<string, unknown>;

export function getField(obj: Evaluatable, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc === null || acc === undefined) return undefined;
    return (acc as Record<string, unknown>)[key];
  }, obj);
}

export function evalCondition(target: Evaluatable, cond: PolicyCondition): boolean {
  const actual = getField(target, cond.field);
  switch (cond.operator) {
    case 'eq':
      return actual === cond.value;
    case 'neq':
      return actual !== cond.value;
    case 'in':
      return Array.isArray(cond.value) && cond.value.includes(actual);
    case 'not_in':
      return Array.isArray(cond.value) && !cond.value.includes(actual);
    case 'lt':
      return typeof actual === 'number' && actual < (cond.value as number);
    case 'lte':
      return typeof actual === 'number' && actual <= (cond.value as number);
    case 'gt':
      return typeof actual === 'number' && actual > (cond.value as number);
    case 'gte':
      return typeof actual === 'number' && actual >= (cond.value as number);
    case 'contains':
      return typeof actual === 'string' && actual.includes(String(cond.value));
    default:
      return false;
  }
}

export function matchesPolicy(target: Evaluatable, policy: Policy): boolean {
  const { all, any } = policy.conditions;
  const allOk = !all || all.every((c) => evalCondition(target, c));
  const anyOk = !any || any.length === 0 || any.some((c) => evalCondition(target, c));
  return allOk && anyOk;
}

async function buildEvaluationContext() {
  const segments = await query<NetworkSegment>('SELECT * FROM network_segments');
  const segmentById = new Map(segments.map((s) => [s.id, s]));

  const hosts = await query<Host>('SELECT * FROM hosts');
  const containers = await query<Container>('SELECT * FROM containers');
  const services = await query<ServiceRecord>('SELECT * FROM services');

  const hostById = new Map(hosts.map((h) => [h.id, h]));
  const containerById = new Map(containers.map((c) => [c.id, c]));

  // Precompute, per segment, the distinct device_class values present —
  // this is what lets a policy detect "cloud and on-prem/IT devices share
  // a segment" (Zero Trust segmentation concern) without the DSL needing
  // to support cross-row aggregation itself.
  const deviceClassesBySegment = new Map<string, Set<string>>();
  for (const host of hosts) {
    if (!host.network_segment_id) continue;
    const set = deviceClassesBySegment.get(host.network_segment_id) ?? new Set<string>();
    set.add(host.device_class);
    deviceClassesBySegment.set(host.network_segment_id, set);
  }

  return { hosts, containers, services, hostById, containerById, segmentById, deviceClassesBySegment };
}

function enrichHost(host: Host, segmentById: Map<string, NetworkSegment>, deviceClassesBySegment?: Map<string, Set<string>>): Evaluatable {
  const segment = host.network_segment_id ? segmentById.get(host.network_segment_id) : undefined;
  const segmentDeviceClasses = host.network_segment_id ? deviceClassesBySegment?.get(host.network_segment_id) : undefined;
  return {
    ...host,
    network_segment: segment ?? null,
    // True when this host's segment also contains at least one host of a
    // different device_class (e.g. a cloud instance sharing a segment with
    // on-prem IT hosts, or IT mixed with ICS) — a genuine Zero Trust
    // segmentation gap, not just a proxy signal.
    segment_has_mixed_device_classes: segmentDeviceClasses ? segmentDeviceClasses.size > 1 : false,
  };
}

function enrichContainer(
  container: Container,
  hostById: Map<string, Host>,
  segmentById: Map<string, NetworkSegment>,
  deviceClassesBySegment?: Map<string, Set<string>>,
): Evaluatable {
  const host = hostById.get(container.host_id);
  return { ...container, host: host ? enrichHost(host, segmentById, deviceClassesBySegment) : null };
}

function enrichService(
  service: ServiceRecord,
  hostById: Map<string, Host>,
  containerById: Map<string, Container>,
  segmentById: Map<string, NetworkSegment>,
  deviceClassesBySegment?: Map<string, Set<string>>,
): Evaluatable {
  const host = service.host_id ? hostById.get(service.host_id) : undefined;
  const container = service.container_id ? containerById.get(service.container_id) : undefined;
  const effectiveHost = host ?? (container ? hostById.get(container.host_id) : undefined);
  return {
    ...service,
    host: effectiveHost ? enrichHost(effectiveHost, segmentById, deviceClassesBySegment) : null,
    container: container ? enrichContainer(container, hostById, segmentById, deviceClassesBySegment) : null,
  };
}

/**
 * Resolves the owning host id for any asset reference (host/container/service),
 * so a scoped (per-segment) evaluation run can tell whether a given
 * violation belongs to its scope without re-deriving the relation ad hoc
 * at every call site.
 */
function ownerHostId(
  assetType: string,
  assetId: string,
  containerById: Map<string, Container>,
  serviceById: Map<string, ServiceRecord>,
): string | undefined {
  if (assetType === 'host') return assetId;
  if (assetType === 'container') return containerById.get(assetId)?.host_id;
  if (assetType === 'service') {
    const service = serviceById.get(assetId);
    if (!service) return undefined;
    return service.host_id ?? (service.container_id ? containerById.get(service.container_id)?.host_id : undefined);
  }
  return undefined;
}

/**
 * Evaluates all enabled policies against current inventory + configs and
 * persists PolicyViolation rows. Existing open violations for assets that no
 * longer match are marked resolved (idempotent re-evaluation).
 *
 * `scopeHostIds`, when provided, restricts both detection and stale-
 * violation resolution to hosts in that set (and their containers/
 * services) — this is what powers segment-scoped distributed evaluation
 * (see distributedEvaluationEngine.ts): violations outside the scope are
 * left completely untouched by this call, so multiple scoped calls across
 * different host sets are safe to run independently/sequentially without
 * clobbering each other's results.
 */
export async function evaluatePolicies(scopeHostIds?: Set<string>): Promise<PolicyViolation[]> {
  const policies = await query<Policy>('SELECT * FROM policies WHERE enabled = true');
  const { hosts: allHosts, containers: allContainers, services: allServices, hostById, containerById, segmentById, deviceClassesBySegment } =
    await buildEvaluationContext();
  const serviceById = new Map(allServices.map((s) => [s.id, s]));

  const hosts = scopeHostIds ? allHosts.filter((h) => scopeHostIds.has(h.id)) : allHosts;
  const containers = scopeHostIds ? allContainers.filter((c) => scopeHostIds.has(c.host_id)) : allContainers;
  const services = scopeHostIds
    ? allServices.filter((s) => {
        const owner = ownerHostId('service', s.id, containerById, serviceById);
        return owner ? scopeHostIds.has(owner) : false;
      })
    : allServices;

  const freshDetections: Array<{ policy: Policy; assetType: string; assetId: string; details: Record<string, unknown> }> = [];

  for (const policy of policies) {
    const { target } = policy.conditions;
    if (target === 'host') {
      for (const host of hosts) {
        const enriched = enrichHost(host, segmentById, deviceClassesBySegment);
        if (matchesPolicy(enriched, policy)) {
          freshDetections.push({ policy, assetType: 'host', assetId: host.id, details: { hostname: host.hostname } });
        }
      }
    } else if (target === 'container') {
      for (const container of containers) {
        const enriched = enrichContainer(container, hostById, segmentById, deviceClassesBySegment);
        if (matchesPolicy(enriched, policy)) {
          freshDetections.push({ policy, assetType: 'container', assetId: container.id, details: { name: container.name, image: container.image } });
        }
      }
    } else if (target === 'service') {
      for (const service of services) {
        const enriched = enrichService(service, hostById, containerById, segmentById, deviceClassesBySegment);
        if (matchesPolicy(enriched, policy)) {
          freshDetections.push({
            policy,
            assetType: 'service',
            assetId: service.id,
            details: { name: service.name, port: service.port, bind_address: service.bind_address },
          });
        }
      }
    }
  }

  // Resolve violations whose (policy, asset) pair is no longer detected —
  // scoped to in-scope violations only when scopeHostIds is set, so a
  // segment-scoped run never touches another segment's open violations.
  const allOpenViolations = await query<PolicyViolation>("SELECT * FROM policy_violations WHERE status = 'open'");
  const openViolations = scopeHostIds
    ? allOpenViolations.filter((v) => {
        const owner = ownerHostId(v.asset_type, v.asset_id, containerById, serviceById);
        return owner ? scopeHostIds.has(owner) : false;
      })
    : allOpenViolations;

  const freshKeys = new Set(freshDetections.map((d) => `${d.policy.id}:${d.assetType}:${d.assetId}`));
  for (const violation of openViolations) {
    const key = `${violation.policy_id}:${violation.asset_type}:${violation.asset_id}`;
    if (!freshKeys.has(key)) {
      await query('UPDATE policy_violations SET status = $1, resolved_at = now() WHERE id = $2', ['resolved', violation.id]);
    }
  }

  const existingOpenKeys = new Set(openViolations.map((v) => `${v.policy_id}:${v.asset_type}:${v.asset_id}`));
  const results: PolicyViolation[] = [];
  for (const detection of freshDetections) {
    const key = `${detection.policy.id}:${detection.assetType}:${detection.assetId}`;
    if (existingOpenKeys.has(key)) continue; // already recorded and open
    const [row] = await query<PolicyViolation>(
      `INSERT INTO policy_violations (policy_id, asset_type, asset_id, severity, details)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [detection.policy.id, detection.assetType, detection.assetId, detection.policy.severity, JSON.stringify(detection.details)],
    );
    results.push(row);
  }

  return query<PolicyViolation>("SELECT * FROM policy_violations WHERE status = 'open' ORDER BY detected_at DESC");
}
