import { collectHost } from './collectors/hostCollector.js';
import { collectNetworkInterfaces, collectRoutes, deriveSubnets } from './collectors/networkCollector.js';
import { collectContainers, collectContainerEnv } from './collectors/dockerCollector.js';
import { collectServices } from './collectors/serviceCollector.js';
import { scanSubnet, type DiscoveredDevice } from './collectors/subnetScanner.js';
import { scanIcsProtocols, classifyIcsDevice } from './collectors/icsScanner.js';
import { scanCloudMetadata } from './collectors/cloudMetadataScanner.js';
import { readArpTable } from './collectors/arpScanner.js';
import { scanTextForSecrets } from './collectors/secretsScanner.js';
import { scanSnmp } from './collectors/snmpScanner.js';
import { scanNetbios } from './collectors/netbiosScanner.js';
import { discoverMdnsServices } from './collectors/mdnsScanner.js';
import { httpRecon } from './collectors/httpReconScanner.js';
import { backendApi } from './services/apiClient.js';
import { withCollectionCycleLock, workerId } from './services/distributedLock.js';

const HTTP_LIKE_PORTS = new Set([80, 443, 8080, 8443]);

const POLL_INTERVAL_MS = Number(process.env.WORKER_POLL_INTERVAL_MS ?? 60_000);
const SUBNET_SCAN_ENABLED = process.env.WORKER_SUBNET_SCAN_ENABLED !== 'false';
const ICS_SCAN_ENABLED = process.env.WORKER_ICS_SCAN_ENABLED !== 'false';
const SECRETS_SCAN_ENABLED = process.env.WORKER_SECRETS_SCAN_ENABLED !== 'false';
const SNMP_SCAN_ENABLED = process.env.WORKER_SNMP_SCAN_ENABLED !== 'false';
const MDNS_SCAN_ENABLED = process.env.WORKER_MDNS_SCAN_ENABLED !== 'false';

// Auto-derived subnets come from the container's own network interfaces,
// which on the default Docker bridge network is always the bridge's
// internal range (e.g. 172.18.0.0/24) — never the real LAN/VLANs the host
// machine sits on. WORKER_SCAN_SUBNETS lets you point the sweep at your
// actual subnets explicitly; this works even without host networking mode
// as long as the container can route to them (Docker Desktop typically
// NATs outbound LAN traffic through the host, so this often just works).
const EXPLICIT_SCAN_SUBNETS = (process.env.WORKER_SCAN_SUBNETS ?? '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const PORT_NAMES: Record<number, string> = {
  22: 'ssh',
  80: 'http',
  443: 'https',
  445: 'smb',
  3389: 'rdp',
  8080: 'http-alt',
  8443: 'https-alt',
  9100: 'printer',
  62078: 'ios-sync',
  502: 'modbus',
  102: 's7comm',
  4840: 'opcua',
  47808: 'bacnet',
};

const ICS_PORTS = new Set([502, 102, 4840, 47808]);

function inferDeviceRole(device: DiscoveredDevice): string {
  if (device.openPorts.some((p) => ICS_PORTS.has(p))) return 'ics-device';
  if (device.openPorts.includes(3389) || device.openPorts.includes(445)) return 'windows-device';
  if (device.openPorts.includes(22)) return 'linux-device';
  if (device.openPorts.includes(9100)) return 'printer';
  if (device.openPorts.includes(62078)) return 'mobile-device';
  return 'device';
}

async function registerDiscoveredDevice(device: DiscoveredDevice, segmentId: string): Promise<void> {
  const hasIcsPort = device.openPorts.some((p) => ICS_PORTS.has(p));
  // Confirm with a real protocol handshake before classifying as ICS/OT —
  // an open port alone (e.g. something else listening on 502) isn't
  // enough evidence to label a device as industrial equipment.
  const icsProtocols = ICS_SCAN_ENABLED && hasIcsPort ? await scanIcsProtocols(device.ip) : [];
  const deviceClass = icsProtocols.length > 0 ? 'ics' : 'it';
  const otherPorts = device.openPorts.filter((p) => !ICS_PORTS.has(p));
  const icsRole = icsProtocols.length > 0 ? classifyIcsDevice(icsProtocols, otherPorts) : null;

  // Enrichment probes (SNMP sysDescr, NetBIOS name) — only run against
  // devices already confirmed alive by the TCP sweep, never against the
  // full /24 address space, to keep sweep time bounded.
  const [snmp, netbios] = await Promise.all([
    SNMP_SCAN_ENABLED ? scanSnmp(device.ip).catch(() => null) : Promise.resolve(null),
    scanNetbios(device.ip).catch(() => null),
  ]);

  const host = await backendApi.upsertHost({
    hostname: netbios?.name ?? device.hostname ?? device.ip,
    ip_address: device.ip,
    os: snmp?.sysDescr ?? null,
    role: icsRole ?? inferDeviceRole(device),
    criticality: deviceClass === 'ics' ? 'high' : 'medium',
    device_class: deviceClass,
    network_segment_id: segmentId,
  });
  const hostId = (host as { id: string }).id;
  const confirmedIcsPorts = new Map(icsProtocols.map((p) => [p.port, p]));

  if (snmp) {
    await backendApi.submitConfigSnapshot({ asset_type: 'host', asset_id: hostId, kind: 'snmp', data: snmp });
  }

  for (const port of device.openPorts) {
    const ics = confirmedIcsPorts.get(port);
    let name = ics?.name ?? PORT_NAMES[port] ?? `port-${port}`;
    let protocolFamily: string | null = ics?.protocolFamily ?? null;

    if (!ics && HTTP_LIKE_PORTS.has(port)) {
      const recon = await httpRecon(device.ip, port).catch(() => []);
      const jenkins = recon.find((r) => r.finding === 'jenkins');
      const gitExposed = recon.find((r) => r.finding === 'git-exposed');
      if (jenkins) {
        name = 'jenkins';
        protocolFamily = 'devops';
        console.log(`[worker] HTTP recon: Jenkins identified at ${device.ip}:${port}`);
      } else if (gitExposed) {
        name = 'git-exposed';
        protocolFamily = 'devops';
        console.log(`[worker] HTTP recon: exposed .git found at ${device.ip}:${port}`);
      }
    }

    await backendApi.upsertService({
      host_id: hostId,
      name,
      port,
      protocol: 'tcp',
      bind_address: device.ip,
      exposed_publicly: true,
      protocol_family: protocolFamily,
    });
  }
}

async function sweepSubnet(cidr: string, description: string, excludeIp: string | null, gateway: string | null): Promise<void> {
  const segment = await backendApi.upsertNetworkSegment({
    name: `subnet-${cidr}`,
    cidr,
    zone: 'internal',
    description: gateway ? `${description} (gateway ${gateway})` : description,
  });
  const segmentId = (segment as { id: string }).id;

  console.log(`[worker] sweeping ${cidr} for devices...`);
  const rawDevices = await scanSubnet(cidr);
  const devices = excludeIp ? rawDevices.filter((d) => d.ip !== excludeIp) : rawDevices;
  console.log(`[worker] discovered ${devices.length} device(s) on ${cidr}`);
  for (const device of devices) {
    await registerDiscoveredDevice(device, segmentId);
  }
}

/** Cross-checks the kernel's ARP table against the current sweep — surfaces devices with recent traffic that the active TCP sweep found no open ports on. */
async function crossCheckArpTable(segmentId: string, alreadyKnownIps: Set<string>): Promise<void> {
  const entries = await readArpTable();
  const newEntries = entries.filter((e) => !alreadyKnownIps.has(e.ip));
  if (newEntries.length === 0) return;
  console.log(`[worker] ARP table cross-check found ${newEntries.length} additional device(s) with no open probed ports`);
  for (const entry of newEntries) {
    await backendApi.upsertHost({
      hostname: entry.ip,
      ip_address: entry.ip,
      role: 'device',
      criticality: 'low',
      device_class: 'it',
      network_segment_id: segmentId,
    });
  }
}

async function scanContainerSecrets(containerId: string, containerAssetId: string): Promise<void> {
  const env = await collectContainerEnv(containerId);
  const findings: Array<Record<string, unknown>> = [];
  for (const entry of env) {
    const [key, ...rest] = entry.split('=');
    const value = rest.join('=');
    for (const match of scanTextForSecrets(value)) {
      findings.push({
        asset_type: 'container',
        asset_id: containerAssetId,
        kind: match.kind,
        match_preview: match.matchPreview,
        source: `container_env:${key}`,
        severity: match.severity,
      });
    }
  }
  if (findings.length > 0) {
    console.log(`[worker] found ${findings.length} potential secret(s) in container env vars`);
    await backendApi.submitSecretFindings(findings);
  }
}

async function checkCloudMetadataExposure(hostId: string): Promise<void> {
  const results = await scanCloudMetadata();
  let strongestEvidence = false;
  for (const result of results) {
    console.log(
      `[worker] cloud metadata endpoint reachable: ${result.provider}${result.iamRoleName ? ` (IAM role enumerated: ${result.iamRoleName})` : ''}`,
    );
    await backendApi.upsertService({
      host_id: hostId,
      name: `cloud-metadata-${result.provider}`,
      port: 80,
      protocol: 'tcp',
      bind_address: '169.254.169.254',
      exposed_publicly: true,
      protocol_family: 'cloud-metadata',
    });
    if (result.iamRoleName) {
      strongestEvidence = true;
      await backendApi.submitConfigSnapshot({
        asset_type: 'host',
        asset_id: hostId,
        kind: 'cloud-iam',
        data: { provider: result.provider, role_name: result.iamRoleName, instance_type: result.instanceType },
      });
    }
  }
  if (results.length > 0) {
    // An enumerated role name is materially stronger evidence than mere
    // reachability (it proves an instance profile/service account is
    // actually attached, not just that the network path is open), so it
    // escalates the host to critical criticality for downstream scoring.
    await backendApi.patchHost(hostId, { device_class: 'cloud', criticality: strongestEvidence ? 'critical' : undefined });
  }
}

/** Real mDNS (RFC 6762) service enumeration — registers each responder as a device with its advertised service types as informational services. */
async function discoverMdnsResponders(segmentId: string): Promise<void> {
  const responders = await discoverMdnsServices();
  if (responders.length === 0) return;
  console.log(`[worker] mDNS discovery found ${responders.length} responder(s)`);
  for (const responder of responders) {
    const host = await backendApi.upsertHost({
      hostname: responder.ip,
      ip_address: responder.ip,
      role: 'device',
      criticality: 'low',
      device_class: 'it',
      network_segment_id: segmentId,
    });
    const hostId = (host as { id: string }).id;
    await backendApi.submitConfigSnapshot({ asset_type: 'host', asset_id: hostId, kind: 'mdns', data: { services: responder.services } });
  }
}

/** Finds the default/most-specific route's gateway for a given subnet, for a more informative segment description ("dynamic segmentation" by gateway). */
function findGatewayForSubnet(routes: Array<{ destination: string; gateway: string | null }>, cidr: string): string | null {
  const base = cidr.split('/')[0];
  const prefix = base.split('.').slice(0, 3).join('.');
  const specific = routes.find((r) => r.destination.startsWith(prefix) && r.gateway);
  if (specific?.gateway) return specific.gateway;
  return routes.find((r) => r.destination === 'default' && r.gateway)?.gateway ?? null;
}

async function runCollectionCycle(): Promise<unknown> {
  console.log('[worker] starting collection cycle');

  const hostInfo = collectHost();
  const host = await backendApi.upsertHost(hostInfo);
  const hostId = (host as { id: string }).id;
  console.log(`[worker] registered host ${hostInfo.hostname} (${hostId})`);

  await backendApi.submitConfigSnapshot({
    asset_type: 'host',
    asset_id: hostId,
    kind: 'os',
    data: hostInfo,
  });

  const interfaces = collectNetworkInterfaces();
  const routes = await collectRoutes();
  await backendApi.submitConfigSnapshot({
    asset_type: 'host',
    asset_id: hostId,
    kind: 'network',
    data: { interfaces, routes },
  });

  const subnets = deriveSubnets(interfaces);
  let primarySegmentId: string | null = null;
  const knownDeviceIps = new Set<string>([hostInfo.ip_address as string]);

  if (subnets.length > 0) {
    const primarySubnet = subnets[0];
    const gateway = findGatewayForSubnet(routes, primarySubnet);
    const segment = await backendApi.upsertNetworkSegment({
      name: `subnet-${primarySubnet}`,
      cidr: primarySubnet,
      zone: 'internal',
      description: gateway
        ? `Auto-discovered from ${hostInfo.hostname}'s network interfaces (gateway ${gateway})`
        : `Auto-discovered from ${hostInfo.hostname}'s network interfaces`,
    });
    primarySegmentId = (segment as { id: string }).id;
    await backendApi.upsertHost({ ...hostInfo, network_segment_id: primarySegmentId });
    console.log(`[worker] linked host to network segment ${primarySubnet} (${primarySegmentId})`);

    if (SUBNET_SCAN_ENABLED) {
      // Exclude the worker's own IP — it's already tracked as the "worker"
      // host above; without this it would also show up as a generic
      // "device" duplicate of itself.
      await sweepSubnet(primarySubnet, `Auto-discovered from ${hostInfo.hostname}'s network interfaces`, hostInfo.ip_address as string | null, gateway);
    }
  }

  if (SUBNET_SCAN_ENABLED && EXPLICIT_SCAN_SUBNETS.length > 0) {
    for (const cidr of EXPLICIT_SCAN_SUBNETS) {
      if (subnets.includes(cidr)) continue; // already swept above
      await sweepSubnet(cidr, 'Configured via WORKER_SCAN_SUBNETS', null, findGatewayForSubnet(routes, cidr));
    }
  }

  if (SUBNET_SCAN_ENABLED && primarySegmentId) {
    await crossCheckArpTable(primarySegmentId, knownDeviceIps);
  }

  await checkCloudMetadataExposure(hostId);

  if (MDNS_SCAN_ENABLED && primarySegmentId) {
    await discoverMdnsResponders(primarySegmentId);
  }

  const containers = await collectContainers();
  console.log(`[worker] discovered ${containers.length} container(s)`);
  for (const container of containers) {
    const created = await backendApi.upsertContainer({
      host_id: hostId,
      name: container.name,
      image: container.image,
      status: container.status,
      ports: container.ports,
      privileged: container.privileged,
    });
    const createdId = (created as { id: string }).id;
    await backendApi.submitConfigSnapshot({
      asset_type: 'container',
      asset_id: createdId,
      kind: 'docker',
      data: container,
    });
    if (SECRETS_SCAN_ENABLED) {
      await scanContainerSecrets(container.id, createdId);
    }
  }

  const services = await collectServices();
  console.log(`[worker] discovered ${services.length} listening service(s)`);
  for (const service of services) {
    const created = await backendApi.upsertService({
      host_id: hostId,
      name: service.name,
      port: service.port,
      protocol: service.protocol,
      bind_address: service.bind_address,
      banner: service.banner,
      version: service.version,
      exposed_publicly: service.exposed_publicly,
    });
    await backendApi.submitConfigSnapshot({
      asset_type: 'service',
      asset_id: (created as { id: string }).id,
      kind: 'service',
      data: service,
    });
  }

  const summary = await backendApi.triggerEvaluation();
  console.log('[worker] evaluation complete', summary);
  return summary;
}

async function sendHeartbeat(isLeader: boolean, lastCycleSummary: unknown): Promise<void> {
  try {
    await backendApi.heartbeat({
      worker_id: workerId(),
      hostname: process.env.WORKER_HOSTNAME_OVERRIDE?.trim() || 'sentineldock-worker',
      is_leader: isLeader,
      last_cycle_summary: lastCycleSummary ?? null,
    });
  } catch (err) {
    console.warn('[worker] heartbeat failed (non-fatal)', (err as Error).message);
  }
}

async function loop(): Promise<void> {
  try {
    // Coordinates across horizontally-scaled worker replicas via Redis so
    // only one replica runs a given cycle (see distributedLock.ts). The
    // lock TTL is generously longer than the poll interval so a slow cycle
    // never causes two replicas to run concurrently. Every replica still
    // heartbeats every tick (leader or not) so /workers shows the full
    // fleet, not just whichever one is currently active.
    const result = await withCollectionCycleLock(POLL_INTERVAL_MS * 2, runCollectionCycle);
    const isLeader = result !== 'skipped-not-leader';
    await sendHeartbeat(isLeader, isLeader ? result : null);
  } catch (err) {
    console.error('[worker] collection cycle failed', err);
    await sendHeartbeat(false, null);
  } finally {
    setTimeout(loop, POLL_INTERVAL_MS);
  }
}

console.log(`[worker] starting (id=${workerId()})`);
loop();
