import { collectHost } from './collectors/hostCollector.js';
import { collectNetworkInterfaces, collectRoutes, deriveSubnets } from './collectors/networkCollector.js';
import { collectContainers } from './collectors/dockerCollector.js';
import { collectServices } from './collectors/serviceCollector.js';
import { scanSubnet, type DiscoveredDevice } from './collectors/subnetScanner.js';
import { backendApi } from './services/apiClient.js';

const POLL_INTERVAL_MS = Number(process.env.WORKER_POLL_INTERVAL_MS ?? 60_000);
const SUBNET_SCAN_ENABLED = process.env.WORKER_SUBNET_SCAN_ENABLED !== 'false';

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
};

function inferDeviceRole(device: DiscoveredDevice): string {
  if (device.openPorts.includes(3389) || device.openPorts.includes(445)) return 'windows-device';
  if (device.openPorts.includes(22)) return 'linux-device';
  if (device.openPorts.includes(9100)) return 'printer';
  if (device.openPorts.includes(62078)) return 'mobile-device';
  return 'device';
}

async function registerDiscoveredDevice(device: DiscoveredDevice, segmentId: string): Promise<void> {
  const host = await backendApi.upsertHost({
    hostname: device.hostname ?? device.ip,
    ip_address: device.ip,
    role: inferDeviceRole(device),
    criticality: 'medium',
    network_segment_id: segmentId,
  });
  const hostId = (host as { id: string }).id;

  for (const port of device.openPorts) {
    await backendApi.upsertService({
      host_id: hostId,
      name: PORT_NAMES[port] ?? `port-${port}`,
      port,
      protocol: 'tcp',
      bind_address: device.ip,
      exposed_publicly: true,
    });
  }
}

async function sweepSubnet(cidr: string, description: string, excludeIp: string | null): Promise<void> {
  const segment = await backendApi.upsertNetworkSegment({
    name: `subnet-${cidr}`,
    cidr,
    zone: 'internal',
    description,
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

async function runCollectionCycle(): Promise<void> {
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
  if (subnets.length > 0) {
    const primarySubnet = subnets[0];
    const segment = await backendApi.upsertNetworkSegment({
      name: `subnet-${primarySubnet}`,
      cidr: primarySubnet,
      zone: 'internal',
      description: `Auto-discovered from ${hostInfo.hostname}'s network interfaces`,
    });
    const segmentId = (segment as { id: string }).id;
    await backendApi.upsertHost({ ...hostInfo, network_segment_id: segmentId });
    console.log(`[worker] linked host to network segment ${primarySubnet} (${segmentId})`);

    if (SUBNET_SCAN_ENABLED) {
      // Exclude the worker's own IP — it's already tracked as the "worker"
      // host above; without this it would also show up as a generic
      // "device" duplicate of itself.
      await sweepSubnet(primarySubnet, `Auto-discovered from ${hostInfo.hostname}'s network interfaces`, hostInfo.ip_address as string | null);
    }
  }

  if (SUBNET_SCAN_ENABLED && EXPLICIT_SCAN_SUBNETS.length > 0) {
    for (const cidr of EXPLICIT_SCAN_SUBNETS) {
      if (subnets.includes(cidr)) continue; // already swept above
      await sweepSubnet(cidr, 'Configured via WORKER_SCAN_SUBNETS', null);
    }
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
    await backendApi.submitConfigSnapshot({
      asset_type: 'container',
      asset_id: (created as { id: string }).id,
      kind: 'docker',
      data: container,
    });
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
}

async function loop(): Promise<void> {
  try {
    await runCollectionCycle();
  } catch (err) {
    console.error('[worker] collection cycle failed', err);
  } finally {
    setTimeout(loop, POLL_INTERVAL_MS);
  }
}

loop();
