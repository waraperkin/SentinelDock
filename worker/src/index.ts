import { collectHost } from './collectors/hostCollector.js';
import { collectNetworkInterfaces, collectRoutes, deriveSubnets } from './collectors/networkCollector.js';
import { collectContainers } from './collectors/dockerCollector.js';
import { collectServices } from './collectors/serviceCollector.js';
import { backendApi } from './services/apiClient.js';

const POLL_INTERVAL_MS = Number(process.env.WORKER_POLL_INTERVAL_MS ?? 60_000);

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
