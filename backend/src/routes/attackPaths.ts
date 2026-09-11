import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';
import type { Host, ServiceRecord } from '../types/models.js';

const ICS_PROTOCOL_FAMILIES = new Set(['modbus', 's7', 'bacnet', 'opcua']);

/**
 * Derives which "layer" a graph node belongs to for multi-layer rendering
 * (network / container / services / ICS / cloud / DevOps) — hosts use
 * their device_class, services use protocol_family when it identifies a
 * specialized protocol, otherwise nodes fall back to their base asset
 * type as the layer.
 */
function layerFor(assetType: string, hostById: Map<string, Host>, serviceById: Map<string, ServiceRecord>, id: string): string {
  if (assetType === 'host') return hostById.get(id)?.device_class ?? 'it';
  if (assetType === 'service') {
    const family = serviceById.get(id)?.protocol_family;
    if (family && ICS_PROTOCOL_FAMILIES.has(family)) return 'ics';
    if (family === 'cloud-metadata') return 'cloud';
    if (family === 'devops') return 'devops';
    return 'service';
  }
  return assetType; // container | network
}

export async function attackPathRoutes(app: FastifyInstance) {
  app.get('/attack-paths', async (req) => {
    const { severity } = req.query as Record<string, string | undefined>;
    if (severity) return query('SELECT * FROM attack_paths WHERE severity = $1 ORDER BY blast_radius DESC', [severity]);
    return query('SELECT * FROM attack_paths ORDER BY blast_radius DESC');
  });

  app.get('/attack-paths/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = await queryOne('SELECT * FROM attack_paths WHERE id = $1', [id]);
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });

  // Flattened nodes/edges for multi-layer graph rendering in the frontend.
  app.get('/attack-paths/graph', async () => {
    const paths = await query<any>('SELECT * FROM attack_paths');
    const hosts = await query<Host>('SELECT * FROM hosts');
    const services = await query<ServiceRecord>('SELECT * FROM services');
    const hostById = new Map(hosts.map((h) => [h.id, h]));
    const serviceById = new Map(services.map((s) => [s.id, s]));

    const nodes = new Map<string, { id: string; type: string; layer: string }>();
    const edges: Array<{ source: string; target: string; via: string; severity: string; path_id: string }> = [];

    for (const path of paths) {
      const addNode = (type: string, id: string) => nodes.set(`${type}:${id}`, { id: `${type}:${id}`, type, layer: layerFor(type, hostById, serviceById, id) });
      addNode(path.entry_asset_type, path.entry_asset_id);
      let prev = `${path.entry_asset_type}:${path.entry_asset_id}`;
      for (const hop of path.hops as Array<{ asset_type: string; asset_id: string; via: string }>) {
        addNode(hop.asset_type, hop.asset_id);
        const current = `${hop.asset_type}:${hop.asset_id}`;
        edges.push({ source: prev, target: current, via: hop.via, severity: path.severity, path_id: path.id });
        prev = current;
      }
    }

    return { nodes: Array.from(nodes.values()), edges };
  });
}
