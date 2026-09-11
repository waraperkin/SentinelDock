import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';

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

  // Flattened nodes/edges for graph rendering in the frontend.
  app.get('/attack-paths/graph', async () => {
    const paths = await query<any>('SELECT * FROM attack_paths');
    const nodes = new Map<string, { id: string; type: string }>();
    const edges: Array<{ source: string; target: string; via: string; severity: string; path_id: string }> = [];

    for (const path of paths) {
      const addNode = (type: string, id: string) => nodes.set(`${type}:${id}`, { id: `${type}:${id}`, type });
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
