import type { FastifyInstance } from 'fastify';
import { query, queryOne } from '../db/pool.js';
import os from 'node:os';

async function ensureDependency(sourceType: string, sourceId: string, targetType: string, targetId: string, relation: string): Promise<void> {
  const existing = await queryOne(
    'SELECT id FROM dependencies WHERE source_asset_type = $1 AND source_asset_id = $2 AND target_asset_type = $3 AND target_asset_id = $4 AND relation = $5',
    [sourceType, sourceId, targetType, targetId, relation],
  );
  if (existing) return;
  await query(
    'INSERT INTO dependencies (source_asset_type, source_asset_id, target_asset_type, target_asset_id, relation) VALUES ($1,$2,$3,$4,$5)',
    [sourceType, sourceId, targetType, targetId, relation],
  );
}

async function linkServiceDependencies(service: { id: string; host_id?: string | null; container_id?: string | null }): Promise<void> {
  if (service.container_id) await ensureDependency('service', service.id, 'container', service.container_id, 'runs_on');
  else if (service.host_id) await ensureDependency('service', service.id, 'host', service.host_id, 'runs_on');
}

export async function assetRoutes(app: FastifyInstance) {
  // ---- Hosts ----
  app.get('/assets/hosts', async () => query('SELECT * FROM hosts ORDER BY hostname'));

  app.get('/assets/hosts/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const host = await queryOne('SELECT * FROM hosts WHERE id = $1', [id]);
    if (!host) return reply.code(404).send({ error: 'not_found' });
    return host;
  });

  // Upserts by hostname so repeated worker collection cycles update the
  // same host row instead of creating duplicates.
  app.post('/assets/hosts', async (req, reply) => {
    const b = req.body as Record<string, unknown>;
    const existing = await queryOne<{ id: string }>('SELECT id FROM hosts WHERE hostname = $1', [b.hostname]);
    if (existing) {
      const row = await queryOne(
        `UPDATE hosts SET os = COALESCE($1, os), os_version = COALESCE($2, os_version), ip_address = COALESCE($3, ip_address),
          role = COALESCE($4, role), criticality = COALESCE($5, criticality), network_segment_id = COALESCE($6, network_segment_id),
          device_class = COALESCE($7, device_class), last_seen = now(), updated_at = now()
         WHERE id = $8 RETURNING *`,
        [
          b.os ?? null,
          b.os_version ?? null,
          b.ip_address ?? null,
          b.role ?? null,
          b.criticality ?? null,
          b.network_segment_id ?? null,
          b.device_class ?? null,
          existing.id,
        ],
      );
      if (row?.network_segment_id) await ensureDependency('host', row.id, 'network', row.network_segment_id, 'member_of');
      return reply.code(200).send(row);
    }
    const row = await queryOne(
      `INSERT INTO hosts (hostname, os, os_version, ip_address, role, network_segment_id, criticality, device_class, last_seen)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now()) RETURNING *`,
      [
        b.hostname,
        b.os ?? null,
        b.os_version ?? null,
        b.ip_address ?? null,
        b.role ?? 'generic',
        b.network_segment_id ?? null,
        b.criticality ?? 'medium',
        b.device_class ?? 'it',
      ],
    );
    if (row?.network_segment_id) await ensureDependency('host', row.id, 'network', row.network_segment_id, 'member_of');
    return reply.code(201).send(row);
  });

  app.patch('/assets/hosts/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const b = req.body as Record<string, unknown>;
    const row = await queryOne(
      `UPDATE hosts SET hostname = COALESCE($1, hostname), os = COALESCE($2, os), os_version = COALESCE($3, os_version),
        ip_address = COALESCE($4, ip_address), role = COALESCE($5, role), criticality = COALESCE($6, criticality),
        device_class = COALESCE($7, device_class), last_seen = now(), updated_at = now() WHERE id = $8 RETURNING *`,
      [b.hostname ?? null, b.os ?? null, b.os_version ?? null, b.ip_address ?? null, b.role ?? null, b.criticality ?? null, b.device_class ?? null, id],
    );
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });

  // ---- Containers ----
  app.get('/assets/containers', async () => query('SELECT * FROM containers ORDER BY name'));

  app.get('/assets/containers/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = await queryOne('SELECT * FROM containers WHERE id = $1', [id]);
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });

  // Upserts by (host_id, name) so repeated worker collection cycles update
  // the same container row instead of creating duplicates.
  app.post('/assets/containers', async (req, reply) => {
    const b = req.body as Record<string, unknown>;
    const existing = await queryOne<{ id: string }>('SELECT id FROM containers WHERE host_id = $1 AND name = $2', [b.host_id, b.name]);
    if (existing) {
      const row = await queryOne(
        `UPDATE containers SET image = $1, image_tag = $2, status = $3, ports = $4, privileged = $5, updated_at = now()
         WHERE id = $6 RETURNING *`,
        [b.image, b.image_tag ?? null, b.status ?? 'running', JSON.stringify(b.ports ?? []), b.privileged ?? false, existing.id],
      );
      if (row?.host_id) await ensureDependency('container', row.id, 'host', row.host_id, 'runs_on');
      return reply.code(200).send(row);
    }
    const row = await queryOne(
      `INSERT INTO containers (host_id, name, image, image_tag, status, ports, privileged)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [b.host_id, b.name, b.image, b.image_tag ?? null, b.status ?? 'running', JSON.stringify(b.ports ?? []), b.privileged ?? false],
    );
    if (row?.host_id) await ensureDependency('container', row.id, 'host', row.host_id, 'runs_on');
    return reply.code(201).send(row);
  });

  // ---- Services ----
  app.get('/assets/services', async () => query('SELECT * FROM services ORDER BY port'));

  app.get('/assets/services/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = await queryOne('SELECT * FROM services WHERE id = $1', [id]);
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });

  // Upserts by (host_id, container_id, port) so repeated worker collection
  // cycles update the same service row instead of creating duplicates.
  app.post('/assets/services', async (req, reply) => {
    const b = req.body as Record<string, unknown>;
    const existing = await queryOne<{ id: string }>(
      'SELECT id FROM services WHERE host_id IS NOT DISTINCT FROM $1 AND container_id IS NOT DISTINCT FROM $2 AND port = $3',
      [b.host_id ?? null, b.container_id ?? null, b.port],
    );
    if (existing) {
      const row = await queryOne(
        `UPDATE services SET name = $1, protocol = $2, bind_address = $3, banner = $4, version = $5, exposed_publicly = $6,
          protocol_family = COALESCE($7, protocol_family), updated_at = now()
         WHERE id = $8 RETURNING *`,
        [
          b.name,
          b.protocol ?? 'tcp',
          b.bind_address ?? '0.0.0.0',
          b.banner ?? null,
          b.version ?? null,
          b.exposed_publicly ?? false,
          b.protocol_family ?? null,
          existing.id,
        ],
      );
      await linkServiceDependencies(row);
      return reply.code(200).send(row);
    }
    const row = await queryOne(
      `INSERT INTO services (host_id, container_id, name, port, protocol, bind_address, banner, version, exposed_publicly, protocol_family)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [
        b.host_id ?? null,
        b.container_id ?? null,
        b.name,
        b.port,
        b.protocol ?? 'tcp',
        b.bind_address ?? '0.0.0.0',
        b.banner ?? null,
        b.version ?? null,
        b.exposed_publicly ?? false,
        b.protocol_family ?? null,
      ],
    );
    await linkServiceDependencies(row);
    return reply.code(201).send(row);
  });

  // ---- Network segments ----
  app.get('/assets/network', async () => query('SELECT * FROM network_segments ORDER BY name'));

  app.get('/assets/network/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = await queryOne('SELECT * FROM network_segments WHERE id = $1', [id]);
    if (!row) return reply.code(404).send({ error: 'not_found' });
    return row;
  });

  // Upserts by name so repeated worker collection cycles update the same
  // segment row instead of hitting the unique-name constraint.
  app.post('/assets/network', async (req, reply) => {
    const b = req.body as Record<string, unknown>;
    const existing = await queryOne<{ id: string }>('SELECT id FROM network_segments WHERE name = $1', [b.name]);
    if (existing) {
      const row = await queryOne(
        `UPDATE network_segments SET cidr = COALESCE($1, cidr), zone = COALESCE($2, zone), description = COALESCE($3, description)
         WHERE id = $4 RETURNING *`,
        [b.cidr ?? null, b.zone ?? null, b.description ?? null, existing.id],
      );
      return reply.code(200).send(row);
    }
    const row = await queryOne(
      `INSERT INTO network_segments (name, cidr, zone, description) VALUES ($1,$2,$3,$4) RETURNING *`,
      [b.name, b.cidr, b.zone ?? 'internal', b.description ?? null],
    );
    return reply.code(201).send(row);
  });

  // ---- Dependencies ----
  app.get('/assets/dependencies', async () => query('SELECT * FROM dependencies'));

  app.post('/assets/dependencies', async (req, reply) => {
    const b = req.body as Record<string, unknown>;
    const row = await queryOne(
      `INSERT INTO dependencies (source_asset_type, source_asset_id, target_asset_type, target_asset_id, relation)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [b.source_asset_type, b.source_asset_id, b.target_asset_type, b.target_asset_id, b.relation ?? 'connects_to'],
    );
    return reply.code(201).send(row);
  });

  // ---- Local discovery stub ----
  app.post('/assets/discover', async () => {
    return {
      hostname: os.hostname(),
      platform: os.platform(),
      release: os.release(),
      network_interfaces: os.networkInterfaces(),
    };
  });
}
