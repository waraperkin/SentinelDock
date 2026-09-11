# SentinelDock — Unified Infra & Security Control Plane

SentinelDock is a Dockerized control plane for infrastructure and security
posture management. It maintains an asset inventory (hosts, containers,
services, network segments), collects configuration snapshots, evaluates
policies against that inventory, derives risks and attack paths, and
generates incident-response playbooks.

## Architecture

```
                    ┌─────────────────┐
                    │   Frontend      │  Next.js console (port 3000)
                    │  (Next.js TS)   │  reads from backend REST API
                    └────────┬────────┘
                             │ HTTP
                    ┌────────▼────────┐
                    │    Backend      │  Fastify REST API (port 4000)
                    │  (Fastify TS)   │  policy/risk/attack-path/incident
                    └───┬────────┬────┘  engines
                        │        │
              ┌─────────▼─┐   ┌──▼──────┐
              │ PostgreSQL │   │  Redis  │  cache / future job queue
              └─────────▲─┘   └─────────┘
                        │ HTTP (ingest + trigger evaluation)
                    ┌───┴─────────────┐
                    │     Worker      │  Node.js collector, polls
                    │  (Node.js TS)   │  host/docker/network/services
                    └─────────────────┘  every WORKER_POLL_INTERVAL_MS
```

- **backend/** — Fastify + TypeScript. Owns the data model, REST API,
  policy evaluation engine, risk engine, attack-path builder and incident
  scenario generator.
- **worker/** — Node.js + TypeScript. Periodically collects host OS info,
  Docker containers (via the Docker Engine API over the unix socket),
  network interfaces, and listening services (TCP probe of common ports),
  then POSTs normalized data to the backend and triggers evaluation.
- **frontend/** — Next.js (App Router) + TypeScript + Tailwind. Dashboard,
  inventory, policies, risks, attack-path graph, and incident scenario
  views.
- **db/migrations/** — plain numbered SQL files, applied automatically by
  the official `postgres` image on first boot (mounted as
  `docker-entrypoint-initdb.d`).
- **policies/** — human-editable example policies in YAML (the backend
  seeds an equivalent JSON copy of these via `002_seed_policies.sql`).

## Data model

| Entity | Purpose |
|---|---|
| `network_segments` | Named CIDR zones (internal/dmz/public/management) |
| `hosts` | Physical/virtual hosts, role, criticality, segment |
| `containers` | Docker containers on a host, image, ports, privileged flag |
| `services` | Listening services on a host or container, port, exposure |
| `dependencies` | Directed edges between any two assets (source → target) |
| `config_snapshots` | Immutable, versioned config blobs per asset (`kind`: os/docker/network/service) |
| `policies` | Policy definitions (see format below) |
| `policy_violations` | Detected breaches of a policy against an asset |
| `risks` | Aggregated risk per asset, scored from open violations + criticality |
| `attack_paths` | Heuristic graph paths from an exposed entry point to a target asset |
| `incident_scenarios` | Generated markdown playbooks for high/critical risks |

## API reference

All endpoints are served by the backend on `BACKEND_PORT` (default 4000).

### Assets
- `GET /assets/hosts` / `GET /assets/hosts/:id` / `POST /assets/hosts` / `PATCH /assets/hosts/:id`
- `GET /assets/containers` / `GET /assets/containers/:id` / `POST /assets/containers`
- `GET /assets/services` / `GET /assets/services/:id` / `POST /assets/services`
- `GET /assets/network` / `GET /assets/network/:id` / `POST /assets/network`
- `GET /assets/dependencies` / `POST /assets/dependencies`
- `POST /assets/discover` — basic local discovery stub (hostname, platform, network interfaces of the backend container itself)

### Configs
- `GET /configs?asset_type=&asset_id=&kind=` — list versioned config snapshots
- `GET /configs/:id`
- `POST /configs` — ingest a new immutable snapshot `{ asset_type, asset_id, kind, data, collected_at? }`

### Policies & violations
- `GET /policies` / `GET /policies/:id` / `POST /policies` / `PATCH /policies/:id` / `DELETE /policies/:id`
- `POST /policies/evaluate` — runs the full pipeline: violations → risks → attack paths → incident scenarios. Returns counts.
- `GET /violations?status=&severity=&asset_type=` / `GET /violations/:id` / `PATCH /violations/:id` (update `status`)

### Risks
- `GET /risks?severity=&category=&asset_type=`
- `GET /risks/:id`
- `GET /risks/global-score` — average score across all current risks

### Attack paths
- `GET /attack-paths?severity=`
- `GET /attack-paths/:id`
- `GET /attack-paths/graph` — flattened `{ nodes, edges }` for the frontend graph view

### Incident scenarios
- `GET /incident-scenarios?severity=`
- `GET /incident-scenarios/:id`

### Dashboard
- `GET /dashboard/summary` — asset counts, global risk score, open violation count, incident scenario count

## Policy format

Policies live in `policies/*.yaml` (human-editable source) and are stored
in the `policies` table as JSON in the `conditions` column. A policy
targets one asset type and evaluates a small condition DSL against it
(and, for containers/services, against the host/segment it's attached to
— fields like `host.role` or `host.network_segment.zone` are available).

```yaml
key: ssh-exposed-public
name: SSH exposed to the public internet
description: >
  Detects any service on port 22 bound to a wildcard address and marked as
  publicly exposed.
severity: critical          # low | medium | high | critical
recommendation: >
  Bind SSH to an internal-only interface or restrict access through a
  bastion host / VPN.
conditions:
  target: service            # host | container | service
  all:                        # every condition here must hold (AND)
    - field: port
      operator: eq
      value: 22
    - field: exposed_publicly
      operator: eq
      value: true
  any: []                     # if present and non-empty, at least one must hold (OR)
```

Supported operators: `eq`, `neq`, `in`, `not_in`, `lt`, `lte`, `gt`, `gte`, `contains`.

Included examples (see `policies/`):
1. `ssh-exposed-public.yaml` — SSH reachable from the public internet
2. `docker-socket-exposed.yaml` — Docker daemon API port reachable
3. `database-publicly-reachable.yaml` — DB default ports exposed publicly
4. `privileged-container.yaml` — container running with `--privileged`
5. `outdated-os-critical-host.yaml` — critical host on an unsupported kernel line

## Incident scenario example

`POST /policies/evaluate` (or the worker's periodic cycle) generates one
`incident_scenarios` row per high/critical risk, e.g.:

> **Title:** CRITICAL exposure risk on service:1f2e...
> **Playbook (markdown):**
> 1. Contain — isolate the affected asset, disable public exposure of the offending port.
> 2. Verify — check access/service logs for the exposure window.
> 3. Eradicate — apply the policy recommendation, re-run `/policies/evaluate`.
> 4. Recover — confirm normal state on the next evaluation pass.
> 5. Review — document root cause; add/adjust a policy to prevent recurrence.

## Running it

```bash
cp .env.example .env
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:4000 (health check at `/health`)
- Postgres: localhost:5432 (seeded automatically from `db/migrations/`)

The worker starts collecting on its own schedule (`WORKER_POLL_INTERVAL_MS`,
default 60s) and will register the backend/worker container's own host,
Docker containers, and locally listening services, then trigger
`/policies/evaluate` after each cycle. Everything is also reachable
directly via the REST API for scripted or declarative ingestion.

## Known limitations

- The attack-path builder is a simple BFS heuristic over the `dependencies`
  graph seeded from exposed services with an existing risk — it is not a
  full graph-theoretic attack-path/MITRE ATT&CK model. It does traverse
  `dependencies` edges bidirectionally, so lateral pivoting between
  services/containers that share a host is modeled (e.g. SSH -> host ->
  Docker API -> container -> database), not just downward containment.
- The worker's service discovery is a real TCP probe + banner grab against
  a curated port list on localhost (not a full port scanner), and extracts
  a version string from the banner where the protocol exposes one (SSH,
  Redis, FTP, PostgreSQL).
- Vulnerability matching (`backend/src/services/vulnerabilityScanner.ts`) is
  a small curated static rule set illustrating the same evaluation shape a
  live NVD/CVE feed would populate — it is intentionally not a live network
  call to an external CVE database, since that is unreliable to depend on
  from this environment.
- Docker collection requires the container to have access to
  `/var/run/docker.sock`; if unavailable, the worker degrades gracefully to
  an empty container list rather than failing.
- Route discovery (`ip route`) requires `iproute2` in the worker image
  (added to `worker/Dockerfile`); if unavailable it degrades to an empty
  route list rather than failing the collection cycle.

## Advanced policies

Beyond the five baseline examples, `policies/` also includes:

6. `sensitive-ports-exposed-wan.yaml` — Telnet/RDP reachable publicly
7. `ot-it-segmentation.yaml` — an OT/ICS-role host sharing a segment with general IT traffic

## Risk categories

Risks are computed from two independent signals — open policy violations
(classified into `exposure` / `network` / `container` / `host` /
`misconfiguration` by the triggering policy) and known-vulnerable service
versions (`vulnerability`, scored from CVSS). An asset can carry risks in
more than one category simultaneously.

## Incident playbooks

Each generated `incident_scenarios` row picks a category-specific playbook
(SSH compromise, Docker API compromise, database compromise, privileged
container compromise, or known-vulnerability response) from
`backend/src/services/incidentEngine.ts`, each with the five standard
sections: **Immediate Actions**, **Containment**, **Eradication**,
**Recovery**, **Lessons Learned**.
