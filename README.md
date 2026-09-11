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
| `hosts` | Physical/virtual hosts, role, criticality, segment, `device_class` (it/ics/cloud) |
| `containers` | Docker containers on a host, image, ports, privileged flag |
| `services` | Listening services on a host or container, port, exposure, `protocol_family` (modbus/s7/opcua/bacnet/cloud-metadata) |
| `dependencies` | Directed edges between any two assets (source → target) |
| `config_snapshots` | Immutable, versioned config blobs per asset (`kind`: os/docker/network/service) |
| `policies` | Policy definitions (see format below) |
| `policy_violations` | Detected breaches of a policy against an asset |
| `risks` | Aggregated risk per asset, scored from open violations + criticality |
| `attack_paths` | Heuristic graph paths from an exposed entry point to a target asset, hops tagged with MITRE ATT&CK technique labels |
| `incident_scenarios` | Generated markdown playbooks for high/critical risks |
| `secrets_findings` | Redacted secret-pattern matches (never the full value) |

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

### Secrets
- `GET /secrets?asset_type=&asset_id=` — list detected secret findings (redacted previews only)
- `POST /secrets` — ingest a batch of findings `{ findings: [...] }`

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
Docker containers, and locally listening services, derive its subnet, and
sweep that subnet for other devices, then trigger `/policies/evaluate`
after each cycle. Everything is also reachable directly via the REST API
for scripted or declarative ingestion.

## Real subnet / LAN device discovery

The worker performs a real TCP-connect sweep (`worker/src/collectors/subnetScanner.ts`)
of every host address in its derived subnet — up to a /16, capped at 254
addresses per cycle, bounded concurrency — probing a curated port list
(SSH, HTTP/S, SMB, RDP, printer, iOS sync, etc.). A device counts as
discovered if any port is open, or if the OS actively refused a connection
(`ECONNREFUSED`, which only happens if something answered on that IP).
Discovered devices are registered as `Host` rows (role inferred from open
ports — `windows-device`, `linux-device`, `printer`, `mobile-device`) with
their open ports as `Service` rows, so they immediately flow through the
same policy/risk/attack-path pipeline as everything else.

**By default this only sees the Docker bridge network** (other containers
in the compose project), because that's all the worker container can
reach. To sweep your actual LAN, run the worker with host networking:

```bash
docker compose -f docker-compose.yml -f docker-compose.host-network.yml up -d --build
```

On Linux this works natively. On Windows/Mac (Docker Desktop) you must
first enable **Settings → Resources → Network → Host Networking** (Docker
Desktop 4.29+) — without it, `network_mode: host` silently falls back to
bridge-like behavior and you'll still only see container IPs. Set
`WORKER_SUBNET_SCAN_ENABLED=false` to disable the sweep entirely.

## Advanced platform capabilities

A note on framing: no amount of README copy makes a project "beat" Wiz,
Tenable, Qualys, Rapid7, or CrowdStrike — those are large commercial
platforms with entire engineering orgs, live threat intel feeds, EDR
agents, and compliance certifications behind them. What follows is an
honest description of what SentinelDock actually does, scoped to what
runs for real in this repo.

**ICS/OT protocol fingerprinting** (`worker/src/collectors/icsScanner.ts`)
— real protocol-level handshakes, not just "port is open":
- **Modbus/TCP (502)**: sends a Read Holding Registers request, confirms
  via the echoed MBAP transaction ID.
- **S7comm (102)**: sends a COTP Connection Request, confirms via the COTP
  Connection Confirm TPDU code.
- **OPC-UA (4840)**: sends a Hello message, confirms via the ACK reply.
- **BACnet (47808)**: best-effort TCP-only probe — BACnet is normally UDP,
  which this worker doesn't probe (would need raw sockets), so BACnet
  under-detects by design.

A host is only classified `device_class: ics` and given `role: ics-device`
after a confirmed handshake — an open port alone never triggers this.

**Cloud metadata exposure** (`worker/src/collectors/cloudMetadataScanner.ts`)
— checks whether AWS/Azure (`169.254.169.254`) and GCP
(`metadata.google.internal`) instance metadata endpoints are reachable.
Reachability is the signal, modeling the SSRF-to-credential-theft path
(see the 2019 Capital One breach) — SentinelDock does not call any real
cloud provider IAM API.

**Secrets detection** (`worker/src/collectors/secretsScanner.ts`) — local,
offline regex matching (AWS access keys, PEM private key headers, generic
`api_key`/`password` assignments) run against container environment
variables fetched via `docker inspect`. Raw values never leave the worker
process — only a short, redacted preview (`AKIA...ple (20 chars)`) is ever
sent to the backend and stored. This is not a replacement for a dedicated
secrets-scanning product (no entropy analysis, no provider-specific key
formats beyond AWS) — it catches the highest-signal, most common cases.
Findings are append-only (not re-verified as resolved on later scans).

**ARP table cross-check** (`worker/src/collectors/arpScanner.ts`) — reads
`/proc/net/arp` (passive; devices the kernel has recently exchanged ARP
frames with) as a cross-check against the active TCP sweep, surfacing
devices with no open probed ports. Active LLDP frame capture was
deliberately **not** implemented — it needs raw socket capture with
elevated container privileges this project intentionally avoids requiring.

**MITRE ATT&CK-flavored kill chain labeling** (`backend/src/services/killChain.ts`)
— tags each attack-path hop with a tactic/technique label (e.g. "Lateral
Movement (TA0008): Remote Services (T1021)") based on the dependency
relation it traversed. This is a small heuristic label set matched to the
handful of relation types SentinelDock's graph actually produces, not a
full ATT&CK Navigator integration.

**Privilege escalation / blast radius** — an attack path that can reach a
privileged container is auto-escalated to `critical` severity regardless
of its other hop severities (privileged containers are a de facto
root-on-host escape route). `blast_radius` is the count of distinct
assets reachable from the entry point via bidirectional graph traversal.

**Ransomware-class incident simulation** — any critical-severity risk
whose attack path reaches 3+ other assets automatically gets the
"isolate the whole blast radius, not just the entry point" playbook
instead of its normal entry-specific one, modeling a realistic large-scale
compromise response.

**Distributed worker coordination** (`worker/src/services/distributedLock.ts`)
— when scaled with `docker compose up -d --scale worker=3`, replicas
coordinate via a Redis `SET NX PX` mutex so only one replica runs a given
collection cycle (fail-open to standalone if Redis is unreachable). This
prevents duplicate concurrent scans; it does **not** yet split work across
replicas (e.g. one subnet per replica) — that needs dynamic replica
membership tracking, which is a natural next step, not implemented here.

## Ultra tier additions

**SNMPv2c inventory** (`worker/src/collectors/snmpScanner.ts`) — a real
UDP SNMP GET (hand-rolled minimal BER encoder, no external SNMP library)
against the `public` community string for `sysDescr`/`sysObjectID`. SNMPv3
(authenticated/encrypted) is not implemented — it needs USM key derivation
this worker does not attempt.

**mDNS service enumeration** (`worker/src/collectors/mdnsScanner.ts`) —
real RFC 6762 discovery over UDP multicast (224.0.0.251:5353), the same
mechanism Bonjour/Avahi use for printers, IoT devices, AirPlay, etc.

**NetBIOS name queries** (`worker/src/collectors/netbiosScanner.ts`) — the
same UDP 137 node-status query `nbtstat -a` sends, useful against legacy
Windows devices and some embedded HMI panels.

**Real BACnet/IP Who-Is/I-Am** (`worker/src/collectors/icsScanner.ts`) —
replaced the previous TCP-only guess with the actual BACnet discovery
mechanism over its native UDP transport, parsing the Device Instance
number out of a real I-Am reply when present.

**Modbus FC1/FC3 real register reads** — issues actual Read Coils / Read
Holding Registers requests and reports the real byte count returned, not
just an echoed transaction ID.

**S7comm two-step handshake** — COTP Connection Request/Confirm followed
by a real S7comm "Setup Communication" PDU. SZL-based device identity
reads (function 0x04/0x0131) are not implemented — vendor-specific and
easy to get subtly wrong by hand.

**ICS device role classification** (`classifyIcsDevice`) — heuristic
PLC/HMI/historian/gateway labeling from the combination of confirmed ICS
protocols and other open ports (e.g. a web/RDP port alongside Modbus
suggests an HMI, not a bare PLC).

**Dynamic segmentation by gateway** — network segments now record the
subnet's actual gateway (from `ip route`) in their description when one
can be determined, rather than just the bare CIDR.

**Read-only cloud IAM role enumeration** — when the AWS/GCP metadata
service is reachable, lists the IAM role / service account **name**
attached to the instance (the equivalent of `aws sts get-caller-identity`
without credentials). It deliberately never fetches or uses the actual
temporary access-key/secret/session-token the same endpoint would also
return — doing that means acting as the compromised identity against real
cloud APIs, which is an authorized-pentest action, not something an
automated defensive scanner should do unprompted. An enumerated role name
is treated as stronger evidence than mere reachability and escalates the
host to critical criticality.

**Known-exploited (KEV-style) flag + CVE chaining** — the static
vulnerability rule set now marks specific CVEs as known-exploited (a small
hand-curated echo of CISA's KEV catalog, not a live feed), boosting their
risk score and severity beyond what CVSS alone implies. Independently, a
host running 2+ vulnerable services gets an additional "CVE chaining" risk
representing the compounded exploitability of chaining footholds across
services on the same host without needing to pivot through the network.

**Multi-segment lateral movement detection** — attack paths now track how
many distinct network segments they cross; crossing 2+ escalates severity
and selects a dedicated "segmentation failure" incident playbook, since
that's a materially worse finding than movement contained within one
segment.

**DevOps/CI-CD exposure policy** — flags a publicly-reachable
Jenkins/GitLab-Runner-named service or the Jenkins JNLP agent port (50000)
as a supply-chain risk. Matched by name/known port, not a full CI/CD
protocol fingerprint.

**LLDP frame capture and full OPC-UA GetEndpoints enumeration remain
explicitly out of scope** — LLDP needs raw Ethernet frame capture with
elevated container privileges this project intentionally avoids
requiring; full OPC-UA endpoint enumeration needs establishing a secure
channel first per the binary protocol spec, which is genuinely complex to
hand-roll correctly (a real OPC-UA client SDK is the right tool for that,
not a hand-rolled parser). NVD live CVE lookups and real cloud IAM API
calls (beyond read-only role-name enumeration) remain out of scope for
the reasons described above — see "Known limitations" below.

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
8. `ics-protocol-exposed.yaml` — a confirmed Modbus/S7/OPC-UA/BACnet handshake, publicly exposed
9. `cloud-metadata-reachable.yaml` — the cloud instance metadata endpoint is reachable
10. `iam-privileged-role-exposed.yaml` — a high/critical asset can reach cloud metadata (proxy signal to review its IAM role)
11. `critical-host-flat-network.yaml` — a critical host with no dedicated management-segment isolation
12. `devops-cicd-exposed.yaml` — a publicly-reachable CI/CD service (Jenkins/GitLab Runner)

## Risk categories

Risks are computed from three independent signals — open policy
violations (classified into `exposure` / `network` / `container` / `host`
/ `ics` / `cloud` / `devops` / `misconfiguration` by the triggering
policy), known-vulnerable service versions (`vulnerability`, scored from
CVSS and boosted for known-exploited CVEs, plus a combined "CVE chaining"
risk when a host runs 2+ independently vulnerable services), and detected
secrets (`secrets`, scored from finding severity). An asset can carry
risks in more than one category simultaneously.

## Incident playbooks

Each generated `incident_scenarios` row picks a category-specific playbook
(SSH compromise, Docker API compromise, database compromise, privileged
container compromise, known-vulnerability response, ICS/OT protocol
exposure, cloud metadata/SSRF exposure, exposed secrets, or a
ransomware-class blast-radius simulation) from
`backend/src/services/incidentEngine.ts`, each with the five standard
sections: **Immediate Actions**, **Containment**, **Eradication**,
**Recovery**, **Lessons Learned**.
