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

### Workers
- `GET /workers` — list all worker nodes that have ever heartbeated, with a derived `online` flag
- `POST /workers/heartbeat` — upserts a worker's heartbeat row by `worker_id`

### Audit log
- `GET /audit-log?action=&limit=` — list recorded mutating actions (default limit 100, max 500)

All mutating endpoints (POST/PATCH/PUT/DELETE) require `Authorization: Bearer <token>` when `API_TOKENS` is set on the backend; unset (the default), no auth is enforced.

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

## OMEGA tier additions

**Distributed worker visibility** (`worker_nodes` table, `GET /workers`,
`POST /workers/heartbeat`, `frontend/src/app/workers/page.tsx`) — every
worker replica heartbeats every poll cycle (leader or not, per the
existing Redis distributed lock), so scaling with
`docker compose up -d --scale worker=3` shows the full fleet, which one
currently holds the leader lock, and each replica's last cycle summary.
This is real fleet *visibility*; it is not distributed *work-splitting* —
see the "Distributed worker coordination" note under Ultra tier below for
what that would additionally require.

**Opt-in API token auth + audit log** (`backend/src/middleware/auth.ts`,
`audit_log` table, `GET /audit-log`) — set `API_TOKENS` (comma-separated
`name:token` pairs) to require a bearer token on every mutating
(POST/PATCH/PUT/DELETE) request; unset (the default) runs with no
enforcement, so the out-of-the-box `docker compose up` flow keeps working
without extra configuration. `policies.evaluate` and `secrets.ingest`
calls are recorded to `audit_log` with the calling token's name (or
`api-token` when auth is disabled). This is a real, testable auth
primitive — **not** a full multi-tenant RBAC system: there is no
per-resource authorization, no roles, no tenants, just "does this request
carry a known token". A true RBAC/multi-tenant model would need a much
larger identity/session/tenant-scoping layer than this iteration adds.

**Entropy-based secrets detection** (`worker/src/collectors/secretsScanner.ts`)
— beyond the known-format regexes (AWS keys, PEM headers, `api_key`/
`password` assignments), a conservative Shannon-entropy heuristic now
flags long (32-256 char) mixed-case alphanumeric strings with entropy
above what natural text or plain identifiers (UUIDs, hashes) produce —
catching generic high-entropy tokens that don't match any known provider
format, without flagging routine non-secret values.

**Real HTTP-layer recon** (`worker/src/collectors/httpReconScanner.ts`) —
identifies Jenkins via its `X-Jenkins` response header (present on
virtually every Jenkins HTTP response, no auth required to detect) and
checks for an exposed `.git/HEAD` — an extremely common real-world
misconfiguration that leaks full source history when a web root is a git
checkout. Feeds the existing DevOps policy (Jenkins) and a new
`git-repository-exposed` policy.

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

## Roadmap-cycle additions (distributed work-splitting, multi-layer graph, and beyond)

**Real distributed work-splitting** (`worker/src/services/distributedLock.ts`,
`worker/src/index.ts`) — the Ultra-tier note above said replica coordination
prevented duplicate scans but did not split work. It now does: every
replica always runs its own per-host collection (self host, containers,
services, secrets), and subnet sweeping is sharded across the live
`/workers` fleet with a deterministic hash (`shardWorkItems()`, djb2 hash
mod fleet size) — each replica independently computes the same partition
with no extra coordination round-trip. Only the Redis-lock leader still
runs the shared evaluation pipeline (policy eval, risks, attack paths,
incidents), since that reads/writes global derived state every replica
would otherwise redundantly recompute. A cold-started replica sends an
initial heartbeat before its first work-splitting decision so it is
visible in its own shard computation; a replica not yet visible to itself
fails open (claims everything) rather than sweeping nothing.

**Multi-layer attack graph** (`backend/src/routes/attackPaths.ts`
`GET /attack-paths/graph`, `frontend/src/components/AttackPathGraph.tsx`) —
graph nodes are now tagged with a derived `layer` (network / container /
service / host IT / ICS-OT / cloud / DevOps) instead of raw asset type,
reusing the existing `device_class` (hosts) and `protocol_family`
(services) columns rather than new schema. The frontend colors and
legends by layer, so a single graph reads as genuinely multi-domain.

**Advanced vulnerability engine** (`backend/src/services/vulnerabilityScanner.ts`) —
`VulnMatch` now carries a distinct `cwe` field (previously CWE identifiers
like `CWE-319` were incorrectly stored inside the `cve_ids` array for
telnet/FTP; `cve_ids` keeps that value for backward compatibility with
stored rows, but `cwe` is now the correct place to read it from) plus a
0-10 `exploitability` heuristic sub-score independent of CVSS impact. The
rule set grew from 6 to 11 curated entries (added MySQL, MongoDB,
Elasticsearch, SMB/EternalBlue-class, RDP/BlueKeep-class). Still a
curated static rule set illustrating the shape a live NVD feed would
populate, not a live CVE lookup.

**ICS/OT advanced identity + write-risk heuristic** (`worker/src/collectors/icsScanner.ts`) —
S7comm now follows a successful Setup Communication with a real SZL
("System Zustandsliste") read (function 0x04, SZL ID 0x001C) to recover
the PLC's order-number/version string as device identity; BACnet follows
a successful Who-Is/I-Am with a real ReadProperty request for the device
object's Object-Name. Both remain strictly read-only. Separately, Modbus
and BACnet probes now record a `likelyAcceptsWrites` heuristic flag when
the device answered a standard read request with no authentication or
restriction — **this is a naming/inference heuristic only; SentinelDock
never sends a real Modbus FC5/FC6 write or BACnet WriteProperty to any
device**, since actually writing to an unauthorized OT device is a
destructive, potentially unsafe action outside this platform's scope as
a defensive scanner. The heuristic feeds a new "ics" category risk via a
`ics-write-risk` config snapshot.

**Cloud advanced: IAM naming heuristic + mixed-segment detection** —
`backend/src/services/riskEngine.ts` now flags IAM roles/service accounts
enumerated by the existing read-only metadata scan whose name contains
"admin", "root", "full-access", "superuser", or "owner" as a likely
overprivileged role (critical risk) — still a naming-convention heuristic,
never a live IAM policy-document inspection. Separately,
`backend/src/services/policyEngine.ts` now precomputes, per network
segment, the distinct `device_class` values present, powering a new
`cloud-onprem-mixed-segment` policy that flags a cloud host sharing a
segment with any other device class.

**DevOps/CI-CD supply-chain risk scoring** — a host running CI/CD tooling
(`protocol_family = 'devops'`, e.g. Jenkins or an exposed `.git`) that
also has a detected secret finding on the same host now gets a dedicated
critical "supply-chain exposure" risk, since that combination is a
materially worse real-world path (pipeline access + leaked credential ->
malicious deployment) than either signal alone.

**Zero Trust Engine** (`backend/src/services/zeroTrustEngine.ts`,
`GET /zero-trust/segments`, `frontend/src/app/zero-trust/page.tsx`) — a
0-100 segmentation-maturity heuristic per network segment, combining zone
exposure (management < internal < dmz < public), device-class mixing,
ICS/OT placement outside a management zone, and attached critical risks.
Explicitly a heuristic maturity indicator built from data this platform
already collects, not a certification against a formal framework like
NIST SP 800-207.

**Auto-policy generation** (`backend/src/services/autoPolicyGenerator.ts`,
`POST /policies/auto-generate`) — scans current inventory for
`protocol_family` (services) and `device_class` (hosts) values with no
existing policy and creates **disabled draft policies** (`enabled: false`)
proposing a starting condition set for human review. It never enables a
policy itself and is idempotent (re-running does not duplicate proposals
for combinations already proposed or already covered by a real policy).
The worker calls this once per leader evaluation cycle, non-fatally on
failure.

## TITAN tier additions

**Threat Intelligence Local Engine (TI-local)** (`backend/src/services/threatIntelEngine.ts`,
`GET /ti/matches`) — a small hand-curated LOCAL dataset, never a live feed
against an external TI provider: known malicious/backdoor/cryptomining
listener ports (Metasploit/Cobalt Strike default 4444, classic backdoor
ports, Stratum mining ports) and a curated map of CVE -> named real-world
campaign (e.g. CVE-2017-0144 -> EternalBlue/WannaCry/NotPetya,
CVE-2022-0543 -> the Muhstik botnet), layered on top of the existing
`isKnownExploited` flag in `vulnerabilityScanner.ts` rather than
duplicating it. Matches persist to `ti_matches` and feed a dedicated
`threat-intel` risk category.

**UEBA-lite** (`backend/src/services/uebaEngine.ts`, `GET /ueba/anomalies`) —
a deterministic baseline-deviation detector, explicitly not a
statistical/ML anomaly model. Each host gets a rolling baseline of its
observed service ports (`ueba_baselines`); each evaluation cycle compares
current state against that baseline and flags concrete, explainable
deviations (`new-service-port`, `service-count-spike`) rather than an
opaque anomaly score. "Entity" here means host, since this platform has
no user/session telemetry to analyze — real UEBA covers user behavior,
this is honestly scoped to asset behavior.

**EDR-lite** (`backend/src/services/edrEngine.ts`, `GET /edr/detections`) —
behavioral detection without deploying any agent on monitored hosts. Real
EDR inspects process trees/syscalls/memory; this is scoped to what the
worker's remote, read-only collection can actually support: known
malicious listener ports, container images matching cryptojacking-tooling
name patterns (xmrig, kinsing, etc.), and a privileged container running
on an ICS-classified host. A heuristic signal, not a host-agent
replacement.

**SIEM-lite** (`backend/src/services/siemEngine.ts`, `GET /siem/timeline`) —
event correlation over SentinelDock's own structured detection tables
(risks, violations, secrets, TI matches, UEBA anomalies, EDR detections),
NOT a general-purpose log SIEM (no raw log ingestion/parsing pipeline).
Events on the same asset within a 10-minute window are grouped into a
`cluster_id` so the timeline reads as "what happened to this asset around
this time" rather than a flat chronological dump.

**Auto-Segmentation Engine** (`backend/src/services/segmentationEngine.ts`,
`GET/PATCH /segmentation/recommendations`) — produces RECOMMENDATIONS
only; it never moves a host or edits a network segment. Reuses the same
mixed-device-class-per-segment signal that powers the Zero Trust score,
turning it into a concrete per-host "move X to a dedicated segment"
recommendation with a suggested target zone.

**Auto-Hardening Engine** (`backend/src/services/hardeningEngine.ts`,
`GET/PATCH /hardening/recommendations`) — also recommendations only.
Maps each open risk's underlying policy key (or, as a fallback, its risk
category) to a concrete, actionable hardening step via a static lookup
table, rather than leaving the operator to derive "what do I actually do
about this" from a risk score alone.

**Attack Graph TITAN** (`GET /attack-paths/graph/titan`) — the same
multi-layer graph from the roadmap cycle, decorated per node with TI hit
count, recent (24h) UEBA anomaly count for the owning host, EDR detection
count, and — for service nodes — an exploitability score reusing
`vulnerabilityScanner.ts`'s curated rule set. Turns the graph into a
prioritization view on top of the topology, without adding any new
detection logic of its own.

**Distributed Evaluation Engine** (`backend/src/services/distributedEvaluationEngine.ts`,
`POST /policies/evaluate/distributed`) — honestly framed: this backend
runs as a single process, so "distributed" means evaluation work is
*partitioned by network segment* (the map step), which is the same
partitioning primitive a real multi-instance deployment would use to
spread evaluation load. `evaluatePolicies(scopeHostIds)` in
`policyEngine.ts` never touches violations outside its given host scope,
so each segment's run is safe to execute independently. Downstream
aggregation (risk scoring, attack-path/incident rebuilding, TI/UEBA/EDR/
segmentation/hardening) inherently needs a whole-graph view — a CVE-
chaining risk or a cross-segment attack path cannot be computed from one
segment alone — so that stays centralized (the reduce step). The worker's
leader now calls this endpoint every cycle instead of the plain
`/policies/evaluate`.

## GODMODE tier additions

**Network Sandbox Engine** (`backend/src/services/sandboxEngine.ts`,
`POST /sandbox/simulate/:attackPathId`, `GET /sandbox/simulations`) — a
NON-DESTRUCTIVE attack simulation: it never sends a single real network
packet. It replays an already-computed AttackPath hop by hop and
estimates each step's success probability from the strongest applicable
signal already collected (CVE exploitability from `vulnerabilityScanner.ts`,
a TI match, or an ICS write-risk heuristic — falling back to a generic
0.55 lateral-move probability), multiplies the chain, and models the
simulated attacker giving up once the cumulative probability drops below
3%. Pure arithmetic over existing rows, safe to run against a production
inventory at any time. Runs are persisted (append-only) so posture
improvement can be tracked over repeated simulations of the same path.
Exposed in the frontend GODMODE page with a live interactive trigger.

**CLOUDMASTER — the Cloud Agent** (`backend/src/services/cloudAgent.ts`,
`GET /cloud/posture`) — aggregates the read-only IAM enumeration, cloud
metadata reachability, and mixed-segment signals already collected
elsewhere into one per-provider posture score, rather than leaving an
operator to piece those signals together from separate risk rows. No live
cloud API calls of its own.

**ICSMASTER — the ICS Agent** (`backend/src/services/icsAgent.ts`,
`GET /ics/posture`) — the same aggregation pattern for ICS/OT: per-segment
posture from device role classification, the Modbus/BACnet write-risk
heuristic, and zone placement. No new protocol probing — reads what
`icsScanner.ts` already discovered.

**XDR-lite** (`backend/src/services/xdrEngine.ts`, `GET /xdr/detections`) —
multi-source correlation. Only emits a row for an asset hit by 2+
independent detection sources (TI, EDR, UEBA, an open policy violation) —
a single-source hit is left to that source's own view, since the actual
value XDR adds is confidence from cross-source correlation, not
duplicating what each engine already reports individually.

**Auto-Remediation Engine** (`backend/src/services/remediationEngine.ts`,
`GET/PATCH /remediation/plans`) — recommendations only, same as
hardeningEngine.ts. Turns each open risk with a concrete hardening
template into a PRIORITIZED, ordered 3-step plan (fix, verify, monitor),
with priority boosted for XDR-correlated and threat-intel-category risks,
so an operator can triage what to work on first instead of facing an
undifferentiated risk list.

**Zero Trust Engine v2 (dynamic segmentation)** — additive, not a rewrite:
`zeroTrustEngine.ts`'s existing static score (zone exposure, device-class
mixing, ICS placement, critical risks) now also folds in a
`dynamic_signal_count` — live XDR correlations, TI matches, and recent
(24h) UEBA anomalies on hosts in the segment — with its own reason line,
so the score reflects current threat activity, not just static topology.

**Distributed Evaluation Engine v2 (horizontal scaling)** — additive to
the TITAN-tier engine: `evaluatePoliciesBySegment()` now accepts optional
`shardIndex`/`shardCount` parameters. `POST /policies/evaluate/distributed?shard=I&of=N`
restricts that call to only the segments whose
`djb2Hash(segment.id) % N === I` (the same hashing scheme the worker
fleet already uses in `worker/src/services/distributedLock.ts`), skipping
the rest — so two shards never touch the same segment's violations
concurrently, a genuine safety property, not just a label.
`GET /policies/evaluate/distributed/plan?of=N` returns the full
segment -> shard assignment in advance, for an external orchestrator (N
scheduled calls, or N backend instances each configured with a distinct
shard index) to plan its workload. The default single-instance deployment
in this repo's `docker-compose.yml` is unaffected — the worker's leader
still calls the unsharded (`shardCount` omitted) form every cycle; sharding
is an opt-in capability for operators who actually run multiple instances.

## GODMODE+ tier additions

**Attack Simulation Engine** (`backend/src/services/attackSimulationEngine.ts`,
`POST /simulation/campaigns/run`, `GET /simulation/campaigns`) — does not
introduce a new simulation mechanism: it batches the existing (non-
destructive) Network Sandbox Engine across EVERY currently-persisted
attack path in one run, covering whatever domains those paths span
(network/ICS/cloud/DevOps, via the multi-layer graph's `layer`
classification), and aggregates the results into one fleet-wide exposure
summary (path count, average and worst-case success probability, which
path is worst) instead of requiring an operator to simulate paths one at
a time. Still pure arithmetic over existing data — never touches the real
network.

**QUANTUM Engine** (`backend/src/services/quantumEngine.ts`,
`GET /quantum/trend`, `GET /quantum/outliers`) — **local statistical
analysis, explicitly NOT quantum computing.** Despite the tier name (kept
to match this project's established naming convention — TITAN, OMEGA,
GODMODE, …), this is classical statistics computed entirely in-process,
no external ML service, no GPU: ordinary least-squares linear regression
over a new append-only `risk_score_snapshots` time series (sampled once
per evaluation cycle) forecasts the next global-risk-score sample and
labels the trend increasing/decreasing/stable; a z-score pass over the
current risk-score distribution flags statistical outliers — an asset
that's unusually extreme relative to everything else observed right now,
a different signal than severity alone. The regression math is exported
standalone (`linearRegressionTrend`) and unit-tested without any database
involved.

**SOVEREIGN Engine** (`backend/src/services/rbac.ts`,
`backend/src/routes/sovereign.ts`, `POST/GET/DELETE /sovereign/tenants`,
`/sovereign/tokens`) — DB-backed, revocable, role-aware (admin/analyst/
readonly) API tokens and optional tenant scoping, layered ADDITIVELY on
top of the existing opt-in `API_TOKENS` env-var mechanism
(`backend/src/middleware/auth.ts`), which is completely unchanged and
still works standalone. A token is never stored raw — only its sha256
hash — and is returned in full exactly once, at creation. Tenant scoping
is applied to the core asset tables (`hosts`, `network_segments`: a
nullable `tenant_id` column, additive migration, `NULL` = default/global
tenant so no existing deployment needs any migration action) and their
`GET`/`POST` routes in `assets.ts` — not yet threaded through every other
subsystem (risks, secrets, etc.), which is an honest scope limit for this
iteration, not a claim of full multi-tenant isolation everywhere.
Unlike the rest of this platform's "opt-in, never rejects by default"
auth philosophy, the new `/sovereign/*` management routes are STRICTLY
gated by `requireRole('admin')` (401 with no token, 403 with an
insufficient role) — there's no legacy default-open behavior to preserve
on a brand-new privileged surface. To bootstrap SOVEREIGN at all, an
operator first authenticates with an env-var `API_TOKENS` admin token
(treated as full "admin", matching its pre-existing unrestricted
behavior) to mint the first DB-backed token. A minimal admin console
lives at `/sovereign` in the frontend — the entered token is kept only in
that browser tab's memory, never persisted.

**OMNIPOTENT Agent** (`worker/src/collectors/omnipotentAgent.ts`,
`WORKER_OMNIPOTENT_ENABLED`, opt-in, **off by default**) — **honesty note:
despite the requested "kernel-level" framing, this is deliberately NOT a
kernel module and NOT eBPF.** A real kernel-level agent needs
CAP_SYS_ADMIN/CAP_BPF, kernel headers matching the exact running kernel,
and carries genuine stability/security risk to ship untested in a
general-purpose project — out of scope here, the same way this project
declined other genuinely risky asks (e.g. live ICS writes, see the ICS/OT
section above). What IS real and shipped: standard `/proc` filesystem
parsing (the same mechanism `ps`/`netstat` use) — process list and TCP
socket state, read entirely from inside the worker container's own PID
and network namespaces. Unless the container is explicitly run with host
PID/network namespace sharing (**not** configured by default in this
repo's `docker-compose.yml`, since that would change the security
posture of the whole stack without explicit operator opt-in), this only
sees the worker container's own processes/sockets — never the Docker
host's other containers or the host kernel itself. Findings are submitted
as a `config_snapshots` row (`kind = 'omnipotent-agent'`); the pure
`/proc/net/tcp` parser is unit-tested against fixture data.

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
13. `git-repository-exposed.yaml` — a confirmed exposed `.git/HEAD` on a web server

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
