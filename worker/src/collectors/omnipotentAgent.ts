import fs from 'node:fs/promises';

/**
 * GODMODE+ tier: OMNIPOTENT Agent — process & socket-level visibility via
 * Linux /proc, opt-in and disabled by default.
 *
 * IMPORTANT HONESTY NOTE (matches the README): despite the requested
 * "kernel-level" framing, this is deliberately NOT a kernel module, NOT
 * eBPF, and does not load anything into the kernel. A real kernel-level
 * agent needs CAP_SYS_ADMIN/CAP_BPF, kernel headers matching the exact
 * running kernel, and carries real stability/security risk to ship
 * untested in a general-purpose project — that is out of scope here, the
 * same way this project has declined other genuinely risky asks (e.g.
 * live ICS writes). What IS real and shipped: standard, well-understood
 * `/proc` filesystem parsing — the same mechanism tools like `ps` and
 * `netstat` use — read entirely from inside the worker container's own
 * PID and network namespaces. Unless the container is explicitly run
 * with host PID/network namespace sharing (NOT configured by default in
 * this repo's docker-compose.yml, since that would change the security
 * posture of the whole stack without explicit operator opt-in), this
 * only sees the worker container's own processes and sockets — it does
 * NOT see the Docker host's other containers or the host kernel itself.
 */

export interface OmnipotentProcessInfo {
  pid: number;
  comm: string;
}

export interface OmnipotentSocketInfo {
  localPort: number;
  state: string;
}

const TCP_STATE_NAMES: Record<string, string> = {
  '01': 'ESTABLISHED',
  '0A': 'LISTEN',
  '06': 'TIME_WAIT',
};

/** Lists processes visible in this container's own /proc — pid + comm (command name) only, no further inspection. */
export async function listVisibleProcesses(): Promise<OmnipotentProcessInfo[]> {
  const entries = await fs.readdir('/proc').catch(() => [] as string[]);
  const pids = entries.filter((e) => /^\d+$/.test(e));
  const results: OmnipotentProcessInfo[] = [];
  for (const pidStr of pids) {
    const comm = await fs.readFile(`/proc/${pidStr}/comm`, 'utf8').catch(() => null);
    if (comm !== null) results.push({ pid: Number(pidStr), comm: comm.trim() });
  }
  return results;
}

/** Parses /proc/net/tcp[6]-formatted content (exposed as a parameter for testability) into local-port + connection-state pairs. */
export function parseProcNetTcp(content: string): OmnipotentSocketInfo[] {
  const lines = content.split('\n').slice(1); // skip header row
  const results: OmnipotentSocketInfo[] = [];
  for (const line of lines) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 4) continue;
    const localAddress = fields[1]; // "hex_ip:hex_port"
    const stateHex = fields[3];
    const hexPort = localAddress?.split(':')[1];
    if (!hexPort) continue;
    const port = parseInt(hexPort, 16);
    if (!Number.isFinite(port)) continue;
    results.push({ localPort: port, state: TCP_STATE_NAMES[stateHex] ?? `0x${stateHex}` });
  }
  return results;
}

/** Reads and parses this container's own /proc/net/tcp + /proc/net/tcp6 (IPv4 and IPv6 sockets), gracefully returning an empty list if unavailable. */
export async function listVisibleTcpSockets(): Promise<OmnipotentSocketInfo[]> {
  const [v4, v6] = await Promise.all([
    fs.readFile('/proc/net/tcp', 'utf8').catch(() => ''),
    fs.readFile('/proc/net/tcp6', 'utf8').catch(() => ''),
  ]);
  return [...parseProcNetTcp(v4), ...parseProcNetTcp(v6)];
}

export interface OmnipotentSnapshot {
  process_count: number;
  listening_ports: number[];
  established_count: number;
  scope_note: string;
}

/**
 * Top-level opt-in collector. Only runs anything when
 * WORKER_OMNIPOTENT_ENABLED=true is set; otherwise returns null so
 * callers can skip submitting a config snapshot entirely.
 */
export async function collectOmnipotentSnapshot(): Promise<OmnipotentSnapshot | null> {
  if (process.env.WORKER_OMNIPOTENT_ENABLED !== 'true') return null;

  const [processes, sockets] = await Promise.all([listVisibleProcesses(), listVisibleTcpSockets()]);
  const listeningPorts = Array.from(new Set(sockets.filter((s) => s.state === 'LISTEN').map((s) => s.localPort))).sort((a, b) => a - b);
  const establishedCount = sockets.filter((s) => s.state === 'ESTABLISHED').length;

  return {
    process_count: processes.length,
    listening_ports: listeningPorts,
    established_count: establishedCount,
    scope_note: 'Visible only within this worker container\'s own PID/network namespace — not host-wide or kernel-level.',
  };
}
