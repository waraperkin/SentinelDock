import { readFile } from 'node:fs/promises';

export interface ArpEntry {
  ip: string;
  mac: string;
  device: string;
}

/**
 * Reads the kernel's ARP table (/proc/net/arp, Linux). This is passive
 * discovery — it only surfaces devices the kernel has already exchanged
 * ARP frames with (recent traffic), not an active sweep — but it's real
 * data and a useful cross-check against the active TCP subnet sweep
 * (devices with no open probed ports but recent ARP activity still show
 * up here). Active LLDP frame capture would need raw sockets with
 * elevated privileges this worker intentionally does not require; ARP
 * table inspection needs none.
 */
export async function readArpTable(): Promise<ArpEntry[]> {
  try {
    const content = await readFile('/proc/net/arp', 'utf8');
    const lines = content.split('\n').slice(1).filter(Boolean);
    return lines
      .map((line) => {
        const cols = line.trim().split(/\s+/);
        return { ip: cols[0], mac: cols[3], device: cols[5] };
      })
      .filter((entry) => entry.mac && entry.mac !== '00:00:00:00:00:00');
  } catch {
    return [];
  }
}
