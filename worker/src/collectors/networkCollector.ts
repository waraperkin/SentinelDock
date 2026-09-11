import os from 'node:os';

export interface CollectedNetworkInterface {
  name: string;
  address: string;
  family: string;
  mac: string;
  internal: boolean;
}

export function collectNetworkInterfaces(): CollectedNetworkInterface[] {
  const result: CollectedNetworkInterface[] = [];
  const interfaces = os.networkInterfaces();
  for (const [name, entries] of Object.entries(interfaces)) {
    for (const entry of entries ?? []) {
      result.push({ name, address: entry.address, family: entry.family, mac: entry.mac, internal: entry.internal });
    }
  }
  return result;
}
