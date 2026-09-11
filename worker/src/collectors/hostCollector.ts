import os from 'node:os';

export interface CollectedHost {
  [key: string]: unknown;
  hostname: string;
  os: string;
  os_version: string;
  ip_address: string | null;
  role: string;
  criticality: string;
}

function primaryIpAddress(): string | null {
  const interfaces = os.networkInterfaces();
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries ?? []) {
      if (entry.family === 'IPv4' && !entry.internal) return entry.address;
    }
  }
  return null;
}

export function collectHost(): CollectedHost {
  return {
    hostname: os.hostname(),
    os: os.platform(),
    os_version: os.release(),
    ip_address: primaryIpAddress(),
    role: 'worker',
    criticality: 'medium',
  };
}
