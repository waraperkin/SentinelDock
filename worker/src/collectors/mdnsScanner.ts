import dgram from 'node:dgram';

export interface MdnsResult {
  ip: string;
  services: string[];
}

const MDNS_ADDRESS = '224.0.0.251';
const MDNS_PORT = 5353;

/** Encodes a DNS name into length-prefixed labels, terminated with a zero byte. */
function encodeName(name: string): Buffer {
  const labels = name.split('.').filter(Boolean);
  const parts = labels.map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label, 'ascii')]));
  return Buffer.concat([...parts, Buffer.from([0])]);
}

/** Builds a standard mDNS query for PTR records on `_services._dns-sd._udp.local` (service enumeration). */
function buildServiceEnumQuery(): Buffer {
  const header = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
  const question = Buffer.concat([encodeName('_services._dns-sd._udp.local'), Buffer.from([0x00, 0x0c]), Buffer.from([0x00, 0x01])]);
  return Buffer.concat([header, question]);
}

/** Very small DNS name decompression — enough to read PTR record targets out of an mDNS response. */
function readName(buffer: Buffer, offset: number): { name: string; next: number } {
  const labels: string[] = [];
  let pos = offset;
  let jumped = false;
  let safety = 0;
  while (safety++ < 64) {
    const len = buffer[pos];
    if (len === 0) {
      pos += 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      const pointer = ((len & 0x3f) << 8) | buffer[pos + 1];
      if (!jumped) pos += 2;
      jumped = true;
      const { name } = readName(buffer, pointer);
      labels.push(name);
      break;
    }
    labels.push(buffer.subarray(pos + 1, pos + 1 + len).toString('ascii'));
    pos += 1 + len;
  }
  return { name: labels.join('.'), next: jumped ? offset + 2 : pos };
}

/**
 * Real mDNS (RFC 6762) service discovery via UDP multicast on
 * 224.0.0.251:5353 — the same protocol Bonjour/Avahi use to advertise
 * printers, Chromecasts, AirPlay devices, IoT gear, etc. Joins the
 * multicast group, sends a `_services._dns-sd._udp.local` PTR query, and
 * collects service-type PTR answers from anything that responds within
 * the collection window.
 */
export function discoverMdnsServices(windowMs = 1500): Promise<MdnsResult[]> {
  return new Promise((resolve) => {
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    const responders = new Map<string, Set<string>>();

    socket.on('message', (msg, rinfo) => {
      try {
        const answerCount = msg.readUInt16BE(6);
        let offset = 12;
        // Skip the question section (we only sent one question).
        const qCount = msg.readUInt16BE(4);
        for (let i = 0; i < qCount; i++) {
          const { next } = readName(msg, offset);
          offset = next + 4; // qtype + qclass
        }
        for (let i = 0; i < answerCount; i++) {
          const { next } = readName(msg, offset);
          offset = next;
          const rdlength = msg.readUInt16BE(offset + 8);
          const rdataOffset = offset + 10;
          const { name: target } = readName(msg, rdataOffset);
          offset = rdataOffset + rdlength;
          if (target) {
            const existing = responders.get(rinfo.address) ?? new Set<string>();
            existing.add(target);
            responders.set(rinfo.address, existing);
          }
        }
      } catch {
        // Malformed/partial packet — ignore and keep listening.
      }
    });

    socket.on('error', () => {
      socket.close();
      resolve([]);
    });

    socket.bind(0, () => {
      try {
        socket.addMembership(MDNS_ADDRESS);
        socket.send(buildServiceEnumQuery(), MDNS_PORT, MDNS_ADDRESS);
      } catch {
        socket.close();
        resolve([]);
        return;
      }
      setTimeout(() => {
        socket.close();
        resolve(Array.from(responders.entries()).map(([ip, services]) => ({ ip, services: Array.from(services) })));
      }, windowMs);
    });
  });
}
