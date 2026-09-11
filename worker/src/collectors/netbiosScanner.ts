import dgram from 'node:dgram';

export interface NetbiosResult {
  name: string | null;
}

/** NetBIOS Name Service (RFC 1002) "*" wildcard node status query — the same query `nbtstat -a` sends. */
function buildNodeStatusQuery(): Buffer {
  const header = Buffer.from([0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
  // Encoded name for the wildcard "*" name (NetBIOS first-level encoding), 16 bytes padded.
  const wildcard = '*' + '\0'.repeat(15);
  const encoded = Buffer.alloc(32);
  for (let i = 0; i < 16; i++) {
    const byte = wildcard.charCodeAt(i);
    encoded[i * 2] = 0x41 + ((byte >> 4) & 0xf);
    encoded[i * 2 + 1] = 0x41 + (byte & 0xf);
  }
  const question = Buffer.concat([Buffer.from([32]), encoded, Buffer.from([0x00, 0x00, 0x21, 0x00, 0x01])]);
  return Buffer.concat([header, question]);
}

function udpRequest(ip: string, port: number, payload: Buffer, timeoutMs = 600): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    const timer = setTimeout(() => {
      socket.close();
      resolve(null);
    }, timeoutMs);
    socket.once('message', (msg) => {
      clearTimeout(timer);
      socket.close();
      resolve(msg);
    });
    socket.once('error', () => {
      clearTimeout(timer);
      socket.close();
      resolve(null);
    });
    socket.send(payload, port, ip);
  });
}

/**
 * NetBIOS Name Service node status query (UDP 137) — real wire protocol,
 * the same one `nbtstat -a <ip>` uses. Most useful against older/legacy
 * Windows devices and some embedded/ICS HMI panels that still run
 * NetBIOS-over-TCP/IP. Returns the primary workstation name if the device
 * answers.
 */
export async function scanNetbios(ip: string): Promise<NetbiosResult | null> {
  const response = await udpRequest(ip, 137, buildNodeStatusQuery());
  if (!response || response.length < 57) return null;
  try {
    const nameCount = response[56];
    if (nameCount === 0) return null;
    const rawName = response.subarray(57, 57 + 15).toString('ascii').replace(/\0/g, '').trim();
    return { name: rawName || null };
  } catch {
    return null;
  }
}
