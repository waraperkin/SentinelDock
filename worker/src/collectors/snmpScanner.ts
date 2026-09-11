import dgram from 'node:dgram';

export interface SnmpResult {
  sysDescr: string | null;
  sysObjectId: string | null;
}

/** Minimal BER/DER encoding helpers — just enough for an SNMPv2c GET request. */
function encodeLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

function encodeInteger(value: number): Buffer {
  return tlv(0x02, Buffer.from([value]));
}

function encodeOctetString(value: string): Buffer {
  return tlv(0x04, Buffer.from(value, 'ascii'));
}

function encodeNull(): Buffer {
  return tlv(0x05, Buffer.alloc(0));
}

/** Encodes a dotted OID string ("1.3.6.1.2.1.1.1.0") into BER OID bytes. */
export function encodeOid(oid: string): Buffer {
  const parts = oid.split('.').map(Number);
  const bytes: number[] = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    if (part < 0x80) {
      bytes.push(part);
    } else {
      const chunk: number[] = [];
      let n = part;
      chunk.unshift(n & 0x7f);
      n >>= 7;
      while (n > 0) {
        chunk.unshift((n & 0x7f) | 0x80);
        n >>= 7;
      }
      bytes.push(...chunk);
    }
  }
  return tlv(0x06, Buffer.from(bytes));
}

function buildGetRequest(community: string, oids: string[], requestId: number): Buffer {
  const varBinds = tlv(0x30, Buffer.concat(oids.map((oid) => tlv(0x30, Buffer.concat([encodeOid(oid), encodeNull()])))));
  const pdu = tlv(
    0xa0, // GetRequest-PDU
    Buffer.concat([encodeInteger(requestId), encodeInteger(0), encodeInteger(0), varBinds]),
  );
  const message = Buffer.concat([encodeInteger(1) /* SNMPv2c */, encodeOctetString(community), pdu]);
  return tlv(0x30, message);
}

/** Extremely small BER walker — just enough to pull OCTET STRING / OID values back out of a GetResponse. */
function parseVarBindValues(buffer: Buffer): string[] {
  const values: string[] = [];
  let i = 0;
  function readLength(pos: number): { len: number; next: number } {
    const first = buffer[pos];
    if (first < 0x80) return { len: first, next: pos + 1 };
    const numBytes = first & 0x7f;
    let len = 0;
    for (let j = 0; j < numBytes; j++) len = (len << 8) | buffer[pos + 1 + j];
    return { len, next: pos + 1 + numBytes };
  }
  while (i < buffer.length - 1) {
    const tag = buffer[i];
    const { len, next } = readLength(i + 1);
    if (next + len > buffer.length) break;
    if (tag === 0x04) values.push(buffer.subarray(next, next + len).toString('ascii'));
    i = next + len;
  }
  return values;
}

function udpRequest(ip: string, port: number, payload: Buffer, timeoutMs = 700): Promise<Buffer | null> {
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
 * SNMPv2c GET for sysDescr (1.3.6.1.2.1.1.1.0) and sysObjectID
 * (1.3.6.1.2.1.1.2.0) against the "public" community string — the SNMPv2c
 * default and still extremely common in the wild, especially on network
 * gear and ICS/OT equipment. SNMPv3 (authenticated/encrypted) is not
 * implemented — it requires USM key derivation this worker does not
 * attempt. Real UDP wire protocol, hand-rolled minimal BER encoder — no
 * external SNMP library dependency.
 */
export async function scanSnmp(ip: string, community = 'public'): Promise<SnmpResult | null> {
  const request = buildGetRequest(community, ['1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.2.0'], Math.floor(Math.random() * 0x7fffffff));
  const response = await udpRequest(ip, 161, request);
  if (!response) return null;
  const values = parseVarBindValues(response);
  if (values.length === 0) return null;
  return { sysDescr: values[0] ?? null, sysObjectId: values[1] ?? null };
}
