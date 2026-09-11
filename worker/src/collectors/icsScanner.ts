import net from 'node:net';
import dgram from 'node:dgram';

export interface IcsProbeResult {
  port: number;
  protocolFamily: 'modbus' | 's7' | 'bacnet' | 'opcua';
  name: string;
  evidence: string;
  /** Device identity string recovered from a real protocol read (S7 SZL, BACnet Object-Name), when available. */
  deviceIdentity?: string;
  /**
   * Risk-only heuristic: true when the device answered standard read
   * requests without any authentication/restriction, so it likely also
   * accepts write function codes (Modbus FC5/FC6, BACnet WriteProperty).
   * This is NEVER derived by sending a real write — writing to an
   * unauthorized OT device is destructive and out of scope; this is
   * inferred purely from the absence of any read-side access control.
   */
  likelyAcceptsWrites?: boolean;
}

export type IcsDeviceRole = 'plc' | 'hmi' | 'historian' | 'gateway' | 'ics-device';

const CONNECT_TIMEOUT_MS = 600;

function sendAndRead(ip: string, port: number, payload: Buffer, timeoutMs = CONNECT_TIMEOUT_MS): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let data = Buffer.alloc(0);
    let settled = false;
    const finish = (result: Buffer | null) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => socket.write(payload));
    socket.on('data', (chunk) => {
      data = Buffer.concat([data, chunk]);
      setTimeout(() => finish(data), 100);
    });
    socket.once('timeout', () => finish(data.length > 0 ? data : null));
    socket.once('error', () => finish(null));
    socket.connect(port, ip);
  });
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
 * Modbus/TCP (port 502): issues a real FC1 (Read Coils) and FC3 (Read
 * Holding Registers) request and parses the actual response byte count —
 * not just an echoed transaction ID — so we can report how many
 * coils/registers the device actually exposed at address 0, which is
 * real evidence beyond "something is listening".
 */
async function probeModbus(ip: string): Promise<{ ok: boolean; evidence: string; likelyAcceptsWrites?: boolean }> {
  const fc3 = Buffer.from([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01]);
  const fc3Response = await sendAndRead(ip, 502, fc3);
  if (fc3Response && fc3Response.length >= 9 && fc3Response[0] === 0x00 && fc3Response[1] === 0x01 && fc3Response[7] === 0x03) {
    const byteCount = fc3Response[8];
    return { ok: true, evidence: `FC3 Read Holding Registers: ${byteCount} byte(s) returned`, likelyAcceptsWrites: true };
  }
  const fc1 = Buffer.from([0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01, 0x00, 0x00, 0x00, 0x08]);
  const fc1Response = await sendAndRead(ip, 502, fc1);
  if (fc1Response && fc1Response.length >= 9 && fc1Response[0] === 0x00 && fc1Response[1] === 0x02 && fc1Response[7] === 0x01) {
    const byteCount = fc1Response[8];
    return { ok: true, evidence: `FC1 Read Coils: ${byteCount} byte(s) returned`, likelyAcceptsWrites: true };
  }
  // Function code 0x83/0x81 = exception response — still proves a real Modbus stack, just no register at that address.
  if (fc3Response && fc3Response.length >= 8 && fc3Response[7] === 0x83) {
    // An exception response still proves the stack parses requests without
    // rejecting them at a transport/auth layer (Modbus/TCP has no native
    // authentication), so writes are still plausible — just not to this
    // specific address.
    return { ok: true, evidence: 'Modbus exception response (confirms real Modbus stack)', likelyAcceptsWrites: true };
  }
  return { ok: false, evidence: '' };
}

/**
 * S7comm over ISO-on-TCP (port 102): full two-step handshake — COTP
 * Connection Request/Confirm, then an S7comm "Setup Communication" PDU
 * (function 0xF0) to negotiate PDU size. A real S7-compatible PLC
 * responds to both steps; this is stronger evidence than the COTP
 * handshake alone. When Setup Communication succeeds, follows up with a
 * real SZL ("System Zustandsliste") read request — function 0x04
 * (userdata/read-SZL) with SZL ID 0x001C (module identification) — which
 * returns the module's order number/version string on real Siemens S7
 * PLCs, giving actual device identity instead of just protocol presence.
 */
async function probeS7(ip: string): Promise<{ ok: boolean; evidence: string; deviceIdentity?: string }> {
  const cotpConnectRequest = Buffer.from([0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02]);
  const cotpResponse = await sendAndRead(ip, 102, cotpConnectRequest);
  if (!cotpResponse || cotpResponse.length < 6 || cotpResponse[0] !== 0x03 || (cotpResponse[5] & 0xf0) !== 0xd0) {
    return { ok: false, evidence: '' };
  }

  const setupCommunication = Buffer.from([
    0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80, // TPKT + COTP data header
    0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, // S7 header (job request)
    0xf0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x1e, // Setup Communication parameter
  ]);
  const s7Response = await sendAndRead(ip, 102, setupCommunication);
  if (!s7Response || s7Response.length <= 7 || s7Response[7] !== 0x32) {
    return { ok: true, evidence: 'COTP connect confirmed (Setup Communication did not respond as expected)' };
  }

  // SZL read: function 0x04 (Read SZL) userdata request, SZL ID 0x001C (module identification).
  const readSzl = Buffer.from([
    0x03, 0x00, 0x00, 0x21, 0x02, 0xf0, 0x80, // TPKT + COTP data header
    0x32, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, // S7 header (userdata request)
    0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00, 0xff, 0x09, 0x00, 0x04, // parameter (SZL functions)
    0x00, 0x1c, 0x00, 0x00, // data: SZL ID 0x001C, index 0
  ]);
  const szlResponse = await sendAndRead(ip, 102, readSzl);
  const identity = parseS7SzlIdentity(szlResponse);
  if (identity) return { ok: true, evidence: 'COTP connect + S7comm Setup Communication + SZL identity read all confirmed', deviceIdentity: identity };
  return { ok: true, evidence: 'COTP connect + S7comm Setup Communication both confirmed (SZL read did not return identity)' };
}

/**
 * Extracts a printable order-number/version string from a Read-SZL
 * response, if the response looks like a valid userdata reply. Real SZL
 * payloads for ID 0x001C carry ASCII fields (order number, version) mixed
 * with binary record structure — this pulls out the longest printable-ASCII
 * run as a pragmatic identity string rather than fully parsing the SZL
 * record layout (vendor-specific and not worth hand-rolling in full here).
 */
export function parseS7SzlIdentity(response: Buffer | null): string | undefined {
  if (!response || response.length < 20 || response[7] !== 0x32) return undefined;
  let best = '';
  let current = '';
  for (const byte of response) {
    const isPrintable = byte >= 0x20 && byte <= 0x7e;
    current = isPrintable ? current + String.fromCharCode(byte) : '';
    if (current.length > best.length) best = current;
  }
  return best.trim().length >= 4 ? best.trim() : undefined;
}

/**
 * OPC-UA (port 4840): sends a Hello message and confirms the ACK reply.
 * Full endpoint enumeration (GetEndpointsRequest/Response) requires
 * establishing a secure channel first per the OPC-UA binary protocol —
 * genuinely complex to hand-roll correctly and easy to get subtly wrong,
 * so it is intentionally not attempted here; a real OPC-UA client SDK
 * would be the correct tool for that, not a hand-rolled parser.
 */
async function probeOpcUa(ip: string): Promise<{ ok: boolean; evidence: string }> {
  const endpointUrl = Buffer.from('opc.tcp://sentineldock/');
  const body = Buffer.concat([
    Buffer.from([0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    Buffer.from([endpointUrl.length, 0, 0, 0]),
    endpointUrl,
  ]);
  const header = Buffer.concat([Buffer.from('HELF'), Buffer.alloc(4)]);
  header.writeUInt32LE(header.length + body.length, 4);
  const response = await sendAndRead(ip, 4840, Buffer.concat([header, body]));
  if (!response || response.length < 3) return { ok: false, evidence: '' };
  return response.subarray(0, 3).toString('ascii') === 'ACK' ? { ok: true, evidence: 'OPC-UA Hello/ACK confirmed' } : { ok: false, evidence: '' };
}

/**
 * BACnet/IP (UDP 47808): sends a real Who-Is broadcast-style unicast APDU
 * and listens for an I-Am reply — the actual BACnet discovery mechanism
 * (this is what a real BACnet workstation does on startup), not a TCP
 * guess. Parses the responding device's Device Instance number out of
 * the I-Am APDU when present, then follows up with a real ReadProperty
 * request for the Object-Name property of that device object to recover
 * a human-readable identity string — still a read-only operation, never
 * a WriteProperty.
 */
async function probeBacnet(ip: string): Promise<{ ok: boolean; evidence: string; deviceIdentity?: string; likelyAcceptsWrites?: boolean }> {
  // BVLC header (Original-Unicast-NPDU) + NPDU + Who-Is APDU (unconstrained, no range).
  const whoIs = Buffer.from([0x81, 0x0a, 0x00, 0x08, 0x01, 0x20, 0x10, 0x08]);
  const response = await udpRequest(ip, 47808, whoIs);
  if (!response || response.length < 8 || response[0] !== 0x81) return { ok: false, evidence: '' };
  // I-Am APDU service choice is 0x00 within an Unconfirmed-REQ (0x10); look for that pattern.
  const hasIAm = response.includes(Buffer.from([0x10, 0x00]));
  if (!hasIAm) return { ok: response[0] === 0x81, evidence: 'BVLC response received (not a parsed I-Am)' };

  const deviceIdIndex = response.indexOf(Buffer.from([0x10, 0x00])) + 3;
  const deviceInstance = deviceIdIndex + 4 <= response.length ? response.readUInt32BE(deviceIdIndex) & 0x3fffff : null;
  if (deviceInstance === null) return { ok: true, evidence: 'I-Am received' };

  const objectName = await readBacnetObjectName(ip, deviceInstance);
  return {
    ok: true,
    evidence: objectName ? `I-Am received (device instance ${deviceInstance}); ReadProperty Object-Name confirmed` : `I-Am received, device instance ${deviceInstance}`,
    deviceIdentity: objectName,
    // BACnet/IP has no transport-level authentication by default; a device
    // that answers ReadProperty unauthenticated is a plausible target for
    // WriteProperty too — inferred, never tested by actually writing.
    likelyAcceptsWrites: true,
  };
}

/** Real ReadProperty request for Object-Name (property id 77) of the device object, parsed from the confirmed response's character-string value. */
async function readBacnetObjectName(ip: string, deviceInstance: number): Promise<string | undefined> {
  const invokeId = 0x01;
  const objectIdentifier = (0x08 << 22) | (deviceInstance & 0x3fffff); // object type 8 = device
  const apdu = Buffer.from([
    0x00, 0x05, invokeId, 0x0c, // Confirmed-REQ, PDU flags, invoke id, service choice ReadProperty(0x0c)
    0x0c, // context tag 0, length 4 (object identifier)
    (objectIdentifier >>> 24) & 0xff, (objectIdentifier >>> 16) & 0xff, (objectIdentifier >>> 8) & 0xff, objectIdentifier & 0xff,
    0x19, 0x4d, // context tag 1, length 1: property identifier 77 (object-name)
  ]);
  const npdu = Buffer.from([0x01, 0x04]);
  const bvlc = Buffer.from([0x81, 0x0a, 0x00, 0x00]);
  const packet = Buffer.concat([bvlc, npdu, apdu]);
  packet.writeUInt16BE(packet.length, 2);

  const response = await udpRequest(ip, 47808, packet, 800);
  if (!response || response.length < 10 || response[0] !== 0x81) return undefined;
  // Look for a character-string application tag (context tag 3, opening tag 0x3e) followed by encoding byte + ASCII text.
  const marker = response.indexOf(Buffer.from([0x3e]));
  if (marker < 0 || marker + 3 >= response.length) return undefined;
  const text = response.subarray(marker + 3).toString('ascii').replace(/[^\x20-\x7e]/g, '');
  return text.trim().length > 0 ? text.trim() : undefined;
}

/**
 * Probes a single IP for ICS/OT protocol stacks with real handshakes:
 * Modbus FC1/FC3 register reads, S7comm COTP+Setup Communication,
 * OPC-UA Hello/ACK, and BACnet/IP Who-Is/I-Am over its native UDP
 * transport.
 */
export async function scanIcsProtocols(ip: string): Promise<IcsProbeResult[]> {
  const results: IcsProbeResult[] = [];
  const [modbus, s7, opcua, bacnet] = await Promise.all([probeModbus(ip), probeS7(ip), probeOpcUa(ip), probeBacnet(ip)]);
  if (modbus.ok) results.push({ port: 502, protocolFamily: 'modbus', name: 'modbus', evidence: modbus.evidence, likelyAcceptsWrites: modbus.likelyAcceptsWrites });
  if (s7.ok) results.push({ port: 102, protocolFamily: 's7', name: 's7comm', evidence: s7.evidence, deviceIdentity: s7.deviceIdentity });
  if (opcua.ok) results.push({ port: 4840, protocolFamily: 'opcua', name: 'opcua', evidence: opcua.evidence });
  if (bacnet.ok) {
    results.push({
      port: 47808,
      protocolFamily: 'bacnet',
      name: 'bacnet',
      evidence: bacnet.evidence,
      deviceIdentity: bacnet.deviceIdentity,
      likelyAcceptsWrites: bacnet.likelyAcceptsWrites,
    });
  }
  return results;
}

/**
 * Heuristic ICS device role classification from the combination of
 * confirmed ICS protocols and other open ports on the same device — not
 * a certainty, just the best signal available without vendor-specific
 * fingerprinting:
 * - Modbus/S7 alone, no web/remote-desktop ports -> likely a PLC.
 * - ICS protocol + HTTP/RDP/VNC -> likely an HMI (has an operator UI).
 * - ICS protocol + a database port -> likely a historian.
 * - More than one distinct ICS protocol family on the same device -> likely a protocol gateway.
 */
export function classifyIcsDevice(icsResults: IcsProbeResult[], otherOpenPorts: number[]): IcsDeviceRole {
  const families = new Set(icsResults.map((r) => r.protocolFamily));
  if (families.size > 1) return 'gateway';
  const hasOperatorUi = otherOpenPorts.some((p) => [80, 443, 3389, 5900, 8080].includes(p));
  const hasDatabase = otherOpenPorts.some((p) => [5432, 3306, 1433, 1521].includes(p));
  if (hasDatabase) return 'historian';
  if (hasOperatorUi) return 'hmi';
  if (families.has('modbus') || families.has('s7')) return 'plc';
  return 'ics-device';
}
