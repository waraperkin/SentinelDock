import net from 'node:net';

export interface IcsProbeResult {
  port: number;
  protocolFamily: 'modbus' | 's7' | 'bacnet' | 'opcua';
  name: string;
}

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
      // Give the peer a brief moment in case it sends a multi-packet reply.
      setTimeout(() => finish(data), 100);
    });
    socket.once('timeout', () => finish(data.length > 0 ? data : null));
    socket.once('error', () => finish(null));
    socket.connect(port, ip);
  });
}

/**
 * Modbus/TCP (port 502): a valid Modbus device echoes back the MBAP header
 * transaction ID we send in a "Read Holding Registers" request, even if the
 * specific register address is invalid — that echo alone confirms a real
 * Modbus stack, not just an open port.
 */
async function probeModbus(ip: string): Promise<boolean> {
  const request = Buffer.from([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01]);
  const response = await sendAndRead(ip, 502, request);
  if (!response || response.length < 2) return false;
  return response[0] === 0x00 && response[1] === 0x01; // echoed transaction ID
}

/**
 * S7comm over ISO-on-TCP (port 102): send a COTP Connection Request; a real
 * Siemens S7 PLC (or compatible) replies with a COTP Connection Confirm
 * (TPDU code 0xD in the high nibble of the 6th byte).
 */
async function probeS7(ip: string): Promise<boolean> {
  const cotpConnectRequest = Buffer.from([0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02]);
  const response = await sendAndRead(ip, 102, cotpConnectRequest);
  if (!response || response.length < 6) return false;
  return response[0] === 0x03 && (response[5] & 0xf0) === 0xd0;
}

/**
 * OPC-UA (port 4840): send a minimal "Hello" message; a real OPC-UA
 * endpoint replies with an "ACK" message (message type "ACK" = 0x41 0x43 0x4b).
 */
async function probeOpcUa(ip: string): Promise<boolean> {
  const endpointUrl = Buffer.from('opc.tcp://sentineldock/');
  const body = Buffer.concat([
    Buffer.from([0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), // version, buffer sizes, max message size, max chunk count (loose defaults)
    Buffer.from([endpointUrl.length, 0, 0, 0]),
    endpointUrl,
  ]);
  const header = Buffer.concat([Buffer.from('HELF'), Buffer.alloc(4)]);
  header.writeUInt32LE(header.length + body.length, 4);
  const message = Buffer.concat([header, body]);
  const response = await sendAndRead(ip, 4840, message);
  if (!response || response.length < 3) return false;
  return response.subarray(0, 3).toString('ascii') === 'ACK';
}

/**
 * BACnet normally runs over UDP (47808), which this TCP-only worker cannot
 * probe without raw sockets. We only confirm a BACnet/IP-over-TCP gateway
 * if the port happens to also answer on TCP — most BACnet devices will
 * simply not respond here, so this is best-effort and under-detects.
 */
async function probeBacnetTcp(ip: string): Promise<boolean> {
  const response = await sendAndRead(ip, 47808, Buffer.from([0x81, 0x0b, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08]));
  return response !== null && response.length > 0 && response[0] === 0x81;
}

/**
 * Probes a single IP for ICS/OT protocol stacks. Real protocol-level
 * fingerprinting (not just "port is open") for Modbus and S7comm; OPC-UA
 * and BACnet are best-effort (see probeBacnetTcp for the BACnet/UDP
 * caveat).
 */
export async function scanIcsProtocols(ip: string): Promise<IcsProbeResult[]> {
  const results: IcsProbeResult[] = [];
  const [modbus, s7, opcua, bacnet] = await Promise.all([probeModbus(ip), probeS7(ip), probeOpcUa(ip), probeBacnetTcp(ip)]);
  if (modbus) results.push({ port: 502, protocolFamily: 'modbus', name: 'modbus' });
  if (s7) results.push({ port: 102, protocolFamily: 's7', name: 's7comm' });
  if (opcua) results.push({ port: 4840, protocolFamily: 'opcua', name: 'opcua' });
  if (bacnet) results.push({ port: 47808, protocolFamily: 'bacnet', name: 'bacnet' });
  return results;
}
