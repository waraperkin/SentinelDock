import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyIcsDevice, parseS7SzlIdentity, type IcsProbeResult } from './icsScanner.js';

function modbus(): IcsProbeResult {
  return { port: 502, protocolFamily: 'modbus', name: 'modbus', evidence: 'test' };
}
function s7(): IcsProbeResult {
  return { port: 102, protocolFamily: 's7', name: 's7comm', evidence: 'test' };
}

test('classifyIcsDevice labels a lone Modbus/S7 device as a PLC', () => {
  assert.equal(classifyIcsDevice([modbus()], []), 'plc');
  assert.equal(classifyIcsDevice([s7()], []), 'plc');
});

test('classifyIcsDevice labels a device with an operator UI port as an HMI', () => {
  assert.equal(classifyIcsDevice([modbus()], [443]), 'hmi');
  assert.equal(classifyIcsDevice([modbus()], [3389]), 'hmi');
});

test('classifyIcsDevice labels a device with a database port as a historian', () => {
  assert.equal(classifyIcsDevice([modbus()], [5432]), 'historian');
});

test('classifyIcsDevice labels a device speaking multiple ICS protocol families as a gateway', () => {
  assert.equal(classifyIcsDevice([modbus(), s7()], []), 'gateway');
});

test('classifyIcsDevice prioritizes database over operator-UI when both are present', () => {
  assert.equal(classifyIcsDevice([modbus()], [443, 5432]), 'historian');
});

test('parseS7SzlIdentity returns undefined for a null or too-short response', () => {
  assert.equal(parseS7SzlIdentity(null), undefined);
  assert.equal(parseS7SzlIdentity(Buffer.from([0x03, 0x00])), undefined);
});

test('parseS7SzlIdentity returns undefined when the response is not a valid S7 userdata reply', () => {
  const notS7 = Buffer.alloc(25, 0x00);
  assert.equal(parseS7SzlIdentity(notS7), undefined);
});

test('parseS7SzlIdentity extracts the longest printable-ASCII run as the identity string', () => {
  const header = Buffer.from([0x03, 0x00, 0x00, 0x21, 0x02, 0xf0, 0x80, 0x32]);
  const binaryNoise = Buffer.from([0x00, 0x01, 0x02, 0x03]);
  const identity = Buffer.from('6ES7 315-2EH14-0AB0 ', 'ascii');
  const trailingNoise = Buffer.from([0x00, 0x00]);
  const response = Buffer.concat([header, binaryNoise, identity, trailingNoise]);
  assert.equal(parseS7SzlIdentity(response), '6ES7 315-2EH14-0AB0');
});
