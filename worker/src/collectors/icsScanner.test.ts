import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyIcsDevice, type IcsProbeResult } from './icsScanner.js';

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
