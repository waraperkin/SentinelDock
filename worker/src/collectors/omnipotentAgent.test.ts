import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseProcNetTcp } from './omnipotentAgent.js';

// Real /proc/net/tcp is whitespace-column-aligned; local_address is
// "hex_ip:hex_port" and st (4th field) is the connection-state hex code.
const SAMPLE_PROC_NET_TCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0277 0100007F:0277 01 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 00000000:01BB 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0
`;

test('parseProcNetTcp extracts local port and human-readable state for a LISTEN socket', () => {
  const results = parseProcNetTcp(SAMPLE_PROC_NET_TCP);
  const listening = results.find((r) => r.state === 'LISTEN');
  assert.ok(listening);
  assert.equal(listening?.localPort, 0x1f90); // 8080
});

test('parseProcNetTcp extracts an ESTABLISHED socket', () => {
  const results = parseProcNetTcp(SAMPLE_PROC_NET_TCP);
  const established = results.find((r) => r.state === 'ESTABLISHED');
  assert.ok(established);
  assert.equal(established?.localPort, 0x0277); // 631
});

test('parseProcNetTcp extracts a TIME_WAIT socket', () => {
  const results = parseProcNetTcp(SAMPLE_PROC_NET_TCP);
  const timeWait = results.find((r) => r.state === 'TIME_WAIT');
  assert.ok(timeWait);
  assert.equal(timeWait?.localPort, 0x01bb); // 443
});

test('parseProcNetTcp returns an empty array for empty or header-only input', () => {
  assert.deepEqual(parseProcNetTcp(''), []);
  assert.deepEqual(parseProcNetTcp('  sl  local_address rem_address   st\n'), []);
});
