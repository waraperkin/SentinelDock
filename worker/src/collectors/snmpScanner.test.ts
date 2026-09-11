import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeOid } from './snmpScanner.js';

test('encodeOid encodes sysDescr (1.3.6.1.2.1.1.1.0) to the well-known BER bytes', () => {
  // First two arcs (1.3) collapse into a single byte (40*1+3=43=0x2b), then
  // each remaining arc is one byte since all are < 128.
  const encoded = encodeOid('1.3.6.1.2.1.1.1.0');
  assert.equal(encoded[0], 0x06); // OID tag
  assert.equal(encoded[1], 8); // length: 8 content bytes follow
  assert.deepEqual(Array.from(encoded.subarray(2)), [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
});

test('encodeOid handles a multi-byte arc value (> 127)', () => {
  // Arc value 200 needs 2 bytes in BER's base-128 encoding: 0x81 0x48.
  const encoded = encodeOid('1.3.200');
  assert.deepEqual(Array.from(encoded.subarray(2)), [0x2b, 0x81, 0x48]);
});
