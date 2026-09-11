import { test } from 'node:test';
import assert from 'node:assert/strict';
import { expandCidrHosts } from './subnetScanner.js';

test('expandCidrHosts enumerates a /24 excluding network and broadcast addresses', () => {
  const hosts = expandCidrHosts('192.168.1.0/24');
  assert.equal(hosts.length, 254);
  assert.equal(hosts[0], '192.168.1.1');
  assert.equal(hosts[hosts.length - 1], '192.168.1.254');
  assert.ok(!hosts.includes('192.168.1.0'));
  assert.ok(!hosts.includes('192.168.1.255'));
});

test('expandCidrHosts handles a /28 subnet', () => {
  const hosts = expandCidrHosts('10.0.0.16/28');
  assert.equal(hosts.length, 14);
  assert.equal(hosts[0], '10.0.0.17');
  assert.equal(hosts[hosts.length - 1], '10.0.0.30');
});

test('expandCidrHosts refuses ranges larger than a /16', () => {
  assert.deepEqual(expandCidrHosts('10.0.0.0/8'), []);
});

test('expandCidrHosts returns empty for a malformed CIDR', () => {
  assert.deepEqual(expandCidrHosts('not-an-ip/24'), []);
});
