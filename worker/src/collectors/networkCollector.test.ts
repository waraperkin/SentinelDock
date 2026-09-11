import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deriveSubnets, type CollectedNetworkInterface } from './networkCollector.js';

function iface(overrides: Partial<CollectedNetworkInterface>): CollectedNetworkInterface {
  return { name: 'eth0', address: '10.0.0.1', family: 'IPv4', mac: '00:00:00:00:00:00', internal: false, ...overrides };
}

test('deriveSubnets computes a /24 from a non-internal IPv4 interface', () => {
  assert.deepEqual(deriveSubnets([iface({ address: '172.18.0.5' })]), ['172.18.0.0/24']);
});

test('deriveSubnets skips internal (loopback) interfaces', () => {
  assert.deepEqual(deriveSubnets([iface({ address: '127.0.0.1', internal: true })]), []);
});

test('deriveSubnets skips non-IPv4 interfaces', () => {
  assert.deepEqual(deriveSubnets([iface({ address: '::1', family: 'IPv6' })]), []);
});

test('deriveSubnets deduplicates interfaces on the same /24', () => {
  const result = deriveSubnets([iface({ address: '10.0.0.5', name: 'eth0' }), iface({ address: '10.0.0.9', name: 'eth1' })]);
  assert.deepEqual(result, ['10.0.0.0/24']);
});

test('deriveSubnets handles multiple distinct subnets', () => {
  const result = deriveSubnets([iface({ address: '10.0.0.5' }), iface({ address: '192.168.1.2' })]);
  assert.deepEqual(result.sort(), ['10.0.0.0/24', '192.168.1.0/24']);
});
