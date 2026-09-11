import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hashToken, generateToken } from './rbac.js';

test('hashToken is deterministic for the same input', () => {
  assert.equal(hashToken('my-secret-token'), hashToken('my-secret-token'));
});

test('hashToken produces different digests for different inputs', () => {
  assert.notEqual(hashToken('token-a'), hashToken('token-b'));
});

test('hashToken never returns the raw input', () => {
  const raw = 'a-very-recognizable-raw-token-value';
  assert.notEqual(hashToken(raw), raw);
  assert.equal(hashToken(raw).length, 64); // sha256 hex digest length
});

test('generateToken produces sufficiently long, distinct random tokens', () => {
  const a = generateToken();
  const b = generateToken();
  assert.notEqual(a, b);
  assert.equal(a.length, 64); // 32 bytes hex-encoded
  assert.match(a, /^[0-9a-f]{64}$/);
});
