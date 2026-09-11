import { test } from 'node:test';
import assert from 'node:assert/strict';
import { categoryForViolation, severityFromCvss, type ViolationWithPolicyKey } from './riskEngine.js';

function makeViolation(overrides: Partial<ViolationWithPolicyKey>): ViolationWithPolicyKey {
  return {
    id: 'v1',
    policy_id: 'p1',
    policy_key: 'ssh-exposed-public',
    asset_type: 'service',
    asset_id: 'a1',
    severity: 'critical',
    details: {},
    status: 'open',
    detected_at: '',
    ...overrides,
  };
}

test('categoryForViolation maps known policy keys to their category', () => {
  assert.equal(categoryForViolation(makeViolation({ policy_key: 'ssh-exposed-public' })), 'exposure');
  assert.equal(categoryForViolation(makeViolation({ policy_key: 'privileged-container', asset_type: 'container' })), 'container');
  assert.equal(categoryForViolation(makeViolation({ policy_key: 'outdated-os-critical-host', asset_type: 'host' })), 'host');
  assert.equal(categoryForViolation(makeViolation({ policy_key: 'ot-it-segmentation', asset_type: 'host' })), 'network');
});

test('categoryForViolation does not false-match substrings within a policy key', () => {
  // Regression: "docker-socket-exposed" incidentally contains "os" (from
  // "exp-os-ed") — a naive substring check against "os" would misclassify
  // this as a "host" category instead of "exposure".
  assert.equal(categoryForViolation(makeViolation({ policy_key: 'docker-socket-exposed' })), 'exposure');
});

test('categoryForViolation falls back to container for unknown container-asset violations', () => {
  assert.equal(categoryForViolation(makeViolation({ policy_key: 'some-future-policy', asset_type: 'container' })), 'container');
});

test('categoryForViolation falls back to misconfiguration for unknown non-container violations', () => {
  assert.equal(categoryForViolation(makeViolation({ policy_key: 'some-future-policy', asset_type: 'host' })), 'misconfiguration');
});

test('severityFromCvss buckets scores per standard CVSS severity bands', () => {
  assert.equal(severityFromCvss(9.8), 'critical');
  assert.equal(severityFromCvss(9.0), 'critical');
  assert.equal(severityFromCvss(8.9), 'high');
  assert.equal(severityFromCvss(7.0), 'high');
  assert.equal(severityFromCvss(6.9), 'medium');
  assert.equal(severityFromCvss(4.0), 'medium');
  assert.equal(severityFromCvss(3.9), 'low');
  assert.equal(severityFromCvss(0), 'low');
});
