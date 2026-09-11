import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evalCondition, matchesPolicy, getField } from './policyEngine.js';
import type { Policy } from '../types/models.js';

test('getField resolves nested dotted paths', () => {
  const target = { host: { network_segment: { zone: 'public' } } };
  assert.equal(getField(target, 'host.network_segment.zone'), 'public');
});

test('getField returns undefined for a missing intermediate key', () => {
  const target = { host: null };
  assert.equal(getField(target, 'host.network_segment.zone'), undefined);
});

test('evalCondition eq/neq', () => {
  assert.equal(evalCondition({ port: 22 }, { field: 'port', operator: 'eq', value: 22 }), true);
  assert.equal(evalCondition({ port: 22 }, { field: 'port', operator: 'eq', value: 80 }), false);
  assert.equal(evalCondition({ port: 22 }, { field: 'port', operator: 'neq', value: 80 }), true);
});

test('evalCondition in/not_in', () => {
  const cond = { field: 'port', operator: 'in' as const, value: [22, 2375, 2376] };
  assert.equal(evalCondition({ port: 22 }, cond), true);
  assert.equal(evalCondition({ port: 443 }, cond), false);
  assert.equal(evalCondition({ port: 443 }, { field: 'port', operator: 'not_in', value: [22, 2375] }), true);
});

test('evalCondition numeric comparisons', () => {
  assert.equal(evalCondition({ score: 12 }, { field: 'score', operator: 'gt', value: 10 }), true);
  assert.equal(evalCondition({ score: 12 }, { field: 'score', operator: 'lte', value: 10 }), false);
  assert.equal(evalCondition({ score: 'not-a-number' }, { field: 'score', operator: 'gt', value: 10 }), false);
});

test('evalCondition contains', () => {
  assert.equal(evalCondition({ os_version: 'linux 4.19.0' }, { field: 'os_version', operator: 'contains', value: '4.' }), true);
  assert.equal(evalCondition({ os_version: 'linux 6.1.0' }, { field: 'os_version', operator: 'contains', value: '4.' }), false);
});

function makePolicy(conditions: Policy['conditions']): Policy {
  return {
    id: 'p1',
    key: 'test-policy',
    name: 'Test Policy',
    severity: 'high',
    conditions,
    enabled: true,
    created_at: '',
    updated_at: '',
  };
}

test('matchesPolicy requires every "all" condition to hold', () => {
  const policy = makePolicy({
    target: 'service',
    all: [
      { field: 'port', operator: 'eq', value: 22 },
      { field: 'exposed_publicly', operator: 'eq', value: true },
    ],
  });
  assert.equal(matchesPolicy({ port: 22, exposed_publicly: true }, policy), true);
  assert.equal(matchesPolicy({ port: 22, exposed_publicly: false }, policy), false);
});

test('matchesPolicy requires at least one "any" condition when present', () => {
  const policy = makePolicy({
    target: 'service',
    any: [
      { field: 'port', operator: 'eq', value: 2375 },
      { field: 'port', operator: 'eq', value: 2376 },
    ],
  });
  assert.equal(matchesPolicy({ port: 2376 }, policy), true);
  assert.equal(matchesPolicy({ port: 8080 }, policy), false);
});

test('matchesPolicy combines "all" and "any" as AND-of-(AND, OR)', () => {
  const policy = makePolicy({
    target: 'service',
    all: [{ field: 'exposed_publicly', operator: 'eq', value: true }],
    any: [
      { field: 'port', operator: 'eq', value: 5432 },
      { field: 'port', operator: 'eq', value: 3306 },
    ],
  });
  assert.equal(matchesPolicy({ exposed_publicly: true, port: 5432 }, policy), true);
  assert.equal(matchesPolicy({ exposed_publicly: false, port: 5432 }, policy), false);
  assert.equal(matchesPolicy({ exposed_publicly: true, port: 22 }, policy), false);
});

test('matchesPolicy with no conditions at all matches everything for its target', () => {
  const policy = makePolicy({ target: 'host' });
  assert.equal(matchesPolicy({ role: 'anything' }, policy), true);
});
