import { test } from 'node:test';
import assert from 'node:assert/strict';
import { worseSeverity } from './attackPathEngine.js';

test('worseSeverity returns the higher-ranked severity', () => {
  assert.equal(worseSeverity('low', 'critical'), 'critical');
  assert.equal(worseSeverity('critical', 'low'), 'critical');
  assert.equal(worseSeverity('medium', 'high'), 'high');
});

test('worseSeverity is stable when both sides are equal', () => {
  assert.equal(worseSeverity('high', 'high'), 'high');
});

test('worseSeverity orders all four severities consistently', () => {
  assert.equal(worseSeverity('low', 'medium'), 'medium');
  assert.equal(worseSeverity('medium', 'low'), 'medium');
  assert.equal(worseSeverity('high', 'critical'), 'critical');
});
