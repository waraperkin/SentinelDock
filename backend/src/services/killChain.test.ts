import { test } from 'node:test';
import assert from 'node:assert/strict';
import { techniqueForRelation, entryTechnique } from './killChain.js';

test('techniqueForRelation maps known dependency relations to ATT&CK labels', () => {
  assert.match(techniqueForRelation('runs_on'), /Lateral Movement/);
  assert.match(techniqueForRelation('member_of'), /Discovery/);
  assert.match(techniqueForRelation('connects_to'), /Command and Control/);
});

test('techniqueForRelation falls back to a lateral movement label for unknown relations', () => {
  assert.match(techniqueForRelation('some_future_relation'), /Lateral Movement/);
});

test('entryTechnique returns an Initial Access tactic label', () => {
  assert.match(entryTechnique(), /Initial Access/);
});
