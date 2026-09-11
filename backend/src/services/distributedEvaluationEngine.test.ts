import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shardFor } from './distributedEvaluationEngine.js';

test('shardFor is deterministic for the same key and shard count', () => {
  const a = shardFor('segment-123', 4);
  const b = shardFor('segment-123', 4);
  assert.equal(a, b);
});

test('shardFor always returns an index within [0, shardCount)', () => {
  for (const key of ['a', 'segment-1', 'subnet-10.0.0.0/24', 'unassigned-hosts']) {
    for (const count of [1, 2, 3, 5, 8]) {
      const index = shardFor(key, count);
      assert.ok(index >= 0 && index < count, `${key} with count ${count} produced out-of-range index ${index}`);
    }
  }
});

test('shardFor with shardCount 1 always assigns shard 0', () => {
  assert.equal(shardFor('anything', 1), 0);
  assert.equal(shardFor('something-else', 1), 0);
});

test('shardFor distributes distinct keys across more than one shard for a reasonably sized key set', () => {
  const shards = new Set<number>();
  for (let i = 0; i < 20; i++) shards.add(shardFor(`segment-${i}`, 4));
  assert.ok(shards.size > 1, 'expected 20 distinct keys to land in more than one shard out of 4');
});
