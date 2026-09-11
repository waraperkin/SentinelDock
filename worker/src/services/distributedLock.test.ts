import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shardWorkItems, workerId } from './distributedLock.js';

test('shardWorkItems claims everything when the fleet is empty (fail-open)', () => {
  const items = ['a', 'b', 'c'];
  assert.deepEqual(shardWorkItems(items, (x) => x, []), items);
});

test('shardWorkItems claims everything when this replica is not in the fleet list', () => {
  const items = ['a', 'b', 'c'];
  assert.deepEqual(shardWorkItems(items, (x) => x, ['some-other-worker-id']), items);
});

test('shardWorkItems claims everything when this is the only fleet member', () => {
  const items = ['10.0.0.0/24', '10.0.1.0/24', '10.0.2.0/24'];
  assert.deepEqual(shardWorkItems(items, (x) => x, [workerId()]), items);
});

test('shardWorkItems is deterministic and only claims a subset when the fleet has other members', () => {
  const items = ['10.0.0.0/24', '10.0.1.0/24', '10.0.2.0/24', '10.0.3.0/24', '10.0.4.0/24', '10.0.5.0/24'];
  const fleet = [
    workerId(),
    'aaaaaaaa-0000-0000-0000-000000000000',
    'bbbbbbbb-0000-0000-0000-000000000000',
    'cccccccc-0000-0000-0000-000000000000',
  ];

  const first = shardWorkItems(items, (x) => x, fleet);
  const second = shardWorkItems(items, (x) => x, fleet);

  assert.deepEqual(first, second, 'same fleet + same items must produce the same shard every time');
  assert.ok(first.length < items.length, 'a four-replica fleet should not claim every item for one replica');
  assert.ok(first.every((item) => items.includes(item)));
});

test('shardWorkItems ignores duplicate worker IDs in the fleet list', () => {
  const items = ['a', 'b', 'c', 'd'];
  const withDupes = shardWorkItems(items, (x) => x, [workerId(), workerId(), workerId()]);
  const withoutDupes = shardWorkItems(items, (x) => x, [workerId()]);
  assert.deepEqual(withDupes, withoutDupes);
});
