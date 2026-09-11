import { test } from 'node:test';
import assert from 'node:assert/strict';
import { linearRegressionTrend } from './quantumEngine.js';

test('linearRegressionTrend returns null with fewer than 2 samples', () => {
  assert.equal(linearRegressionTrend([]), null);
  assert.equal(linearRegressionTrend([42]), null);
});

test('linearRegressionTrend detects a clear increasing trend', () => {
  const trend = linearRegressionTrend([10, 20, 30, 40, 50]);
  assert.ok(trend);
  assert.equal(trend?.direction, 'increasing');
  assert.ok(trend!.slope > 0);
  assert.equal(trend?.current_score, 50);
  assert.ok(trend!.forecast_next > 50, 'forecast should extrapolate beyond the last observed increasing value');
});

test('linearRegressionTrend detects a clear decreasing trend', () => {
  const trend = linearRegressionTrend([50, 40, 30, 20, 10]);
  assert.ok(trend);
  assert.equal(trend?.direction, 'decreasing');
  assert.ok(trend!.slope < 0);
});

test('linearRegressionTrend reports "stable" for a flat series', () => {
  const trend = linearRegressionTrend([25, 25, 25, 25]);
  assert.ok(trend);
  assert.equal(trend?.direction, 'stable');
  assert.equal(trend?.slope, 0);
});

test('linearRegressionTrend never forecasts a negative score', () => {
  const trend = linearRegressionTrend([5, 3, 1]);
  assert.ok(trend);
  assert.ok(trend!.forecast_next >= 0);
});
