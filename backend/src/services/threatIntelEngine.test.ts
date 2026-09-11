import { test } from 'node:test';
import assert from 'node:assert/strict';
import { maliciousPortIndicatorFor, targetedCampaignForCve } from './threatIntelEngine.js';

test('maliciousPortIndicatorFor matches a known C2/backdoor port', () => {
  const indicator = maliciousPortIndicatorFor(4444);
  assert.ok(indicator);
  assert.equal(indicator?.severity, 'critical');
});

test('maliciousPortIndicatorFor returns undefined for an ordinary port', () => {
  assert.equal(maliciousPortIndicatorFor(80), undefined);
});

test('targetedCampaignForCve returns campaign context for a curated CVE', () => {
  assert.match(targetedCampaignForCve('CVE-2017-0144') ?? '', /EternalBlue/);
});

test('targetedCampaignForCve returns undefined for a CVE not in the curated set', () => {
  assert.equal(targetedCampaignForCve('CVE-9999-99999'), undefined);
});
