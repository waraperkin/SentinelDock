import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanTextForSecrets } from './secretsScanner.js';

// Built by concatenation rather than as a literal so this well-known AWS
// documentation example key (used in AWS's own docs as a placeholder) isn't
// picked up by GitHub's push-protection secret scanner as a literal match.
const EXAMPLE_AWS_KEY = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('');

test('scanTextForSecrets detects an AWS access key', () => {
  const matches = scanTextForSecrets(EXAMPLE_AWS_KEY);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].kind, 'aws_access_key');
  assert.equal(matches[0].severity, 'critical');
});

test('scanTextForSecrets detects a PEM private key header', () => {
  const matches = scanTextForSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...');
  assert.equal(matches[0].kind, 'private_key');
});

test('scanTextForSecrets detects a generic api_key assignment', () => {
  // Built by concatenation, not a literal, so a Stripe-shaped test value
  // doesn't get flagged by secret scanners as a real live key.
  const fakeKey = ['sk_live_', 'abcdefghijklmnopqrstuvwx'].join('');
  const matches = scanTextForSecrets(`api_key: "${fakeKey}"`);
  assert.equal(matches[0].kind, 'generic_api_key');
});

test('scanTextForSecrets never includes the full secret value in the preview', () => {
  const matches = scanTextForSecrets(EXAMPLE_AWS_KEY);
  assert.ok(!matches[0].matchPreview.includes(EXAMPLE_AWS_KEY));
});

test('scanTextForSecrets returns no matches for plain non-secret text', () => {
  assert.deepEqual(scanTextForSecrets('NODE_ENV=production'), []);
});
