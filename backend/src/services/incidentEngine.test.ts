import { test } from 'node:test';
import assert from 'node:assert/strict';
import { selectScenario } from './incidentEngine.js';

test('selectScenario matches SSH-related risks to the SSH playbook', () => {
  const scenario = selectScenario('1 open violation(s) on service abc, worst severity critical ssh-exposed-public', 'exposure');
  assert.equal(scenario.title, 'SSH exposure / potential compromise');
  assert.ok(scenario.steps.immediate.length > 0);
});

test('selectScenario matches Docker-related risks to the Docker playbook', () => {
  const scenario = selectScenario('Service "docker" (v20.10) matches known vulnerabilities: CVE-2019-5736', 'vulnerability');
  assert.equal(scenario.title, 'Docker Engine API exposure / potential container escape');
});

test('selectScenario matches database-related risks to the database playbook', () => {
  const scenario = selectScenario('1 open violation(s) database-publicly-reachable', 'exposure');
  assert.equal(scenario.title, 'Database exposure / potential data compromise');
});

test('selectScenario matches privileged-container risks to the container playbook', () => {
  const scenario = selectScenario('1 open violation(s) privileged-container', 'container');
  assert.equal(scenario.title, 'Privileged container compromise');
});

test('selectScenario matches known-vulnerability risks to the vulnerability playbook when no more specific service is named', () => {
  // "redis"/"postgres"/etc. deliberately take priority over the generic
  // vulnerability playbook (a database CVE should still get DB-specific
  // guidance) — this covers a CVE on a service with no dedicated playbook.
  const scenario = selectScenario('Service "telnet" matches known vulnerabilities: CWE-319', 'vulnerability');
  assert.equal(scenario.title, 'Known-vulnerable service version');
});

test('selectScenario matches an attack path name that crosses network segments', () => {
  const scenario = selectScenario('Exposure via ssh -> crosses 3 network segments -> host', 'exposure');
  assert.equal(scenario.title, 'Lateral movement across network segments — segmentation failure');
});

test('selectScenario falls back to a generic playbook for unmatched risks', () => {
  const scenario = selectScenario('1 open violation(s) ot-it-segmentation', 'network');
  assert.equal(scenario.title, 'network risk');
  assert.ok(scenario.steps.immediate.length > 0);
  assert.ok(scenario.steps.containment.length > 0);
  assert.ok(scenario.steps.eradication.length > 0);
  assert.ok(scenario.steps.recovery.length > 0);
  assert.ok(scenario.steps.lessonsLearned.length > 0);
});
