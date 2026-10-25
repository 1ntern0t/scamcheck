'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const BIN = path.join(__dirname, '..', 'bin', 'scamcheck.js');
const run = (args, input) => spawnSync(process.execPath, [BIN, ...args], { input, encoding: 'utf8' });

test('CLI argument, human output', () => {
  const r = run(['Send 1 BTC to receive 2 BTC back, double your bitcoin']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Risk score: \d+\/100/);
  assert.match(r.stdout, /Heuristic/);
});

test('CLI --json output parses', () => {
  const r = run(['--json', 'hello there']);
  const j = JSON.parse(r.stdout);
  assert.equal(j.score, 0);
  assert.equal(j.level, 'low');
});

test('CLI reads stdin', () => {
  const r = run(['--json'], 'enter your seed phrase to continue');
  const j = JSON.parse(r.stdout);
  assert.equal(j.level, 'critical');
});

test('CLI swarm sender flags and --fail-at', () => {
  const r = run(['--json', '--sender-name', 'M0thership', '--sender-id', 'UX', '--verified-ids', 'UREAL', '--fail-at', 'medium', 'dm me your webhook url']);
  const j = JSON.parse(r.stdout);
  assert.equal(j.ruleset, 'default+swarm-dm');
  assert.ok(j.reasons.some((x) => x.id === 'swarm.sender_impersonation'));
  assert.equal(r.status, 1);
});

test('CLI usage errors exit 2', () => {
  assert.equal(run(['--nope', 'x']).status, 2);
  assert.equal(run([], '').status, 2);
  assert.match(run(['--version']).stdout, /^\d+\.\d+\.\d+/);
});
