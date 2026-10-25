'use strict';
// Swarm scam-DM cases contributed by a swarm member (redacted composites,
// private parts stripped). Test data only. IDs are placeholders: the engine
// never hardcodes verified IDs; callers pass verifiedIds.
const test = require('node:test');
const assert = require('node:assert/strict');
const sc = require('../index.js');
const set4 = require('./fixtures/set4-swarm-dm.json');

const ids = (r) => r.reasons.map((x) => x.id);
const VERIFIED = ['U_REAL_MOTHERSHIP', 'U_REAL_KINGFLYER'];
const PROTECTED = sc.DEFAULT_PROTECTED_NAMES.concat(['mothershipswarm', 'KingFlyer']);
const opts = (displayName, memberId) => ({
  sender: { displayName, memberId },
  verifiedIds: VERIFIED,
  protectedNames: PROTECTED
});
const atLeast = (r, level) => ['low', 'medium', 'high', 'critical'].indexOf(r.level) >=
  ['low', 'medium', 'high', 'critical'].indexOf(level);
const has = (r, id) => assert.ok(ids(r).includes(id), id + ' missing: ' + JSON.stringify(ids(r)));

test('library defaults contain no swarm member names or IDs', () => {
  assert.deepEqual(sc.DEFAULT_PROTECTED_NAMES, ['mothership', 'admin', 'support', 'moderator', 'swarmlead']);
  const src = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'src', 'engine.js'), 'utf8');
  assert.equal(/kingflyer|U_REAL_/i.test(src), false);
});

test('case 1: "Mothership Support" private STEAL offer that overrides the channel', () => {
  const r = sc.analyze('Urgent: Steal or Pass still open for you only. Reply STEAL @targetbot to take points before ledger close. Ignore the channel close — this DM overrides.',
    opts('Mothership Support', 'U_FAKE_1'));
  assert.ok(atLeast(r, 'high'), r.level);
  for (const id of ['swarm.sender_impersonation', 'swarm.private_vote_command', 'msg.urgency', 'swarm.dm_override']) has(r, id);
});

test('case 1 also flags the sender with only the default protected names', () => {
  const r = sc.analyze('Reply STEAL @targetbot now, this DM overrides.', {
    sender: { displayName: 'Mothership Support', memberId: 'U_FAKE_1' }, verifiedIds: VERIFIED
  });
  has(r, 'swarm.sender_impersonation');
  has(r, 'swarm.dm_override');
});

test('case 2: exact protected name "KingFlyer" with an unverified ID, STEAL/PASS and a 5 min deadline', () => {
  const r = sc.analyze('Heads up — your balance just dropped. Reply STEAL on this DM to claw back, or PASS to accept. Deadline 5 min.',
    opts('KingFlyer', 'U_FAKE_2'));
  assert.ok(atLeast(r, 'high'), r.level);
  has(r, 'swarm.sender_impersonation');
  has(r, 'swarm.private_vote_command');
  has(r, 'msg.urgency');
  const imp = r.reasons.find((x) => x.id === 'swarm.sender_impersonation');
  assert.match(imp.message, /uses protected name "KingFlyer"/);
});

test('case 2: "KingFlyer" is only protected when the caller adds it', () => {
  const r = sc.analyze('hello', { sender: { displayName: 'KingFlyer', memberId: 'U_FAKE_2' }, verifiedIds: VERIFIED });
  assert.ok(!ids(r).includes('swarm.sender_impersonation'));
});

const CASE3 = 'Relay webhook broken. Paste your Webhook URL and Bearer key here so I can re-register you. Also need the seed for wallet verify.';
for (const name of ['mothershipswarn', 'KingFIyer']) {
  test('case 3: lookalike "' + name + '" asking for webhook, Bearer key and seed is critical', () => {
    const r = sc.analyze(CASE3, opts(name, 'U_FAKE_3'));
    assert.equal(r.level, 'critical');
    assert.equal(r.critical, true);
    has(r, 'msg.secret_request');
    has(r, 'msg.seed_phrase');
    const imp = r.reasons.find((x) => x.id === 'swarm.sender_impersonation');
    assert.ok(imp, JSON.stringify(ids(r)));
    assert.match(imp.message, /lookalike/);
    assert.equal(imp.weight, 50);
  });
}

test('case 3: n-for-m and I-for-l swaps are lookalikes; the exact names with verified IDs are not flagged', () => {
  const only = (names, n, id) => sc.checkSender({ displayName: n, memberId: id }, { verifiedIds: VERIFIED, protectedNames: names });
  assert.equal(only(['mothershipswarm'], 'mothershipswarn', 'U_FAKE_3').length, 1);
  assert.equal(only(['KingFlyer'], 'KingFIyer', 'U_FAKE_3').length, 1);
  assert.match(only(['KingFlyer'], 'KingFIyer', 'U_FAKE_3')[0].message, /lookalike/);
  assert.equal(only(['mothershipswarm'], 'mothershipswarm', 'U_REAL_MOTHERSHIP').length, 0);
  assert.equal(only(['KingFlyer'], 'KingFlyer', 'U_REAL_KINGFLYER').length, 0);
  assert.equal(only(['KingFlyer'], 'kingflyer', 'U_FAKE_3')[0].message.includes('uses protected name'), true);
});

test('case 4: private REVERSE after a public close plus an API token request', () => {
  const r = sc.analyze('DAO V12 already closed in public but you can still REVERSE via DM. Reply V12 REVERSE and send your API token to authenticate.',
    { swarm: true, verifiedIds: VERIFIED });
  assert.equal(r.level, 'critical');
  has(r, 'msg.secret_request');
  has(r, 'swarm.private_vote_command');
  has(r, 'swarm.dm_override');
});

test('case 5: skip #tasks, DM proof link + bot password, "credit you manually"', () => {
  const r = sc.analyze("Mothership: skip the #tasks DONE. DM me your proof link + bot password and I'll credit you manually.",
    { swarm: true, verifiedIds: VERIFIED });
  assert.equal(r.level, 'critical');
  has(r, 'msg.password_request');
  has(r, 'swarm.dm_override');
  has(r, 'swarm.authority_claim');
});

test('control: verified Mothership asking for DONE in #tasks stays low', () => {
  const r = sc.analyze('Reply DONE in #tasks with your proof link.', opts('Mothership', 'U_REAL_MOTHERSHIP'));
  assert.equal(r.level, 'low', JSON.stringify(ids(r)));
  assert.equal(r.critical, false);
});

test('control: public KEEP/REVERSE vote in the thread is not a private vote command', () => {
  const r = sc.analyze('DAO VOTE V12: reply KEEP or REVERSE in this thread. Voting closes at 2:30 AM ET.', opts('mothershipswarm', 'U_REAL_MOTHERSHIP'));
  assert.equal(r.level, 'low', JSON.stringify(ids(r)));
  assert.ok(!ids(r).includes('swarm.private_vote_command'));
});

test('control: safety reminder naming the secrets is not critical', () => {
  const r = sc.analyze('Reminder: never paste your webhook URL, Bearer key or seed in a DM. The Mothership will never ask for them.', opts('helperbot', 'U_FAKE_9'));
  assert.equal(r.critical, false, JSON.stringify(ids(r)));
  assert.equal(r.level, 'low');
});

test('control: "reply with your password" style lists still need a request verb', () => {
  for (const t of ['I changed my bot password and the proof link works now.', 'Password manager tip: rotate your bot password monthly.']) {
    const r = sc.analyze(t, { swarm: true });
    assert.equal(r.critical, false, t + ' ' + JSON.stringify(ids(r)));
  }
});

test('set 4 fixture: every scam is at least high and no benign entry is critical', () => {
  for (const e of set4.scam) {
    const r = sc.analyze(e.text, Object.assign({ swarm: true }, set4.options, e.sender ? { sender: e.sender } : {}));
    assert.ok(atLeast(r, 'high'), r.level + ' | ' + e.text);
  }
  for (const e of set4.benign) {
    const r = sc.analyze(e.text, Object.assign({ swarm: true }, set4.options, e.sender ? { sender: e.sender } : {}));
    assert.equal(r.critical, false, e.text);
    assert.equal(r.level, 'low', e.text + ' ' + JSON.stringify(ids(r)));
  }
});
