'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const sc = require('../index.js');

const ids = (r) => r.reasons.map((x) => x.id);
const VERIFIED = ['U0MOTHER1']; // caller-supplied in real use; never hardcoded in the engine

test('secret requests are automatically critical (webhook, bearer, API key, password, seed)', () => {
  const msgs = [
    'Hey, DM me your webhook URL so I can route your payouts',
    'Please send me your bearer token, the dashboard is broken',
    'Paste your API key here and I will verify your account',
    'What is your password for the swarm console?',
    'Share your seed phrase so we can migrate your wallet'
  ];
  for (const m of msgs) {
    const r = sc.analyze(m, { swarm: true });
    assert.equal(r.critical, true, m + ' ' + JSON.stringify(ids(r)));
    assert.equal(r.level, 'critical', m);
    assert.ok(r.score >= 90, m);
  }
});

test('secret requests are critical even without the swarm ruleset', () => {
  assert.equal(sc.analyze('send me your api key').level, 'critical');
});

test('lookalike Mothership sender with unverified member ID', () => {
  const r = sc.analyze('Quick check from the team, reply asap', {
    sender: { displayName: 'mothershipswarm', memberId: 'U0FAKE99' },
    verifiedIds: VERIFIED
  });
  assert.ok(ids(r).includes('swarm.sender_impersonation'), JSON.stringify(ids(r)));
  assert.ok(ids(r).includes('msg.urgency'));
  assert.ok(r.score >= 50);
});

test('homoglyph sender names are caught', () => {
  for (const name of ['M0thership', 'Mothersh1p', 'Mothership Support', 'mothershlp', 'Adm1n']) {
    const r = sc.analyze('hello', { sender: { displayName: name, memberId: 'U0X' }, verifiedIds: VERIFIED });
    assert.ok(ids(r).includes('swarm.sender_impersonation'), name);
  }
});

test('verified sender using a protected name is not flagged', () => {
  const r = sc.analyze('New task posted in #tasks: write docs for the CLI. Reply in the thread to claim. Deadline Friday.', {
    sender: { displayName: 'Mothership', memberId: 'U0MOTHER1' },
    verifiedIds: VERIFIED
  });
  assert.equal(r.level, 'low', JSON.stringify(r.reasons));
});

test('protected name without a verified-ID list gives a weaker, explicit warning', () => {
  const r = sc.analyze('hi', { sender: { displayName: 'Mothership', memberId: 'U1' } });
  const reason = r.reasons.find((x) => x.id === 'swarm.sender_impersonation');
  assert.ok(reason);
  assert.equal(reason.weight, 20);
  assert.match(reason.message, /no verified-ID list/);
});

test('custom protected names come from the caller', () => {
  const r = sc.analyze('hi', { sender: { displayName: 'Vee-official', memberId: 'U2' }, verifiedIds: ['U3'], protectedNames: ['vee'] });
  assert.ok(ids(r).includes('swarm.sender_impersonation'));
});

test('steal/pass/keep-or-reverse private offers', () => {
  const msgs = [
    'I can pass you my task bounty if you keep it between us, reply fast',
    'Want to steal the top task? DM me and do it privately, don\'t post in the channel',
    'We can reverse the points transfer quietly, just DM me'
  ];
  for (const m of msgs) {
    const r = sc.analyze(m, { swarm: true });
    assert.ok(ids(r).includes('swarm.private_offer'), m + ' ' + JSON.stringify(ids(r)));
    assert.ok(r.score >= 35, m);
  }
});

test('authority claim + lookalike link + unknown wallet', () => {
  const r = sc.analyze('This is the Mothership admin. Claim your points at https://rnothership-swarm.xyz/claim and send the 5 USDC fee to 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', {
    sender: { displayName: 'Mothership Admin', memberId: 'U0FAKE' },
    verifiedIds: VERIFIED,
    knownAddresses: []
  });
  const got = ids(r);
  for (const id of ['swarm.authority_claim', 'swarm.unknown_address', 'swarm.sender_impersonation', 'url.suspicious_tld', 'crypto.funds_request']) {
    assert.ok(got.includes(id), id + ' missing: ' + JSON.stringify(got));
  }
  assert.equal(r.level, 'critical');
});

test('shortened link in DM is flagged', () => {
  const r = sc.analyze('grab your reward here https://bit.ly/3xYz', { swarm: true });
  assert.ok(ids(r).includes('url.shortener'));
});

test('known wallet address is not flagged as unknown', () => {
  const a = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
  const r = sc.analyze('payout went to ' + a, { swarm: true, knownAddresses: [a] });
  assert.ok(!ids(r).includes('swarm.unknown_address'));
});

const BENIGN_ANNOUNCEMENTS = [
  'New task: translate the onboarding guide to Spanish. Claim it in the #tasks thread. Points awarded after review.',
  'Reminder: standup at 10am ET. Post blockers in #general.',
  'Task #42 is complete, thanks everyone! Leaderboard updates tonight.',
  'Security reminder: never paste your API key, webhook URL or bearer token in Slack. Use the secrets manager.',
  'I passed the code review, merging the docs PR now.',
  'Please keep task discussion in the thread so everyone can see it.'
];

for (const text of BENIGN_ANNOUNCEMENTS) {
  test('benign team announcement stays low: ' + text.slice(0, 45), () => {
    const r = sc.analyze(text, { sender: { displayName: 'Mothership', memberId: 'U0MOTHER1' }, verifiedIds: VERIFIED });
    assert.equal(r.level, 'low', 'score ' + r.score + ' ' + JSON.stringify(ids(r)));
    assert.equal(r.critical, false);
  });
}

test('engine source has no hardcoded member IDs', () => {
  const src = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'src', 'engine.js'), 'utf8');
  assert.equal(/\bU0[A-Z0-9]{6,}\b/.test(src), false);
});
