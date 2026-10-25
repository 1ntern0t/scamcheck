'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const sc = require('../index.js');

const has = (r, id) => r.reasons.some((x) => x.id === id);

const POSITIVE = [
  ['URGENT: your account has been suspended. Verify your account within 24 hours at http://paypa1.com/login', ['msg.urgency', 'msg.account_threat', 'msg.verify_account'], 'high'],
  ['Huge ETH giveaway! Send 0.5 ETH to 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed and receive 1 ETH back. Double your crypto!', ['msg.double_crypto', 'msg.giveaway', 'crypto.funds_request'], 'critical'],
  ['Wallet support: to fix the sync error please enter your 12 word seed phrase here', ['msg.seed_phrase'], 'critical'],
  ['Please validate your wallet to claim your airdrop allocation', ['msg.wallet_validation', 'msg.giveaway'], 'medium'],
  ['Hi this is support, contact us on WhatsApp to recover your funds', ['msg.support_impersonation'], 'medium'],
  ['Your Norton 360 subscription has been renewed and you were charged $399.99. If you did not authorize this, call us at 1-800-555-0100', ['msg.fake_invoice', 'msg.tech_support_brand'], 'medium'],
  ['Congratulations! You have won the international lottery. Claim your prize today.', ['msg.prize'], 'medium'],
  ['I am a barrister. Your late relative left an inheritance of 10.5 million USD; pay the processing fee to release the funds.', ['msg.advance_fee'], 'medium'],
  ['Pay the fine with Google Play cards and send the card numbers. Do not tell your bank.', ['msg.untraceable_payment', 'msg.secrecy'], 'medium'],
  ['Please send me the verification code we just texted you', ['msg.otp_request'], 'medium'],
  ['Our bot pays 5% daily ROI, guaranteed profit', ['msg.guaranteed_returns'], 'medium'],
  ['Install AnyDesk so our technician can fix your refund', ['msg.remote_access'], 'medium']
];

for (const [text, expectIds, minLevel] of POSITIVE) {
  test('flags: ' + text.slice(0, 50), () => {
    const r = sc.analyze(text);
    for (const id of expectIds) assert.ok(has(r, id), 'missing ' + id + ' in ' + JSON.stringify(r.reasons.map((x) => x.id)));
    const order = ['low', 'medium', 'high', 'critical'];
    assert.ok(order.indexOf(r.level) >= order.indexOf(minLevel), 'level ' + r.level + ' < ' + minLevel + ' (score ' + r.score + ')');
  });
}

const BENIGN = [
  'Hi, lunch at noon tomorrow? I booked a table at the place on 5th street.',
  'Never share your seed phrase or private key with anyone. Support will never DM you first.',
  'Attached is invoice #1042 for March consulting. Payment is due in 30 days. Thanks!',
  'The meeting notes are at https://docs.google.com/document/d/abc123/edit. See you Thursday.',
  'Release notes: v2.3.1 fixes a crash on startup. Download from https://github.com/example/app/releases',
  'Reminder: your dentist appointment is on Tuesday at 3pm. Reply C to confirm.',
  'Can you review my PR? It updates the README and bumps node to 20.11.0.',
  'Do not send crypto to anyone promising to double it. Scammers will ask you to send first.',
  'Your package from amazon.com was delivered to the front porch.',
  'We should verify the build passes before tagging the release.',
  'I bought a gift for mom and wrapped it, can you pick up the card?',
  'Blender 4.2 tip: press Shift+A to add a mesh; render settings are in the properties panel.'
];

for (const text of BENIGN) {
  test('benign stays low: ' + text.slice(0, 50), () => {
    const r = sc.analyze(text);
    assert.equal(r.level, 'low', 'score ' + r.score + ' ' + JSON.stringify(r.reasons.map((x) => x.id)));
    assert.equal(r.critical, false);
  });
}

test('result shape', () => {
  const r = sc.analyze('hello');
  assert.equal(typeof r.score, 'number');
  assert.ok(Array.isArray(r.reasons));
  assert.ok(Array.isArray(r.urls));
  assert.ok(Array.isArray(r.addresses));
  assert.match(r.disclaimer, /Heuristic/);
  assert.equal(sc.analyze('').score, 0);
  assert.equal(sc.analyze(null).score, 0);
});

test('score is capped at 100', () => {
  const r = sc.analyze('URGENT final notice! Send 1 BTC to receive 2 BTC. Enter your seed phrase at http://paypa1.com and http://bit.ly/x. You have won the lottery! Pay with gift cards.');
  assert.equal(r.score, 100);
});
