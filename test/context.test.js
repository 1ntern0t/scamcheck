'use strict';
// Second-pass precision fixes: mentions without a request, and prize/payment
// words without any payment, link or pressure context, should not alarm.
const test = require('node:test');
const assert = require('node:assert/strict');
const sc = require('../index.js');

const ids = (r) => r.reasons.map((x) => x.id);

test('"private key" mention without a request is not critical', () => {
  const r = sc.analyze('The private key ceremony for the HSM is scheduled with security on Monday.');
  assert.equal(r.critical, false);
  assert.equal(r.level, 'low');
  assert.ok(ids(r).includes('msg.seed_phrase_mention'));
});

test('"private key" / seed phrase with a request is still critical', () => {
  for (const s of [
    'Please send me your private key so I can fix the wallet',
    'Paste your private key below to continue',
    'Enter your secret recovery phrase on the claim page',
    'you need to re-type the words u wrote down when u made ur wallet'
  ]) {
    const r = sc.analyze(s);
    assert.equal(r.critical, true, s + ' ' + JSON.stringify(ids(r)));
  }
});

test('winning a non-monetary contest is low; prize with payment/link is not', () => {
  assert.equal(sc.analyze('Congratulations, you won the office chili cook-off! Trophy is on your desk.').level, 'low');
  assert.notEqual(sc.analyze('Congratulations, you have won! Pay $1.95 shipping to get your prize.').level, 'low');
  assert.notEqual(sc.analyze('You have won a new phone, details at https://example-prize.top').level, 'low');
});

test('gift cards mentioned without a request are low; a request is flagged', () => {
  assert.equal(sc.analyze('The gift cards for the holiday party raffle are in the kitchen drawer.').level, 'low');
  assert.notEqual(sc.analyze('I need you to buy 3 gift cards and send me photos of the codes.').level, 'low');
  assert.notEqual(sc.analyze('Hey bro, can you lend me 200 in Amazon cards real quick').level, 'low');
});

test('friend asking for ETH with no other warning sign is low', () => {
  const r = sc.analyze('Can you send 0.05 ETH to my address 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed for our shared gas costs? Thanks!');
  assert.equal(r.level, 'low');
  const s = sc.analyze('URGENT: send 0.05 ETH to 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed within 1 hour to keep your account');
  assert.notEqual(s.level, 'low');
});
