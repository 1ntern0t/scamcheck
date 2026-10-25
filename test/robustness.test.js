'use strict';
// Regression tests from an independent audit: inputs that used to crash.
const test = require('node:test');
const assert = require('node:assert/strict');
const sc = require('../index.js');

test('malformed percent-encoding in URL userinfo does not throw', () => {
  for (const s of ['http://%zz@a.com', 'https://%E0%A4%A@evil.com/x']) {
    assert.doesNotThrow(() => sc.analyzeUrl(s));
    const r = sc.analyzeUrl(s);
    assert.ok(r.reasons.some((x) => x.id === 'url.userinfo'));
  }
  const r = sc.analyze('see http://%zz@paypal.com.evil.xyz now');
  assert.ok(r.score > 0);
});

test('non-string and hostile inputs never throw', () => {
  const vals = [undefined, null, 42, NaN, true, {}, [1, 2], Object.create(null), Symbol('x'), 10n,
    { toString() { throw new Error('boom'); } }, Buffer.from([0, 255, 0xc3, 0x28]), new Uint8Array(16), () => 1];
  for (const v of vals) {
    assert.doesNotThrow(() => sc.analyze(v));
    assert.doesNotThrow(() => sc.analyzeUrl(v));
    assert.doesNotThrow(() => sc.analyzeAddress(v));
    assert.doesNotThrow(() => sc.extractUrls(v));
    assert.doesNotThrow(() => sc.extractAddresses(v));
    assert.doesNotThrow(() => sc.checkSender(v, {}));
  }
  assert.equal(sc.analyze(Object.create(null)).score, 0);
});

test('malformed options do not throw', () => {
  assert.doesNotThrow(() => sc.analyze('x', { sender: { displayName: {}, memberId: {} }, verifiedIds: 'abc', protectedNames: 5 }));
  const r = sc.analyze('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', { swarm: true, knownAddresses: '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed' });
  assert.equal(r.reasons.some((x) => x.id === 'swarm.unknown_address'), false);
  assert.doesNotThrow(() => sc.checkSender({ displayName: 'admin' }, undefined));
});
