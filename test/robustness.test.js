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

// ReDoS regressions. Each input is 100KB; before the fix these took 3s to >20s.
const N = 100000;
const rep = (s) => s.repeat(Math.ceil(N / s.length)).slice(0, N);
function timed(fn) {
  const t = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - t) / 1e6;
}

test('no catastrophic backtracking on adversarial 100KB inputs', () => {
  const cases = {
    'html anchor openers': rep('<a href="'),
    'markdown link openers': rep('[a]('),
    'cyrillic dotted labels': rep('\u0430a.'),
    'mixed-script domain chain': rep('p\u0430ypal.'),
    'cyrillic brand-lure chain': rep('p\u0430ypal-login.')
  };
  for (const [name, s] of Object.entries(cases)) {
    const ms = timed(() => sc.analyze(s));
    assert.ok(ms < 1000, name + ' took ' + ms.toFixed(0) + 'ms');
  }
});

test('anchor and markdown mismatch detection still works after the rewrite', () => {
  const a = sc.analyze('<a class="x" href="http://evil.example/login">https://www.paypal.com</a>');
  assert.ok(a.reasons.some((x) => x.id === 'url.display_mismatch'));
  const b = sc.analyze('[https://www.paypal.com](http://evil.example/login)');
  assert.ok(b.reasons.some((x) => x.id === 'url.display_mismatch'));
  const c = sc.analyze('<A HREF=\'javascript:alert(1)\'><b>https://bank.com</b></A>');
  assert.ok(c.reasons.some((x) => x.id === 'url.display_mismatch'));
  const ok = sc.analyze('<a href="https://github.com/x">github.com/x</a> and [docs](https://github.com/y)');
  assert.equal(ok.reasons.some((x) => x.id === 'url.display_mismatch'), false);
});

test('bare unicode domains are still extracted at token boundaries', () => {
  const u = sc.extractUrls('visit p\u0430ypal.com today');
  assert.equal(u.length, 1);
  assert.equal(u[0].value, 'p\u0430ypal.com');
});
