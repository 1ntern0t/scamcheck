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

test('thousands of links or addresses stay fast and report truncation', () => {
  const cases = {
    'bare domains': rep('a.co '),
    'http links': rep('http://a.co '),
    'defanged links': rep('hxxp://a[.]com '),
    'markdown links': rep('[http://a.com](http://b.com) '),
    'html anchors': rep('<a href="http://b.com">http://a.com</a> '),
    'distinct mixed-case EVM addresses': Array.from({ length: 2300 }, (_, i) => '0xAb' + i.toString(16).padStart(38, 'c')).join(' ')
  };
  for (const [name, s] of Object.entries(cases)) {
    let r;
    const ms = timed(() => { r = sc.analyze(s); });
    assert.ok(ms < 1000, name + ' took ' + ms.toFixed(0) + 'ms');
    assert.ok(r.truncated, name + ' should report truncation');
  }
  assert.ok(timed(() => sc.checkSender({ displayName: rep('a'), memberId: 'x' }, { verifiedIds: ['y'] })) < 200);
});

test('ordinary messages are not marked truncated', () => {
  assert.equal(sc.analyze('see https://github.com/x and 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed').truncated, undefined);
});

test('Cyrillic shha (U+04BB) is treated as a look-alike of "h"', () => {
  const r = sc.analyzeUrl('https://xn--gitub-0kf.com/login'); // git\u04bbub.com
  assert.ok(r.reasons.some((x) => x.id === 'url.homograph_brand'));
});

test('script-scheme links behind brand-looking text are reported as such', () => {
  const md = sc.analyze('[https://paypal.com](javascript:alert(6))');
  const a = sc.analyze('<a href="javascript:alert(5)">https://paypal.com</a>');
  for (const r of [md, a]) {
    const mm = r.reasons.find((x) => x.id === 'url.display_mismatch');
    assert.ok(mm, 'display mismatch expected');
    assert.match(mm.message, /runs a javascript: link/);
  }
  const paren = sc.analyze('[https://paypal.com](https://evil.example/a_(b))');
  assert.ok(paren.reasons.some((x) => x.id === 'url.display_mismatch'));
  assert.ok(timedOk(() => sc.analyze(rep('[a]((('))));
});

function timedOk(fn) { return timed(fn) < 1000; }

test('a bare "12 words" count is not treated as a seed-phrase request', () => {
  assert.equal(sc.analyze('The 12 words in the poem assignment should rhyme, per the teacher.').critical, false);
  for (const s of ['Enter your 24 word phrase at the link', 'Type your 12 words to restore access', 'share your 12-word recovery phrase']) {
    assert.ok(sc.analyze(s).reasons.some((x) => x.id === 'msg.seed_phrase'), s);
  }
});
