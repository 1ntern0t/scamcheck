'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const sc = require('../index.js');

const ids = (r) => r.reasons.map((x) => x.id);

test('punycode homograph imitating a brand', () => {
  const r = sc.analyzeUrl('https://www.xn--pypal-4ve.com/signin');
  assert.ok(ids(r).includes('url.homograph_brand'));
  assert.ok(r.score >= 50);
});

test('raw unicode homograph host is detected', () => {
  const r = sc.analyze('Log in at https://\u0430pple.com/id');
  assert.ok(ids(r).includes('url.homograph_brand'));
});

test('digit-substitution lookalike', () => {
  assert.ok(ids(sc.analyzeUrl('http://paypa1.com')).includes('url.lookalike_homoglyph'));
  assert.ok(ids(sc.analyzeUrl('rnicrosoft.com')).includes('url.lookalike_homoglyph'));
  assert.ok(ids(sc.analyzeUrl('http://paypa1-secure.com/login')).includes('url.lookalike_homoglyph'));
});

test('edit-distance typosquats', () => {
  assert.ok(ids(sc.analyzeUrl('paypall.com')).includes('url.lookalike_typo'));
  assert.ok(ids(sc.analyzeUrl('coinbsae.com')).includes('url.lookalike_typo'));
  assert.ok(ids(sc.analyzeUrl('metamaks.io')).includes('url.lookalike_typo'));
});

test('brand embedded with lure words or in subdomain', () => {
  assert.ok(ids(sc.analyzeUrl('secure-paypal.net')).includes('url.brand_embedded'));
  assert.ok(ids(sc.analyzeUrl('appleid-verify.com')).includes('url.brand_embedded'));
  assert.ok(ids(sc.analyzeUrl('https://paypal.com.login-check.xyz/')).includes('url.brand_in_subdomain'));
  assert.ok(ids(sc.analyzeUrl('https://paypal.xyz')).includes('url.brand_unofficial_tld'));
});

test('IP-literal and obfuscated IP hosts', () => {
  assert.ok(ids(sc.analyzeUrl('http://203.0.113.9/login')).includes('url.ip_host'));
  const r = sc.analyzeUrl('http://3405803785/');
  assert.ok(ids(r).includes('url.ip_host'));
  assert.ok(ids(r).includes('url.ip_obfuscated'));
  assert.ok(ids(sc.analyzeUrl('http://[2001:db8::1]/')).includes('url.ip_host'));
});

test('userinfo @ trick', () => {
  const r = sc.analyzeUrl('https://paypal.com@evil.example/');
  assert.ok(ids(r).includes('url.userinfo'));
  assert.equal(r.host, 'evil.example');
});

test('excessive subdomains, suspicious TLD, shortener, script scheme', () => {
  assert.ok(ids(sc.analyzeUrl('https://a.b.c.d.e.example.com')).includes('url.many_subdomains'));
  assert.ok(ids(sc.analyzeUrl('https://cheap-deals.zip')).includes('url.suspicious_tld'));
  assert.ok(ids(sc.analyzeUrl('https://bit.ly/3abc')).includes('url.shortener'));
  assert.ok(ids(sc.analyzeUrl('javascript:alert(1)')).includes('url.script_scheme'));
});

test('displayed vs real link mismatch (markdown and HTML)', () => {
  assert.ok(ids(sc.analyze('[https://www.paypal.com](https://evil.example.xyz/login)')).includes('url.display_mismatch'));
  assert.ok(ids(sc.analyze('<a href="http://203.0.113.9/x">www.chase.com</a>')).includes('url.display_mismatch'));
});

test('no false positives on official / ordinary domains', () => {
  const benign = [
    'https://www.paypal.com/myaccount/summary', 'https://accounts.google.com/', 'https://github.com/nodejs/node',
    'https://www.amazon.co.uk/', 'https://google.de', 'https://en.wikipedia.org/wiki/Phishing',
    'https://stream.com', 'https://www.applebees.com', 'https://pineapple.com', 'https://docs.solana.com/',
    'https://login.microsoftonline.com/', 'https://phantom.app/', 'https://example.org/blog/post-1'
  ];
  for (const u of benign) {
    const r = sc.analyzeUrl(u);
    assert.equal(r.score, 0, u + ' -> ' + JSON.stringify(ids(r)));
  }
});

test('legit IDN without brand imitation is only a mild signal', () => {
  const r = sc.analyzeUrl('https://xn--mnchen-3ya.de/');
  assert.ok(r.score <= 15, JSON.stringify(r.reasons));
});

test('"brand.com-word.tld" fake-TLD label trick', () => {
  for (const u of ['https://ezpass-toll.com-pay.info', 'https://usps.com-track.top/x', 'http://bank.net-secure.example/login']) {
    const r = sc.analyzeUrl(u);
    assert.ok(ids(r).includes('url.fake_tld_label'), u + ' ' + JSON.stringify(ids(r)));
    assert.ok(r.score >= 35, u);
  }
  for (const u of ['https://www.example.com/com-pay', 'https://com-pay.example', 'https://my-company.com']) {
    assert.equal(ids(sc.analyzeUrl(u)).includes('url.fake_tld_label'), false, u);
  }
});

test('github.blog is an official GitHub domain (post-hoc, found by held-out set 3)', () => {
  assert.equal(ids(sc.analyzeUrl('https://github.blog/2026-10-01-ci/')).includes('url.brand_unofficial_tld'), false);
  assert.ok(ids(sc.analyzeUrl('https://github.top/login')).includes('url.brand_unofficial_tld'));
});
