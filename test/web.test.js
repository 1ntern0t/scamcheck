'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { build } = require('../scripts/build-web.js');

const html = fs.readFileSync(path.join(__dirname, '..', 'docs', 'index.html'), 'utf8');

test('docs/index.html is up to date with the engine (run npm run build:web)', () => {
  assert.equal(html, build());
});

test('static page makes no external requests', () => {
  assert.equal(/<(script|link|img|iframe)[^>]+(src|href)\s*=/i.test(html), false);
  assert.equal(/\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon/.test(html), false);
  assert.match(html, /Content-Security-Policy" content="default-src 'none'/);
});

test('inlined engine runs in a browser-like global and matches Node results', () => {
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  const ctx = { self: {}, TextEncoder, URL, console };
  ctx.self = ctx;
  vm.createContext(ctx);
  vm.runInContext(scripts[0], ctx);
  const node = require('../index.js');
  const sample = 'URGENT: verify your account at http://paypa1.com and send 1 ETH to receive 2 ETH';
  const a = ctx.Scamcheck.analyze(sample);
  const b = node.analyze(sample);
  assert.equal(a.score, b.score);
  assert.equal(JSON.stringify(a.reasons.map((x) => x.id)), JSON.stringify(b.reasons.map((x) => x.id)));
});
