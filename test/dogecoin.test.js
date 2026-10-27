'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const sc = require('../index.js');
const P = require('../src/primitives.js');

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58CheckEncode(version, payload) {
  const body = [version, ...payload];
  const check = P.sha256(P.sha256(Uint8Array.from(body))).slice(0, 4);
  const bytes = [...body, ...check];
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; s = '1' + s; }
  return s;
}
const hash160 = Array.from({ length: 20 }, (_, i) => (i * 37 + 11) & 0xff);

test('valid Dogecoin P2PKH and P2SH addresses are recognised', () => {
  const p2pkh = base58CheckEncode(0x1e, hash160);
  assert.match(p2pkh, /^D/);
  const r = sc.analyzeAddress(p2pkh);
  assert.equal(r.chain, 'dogecoin');
  assert.equal(r.valid, true);
  const p2sh = base58CheckEncode(0x16, hash160);
  assert.equal(sc.analyzeAddress(p2sh).chain, 'dogecoin');
  assert.equal(sc.analyzeAddress(p2sh).valid, true);
});

test('a Dogecoin address with one character changed fails its checksum', () => {
  const good = base58CheckEncode(0x1e, hash160);
  const i = 10;
  const bad = good.slice(0, i) + (good[i] === 'a' ? 'b' : 'a') + good.slice(i + 1);
  const r = sc.analyzeAddress(bad);
  assert.equal(r.chain, 'dogecoin');
  assert.equal(r.valid, false);
  const msg = sc.analyze('Send the DOGE to ' + bad + ' today');
  assert.ok(msg.reasons.some((x) => x.id === 'crypto.invalid_address'));
});

test('a valid Dogecoin address in a message is listed and not flagged as invalid', () => {
  const good = base58CheckEncode(0x1e, hash160);
  const r = sc.analyze('My tip address is ' + good);
  assert.ok(r.addresses.some((a) => a.chain === 'dogecoin' && a.valid));
  assert.ok(!r.reasons.some((x) => x.id === 'crypto.invalid_address'));
});
