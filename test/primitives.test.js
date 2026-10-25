'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const P = require('../src/primitives.js');

test('sha256 matches node:crypto', () => {
  for (const s of ['', 'abc', 'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(64), 'x'.repeat(1000), 'héllo wörld']) {
    assert.equal(P.toHex(P.sha256(s)), crypto.createHash('sha256').update(s).digest('hex'));
  }
});

test('keccak256 known vectors (Ethereum Keccak, not SHA3)', () => {
  assert.equal(P.toHex(P.keccak256('')), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(P.toHex(P.keccak256('abc')), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
  // Multi-block input (> 136 byte rate).
  assert.equal(P.keccak256('a'.repeat(200)).length, 32);
});

test('base58 decode lengths', () => {
  assert.equal(P.base58Decode('11111111111111111111111111111111').length, 32);
  assert.equal(P.base58Decode('So11111111111111111111111111111111111111112').length, 32);
  assert.equal(P.base58Decode('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa').length, 25);
  assert.equal(P.base58Decode('0OIl'), null);
});

test('bech32 / bech32m decoding (BIP-173 / BIP-350 vectors)', () => {
  assert.equal(P.bech32Decode('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4').encoding, 'bech32');
  assert.equal(P.bech32Decode('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0').encoding, 'bech32m');
  assert.equal(P.bech32Decode('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5'), null);
  assert.equal(P.bech32Decode('bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), null);
});

test('punycode decode and edit distance', () => {
  assert.equal(P.punycodeDecodeHost('xn--pypal-4ve.com'), 'p\u0430ypal.com');
  assert.equal(P.punycodeDecodeHost('example.com'), 'example.com');
  assert.equal(P.editDistance('paypal', 'paypal'), 0);
  assert.equal(P.editDistance('paypal', 'paypall'), 1);
  assert.equal(P.editDistance('coinbase', 'coinbsae'), 1);
  assert.equal(P.editDistance('', 'abc'), 3);
});
