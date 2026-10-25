'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const sc = require('../index.js');

test('EIP-55 checksum vectors', () => {
  const good = [
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
    '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'
  ];
  for (const a of good) {
    assert.deepEqual(sc.checkEthChecksum(a), { valid: true, checksummed: true }, a);
    assert.equal(sc.toEthChecksum(a.toLowerCase()), a);
  }
  const bad = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD';
  assert.equal(sc.checkEthChecksum(bad).valid, false);
  assert.equal(sc.checkEthChecksum(good[0].toLowerCase()).checksummed, false);
});

test('address classification', () => {
  assert.equal(sc.analyzeAddress('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa').valid, true);
  assert.equal(sc.analyzeAddress('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy').valid, true);
  assert.equal(sc.analyzeAddress('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb').valid, false);
  assert.equal(sc.analyzeAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4').valid, true);
  assert.equal(sc.analyzeAddress('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0').valid, true);
  assert.equal(sc.analyzeAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5').valid, false);
  const sol = sc.analyzeAddress('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
  assert.equal(sol.chain, 'solana');
  assert.equal(sol.valid, true);
  assert.equal(sc.analyzeAddress('0x1234').valid, false);
});

test('bad checksum in text is flagged', () => {
  const r = sc.analyze('my address: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD');
  assert.ok(r.reasons.some((x) => x.id === 'crypto.invalid_address'));
});

test('request to send funds to an address is flagged', () => {
  const r = sc.analyze('Send 0.2 SOL to TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA to activate your account');
  assert.ok(r.reasons.some((x) => x.id === 'crypto.funds_request'));
  assert.ok(r.score >= 50);
});

test('an address mentioned without a send request is low risk', () => {
  const r = sc.analyze('The USDC token program is TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, see docs.');
  assert.equal(r.level, 'low');
  assert.equal(r.addresses.length, 1);
});
