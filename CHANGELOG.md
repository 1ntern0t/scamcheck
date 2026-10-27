# Changelog

## Unreleased (2026-10-27)

### Added
- Dogecoin address validation (Base58Check, P2PKH version 0x1e and P2SH version 0x16). Before this,
  `D...` addresses were not recognised at all, so a mistyped or altered DOGE address in a message was
  never flagged. A valid one is now listed with `chain: 'dogecoin'`, and a `D...` string whose checksum
  fails adds `crypto.invalid_address`. Tests are in `test/dogecoin.test.js`. `docs/index.html` was rebuilt.

### Changed
- One tuning sample in `test/fixtures/set2-tuning.json` now uses a generic first name. Eval results did not change.
