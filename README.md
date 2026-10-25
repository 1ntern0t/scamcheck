# scamcheck

An offline, open-source **heuristic** checker for scam and fraud warning signs in messages,
links and crypto addresses. It returns a risk score from 0 to 100 and a plain-language list of reasons.

- **Offline-first.** No network calls, no threat feeds, no telemetry. Your text stays on your machine.
- **Zero dependencies.** Plain Node.js 20+. The same engine also runs in the browser.
- **Three ways to use it:** a CLI, a small library API, and a single static HTML page.

> **Important:** this tool is a heuristic aid. It is **not** a guarantee.
> A low score does **not** mean something is safe, and a high score does **not** prove fraud.
> When money, passwords or wallet access are involved, verify through an official channel you
> look up yourself.

## Try it in the browser

Open [`docs/index.html`](docs/index.html) locally, or use the GitHub Pages copy if it is enabled:
<https://1ntern0t.github.io/scamcheck/>. The page is one self-contained file. Its Content-Security-Policy
(`default-src 'none'`) stops it from loading or sending anything over the network.

## CLI

```sh
git clone https://github.com/1ntern0t/scamcheck.git && cd scamcheck
node bin/scamcheck.js "URGENT: your account is suspended. Verify at http://paypa1-secure.com/login"
echo "Send 0.5 ETH and receive 1 ETH back!" | node bin/scamcheck.js --json
```

Example output:

```
Risk score: 93/100 (CRITICAL)
Reasons:
  [+50] Domain paypa1-secure.com imitates "paypal" using look-alike characters.  ("paypa1-secure.com")
  [+15] Creates time pressure ("act now", "within 24 hours").  ("URGENT")
  ...
```

Options:

| Flag | Meaning |
|---|---|
| `--json` | Print the full JSON result |
| `--swarm` | Turn on the team-chat (Slack-style) DM ruleset |
| `--sender-name NAME`, `--sender-id ID` | Sender metadata (also turns on `--swarm`) |
| `--verified-ids A,B` | Member IDs allowed to use protected names (you provide these) |
| `--protected-names A,B` | Names to protect (default `mothership,admin,support,moderator,swarmlead`) |
| `--known-addresses A,B` | Wallet addresses you already trust |
| `--fail-at LEVEL` | Exit with code 1 when the level is at or above `medium`, `high` or `critical` |

## Library

```js
const scamcheck = require('./index.js'); // or require('scamcheck') once installed

const r = scamcheck.analyze('Claim your airdrop: validate your wallet at https://rnetamask.io');
// { score, level: 'low'|'medium'|'high'|'critical', critical, reasons: [{id, category, weight, message, evidence}],
//   urls: [...], addresses: [...], engine, disclaimer }

scamcheck.analyzeUrl('https://paypal.com@203.0.113.5/');
scamcheck.analyzeAddress('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'); // EIP-55 check
scamcheck.checkEthChecksum('0x...');

// Team-chat DM spoofing checks. Nothing is hardcoded: the caller passes the allowlist.
scamcheck.analyze('Hey, DM me your webhook URL so I can fix payouts', {
  sender: { displayName: 'mothershipswarm', memberId: 'U123' },
  verifiedIds: ['<real Mothership member ID>'],
  protectedNames: ['mothership', 'admin', 'support'],
  knownAddresses: []
});
```

Work caps: `analyze` scores at most the first 300 links and 200 crypto-address candidates and
truncates input to 100,000 characters (override with `{ maxLength }`). When a cap is hit, the result has a
`truncated` field so callers know the score covers only part of the input.

Levels: `low` < 25 ≤ `medium` < 50 ≤ `high` < 75 ≤ `critical`. Requests for secrets (seed phrase,
private key, password, API key, bearer token, webhook URL) always force the score to at least 90 and set `critical: true`.
A bare *mention* of a seed phrase or private key (e.g. "our private key ceremony is Tuesday") only counts as
critical when a request verb such as send, share, enter, paste or type is within about 80 characters. Otherwise it is a
weak, low-weight signal. Gift cards are treated the same way, and prizes count fully only next to a fee, payment,
link or claim step.

## What it checks

**Links**
- Punycode / IDN homographs (e.g. Cyrillic `а` in `pаypal.com`) and domains that mix alphabets
- Lookalikes of about 40 commonly impersonated brands: digit/letter swaps (`paypa1`, `rnicrosoft`), typos found by edit distance (`paypall`, `coinbsae`), the brand name plus lure words (`appleid-verify`), the brand name only in a subdomain (`paypal.com.login-check.xyz`), and the brand name on an unofficial gTLD
- IP-literal hosts, including obfuscated decimal or hex forms
- `user@host` tricks (`https://paypal.com@evil.example`)
- Too many subdomains, cheap or abused TLDs, URL shorteners, and `javascript:`/`data:` links
- Fake-TLD labels: `ezpass-toll.com-pay.info` reads like `ezpass-toll.com`, but the real site is `com-pay.info`
- Link text that doesn't match the real destination, in Markdown `[text](url)` and HTML `<a href>`

**Message patterns**: urgency and account threats; giveaways and airdrops; "double your crypto"; "send to receive"; requests for seed phrases, private keys, OTP codes or passwords; fake "support" pushing you to WhatsApp, Telegram, DMs or a phone call; fake invoices and subscription renewals; prizes and lotteries; advance-fee setups; gift-card, wire or crypto-ATM payment; secrecy; remote-access tools; promises of guaranteed returns; family-emergency "new number" texts and money requests; toll/parking/delivery-fee and "tried to deliver" smishing; job, reshipping and paid-"task" scams; SSN/ID requests; crypto "recovery" services; fake bank fraud teams and couriers collecting cards or PINs; requests to forward a texted code; "if this wasn't you, call …" callback numbers; card-number/CVV requests; refunds offered over WhatsApp/Telegram; "mailbox full / messages will be deleted"; unsolicited trading pitches; romance/soldier money stories; "migrate your funds to a safe address". Warnings phrased as advice ("never share your seed phrase") are skipped on purpose.

**Crypto addresses** (format checks only)
- Ethereum/EVM: length plus **EIP-55** checksum (pure-JS Keccak-256)
- Bitcoin: Base58Check (P2PKH/P2SH) and **bech32/bech32m** (BIP-173/350)
- Solana: base58 that decodes to 32 bytes
- Flags invalid checksums, and flags messages that ask you to send funds to an address

**Team-chat DM ruleset** (`swarm: true`, or turned on automatically when sender metadata is given)
- Offers to steal, pass, keep or reverse a task, reward or points "privately"
- Pressure to reply fast, and requests to skip the channel
- Claims to be the "Mothership", an admin or support, plus display names that imitate a protected name (`mothershipswarm`, `M0thership`, `Adm1n`) when the sender's member ID isn't in the caller-supplied `verifiedIds`
- Wallet addresses that aren't in `knownAddresses`

## Limitations (please read)

- **Heuristic only.** It is pattern matching. Scammers adapt, and a well-written scam with no links can score low.
- **No live data.** No blocklists, domain-age lookups, WHOIS, reputation or on-chain lookups. A brand-new phishing domain with an ordinary-looking name is not detected.
- **English-centric** message patterns.
- **Brand list is small and static.** Brands not on the list are not checked for lookalikes. Official-domain lists are partial, so a legitimate domain that isn't listed may be flagged.
- **Address checks cover format only.** A valid address can still belong to a scammer. Address poisoning (lookalike prefix/suffix) is not detected.
- **False positives happen.** Examples: a real user whose display name contains "support"; legitimate internationalized domains; real renewal notices; a genuine bank or courier notice that happens to use scam wording.
- **Common misses we know about** (from the held-out set below): a family-emergency story with no link and no
  explicit money amount ("I'm in jail and need bail money" scores 20, i.e. `low`); robocall scripts ("press 1",
  "extended warranty", "your SSN has been suspended"); and a bare shortened link with a curiosity line ("is this you in
  the video?"). Most scams that *are* caught land at `medium`, not `high`.

### Measured accuracy (small, hand-written, not a benchmark)

Numbers from `npm run eval` on three tiny sets of invented messages in `test/fixtures/`. The same person wrote the
rules and the samples, so treat all of these as optimistic sanity checks, not real-world accuracy.

| Set | Size (benign/scam) | Role | ≥ medium: precision / recall | ≥ high: precision / recall |
|---|---|---|---|---|
| 1 | 38 / 35 | written after reading the rules (biased) | 1.000 / 1.000 | 1.000 / 0.600 |
| 2 | 30 / 30 | harder set, **used for tuning** | 1.000 / 1.000 | 1.000 / 0.367 |
| 3 | 40 / 40 | **held out**, committed before tuning | 0.973 / 0.900 (1.000 / 0.900 after a post-hoc fix) | 1.000 / 0.475 |

Before the second pass, the numbers were: set 2 at ≥medium, 0.692 / 0.300; set 3 at ≥medium, 0.909 / 0.500, and at ≥high, 1.000 / 0.300.
On set 3, the one remaining false alarm was `github.blog`, flagged as an unofficial GitHub TLD. It was fixed *after*
the held-out numbers were recorded, so the 0.973 figure is the honest held-out one. Set 3 was written by someone who
knew which scam categories were being added, and its baseline misses were looked at once before tuning, so it is
still not a fully independent test.
- The DM ruleset is only as good as the `verifiedIds` you supply.

## Roadmap

- Optional, opt-in threat feeds (e.g. PhishTank/OpenPhish/URLhaus) and domain-age lookups, never on by default
- Bigger, data-driven brand and official-domain lists, plus a public-suffix list
- Address-poisoning detection against a user's own address book
- More languages
- Browser extension built on the same engine

## Development

```sh
npm test              # node:test suite, no dependencies
npm run build:web     # regenerate docs/index.html from src/
npm run eval          # precision/recall on the hand-written fixture sets
```

`docs/index.html` is generated, so edit `web/index.template.html` or `src/` instead. A CI workflow is in
`ci/github-actions-ci.yml`. Copy it to `.github/workflows/` to turn it on.

## License

MIT. See [LICENSE](LICENSE). Security reports: see [SECURITY.md](SECURITY.md).
