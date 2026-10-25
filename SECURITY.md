# Security policy

## Scope

scamcheck is a **heuristic** helper. It is not an anti-phishing service, an antivirus,
or a guarantee that a message, link, or address is safe. Missed detections (false
negatives) and false positives are expected and are **not** security vulnerabilities by
themselves. Please file them as normal issues with a sample (redact personal data first).

Things we do treat as security issues:

- The static page (`docs/index.html`) making any network request, or leaking pasted
  input anywhere (it should be fully offline, enforced by a strict CSP).
- Script injection / XSS in the static page from analyzed input.
- Denial of service, e.g. catastrophic regex backtracking on crafted input that hangs
  the CLI or the browser tab.
- Anything that makes the tool **advise users to do something unsafe** (for example a
  bug that labels a seed-phrase request as safe advice).
- Supply-chain concerns. The project intentionally has zero runtime dependencies.

## Reporting

Please report privately through GitHub's
[private vulnerability reporting](https://github.com/1ntern0t/scamcheck/security/advisories/new)
for this repository. Do not open a public issue for an unfixed vulnerability.

Include: affected version or commit, reproduction input, and expected vs. actual behavior.
This is a small volunteer project; there is no bug bounty and no guaranteed response time,
but reports will be acknowledged and fixed on a best-effort basis.

## Handling secrets

Never paste real secrets (API keys, bearer tokens, webhook URLs, seed phrases,
passwords) into issues or test cases. Use obviously fake placeholders.
The tool itself never transmits input; it runs locally in Node or in your browser.
