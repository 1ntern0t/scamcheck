# Sample fixtures

These files are small **hand-written** message sets used to sanity-check precision and recall.
They are invented examples, not real user data and **not a benchmark**. All URLs, phone numbers
and addresses are fictional or example values.

- `set3-heldout.json`: written before the second-pass rule tuning and committed before any
  rule change, so it was not used to tune rules. Numbers on it are the least biased we have,
  but 80 hand-written messages are still far too few to estimate real-world accuracy.
- `set1-written-after-rules.json` (38 benign / 35 scam): written after reading the first-pass
  rules, so it is biased toward what the rules already catch.
- `set2-tuning.json` (30 benign / 30 scam): written as a harder set during the first audit, then
  used as **tuning data** for the second-pass rules. Its second-pass scores are optimistic.

Run `npm run eval` (or `node scripts/eval-samples.js --verbose`) to reproduce the numbers.
