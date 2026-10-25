#!/usr/bin/env node
'use strict';
// Prints precision/recall of analyze() on the small hand-written fixture sets.
// Usage: node scripts/eval-samples.js [--verbose]
// These are tiny invented sets; see test/fixtures/README.md before quoting numbers.
// Entries are plain strings, or { text, sender } objects (team-chat DM sets);
// a set-level "options" object (verifiedIds, protectedNames...) is passed to analyze().
const path = require('path');
const { analyze } = require('../index.js');
const L = ['low', 'medium', 'high', 'critical'];
const dir = path.join(__dirname, '..', 'test', 'fixtures');
const sets = ['set1-written-after-rules.json', 'set2-tuning.json', 'set3-heldout.json', 'set4-swarm-dm.json'];
const verbose = process.argv.includes('--verbose');

function run(entry, setOptions) {
  if (typeof entry === 'string') return { text: entry, r: analyze(entry, setOptions) };
  const opts = Object.assign({ swarm: true }, setOptions, entry.sender ? { sender: entry.sender } : {});
  return { text: entry.text, r: analyze(entry.text, opts) };
}

for (const f of sets) {
  const { benign, scam, options } = require(path.join(dir, f));
  for (const th of ['medium', 'high', 'critical']) {
    let fp = 0, tp = 0; const lines = [];
    for (const e of benign) { const { text, r } = run(e, options); if (L.indexOf(r.level) >= L.indexOf(th)) { fp++; lines.push('  FP ' + r.level + ' | ' + text.slice(0, 90)); } }
    for (const e of scam) { const { text, r } = run(e, options); if (L.indexOf(r.level) >= L.indexOf(th)) tp++; else lines.push('  FN ' + r.level + ' | ' + text.slice(0, 90)); }
    const p = tp + fp ? tp / (tp + fp) : 1;
    console.log(`${f.padEnd(32)} >=${th.padEnd(8)} benign=${benign.length} scam=${scam.length} TP=${tp} FP=${fp} FN=${scam.length - tp} precision=${p.toFixed(3)} recall=${(tp / scam.length).toFixed(3)}`);
    if (verbose && lines.length) console.log(lines.join('\n'));
  }
}
