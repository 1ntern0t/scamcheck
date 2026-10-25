#!/usr/bin/env node
'use strict';
// Prints precision/recall of analyze() on the small hand-written fixture sets.
// Usage: node scripts/eval-samples.js [--verbose]
// These are tiny invented sets; see test/fixtures/README.md before quoting numbers.
const path = require('path');
const { analyze } = require('../index.js');
const L = ['low', 'medium', 'high', 'critical'];
const dir = path.join(__dirname, '..', 'test', 'fixtures');
const sets = ['set1-written-after-rules.json', 'set2-tuning.json', 'set3-heldout.json'];
const verbose = process.argv.includes('--verbose');
for (const f of sets) {
  const { benign, scam } = require(path.join(dir, f));
  for (const th of ['medium', 'high']) {
    let fp = 0, tp = 0; const lines = [];
    for (const t of benign) { const r = analyze(t); if (L.indexOf(r.level) >= L.indexOf(th)) { fp++; lines.push('  FP ' + r.level + ' | ' + t.slice(0, 90)); } }
    for (const t of scam) { const r = analyze(t); if (L.indexOf(r.level) >= L.indexOf(th)) tp++; else lines.push('  FN ' + r.level + ' | ' + t.slice(0, 90)); }
    const p = tp + fp ? tp / (tp + fp) : 1;
    console.log(`${f.padEnd(32)} >=${th.padEnd(6)} benign=${benign.length} scam=${scam.length} TP=${tp} FP=${fp} FN=${scam.length - tp} precision=${p.toFixed(3)} recall=${(tp / scam.length).toFixed(3)}`);
    if (verbose && lines.length) console.log(lines.join('\n'));
  }
}
