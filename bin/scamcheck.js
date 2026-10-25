#!/usr/bin/env node
'use strict';

const engine = require('../src/engine.js');

const HELP = `scamcheck ${engine.VERSION}: offline heuristic scam/fraud checker

Usage:
  scamcheck "text, link or address"
  echo "text" | scamcheck
  scamcheck --json "text"

Options:
  --json                 Print the full JSON result
  --swarm                Enable the team-chat (Slack-style) DM ruleset
  --sender-name NAME     Display name of the message sender (enables --swarm)
  --sender-id ID         Member ID of the sender
  --verified-ids A,B     Comma-separated member IDs allowed to use protected names
  --protected-names A,B  Names to protect (default: ${engine.DEFAULT_PROTECTED_NAMES.join(',')})
  --known-addresses A,B  Wallet addresses you already trust (DM ruleset)
  --fail-at LEVEL        Exit with code 1 if level >= LEVEL (medium|high|critical)
  -h, --help             Show help
  -v, --version          Show version

Heuristic only: no live threat feeds, not a guarantee. See README.`;

const LEVELS = ['low', 'medium', 'high', 'critical'];

function parseArgs(argv) {
  const opts = { json: false, text: [], engine: {} };
  const list = (v) => String(v || '').split(',').map((x) => x.trim()).filter(Boolean);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error('missing value for ' + a);
      return argv[++i];
    };
    switch (a) {
      case '--json': opts.json = true; break;
      case '--swarm': opts.engine.swarm = true; break;
      case '--sender-name': opts.engine.sender = Object.assign(opts.engine.sender || {}, { displayName: next() }); break;
      case '--sender-id': opts.engine.sender = Object.assign(opts.engine.sender || {}, { memberId: next() }); break;
      case '--verified-ids': opts.engine.verifiedIds = list(next()); break;
      case '--protected-names': opts.engine.protectedNames = list(next()); break;
      case '--known-addresses': opts.engine.knownAddresses = list(next()); break;
      case '--fail-at': opts.failAt = next(); break;
      case '-h': case '--help': opts.help = true; break;
      case '-v': case '--version': opts.version = true; break;
      case '-': break;
      default:
        if (a.startsWith('--')) throw new Error('unknown option ' + a);
        opts.text.push(a);
    }
  }
  if (opts.failAt && !LEVELS.includes(opts.failAt)) throw new Error('--fail-at must be one of ' + LEVELS.join(', '));
  return opts;
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

function formatHuman(r) {
  const lines = [];
  lines.push(`Risk score: ${r.score}/100 (${r.level.toUpperCase()})${r.critical ? ' [automatic critical: secret/credential request]' : ''}`);
  if (r.reasons.length === 0) {
    lines.push('No heuristic warning signs found. That does not mean it is safe.');
  } else {
    lines.push('Reasons:');
    for (const x of r.reasons) {
      lines.push(`  [+${x.weight}] ${x.message}${x.evidence ? `  (${JSON.stringify(x.evidence)})` : ''}`);
    }
  }
  for (const a of r.addresses) {
    lines.push(`Address ${a.input}: ${a.chain}, ${a.valid ? 'valid format' : 'INVALID'} - ${a.note}`);
  }
  lines.push('');
  lines.push(r.disclaimer);
  return lines.join('\n');
}

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (e) {
    process.stderr.write('scamcheck: ' + e.message + '\n\n' + HELP + '\n');
    process.exit(2);
  }
  if (opts.help) { process.stdout.write(HELP + '\n'); return; }
  if (opts.version) { process.stdout.write(engine.VERSION + '\n'); return; }
  let text = opts.text.join(' ');
  if (!text && !process.stdin.isTTY) text = await readStdin();
  if (!text.trim()) {
    process.stderr.write(HELP + '\n');
    process.exit(2);
  }
  const result = engine.analyze(text, opts.engine);
  process.stdout.write((opts.json ? JSON.stringify(result, null, 2) : formatHuman(result)) + '\n');
  if (opts.failAt && LEVELS.indexOf(result.level) >= LEVELS.indexOf(opts.failAt)) process.exitCode = 1;
}

main();
