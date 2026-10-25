#!/usr/bin/env node
'use strict';
// Inlines src/primitives.js + src/engine.js into web/index.template.html and
// writes docs/index.html (single self-contained file, no external requests).
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');

function build() {
  const tpl = fs.readFileSync(path.join(root, 'web', 'index.template.html'), 'utf8');
  const prim = fs.readFileSync(path.join(root, 'src', 'primitives.js'), 'utf8');
  const eng = fs.readFileSync(path.join(root, 'src', 'engine.js'), 'utf8');
  const bundle = prim + '\n' + eng;
  if (bundle.includes('</script')) throw new Error('engine source contains </script');
  return tpl.replace('/*__ENGINE__*/', () => bundle);
}

if (require.main === module) {
  const out = path.join(root, 'docs', 'index.html');
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, build());
  process.stdout.write('wrote ' + path.relative(root, out) + '\n');
}

module.exports = { build };
