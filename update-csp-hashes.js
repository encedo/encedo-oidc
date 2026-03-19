#!/usr/bin/env node
// Recomputes SHA-256 hashes of inline <style> blocks in HTML files
// and updates the STYLE_HASHES array in src/app.js.
//
// Usage: node update-csp-hashes.js

import { createHash } from 'crypto';
import { readFileSync, writeFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const ROOT = dirname(fileURLToPath(import.meta.url));

const FILES = [
  { file: 'signin.html',      label: 'signin.html' },
  { file: 'enrollment.html',  label: 'enrollment.html' },
  { file: 'admin-panel.html', label: 'admin-panel.html' },
];

function styleHash(html) {
  const matches = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)];
  if (matches.length === 0) throw new Error('No <style> block found');
  if (matches.length > 1)   console.warn(`  WARNING: ${matches.length} <style> blocks, hashing all`);
  return matches.map(m => {
    const hash = createHash('sha256').update(m[1]).digest('base64');
    return `sha256-${hash}`;
  });
}

const hashes = [];
for (const { file, label } of FILES) {
  const html = readFileSync(resolve(ROOT, file), 'utf8');
  const h = styleHash(html);
  h.forEach(hash => {
    hashes.push({ hash, label });
    console.log(`${label}: ${hash}`);
  });
}

const appPath = resolve(ROOT, 'src/app.js');
let appJs = readFileSync(appPath, 'utf8');

const newBlock = [
  'const STYLE_HASHES = [',
  ...hashes.map(({ hash, label }) => `  "'${hash}'", // ${label}`),
  '].join(\' \');',
].join('\n');

appJs = appJs.replace(
  /const STYLE_HASHES = \[[\s\S]*?\]\.join\(' '\);/,
  newBlock,
);

writeFileSync(appPath, appJs);
console.log('\nsrc/app.js updated.');
