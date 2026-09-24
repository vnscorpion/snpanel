// Keeps src/i18n/vi.js honest against the code.
//
//     node scripts/i18n-check.mjs
//
// It collects every literal passed to t() or msg() under src/, then reports:
//
//   * a Vietnamese entry nothing uses any more       - an error: its English
//     changed, so the translation is now for a string the panel never shows;
//   * a Vietnamese entry whose {placeholders} differ  - an error: it would
//     print a literal "{count}" or drop a value;
//   * an English string with no translation           - a count, not an
//     error: it shows in English until somebody translates it, which is the
//     designed fallback, and while the sweep is in progress there are many.
//
// No parser, on purpose: t() and msg() take a literal first argument by
// convention, and a regular expression over the source keeps this runnable
// without installing anything.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const src = join(root, 'src');

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : /\.(jsx?|mjs)$/.test(name) ? [p] : [];
  });
}

const CALL = /\b(?:t|msg)\(\s*(['"])((?:\\.|(?!\1)[^\\])*)\1/g;
const unescape = (s, q) => s.replace(/\\n/g, '\n').replace(new RegExp(`\\\\${q}`, 'g'), q).replace(/\\\\/g, '\\');

const used = new Map();
for (const file of walk(src)) {
  if (file.endsWith(join('i18n', 'vi.js'))) continue;
  // Whole-line comments are skipped - that is where usage examples live.
  // Only whole lines: a `//` in the middle of a line may be inside a URL.
  const code = readFileSync(file, 'utf8')
    .split('\n')
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
    .join('\n');
  for (const m of code.matchAll(CALL)) {
    const key = unescape(m[2], m[1]);
    if (!used.has(key)) used.set(key, relative(root, file));
  }
}

const vi = (await import(join(src, 'i18n', 'vi.js'))).default;
const PH = /\{(\w+)\}/g;
const placeholders = (s) => [...s.matchAll(PH)].map((m) => m[1]).sort().join(',');

let errors = 0;
for (const [en, tr] of Object.entries(vi)) {
  if (!used.has(en)) {
    errors++;
    console.log(`unused translation: ${JSON.stringify(en)}`);
  }
  if (placeholders(en) !== placeholders(tr)) {
    errors++;
    console.log(`placeholders differ: ${JSON.stringify(en)} -> ${JSON.stringify(tr)}`);
  }
}
const untranslated = [...used.keys()].filter((k) => !(k in vi));
console.log(`${used.size} strings go through t()/msg(); ${Object.keys(vi).length} translated; ${untranslated.length} still English-only`);
if (process.argv.includes('--list')) for (const k of untranslated) console.log(`  ${used.get(k)}: ${JSON.stringify(k)}`);
console.log(errors ? `FAIL: ${errors} problem(s)` : 'PASS');
process.exit(errors ? 1 : 0);
