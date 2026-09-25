// Keeps src/i18n/vi.js and src/i18n/vi-server.js honest against the code.
//
//     node scripts/i18n-check.mjs [--list] [--list-server]
//
// vi.js translates the panel's own strings. It collects every literal passed
// to t() or msg() under src/, then reports:
//
//   * a Vietnamese entry nothing uses any more       - an error: its English
//     changed, so the translation is now for a string the panel never shows;
//   * a Vietnamese entry whose {placeholders} differ  - an error: it would
//     print a literal "{count}" or drop a value;
//   * an English string with no translation           - a count, not an
//     error: it shows in English until somebody translates it, which is the
//     designed fallback.
//
// vi-server.js translates the server's messages, whose templates
// scripts/server-messages.mjs collects from the Rust sources. The same three
// reports, against those templates - and each template, filled with marker
// values, is run through src/i18n/server.js, the code the panel runs: it
// must come back as its own translation with the values in place, and not
// as another template's.
//
// No parser for the JavaScript, on purpose: t() and msg() take a literal
// first argument by convention, and a regular expression over the source
// keeps this runnable without installing anything.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { serverTemplates } from './server-messages.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const src = join(root, 'src');
const I18N = join(src, 'i18n');

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : /\.(jsx?|mjs)$/.test(name) ? [p] : [];
  });
}

const CALL = /\b(?:t|msg)\(\s*(['"])((?:\\.|(?!\1)[^\\])*)\1/g;
const unescape = (s, q) => s
  .replace(/\\n/g, '\n')
  .replace(/\\u([0-9a-fA-F]{4})/g, (m, hex) => String.fromCharCode(parseInt(hex, 16)))
  .replace(new RegExp(`\\\\${q}`, 'g'), q)
  .replace(/\\\\/g, '\\');

const CATALOGUE_FILES = new Set(['vi.js', 'vi-server.js', 'server.js'].map((name) => join(I18N, name)));
const used = new Map();
for (const file of walk(src)) {
  if (CATALOGUE_FILES.has(file)) continue;
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

const load = async (name) => (await import(pathToFileURL(join(I18N, name)).href)).default;
const vi = await load('vi.js');
const viServer = await load('vi-server.js');
const { compile, translateMessage } = await import(pathToFileURL(join(I18N, 'server.js')).href);

const PH = /\{(\w+)\}/g;
const placeholders = (s) => [...s.matchAll(PH)].map((m) => m[1]).sort().join(',');

let errors = 0;
const problem = (text) => { errors++; console.log(text); };

for (const [en, tr] of Object.entries(vi)) {
  if (!used.has(en)) problem(`unused translation: ${JSON.stringify(en)}`);
  if (placeholders(en) !== placeholders(tr)) problem(`placeholders differ: ${JSON.stringify(en)} -> ${JSON.stringify(tr)}`);
}
const untranslated = [...used.keys()].filter((k) => !(k in vi));
console.log(`${used.size} strings go through t()/msg(); ${Object.keys(vi).length} translated; ${untranslated.length} still English-only`);
if (process.argv.includes('--list')) for (const k of untranslated) console.log(`  ${used.get(k)}: ${JSON.stringify(k)}`);

const { templates } = serverTemplates();
const compiled = compile(viServer);
const fill = (template, values) => template.replace(PH, (m, name) => values[name]);
for (const [en, tr] of Object.entries(viServer)) {
  if (!templates.has(en)) problem(`server translation for a message the server no longer sends: ${JSON.stringify(en)}`);
  if (placeholders(en) !== placeholders(tr)) {
    problem(`server placeholders differ: ${JSON.stringify(en)} -> ${JSON.stringify(tr)}`);
    continue;
  }
  const values = {};
  for (const [i, name] of [...new Set([...en.matchAll(PH)].map((m) => m[1]))].entries()) values[name] = `⟨v${i}⟩`;
  const got = translateMessage(compiled, fill(en, values));
  const want = fill(tr, values);
  if (got !== want) problem(`server message comes back wrong: ${JSON.stringify(fill(en, values))}\n  got  ${JSON.stringify(got)}\n  want ${JSON.stringify(want)}`);
}
const serverUntranslated = [...templates.keys()].filter((k) => !(k in viServer));
console.log(`${templates.size} server messages; ${Object.keys(viServer).length} translated; ${serverUntranslated.length} still English-only`);
if (process.argv.includes('--list-server')) for (const k of serverUntranslated) console.log(`  ${templates.get(k)[0]}: ${JSON.stringify(k)}`);

console.log(errors ? `FAIL: ${errors} problem(s)` : 'PASS');
process.exit(errors ? 1 : 0);
