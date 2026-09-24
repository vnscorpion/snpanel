// Capture the build the panel is serving now and compare it with a baseline.
//
//     node compare.mjs <baseline-dir> <out-dir>
//
// Passes when every page's aria snapshot matches the baseline and no page
// logs a console error the baseline did not have.
//
// Relative times from `systemctl list-timers` - "#min ago", "#h #min ago" -
// are the server's text, not the frontend's, and their shape changes as time
// passes between two captures; they are folded before diffing, and nothing
// else is.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { capture } from './capture.mjs';

const [baseline, out] = process.argv.slice(2);
if (!baseline || !out) {
  console.error('usage: node compare.mjs <baseline-dir> <out-dir>');
  process.exit(2);
}

await capture(out, ['light']);

function fold(from, to) {
  mkdirSync(to, { recursive: true });
  for (const f of readdirSync(from)) {
    writeFileSync(`${to}/${f}`, readFileSync(`${from}/${f}`, 'utf8').replace(/(#[a-z]+ )+ago/g, '<ago>'));
  }
}
fold(`${baseline}/aria`, `${out}/aria.base.folded`);
fold(`${out}/aria`, `${out}/aria.folded`);

let failed = false;
try {
  execFileSync('diff', ['-ru', `${out}/aria.base.folded`, `${out}/aria.folded`], { stdio: 'pipe' });
  console.log(`aria: all ${readdirSync(`${out}/aria`).length} snapshots identical`);
} catch (e) {
  failed = true;
  const diff = e.stdout.toString();
  writeFileSync(`${out}/aria.diff`, diff);
  console.log('aria: DIFFERS');
  console.log(diff.split('\n').slice(0, 60).join('\n'));
}

const before = JSON.parse(readFileSync(`${baseline}/report.json`, 'utf8'));
const after = JSON.parse(readFileSync(`${out}/report.json`, 'utf8'));
let newErrors = 0;
for (const [k, v] of Object.entries(after)) {
  const known = new Set(before[k]?.errors || []);
  const extra = v.errors.filter((e) => !known.has(e));
  if (extra.length) {
    newErrors++;
    console.log(`new errors on ${k}:\n  ${extra.join('\n  ')}`);
  }
}
console.log(newErrors ? 'console: NEW ERRORS' : 'console: no new errors');

const ok = !failed && newErrors === 0;
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
