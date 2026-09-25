// A deleted site's nginx logs go with it, and nobody else's do.
//
//     node site-logs.mjs
//
// Runs on the box, as root. Makes two static sites whose names nest -
// <stamp>.example.co and <stamp>.example.com - and sends each a request
// nginx logs, then gives both the copies logrotate leaves: `.1` and `.2.gz`
// on Debian, `-20260925.gz` under the RHEL family's `dateext`. Deletes the
// first and checks:
//
//   - every log of the first is gone, the rotated copies too;
//   - the second's, whose name starts with the first's, are untouched;
//   - a new site taking the first's name opens its log viewer on nothing of
//     the old one's.
//
// Removes both sites, and checks their logs went with them.
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const STAMP = `lg${Date.now() % 1000000}`;
const FIRST = `${STAMP}.example.co`;
const SECOND = `${STAMP}.example.com`;
const LOGS = '/var/log/nginx';
const MARK = `/before-delete-${STAMP}`;

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return String(e.stdout || '') + String(e.stderr || ''); } };
const logsOf = (domain) => readdirSync(LOGS).filter((n) => n.startsWith(`${domain}.access.log`) || n.startsWith(`${domain}.error.log`)).sort();
const visit = (domain, path) => run('curl', ['-s', '-o', '/dev/null', '-w', '%{http_code}', '-H', `Host: ${domain}`, `http://127.0.0.1${path}`]);
const rotated = (domain) => {
  writeFileSync(`${LOGS}/${domain}.access.log.1`, `203.0.113.9 - - [24/Sep/2026:10:00:00 +0000] "GET ${MARK} HTTP/1.1" 404 0\n`);
  writeFileSync(`${LOGS}/${domain}.access.log.2.gz`, 'not really gzip');
  writeFileSync(`${LOGS}/${domain}.error.log-20260925.gz`, 'not really gzip');
};

const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true });
await logIn(context);
const csrf = async () => (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
const api = async (method, path, data) => context.request.fetch(`${BASE}/api${path}`, { method, data, headers: { 'X-CSRF-Token': await csrf() }, timeout: 600000 });
const json = async (res) => res.json().catch(() => ({}));
const create = async (domain) => json(await api('POST', '/websites', { domain, app_type: 'static' }));
const viewer = async (id) => json(await api('GET', `/websites/${id}/logs?kind=access&lines=200`));

let firstId = null;
let secondId = null;
try {
  firstId = (await create(FIRST)).id;
  secondId = (await create(SECOND)).id;
  check(firstId && secondId, `two sites whose names nest: ${FIRST} and ${SECOND}`);

  const codes = [visit(FIRST, MARK), visit(SECOND, MARK), visit(SECOND, '/')];
  rotated(FIRST);
  rotated(SECOND);
  const firstBefore = logsOf(FIRST);
  const secondBefore = logsOf(SECOND);
  check(firstBefore.length === 5, `nginx logged both (${codes.join(' ')}), and each has logrotate's copies: ${firstBefore.join(' ')}`);
  check((await viewer(firstId)).content?.includes(MARK), `the first's log viewer shows its request for ${MARK}`);
  const secondLog = readFileSync(`${LOGS}/${SECOND}.access.log`, 'utf8');

  const deleted = await api('DELETE', `/websites/${firstId}?delete_files=true`);
  check(deleted.ok(), `the first is deleted (HTTP ${deleted.status()})`);
  if (deleted.ok()) firstId = null;
  check(logsOf(FIRST).length === 0, `none of its logs is left (${logsOf(FIRST).join(' ') || 'none'})`);
  check(JSON.stringify(logsOf(SECOND)) === JSON.stringify(secondBefore), `the second's are all there: ${logsOf(SECOND).join(' ')}`);
  check(readFileSync(`${LOGS}/${SECOND}.access.log`, 'utf8').startsWith(secondLog), "and the second's live log is as it was");
  check(visit(SECOND, '/after') !== '' && readFileSync(`${LOGS}/${SECOND}.access.log`, 'utf8').includes('/after'), 'nginx still writes it');

  firstId = (await create(FIRST)).id;
  const fresh = await viewer(firstId);
  check(firstId && !String(fresh.content || '').includes(MARK), `a new site named ${FIRST} opens on none of the old one's traffic (${JSON.stringify(fresh.content || '').slice(0, 60)})`);
} finally {
  for (const id of [firstId, secondId]) {
    if (id) await api('DELETE', `/websites/${id}?delete_files=true`);
  }
  await browser.close();
}
check(logsOf(FIRST).length === 0 && logsOf(SECOND).length === 0, `with both deleted, neither has a log left (${[...logsOf(FIRST), ...logsOf(SECOND)].join(' ') || 'none'})`);
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
