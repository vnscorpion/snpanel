// Whose a database is - on the Databases page, in the user's backup, after a
// restore, and after their site moves.
//
//     node dbowner.mjs [out-dir]
//
// Runs on the box, as root: it reads MariaDB and the backup archive directly.
// Makes a user of its own, `dbownercheck`, and removes it and everything it
// made at the end.
//
//   - An administrator makes a database for the user, on no site, from the
//     Databases page; and hands one of their own to the user with the Owner
//     editor. Both show the user as owner.
//   - The user's backup holds both, each dumped - they used to be left out:
//     neither is on a site - and a restore brings a deleted one back, data
//     and all, still the user's.
//   - A database cannot be put on another user's site.
//   - A site moved to the user takes its database with it.
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/dbowner';
mkdirSync(OUT, { recursive: true });
const NAME = 'dbownercheck';
const STANDALONE = 'dbo_standalone';
const MOVED = 'dbo_moved';
const ONSITE = 'dbo_onsite';
const DOMAIN = `dbo${Date.now() % 1000000}.example.com`;

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return String(e.stdout || '') + String(e.stderr || ''); } };
const sql = (statement) => run('mariadb', ['-N', '-B', '-e', statement]).trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await chromium.launch();
const admin = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: 'en-US' });
await admin.addInitScript(() => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', 'en'); } catch {} });
await logIn(admin);
const csrf = async () => (await admin.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
const api = async (method, path, data) => admin.request.fetch(`${BASE}/api${path}`, { method, data, headers: { 'X-CSRF-Token': await csrf() }, timeout: 600000 });
const json = async (res) => res.json().catch(() => ({}));
const page = await admin.newPage();
page.on('dialog', (d) => d.accept());
const consoleErrors = [];
page.on('console', (m) => { if (m.type() === 'error' && !/jobs\/latest/.test(m.location()?.url || '')) consoleErrors.push(m.text()); });
const go = async (path) => { await page.goto(`${BASE}${path}`, { waitUntil: 'networkidle' }); await page.waitForTimeout(400); };
const dbList = async () => json(await api('GET', '/databases'));
const dbRow = (name) => page.locator('.db-entry', { has: page.locator('strong', { hasText: new RegExp(`^${name}$`) }) });

let userId = null;
let siteId = null;
try {
  // ---------------------------------------------------------------- setup
  for (const db of (await dbList()).filter((d) => [STANDALONE, MOVED, ONSITE].includes(d.db_name))) {
    await api('DELETE', `/databases/${db.id}`);
  }
  const old = (await json(await api('GET', '/users?usage=0'))).find((u) => u.username === NAME);
  if (old) await api('DELETE', `/users/${old.id}`);
  const made = await api('POST', '/users', { username: NAME, email: `${NAME}@example.com`, password: 'dbowner check password 1', role: 'end_user', website_limit: 2, storage_limit_mb: 200 });
  userId = (await json(made)).id;
  check(made.status() === 200 && userId, 'a user to own things');

  // ---------------------------------------------------------------- made for the user
  await go('/databases');
  await page.getByLabel('Database name').fill(STANDALONE);
  await page.getByLabel('Owner').selectOption({ label: `For ${NAME}` });
  await page.getByRole('button', { name: 'Create database' }).click();
  await page.getByText('Database created').waitFor({ timeout: 60000 });
  let row = dbRow(STANDALONE);
  await row.waitFor();
  const where = await row.locator('.db-where').innerText();
  check(where.includes(NAME) && where.includes('No website'), `an administrator makes a database for the user, on no site (${where.replace(/\s+/g, ' ')})`);
  sql(`CREATE TABLE ${STANDALONE}.kept (v TEXT); INSERT INTO ${STANDALONE}.kept VALUES ('still here');`);
  await page.screenshot({ path: `${OUT}/databases-light-en.png`, fullPage: true });

  // ---------------------------------------------------------------- handed to the user
  const mine = await api('POST', '/databases', { db_name: MOVED });
  check(mine.status() === 200 && (await json(mine)).owner_id !== userId, "one of the administrator's own");
  await go('/databases');
  row = dbRow(MOVED);
  await row.getByRole('button', { name: 'Owner' }).click();
  await row.locator('.db-owner-editor').getByLabel('Owner').selectOption({ label: NAME });
  await row.locator('.db-owner-editor').getByRole('button', { name: 'Save' }).click();
  await page.getByText(`${MOVED} now belongs to ${NAME}.`).waitFor({ timeout: 30000 });
  const moved = (await dbList()).find((d) => d.db_name === MOVED);
  check(moved?.owner_id === userId && moved?.owner === NAME && moved?.website_id === null, 'handed to the user with the Owner editor');

  // ---------------------------------------------------------------- the user's backup
  const queued = await json(await api('POST', '/maintenance/user-backup', { user_id: userId }));
  let job = queued;
  for (let i = 0; i < 120 && !['done', 'error'].includes(job.status); i++) {
    await sleep(1000);
    job = await json(await api('GET', `/maintenance/backup-jobs/${queued.job_id}`));
  }
  check(job.status === 'done' && job.backup_file, `the user's backup is made (${job.status} ${job.error || ''})`);
  const archive = job.backup_file.startsWith('/') ? job.backup_file : run('find', ['/', '-xdev', '-name', job.backup_file, '-path', '*backups*']).split('\n')[0];
  const members = run('tar', ['-tzf', archive]);
  const manifest = JSON.parse(run('tar', ['-xzOf', archive, 'manifest.json']) || '{}');
  const listed = (manifest.databases || []).map((d) => d.db_name).sort();
  check(JSON.stringify(listed) === JSON.stringify([MOVED, STANDALONE]),
    `it lists both databases, on no site (${listed.join(', ')})`);
  const member = (manifest.databases || []).find((d) => d.db_name === STANDALONE)?.sql_member || '';
  check(members.includes(member) && member.startsWith('databases/owned/'), `and holds their dumps (${member})`);
  check(run('tar', ['-xzOf', archive, member]).includes('still here'), 'with the data in them');

  // ---------------------------------------------------------------- restored
  const standalone = (await dbList()).find((d) => d.db_name === STANDALONE);
  await api('DELETE', `/databases/${standalone.id}`);
  check(!sql('SHOW DATABASES').split('\n').includes(STANDALONE), 'the database is deleted');
  const restored = await api('POST', '/maintenance/user-restore', { backup_file: archive });
  const outcome = await json(restored);
  check(restored.status() === 200 && (outcome.databases || []).every((d) => d.restored),
    `a restore brings the databases back (${JSON.stringify(outcome.databases || outcome.detail)})`);
  check(sql(`SELECT v FROM ${STANDALONE}.kept`) === 'still here', 'with their data');
  const back = (await dbList()).find((d) => d.db_name === STANDALONE);
  check(back?.owner_id === userId && back?.website_id === null, "still the user's, on no site");

  // ---------------------------------------------------------------- sites
  const site = await json(await api('POST', '/websites', { domain: DOMAIN, app_type: 'static' }));
  siteId = site.id;
  check(!!siteId, `a site of the administrator's (${DOMAIN})`);
  const refused = await api('PATCH', `/databases/${moved.id}`, { owner_id: userId, website_id: siteId });
  check(refused.status() === 422 && /another user/.test(await refused.text()), "a database cannot go on another user's site");
  const onsite = await api('POST', '/databases', { db_name: ONSITE, website_id: siteId });
  check(onsite.status() === 200 && (await json(onsite)).website_id === siteId, 'a database made on that site');
  const handed = await api('PATCH', `/websites/${siteId}`, { owner_id: userId });
  check(handed.status() === 200, `the site is moved to the user (${handed.status()})`);
  const followed = (await dbList()).find((d) => d.db_name === ONSITE);
  check(followed?.owner_id === userId && followed?.website === DOMAIN, 'and its database goes with it');

  check(consoleErrors.length === 0, `no console errors (${consoleErrors.slice(0, 3).join(' | ')})`);
} finally {
  for (const db of (await dbList()).filter((d) => [STANDALONE, MOVED, ONSITE].includes(d.db_name))) {
    await api('DELETE', `/databases/${db.id}`);
  }
  if (siteId) await api('DELETE', `/websites/${siteId}?delete_files=true`);
  if (userId) await api('DELETE', `/users/${userId}`);
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
