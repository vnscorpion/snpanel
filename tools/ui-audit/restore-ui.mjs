// The Restore tab in a browser, as the administrator: this server's backups
// are listed one row per account, an account with several backups offers
// their dates - the newest chosen - and picking another date ticks the
// account; Restore - after asking - restores the chosen backup while the
// page follows the job to its end, and says in a line what came back.
//
//     node restore-ui.mjs [account] [out-dir]
//
// `account` (demo by default) is given a second backup first when it has
// only one, and that backup is deleted again at the end. The newest backup of
// `account` is restored over the account as it is: on a test box, the same
// files and databases again.
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const ACCOUNT = process.argv[2] || 'demo';
const OUT = process.argv[3] || '/root/ui-audit/restore';
mkdirSync(OUT, { recursive: true });
let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };

const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
await context.addInitScript(() => { try { localStorage.setItem('snpanel-locale', 'en'); } catch {} });
await logIn(context);
const csrf = async () => (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value || '';
const api = async (method, path, data) => {
  const r = await context.request.fetch(`${BASE}/api${path}`, { method, data, headers: { 'X-CSRF-Token': await csrf() }, timeout: 600000 });
  let json = null;
  try { json = await r.json(); } catch {}
  return { status: r.status(), ok: r.ok(), json };
};
const localBackups = async () => ((await api('GET', '/maintenance/restore/local')).json?.items || []).filter((i) => i.valid);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// At least two backups of the account, so it has dates to choose from.
let made = null;
const before = (await localBackups()).filter((i) => i.username === ACCOUNT);
if (before.length < 2) {
  const users = (await api('GET', '/users?usage=0')).json;
  const user = (users?.items || users || []).find((u) => u.username === ACCOUNT);
  await api('POST', '/maintenance/user-backup', { user_id: user?.id });
  for (let i = 0; i < 120 && !made; i += 1) {
    await sleep(2500);
    made = (await localBackups()).find((b) => b.username === ACCOUNT && !before.some((o) => o.backup_file === b.backup_file)) || null;
  }
  check(!!made, `a second backup of ${ACCOUNT} to choose from (${made?.filename || 'none'})`);
}

const page = await context.newPage();
const errors = [];
page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
page.on('pageerror', (e) => errors.push(String(e)));
const dialogs = [];
page.on('dialog', (d) => { dialogs.push(d.message()); d.accept(); });

try {
  await page.goto(`${BASE}/backups`, { waitUntil: 'networkidle' });
  await page.getByRole('tab', { name: 'Restore' }).click();
  const rows = page.locator('.bk-accounts .bk-account');
  await rows.first().waitFor({ timeout: 20000 });
  check(await page.getByRole('radio', { name: /This server/ }).getAttribute('aria-checked') === 'true', 'this server is the source it opens on');

  const valid = await localBackups();
  const accounts = new Set(valid.map((i) => i.username));
  const names = await page.locator('.bk-account-name strong').allTextContents();
  check(names.length === accounts.size && new Set(names).size === names.length,
    `one row per account: ${names.length} rows for ${valid.length} backups of ${accounts.size} accounts`);

  const restore = page.locator('.bk-restore-go button');
  check(await restore.isDisabled(), 'Restore waits for a choice');
  await page.locator('.bk-check-inline input').check();
  check(await page.locator('.bk-accounts input[type=checkbox]:checked').count() === names.length, 'All ticks every account');
  await page.locator('.bk-check-inline input').uncheck();
  check(await page.locator('.bk-accounts input[type=checkbox]:checked').count() === 0, 'and again, none');

  // The account's dates: the newest chosen.
  const row = rows.filter({ has: page.locator('.bk-account-name strong', { hasText: new RegExp(`^${ACCOUNT}$`) }) }).first();
  const dates = row.locator('.bk-account-date select');
  const theirs = valid.filter((i) => i.username === ACCOUNT)
    .sort((a, b) => String(b.generated_at || b.modified).localeCompare(String(a.generated_at || a.modified)));
  const options = await dates.locator('option').evaluateAll((list) => list.map((o) => o.value));
  check(options.length === theirs.length && options.length >= 2 && await dates.inputValue() === theirs[0].backup_file,
    `${ACCOUNT} has its ${theirs.length} backups as dates, the newest chosen`);
  check((await row.locator('.bk-account-name small').textContent()).startsWith(`${theirs.length} backups`), 'and says how many');

  // Another date: the account is ticked, and the choice says which.
  await dates.selectOption(options[1]);
  check(await row.locator('input[type=checkbox]').isChecked() && /\bon\b/.test(await row.getAttribute('class')), 'picking another date ticks the account, and the card shows it');
  check(await row.getAttribute('title') === theirs[1].filename, `the card is that backup (${theirs[1].filename})`);
  const hint = await page.locator('.bk-restore-chosen').textContent();
  check(hint.startsWith('1 chosen') && hint.includes(`${ACCOUNT} · `), `the choice is said beside the button (${hint})`);
  await row.scrollIntoViewIfNeeded();
  await page.screenshot({ path: `${OUT}/grouped-light-en.png` });

  // Back to the newest, and restored.
  await dates.selectOption(options[0]);
  await restore.click();
  check(dialogs.some((m) => m.startsWith('Restore 1 backup(s)?')), `it asks first (${dialogs.at(-1)?.slice(0, 60)})`);
  const banner = page.locator('.bk-restore-job');
  await banner.waitFor({ timeout: 15000 });
  await page.locator('.bk-restore-job.done').waitFor({ timeout: 300000 });
  const said = (await banner.textContent()).replace(/\s+/g, ' ').trim();
  check(new RegExp(`^Restored ${ACCOUNT}: \\d+ website\\(s\\), \\d+ database\\(s\\)\\.$`).test(said), `the page follows the restore to its end, and says what came back in a line (${said})`);
  check(await banner.locator('.bk-restore-steps').count() === 0, 'with nothing failed, no list under it');
  check(await page.locator('.app-toast-stack').getByText(/Restore finished|Restored/).count() === 0, 'and no toast saying it again');
  await page.screenshot({ path: `${OUT}/restored-light-en.png`, fullPage: true });

  // Opened again: the last restore is still there to read.
  await page.reload({ waitUntil: 'networkidle' });
  await page.getByRole('tab', { name: 'Restore' }).click();
  await banner.waitFor({ timeout: 10000 });
  check((await banner.textContent()).includes(`Restored ${ACCOUNT}:`), 'opened again, the page shows the last restore');
  check(errors.length === 0, `no console errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} catch (err) {
  ok = false;
  console.log(`FAIL  ${err.message.split('\n')[0]}`);
} finally {
  if (made) {
    const gone = await api('DELETE', `/maintenance/user-backups?backup_file=${encodeURIComponent(made.backup_file)}`);
    console.log(`${gone.ok ? 'PASS' : 'FAIL'}  the backup made for this check is deleted again (${gone.status})`);
    ok &&= gone.ok;
  }
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
