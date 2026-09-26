// The Restore tab in a browser, as the administrator: this server's backups
// are listed with their accounts, "Newest of each account" picks one per
// account, a tick picks one, and Restore - after asking - restores it while
// the page follows the job to its end.
//
//     node restore-ui.mjs [account] [out-dir]
//
// Restores the newest backup of `account` (demo by default) over the
// account as it is: on a test box, the same files and databases again.
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
const page = await context.newPage();
const errors = [];
page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
page.on('pageerror', (e) => errors.push(String(e)));
const dialogs = [];
page.on('dialog', (d) => { dialogs.push(d.message()); d.accept(); });

await page.goto(`${BASE}/backups`, { waitUntil: 'networkidle' });
await page.getByRole('tab', { name: 'Restore' }).click();
const rows = page.locator('.bk-restore-table tbody tr');
await rows.first().waitFor({ timeout: 20000 });
check(await page.getByRole('radio', { name: /This server/ }).getAttribute('aria-checked') === 'true', 'this server is the source it opens on');
const count = await rows.count();
check(count > 0, `this server's backups are listed (${count})`);

const restore = page.locator('.bk-restore-go button');
check(await restore.isDisabled(), 'Restore waits for a choice');
await page.getByRole('button', { name: 'Newest of each account' }).click();
const accounts = new Set(await page.locator('.bk-restore-table tbody tr td:nth-child(2) strong').allTextContents());
const picked = await page.locator('.bk-restore-table tbody input[type=checkbox]:checked').count();
check(picked === accounts.size, `"Newest of each account" picks one per account (${picked} of ${count} for ${accounts.size} accounts)`);
await page.locator('.bk-check-inline input').check();
await page.locator('.bk-check-inline input').uncheck();
check(await page.locator('.bk-restore-table tbody input[type=checkbox]:checked').count() === 0, 'All, twice, picks none');

const row = rows.filter({ has: page.locator('td:nth-child(2) strong', { hasText: new RegExp(`^${ACCOUNT}$`) }) }).first();
await row.locator('input[type=checkbox]').check();
check((await page.locator('.bk-restore-go .hint').textContent()).includes(ACCOUNT), `the choice is said beside the button (${await page.locator('.bk-restore-go .hint').textContent()})`);
await page.screenshot({ path: `${OUT}/chosen-light-en.png`, fullPage: true });
await restore.click();
check(dialogs.some((m) => m.startsWith('Restore 1 backup(s)?')), `it asks first (${dialogs.at(-1)?.slice(0, 60)})`);
const banner = page.locator('.bk-restore-job');
await banner.waitFor({ timeout: 15000 });
await page.locator('.bk-restore-job.done').waitFor({ timeout: 300000 });
const said = (await banner.textContent()).replace(/\s+/g, ' ');
check(/Restore finished: 1 restored, 0 failed/.test(said) && said.includes(ACCOUNT), `the page follows the restore to its end (${said.slice(0, 140)})`);
await page.screenshot({ path: `${OUT}/restored-light-en.png`, fullPage: true });

// Opened again: the last restore is still there to read.
await page.reload({ waitUntil: 'networkidle' });
await page.getByRole('tab', { name: 'Restore' }).click();
await banner.waitFor({ timeout: 10000 });
check(/1 restored/.test(await banner.textContent()), 'opened again, the page shows the last restore');
check(errors.length === 0, `no console errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
await browser.close();
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
