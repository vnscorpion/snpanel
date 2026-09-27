// The SFTP page in a browser, as the administrator: SFTP is a page of its
// own and no longer on Account security; picking a customer shows one list,
// their own login first (Main) and their SFTP accounts under it; "Add an
// SFTP account" makes one - its password shown once - its row gives it a
// new password, and deletes it again, after asking.
//
//     node sftp-page.mjs [customer] [out-dir]
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const CUSTOMER = process.argv[2] || 'demo';
const OUT = process.argv[3] || '/root/ui-audit/sftp';
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

await page.goto(`${BASE}/security`, { waitUntil: 'networkidle' });
check(await page.getByText('SFTP access', { exact: true }).count() === 0, 'Account security no longer has SFTP');
await page.locator('.sidebar, nav, aside').getByRole('button', { name: 'SFTP', exact: true }).first().click();
await page.waitForURL(/\/sftp$/);
check(true, 'SFTP is a page of its own, in the menu');
await page.getByLabel('Account', { exact: true }).selectOption({ label: CUSTOMER });
await page.getByRole('heading', { name: 'SFTP accounts' }).waitFor();
await page.waitForTimeout(800);
const first = page.locator('.sftp-list li').first();
check((await first.textContent()).includes(CUSTOMER) && await first.getByText('Main', { exact: true }).isVisible(),
  `one list, the customer's own login first, marked Main (${CUSTOMER})`);
check(await page.locator('.sftp-access').count() === 0, 'no second, separate SFTP section');

const before = await page.locator('.sftp-list li').count();
await page.getByRole('button', { name: 'Add an SFTP account' }).click();
const add = page.locator('form.sftp-add-form');
await add.getByLabel('Name', { exact: true }).fill('uitest');
await add.getByLabel('Folder', { exact: true }).selectOption({ index: 1 });
const folder = await add.getByLabel('Folder', { exact: true }).inputValue();
const made = page.waitForResponse((r) => r.url().includes('/sftp/accounts') && r.request().method() === 'POST');
await add.getByRole('button', { name: 'Create account' }).click();
check((await made).ok(), `the form makes the account (${folder})`);
await page.locator('.sftp-shown code').waitFor();
const firstPassword = await page.locator('.sftp-shown code').textContent();
check((await page.locator('.sftp-shown').textContent()).includes(`${CUSTOMER}_uitest`) && firstPassword.length >= 12, 'its password is shown once, named');
const row = page.locator('.sftp-list li', { hasText: `${CUSTOMER}_uitest` });
await row.waitFor();
check(await page.locator('.sftp-list li').count() === before + 1 && (await row.textContent()).includes(folder), `a row with its folder (${(await row.textContent()).replace(/\s+/g, ' ').trim().slice(0, 100)})`);
check(await add.count() === 0, 'and the form folds away');

// A new password, from the row itself: empty generates one.
await row.getByRole('button', { name: 'Change password' }).click();
const renewed = page.waitForResponse((r) => r.url().includes('/password') && r.request().method() === 'POST');
await row.locator('form').getByRole('button', { name: 'Save' }).click();
check((await renewed).ok(), 'Change password in the row, left empty, makes a new one');
await page.waitForTimeout(500);
const second = await page.locator('.sftp-shown code').textContent();
check(second && second !== firstPassword, 'shown once, and not the old one');
await page.screenshot({ path: `${OUT}/made-light-en.png`, fullPage: true });

await row.getByRole('button', { name: `Delete ${CUSTOMER}_uitest` }).click();
await row.waitFor({ state: 'detached', timeout: 60000 });
check(dialogs.some((m) => m.startsWith(`Delete the SFTP account ${CUSTOMER}_uitest?`)), 'deleting asks first, then the row goes');
check(errors.length === 0, `no console errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
await browser.close();
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
