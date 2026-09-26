// The SFTP page in a browser, as the administrator: SFTP is a page of its
// own and no longer on Account security; picking a customer shows their
// login and their SFTP accounts; the form makes one - its password shown
// once - and its row deletes it again, after asking.
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
check((await page.locator('.sftp-access dd code').allTextContents()).includes(CUSTOMER), `the customer's own login is shown (${CUSTOMER})`);

const before = await page.locator('.sftp-account-list li').count();
await page.getByLabel('Name', { exact: true }).fill('uitest');
await page.getByLabel('Folder', { exact: true }).selectOption({ index: 1 });
const folder = await page.getByLabel('Folder', { exact: true }).inputValue();
const made = page.waitForResponse((r) => r.url().includes('/sftp/accounts') && r.request().method() === 'POST');
await page.getByRole('button', { name: 'Create account' }).click();
check((await made).ok(), `the form makes the account (${folder})`);
await page.locator('.sftp-shown code').waitFor();
const shown = await page.locator('.sftp-shown').textContent();
check(shown.includes(`${CUSTOMER}_uitest`) && (await page.locator('.sftp-shown code').textContent()).length >= 12, 'its password is shown once, named');
const row = page.locator('.sftp-account-list li', { hasText: `${CUSTOMER}_uitest` });
await row.waitFor();
check(await page.locator('.sftp-account-list li').count() === before + 1 && (await row.textContent()).includes(folder), `a row with its folder (${(await row.textContent()).replace(/\s+/g, ' ').trim().slice(0, 100)})`);
await page.screenshot({ path: `${OUT}/made-light-en.png`, fullPage: true });

await row.getByRole('button', { name: `Delete ${CUSTOMER}_uitest` }).click();
await row.waitFor({ state: 'detached', timeout: 60000 });
check(dialogs.some((m) => m.startsWith(`Delete the SFTP account ${CUSTOMER}_uitest?`)), 'deleting asks first, then the row goes');
check(errors.length === 0, `no console errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
await browser.close();
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
