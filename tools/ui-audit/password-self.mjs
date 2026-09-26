// Account security in a browser, as a customer: the login password is
// changed there - the current one, the new one twice - and the session
// ends; the new one signs in and the old one no longer does; a wrong
// current password changes nothing.
//
//     node password-self.mjs [out-dir]        (LOGIN_FILE: the administrator's)
//
// Makes a throwaway customer (random passwords, never printed) and deletes
// it again, also when a check fails.
import { chromium } from 'playwright';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/password-self';
const NAME = 'pwprobe';
mkdirSync(OUT, { recursive: true });
let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };

const browser = await chromium.launch();
const admin = await browser.newContext({ ignoreHTTPSErrors: true });
await logIn(admin);
const csrf = (await admin.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
const adminApi = (method, path, data) => admin.request.fetch(`${BASE}/api${path}`, { method, data, headers: csrf ? { 'X-CSRF-Token': csrf } : {} });
const signIn = async (password) => (await browser.newContext({ ignoreHTTPSErrors: true })).request
  .post(`${BASE}/api/auth/login`, { form: { username: NAME, password } }).then((r) => r.status());

async function removeProbe() {
  const users = await (await adminApi('GET', '/users')).json();
  const probe = (users.items || users).find((u) => u.username === NAME);
  if (probe) await adminApi('DELETE', `/users/${probe.id}`);
}

await removeProbe();
const first = `P1-${randomBytes(15).toString('base64url')}`;
const second = `P2-${randomBytes(15).toString('base64url')}`;
const made = await adminApi('POST', '/users', { username: NAME, email: `${NAME}@example.invalid`, password: first, role: 'end_user', website_limit: 1, storage_limit_mb: 100 });
check(made.ok(), `a customer ${NAME} (${made.status()})`);
try {
  const user = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  await user.addInitScript(() => { try { localStorage.setItem('snpanel-locale', 'en'); } catch {} });
  const login = await user.request.post(`${BASE}/api/auth/login`, { form: { username: NAME, password: first } });
  check(login.status() === 200, `it signs in (${login.status()})`);
  const page = await user.newPage();
  await page.goto(`${BASE}/security`, { waitUntil: 'networkidle' });
  const heading = page.getByRole('heading', { name: 'Login password' });
  check(await heading.isVisible(), 'Account security has a Login password section');
  const button = page.getByRole('button', { name: 'Change password' });
  check(await button.isDisabled(), 'Change password waits for the fields');
  await page.getByLabel('New password', { exact: true }).fill(second);
  await page.getByLabel('New password again').fill(`${second}x`);
  check(await page.getByText('The two new passwords differ.').isVisible() && await button.isDisabled(), 'two new passwords that differ are said to, and kept from being sent');
  await page.getByLabel('New password again').fill(second);
  await page.getByLabel('Current password').fill('not the password at all');
  check(await button.isEnabled(), 'filled in, it can be sent');
  await button.click();
  await page.waitForTimeout(1500);
  check(await heading.isVisible() && await signIn(first) === 200 && await signIn(second) === 401,
    'a wrong current password changes nothing, and the page stays');
  await page.screenshot({ path: `${OUT}/refused-light-en.png`, fullPage: true });

  await page.getByLabel('Current password').fill(first);
  await button.click();
  await page.getByText('Password changed. Please log in again.').waitFor({ timeout: 15000 });
  check(true, 'the right one changes it, and the session ends with the reason said');
  check(await signIn(second) === 200, 'the new password signs in');
  check(await signIn(first) === 401, 'the old one no longer does');
  await page.screenshot({ path: `${OUT}/changed-light-en.png`, fullPage: true });
  await user.close();
} finally {
  await removeProbe();
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
