// Settings, Notifications, in a browser.
//
//     node notifications-page.mjs [out-dir]        (LOGIN_FILE: the administrator's)
//
// As the administrator: the page says nothing goes out yet; an SMTP server
// saved through the form - its password never shown again - makes e-mail
// ready; a test to a server that is not there says why it failed; turning
// an event on is kept. As a throwaway customer: only its own events, and
// e-mail offered at its account's address. In Vietnamese on a phone, nothing
// runs off the screen. The SMTP server is removed and the customer deleted
// at the end; the addon is left as it was found.
import { chromium } from 'playwright';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/notifications-page';
const NAME = 'notifypage';
const PASSWORD = `U-${randomBytes(15).toString('base64url')}`;
const RELAY_PASSWORD = `R-${randomBytes(12).toString('base64url')}`;
mkdirSync(OUT, { recursive: true });
let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };

const browser = await chromium.launch();
const errors = [];
async function context(locale = 'en', width = 1440) {
  const c = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width, height: 900 }, locale: 'en-US' });
  await c.addInitScript((l) => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', l); } catch {} }, locale);
  return c;
}
const csrfOf = async (c) => (await c.cookies()).find((k) => k.name === 'snpanel_csrf')?.value;
const api = async (c, method, path, data) => c.request.fetch(`${BASE}/api${path}`, { method, data, headers: { 'X-CSRF-Token': (await csrfOf(c)) || '' } });

const admin = await context();
await logIn(admin);
const addons = await (await api(admin, 'GET', '/addons')).json();
const wasInstalled = !!addons.items?.find((a) => a.slug === 'notifications')?.installed;
const removeCustomer = async () => {
  const users = await (await api(admin, 'GET', '/users?usage=0')).json();
  const old = (users.items || users).find((u) => u.username === NAME);
  if (old) await api(admin, 'DELETE', `/users/${old.id}`);
};

try {
  if (!wasInstalled) await api(admin, 'POST', '/addons/notifications/install');
  await api(admin, 'DELETE', '/notifications/smtp');
  await removeCustomer();
  const made = await api(admin, 'POST', '/users', { username: NAME, email: `${NAME}@example.invalid`, password: PASSWORD, role: 'end_user', website_limit: 1, storage_limit_mb: 100 });
  check(made.ok(), `a customer ${NAME} (${made.status()})`);

  // ------------------------------------------------ the administrator
  const page = await admin.newPage();
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(`${BASE}/notifications`, { waitUntil: 'networkidle' });
  await page.getByRole('heading', { name: 'How messages go out' }).waitFor({ timeout: 15000 });
  check(await page.getByText('The administrator has not set up e-mail yet.').isVisible(), 'with nothing set up, the page says e-mail is not ready');
  check(await page.getByRole('link', { name: 'Notifications' }).count() + await page.getByRole('button', { name: 'Notifications' }).count() > 0, 'Settings has a Notifications item');
  await page.screenshot({ path: `${OUT}/admin-empty-light-en.png`, fullPage: true });

  await page.getByLabel('SMTP server').fill('127.0.0.1');
  await page.getByLabel('Security').selectOption('none');
  check(await page.getByLabel('Port').inputValue() === '25', 'choosing the security fills the usual port in');
  await page.getByLabel('Port').fill('2599');
  await page.getByLabel('User name').fill('relayuser');
  await page.getByLabel('Password', { exact: true }).fill(RELAY_PASSWORD);
  await page.getByLabel('Sender address').fill('panel@example.invalid');
  await page.locator('form[aria-labelledby="notif-smtp-title"]').getByRole('button', { name: 'Save' }).click();
  await page.getByText('The SMTP server is saved.').first().waitFor({ timeout: 15000 });
  check(await page.locator('#smtp-password').inputValue() === ''
    && await page.locator('#smtp-password').getAttribute('placeholder') === 'Saved - empty keeps it',
  'saved: the password is not shown again, the field says an empty one keeps it');
  check(await page.getByLabel('By e-mail').isEnabled(), 'e-mail is now offered to the administrator too');
  await page.getByRole('button', { name: 'Send a test', exact: true }).click();
  await page.getByText(/Cannot connect to 127\.0\.0\.1:2599/).first().waitFor({ timeout: 40000 });
  check(true, 'a test to a server that is not there says why it failed');

  const doneSwitch = page.getByRole('switch', { name: /A scheduled backup finished/ });
  check(!(await doneSwitch.isChecked()), '"A scheduled backup finished" starts off');
  await doneSwitch.click();
  await page.waitForTimeout(1200);
  await page.reload({ waitUntil: 'networkidle' });
  check(await page.getByRole('switch', { name: /A scheduled backup finished/ }).isChecked(), 'turned on, it stays on');
  await page.getByRole('switch', { name: /A scheduled backup finished/ }).click();
  await page.waitForTimeout(1200);
  await page.getByRole('heading', { name: 'Recently sent' }).scrollIntoViewIfNeeded();
  check(await page.locator('.notif-log').getByText('Failed').first().isVisible(), 'Recently sent shows the failed test, and why');
  await page.screenshot({ path: `${OUT}/admin-set-light-en.png`, fullPage: true });

  // ------------------------------------------------ a customer
  const customer = await context();
  const login = await customer.request.post(`${BASE}/api/auth/login`, { form: { username: NAME, password: PASSWORD } });
  check(login.status() === 200, `the customer signs in (${login.status()})`);
  const cpage = await customer.newPage();
  cpage.on('pageerror', (e) => errors.push(String(e)));
  await cpage.goto(`${BASE}/notifications`, { waitUntil: 'networkidle' });
  await cpage.getByRole('heading', { name: 'Where you are told' }).waitFor({ timeout: 15000 });
  check(await cpage.getByRole('heading', { name: 'How messages go out' }).count() === 0
    && await cpage.getByRole('heading', { name: 'Recently sent' }).count() === 0, 'a customer sees neither the channels\' setup nor the log');
  check(await cpage.getByRole('switch').count() === 7, `a customer has its own 7 events (${await cpage.getByRole('switch').count()})`);
  check(await cpage.getByLabel('Address', { exact: true }).getAttribute('placeholder') === `${NAME}@example.invalid`, 'e-mail goes to its account\'s address unless it gives another');
  check(await cpage.getByText('The administrator has not set up Telegram yet.').isVisible(), 'Telegram is said not to be set up');
  await cpage.screenshot({ path: `${OUT}/customer-light-en.png`, fullPage: true });

  // ------------------------------------------------ in Vietnamese, on a phone
  const vi = await context('vi', 390);
  await logIn(vi);
  const vpage = await vi.newPage();
  vpage.on('pageerror', (e) => errors.push(String(e)));
  await vpage.goto(`${BASE}/notifications`, { waitUntil: 'networkidle' });
  await vpage.getByRole('heading', { name: 'Cách gửi thông báo' }).waitFor({ timeout: 15000 });
  const overflow = await vpage.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check(overflow <= 0, `in Vietnamese on a phone nothing runs off the screen (${overflow}px)`);
  await vpage.screenshot({ path: `${OUT}/admin-phone-light-vi.png`, fullPage: true });

  check(errors.length === 0, `no page errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} catch (err) {
  ok = false;
  console.log(`FAIL  ${err.message.split('\n')[0]}`);
} finally {
  await api(admin, 'DELETE', '/notifications/smtp');
  await removeCustomer();
  if (!wasInstalled) await api(admin, 'POST', '/addons/notifications/uninstall');
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
