// Settings, Notifications, in a browser.
//
//     node notifications-page.mjs [out-dir]        (LOGIN_FILE: the administrator's)
//
// Wants telegram-mock.mjs running on the box, the panel pointed at it:
//
//     systemd-run --unit=snpanel-telegram-mock node telegram-mock.mjs   (on the box)
//
// As the administrator: the page says nothing goes out yet; an SMTP server
// and the addresses to send to saved through the form - the password never
// shown again - and a test to a server that is not there says why it
// failed; the Telegram card: a bot token pasted, Find chat ID lists the
// chats that wrote to the bot, one is picked and saved - a test message
// reaching it first - and a chat Telegram does not know is refused; an event
// and the language changed are kept. As a throwaway customer: no
// Notifications in the menu, and the page says it is the administrators'.
// In Vietnamese on a phone, nothing runs off the screen. The channels are
// removed, what is sent put back to the defaults and the customer deleted at
// the end; the addon is left as it was found.
import { chromium } from 'playwright';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/notifications-page';
const NAME = 'notifypage';
const PASSWORD = `U-${randomBytes(15).toString('base64url')}`;
const RELAY_PASSWORD = `R-${randomBytes(12).toString('base64url')}`;
const BOT_TOKEN = `123456789:${randomBytes(27).toString('base64url')}`;
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
let defaults = null;

try {
  if (!wasInstalled) await api(admin, 'POST', '/addons/notifications/install');
  await api(admin, 'DELETE', '/notifications/smtp');
  await api(admin, 'DELETE', '/notifications/telegram');
  const start = await (await api(admin, 'GET', '/notifications')).json();
  defaults = Object.fromEntries(start.events.map((e) => [e.key, e.default]));
  await api(admin, 'PUT', '/notifications/settings', { language: 'vi', events: defaults });
  await removeCustomer();
  const made = await api(admin, 'POST', '/users', { username: NAME, email: `${NAME}@example.invalid`, password: PASSWORD, role: 'end_user', website_limit: 1, storage_limit_mb: 100 });
  check(made.ok(), `a customer ${NAME} (${made.status()})`);

  // ------------------------------------------------ the administrator: e-mail
  const page = await admin.newPage();
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('dialog', (d) => d.accept());
  await page.goto(`${BASE}/notifications`, { waitUntil: 'networkidle' });
  await page.getByRole('heading', { name: 'How messages go out' }).waitFor({ timeout: 15000 });
  check(await page.getByText('Nothing is sent until e-mail, or a Telegram bot and its chat, is set up.').isVisible(), 'with nothing set up, the page says nothing is sent');
  check(await page.getByRole('link', { name: 'Notifications' }).count() + await page.getByRole('button', { name: 'Notifications' }).count() > 0, 'Settings has a Notifications item');
  await page.locator('section[aria-labelledby="notif-channels-title"]').screenshot({ path: `${OUT}/channels-empty-light-en.png` });

  const mail = page.locator('form[aria-labelledby="notif-smtp-title"]');
  await page.getByLabel('SMTP server').fill('127.0.0.1');
  await page.getByLabel('Security').selectOption('none');
  check(await page.getByLabel('Port').inputValue() === '25', 'choosing the security fills the usual port in');
  await page.getByLabel('Port').fill('2599');
  await page.getByLabel('User name').fill('relayuser');
  await page.getByLabel('Password', { exact: true }).fill(RELAY_PASSWORD);
  await page.getByLabel('Sender address').fill('panel@example.invalid');
  check(/every administrator's own address/.test(await mail.locator('#smtp-to + small').innerText()), 'Send to says an empty one is every administrator\'s own address');
  await page.getByLabel('Send to', { exact: true }).fill('ops@example.invalid, oncall@example.invalid');
  await mail.getByRole('button', { name: 'Save' }).click();
  await page.getByText('The SMTP server is saved.').first().waitFor({ timeout: 15000 });
  await page.reload({ waitUntil: 'networkidle' });
  await page.getByRole('heading', { name: 'How messages go out' }).waitFor({ timeout: 15000 });
  check(await page.locator('#smtp-password').inputValue() === ''
    && await page.locator('#smtp-password').getAttribute('placeholder') === 'Saved - empty keeps it',
  'saved: the password is not shown again, the field says an empty one keeps it');
  check(await page.getByLabel('Send to', { exact: true }).inputValue() === 'ops@example.invalid, oncall@example.invalid', 'the addresses to send to are kept');
  await mail.getByRole('button', { name: 'Send a test', exact: true }).click();
  await page.getByText(/Cannot connect to 127\.0\.0\.1:2599/).first().waitFor({ timeout: 40000 });
  check(true, 'a test to a server that is not there says why it failed');

  // ------------------------------------------------ the administrator: Telegram
  const card = page.locator('form[aria-labelledby="notif-bot-title"]');
  check(await card.getByRole('button', { name: 'Find chat ID' }).isDisabled(), 'Find chat ID waits for a token');
  await card.getByLabel('Bot token').fill(BOT_TOKEN);
  await card.getByRole('button', { name: 'Find chat ID' }).click();
  const found = card.getByRole('region', { name: 'Chats found' });
  await found.getByRole('button', { name: /Ops team/ }).waitFor({ timeout: 20000 });
  check(await found.getByRole('button').count() === 2 && await found.getByRole('button', { name: /Ops \(@ops_admin\)/ }).isVisible(),
    'Find chat ID lists the group the bot is in and the person who wrote to it');
  await found.getByRole('button', { name: /Ops team/ }).click();
  check(await card.getByLabel('Chat ID').inputValue() === '-100777002', 'picking one fills its chat ID in');
  await card.screenshot({ path: `${OUT}/telegram-found-light-en.png` });
  await card.getByRole('button', { name: 'Save' }).click();
  await page.getByText('Saved: the test message reached the chat.').first().waitFor({ timeout: 20000 });
  check(await card.locator('.badge.ok').innerText() === '@snpanel_check_bot'
    && await card.getByText('Messages go to Ops team (-100777002).').isVisible(), 'saved: the card names the bot and the chat');
  check(await card.getByLabel('Bot token').inputValue() === ''
    && await card.getByLabel('Bot token').getAttribute('placeholder') === 'Saved - empty keeps it', 'the token is not shown again');
  await page.waitForTimeout(5500);
  await card.getByRole('button', { name: 'Send a test' }).click();
  await page.getByText('Sent to Ops team (-100777002) on Telegram.').first().waitFor({ timeout: 20000 });
  check(true, 'a test from the card reaches the chat');
  await card.getByLabel('Chat ID').fill('404');
  await card.getByRole('button', { name: 'Save' }).click();
  await page.getByText(/Telegram does not know that chat for this bot/).first().waitFor({ timeout: 20000 });
  const still = await (await api(admin, 'GET', '/notifications')).json();
  check(still.telegram.chat_id === '-100777002', 'a chat Telegram does not know is refused in words, and the saved one stays');
  await page.locator('section[aria-labelledby="notif-channels-title"]').screenshot({ path: `${OUT}/channels-set-light-en.png` });

  // ------------------------------------------------ what is sent
  for (const group of ['Websites and backups', 'The server', 'Administrator accounts']) {
    check(await page.getByRole('heading', { name: group, exact: true }).isVisible(), `the events are grouped: ${group}`);
  }
  check(await page.getByRole('switch').count() === 10, `10 events (${await page.getByRole('switch').count()})`);
  const doneSwitch = page.getByRole('switch', { name: /A scheduled backup finished/ });
  check(!(await doneSwitch.isChecked()), '"A scheduled backup finished" starts off');
  await doneSwitch.click();
  await page.waitForTimeout(1200);
  await page.getByLabel('Language of the messages').selectOption('en');
  await page.waitForTimeout(1200);
  await page.reload({ waitUntil: 'networkidle' });
  await page.getByRole('heading', { name: 'What is sent' }).waitFor({ timeout: 15000 });
  check(await page.getByRole('switch', { name: /A scheduled backup finished/ }).isChecked()
    && await page.getByLabel('Language of the messages').inputValue() === 'en', 'an event turned on and the language chosen are kept');
  await page.getByRole('heading', { name: 'Recently sent' }).scrollIntoViewIfNeeded();
  const log = page.locator('.notif-log');
  check(await log.getByText('Failed').first().isVisible() && await log.getByText('Sent').first().isVisible(),
    'Recently sent shows the Telegram tests sent and the e-mail test failed');
  await page.locator('section[aria-labelledby="notif-events-title"]').screenshot({ path: `${OUT}/events-light-en.png` });
  // ------------------------------------------------ a customer
  const customer = await context();
  const login = await customer.request.post(`${BASE}/api/auth/login`, { form: { username: NAME, password: PASSWORD } });
  check(login.status() === 200, `the customer signs in (${login.status()})`);
  const cpage = await customer.newPage();
  cpage.on('pageerror', (e) => errors.push(String(e)));
  await cpage.goto(`${BASE}/notifications`, { waitUntil: 'networkidle' });
  await cpage.getByText('Notifications go to the panel\'s administrators, and only they set them up.').waitFor({ timeout: 15000 });
  check(await cpage.getByRole('switch').count() === 0 && await cpage.getByRole('heading', { name: 'How messages go out' }).count() === 0,
    'a customer is told the page is the administrators\', and sees nothing of it');
  check(await cpage.getByRole('link', { name: 'Notifications' }).count() + await cpage.getByRole('button', { name: 'Notifications' }).count() === 0,
    'and has no Notifications in the menu');
  check((await customer.request.get(`${BASE}/api/notifications`)).status() === 403, 'the API refuses it too');
  await cpage.screenshot({ path: `${OUT}/customer-light-en.png` });

  // ------------------------------------------------ in Vietnamese, on a phone
  const vi = await context('vi', 390);
  await logIn(vi);
  const vpage = await vi.newPage();
  vpage.on('pageerror', (e) => errors.push(String(e)));
  await vpage.goto(`${BASE}/notifications`, { waitUntil: 'networkidle' });
  await vpage.getByRole('heading', { name: 'Cách gửi thông báo' }).waitFor({ timeout: 15000 });
  check(await vpage.getByRole('button', { name: 'Tìm Chat ID' }).isVisible() && await vpage.getByText('Thông báo được gửi tới Ops team (-100777002).').isVisible(),
    'in Vietnamese: the Telegram card finds and names the chat');
  const overflow = await vpage.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check(overflow <= 0, `in Vietnamese on a phone nothing runs off the screen (${overflow}px)`);
  await vpage.locator('form[aria-labelledby="notif-bot-title"]').screenshot({ path: `${OUT}/telegram-phone-light-vi.png` });
  await vpage.locator('section[aria-labelledby="notif-events-title"]').screenshot({ path: `${OUT}/events-phone-light-vi.png` });

  check(errors.length === 0, `no page errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} catch (err) {
  ok = false;
  console.log(`FAIL  ${err.message.split('\n')[0]}`);
} finally {
  await api(admin, 'DELETE', '/notifications/smtp');
  await api(admin, 'DELETE', '/notifications/telegram');
  if (defaults) await api(admin, 'PUT', '/notifications/settings', { language: 'vi', events: defaults });
  await removeCustomer();
  if (!wasInstalled) await api(admin, 'POST', '/addons/notifications/uninstall');
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
