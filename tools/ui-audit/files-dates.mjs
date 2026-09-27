// The file manager's dates and sorting, in a browser.
//
//     node files-dates.mjs [out-dir]        (LOGIN_FILE: the administrator's)
//
// A throwaway customer with a website of its own: three files written a
// second apart and of different sizes, and a folder whose name sorts last.
// Each row shows when its entry was modified, in the viewer's zone, and the
// headings sort by name, size and date - both ways - with folders first
// throughout. On a phone the date is on the row too. The customer and the
// website are removed at the end.
import { chromium } from 'playwright';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/files-dates';
const NAME = 'filedates';
const PASSWORD = `F-${randomBytes(15).toString('base64url')}`;
const DOMAIN = `fd${Date.now() % 1000000}.example.com`;
const ZONE = 'Asia/Ho_Chi_Minh';
mkdirSync(OUT, { recursive: true });
let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await chromium.launch();
const errors = [];
async function context(width = 1440) {
  const c = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width, height: 900 }, locale: 'en-US', timezoneId: ZONE });
  await c.addInitScript(() => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', 'en'); } catch {} });
  return c;
}
const csrfOf = async (c) => (await c.cookies()).find((k) => k.name === 'snpanel_csrf')?.value;
const api = async (c, method, path, data) => c.request.fetch(`${BASE}/api${path}`, { method, data, headers: { 'X-CSRF-Token': (await csrfOf(c)) || '' } });

// What the page should print for a time: the viewer's zone, YYYY-MM-DD HH:mm.
function shown(seconds) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-GB', {
    timeZone: ZONE, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false,
  }).formatToParts(new Date(seconds * 1000)).map((p) => [p.type, p.value]));
  return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}`;
}

const admin = await context();
await logIn(admin);
let userId = null;
let siteId = null;
async function removeAll() {
  if (siteId) await api(admin, 'DELETE', `/websites/${siteId}`);
  const users = await (await api(admin, 'GET', '/users?usage=0')).json();
  const old = (users.items || users).find((u) => u.username === NAME);
  if (old) await api(admin, 'DELETE', `/users/${old.id}`);
}

try {
  await removeAll();
  userId = (await (await api(admin, 'POST', '/users', { username: NAME, email: `${NAME}@example.invalid`, password: PASSWORD, role: 'end_user', website_limit: 1, storage_limit_mb: 100 })).json()).id;
  const site = await (await api(admin, 'POST', '/websites', { domain: DOMAIN, app_type: 'static', owner_id: userId })).json();
  siteId = site.id;
  check(userId && siteId, `a customer with a website (${DOMAIN})`);

  const customer = await context();
  const login = await customer.request.post(`${BASE}/api/auth/login`, { form: { username: NAME, password: PASSWORD } });
  check(login.status() === 200, `the customer signs in (${login.status()})`);
  const listing = async () => (await (await api(customer, 'GET', `/maintenance/files/${siteId}?path=public_html`)).json());
  const where = (await listing());
  const base = 'public_html';
  await api(customer, 'POST', '/maintenance/files/mkdir', { website_id: siteId, path: base, name: 'zz-folder' });
  for (const [name, bytes] of [['a-small.txt', 10], ['b-large.txt', 5000], ['c-medium.txt', 500]]) {
    await api(customer, 'POST', '/maintenance/files/write', { website_id: siteId, path: `${base}/${name}`, content: 'x'.repeat(bytes) });
    await sleep(1200);
  }
  const listed = await listing();
  const items = listed.items || listed.files || listed;
  check(Array.isArray(items) && items.length >= 4 && Array.isArray(where.items || where.files || where), `the folder holds what was written (${Array.isArray(items) ? items.length : typeof items} entries)`);

  const page = await customer.newPage();
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(`${BASE}/filemanager`, { waitUntil: 'networkidle' });
  const crumb = page.getByRole('button', { name: 'public_html', exact: true });
  if (await crumb.count()) await crumb.click();
  await page.locator('.file-item', { hasText: 'c-medium.txt' }).waitFor({ timeout: 15000 });
  const names = async () => (await page.locator('.file-item .file-name strong').allTextContents()).map((s) => s.trim());

  // Each row's date, as the page writes it, against the listing's.
  let dated = true;
  for (const item of items) {
    const row = page.locator('.file-item', { has: page.locator('.file-name strong', { hasText: new RegExp(`^${item.name.replace(/\./g, '\\.')}$`) }) });
    const text = (await row.locator('.file-date').textContent()).trim();
    const title = await row.locator('.file-date').getAttribute('title');
    if (text !== shown(item.modified) || !/^Modified /.test(title || '')) {
      dated = false;
      console.log(`      ${item.name}: shown ${text}, expected ${shown(item.modified)} (title ${title})`);
    }
  }
  check(dated, `every row shows when it was modified, in the viewer's zone, with the full time on hover (${items.length} rows)`);

  // The expected orders, from the listing itself.
  const folders = items.filter((i) => i.is_dir).map((i) => i.name);
  const files = items.filter((i) => !i.is_dir);
  const byName = (a, b) => (a.name.toLowerCase() < b.name.toLowerCase() ? -1 : a.name.toLowerCase() > b.name.toLowerCase() ? 1 : 0);
  const order = (list) => [...folders, ...list.map((i) => i.name)];
  check(JSON.stringify(await names()) === JSON.stringify(order([...files].sort(byName))), `at first: folders first, then A to Z, as the server lists them (${(await names()).join(', ')})`);

  await page.getByRole('button', { name: 'Sort by Modified' }).click();
  const newest = order([...files].sort((a, b) => (b.modified - a.modified) || byName(a, b)));
  check(JSON.stringify(await names()) === JSON.stringify(newest), `Modified: newest first, the folder still first (${(await names()).join(', ')})`);
  await page.screenshot({ path: `${OUT}/newest-first-light-en.png`, fullPage: true });
  await page.getByRole('button', { name: /^Modified: sorted descending/ }).click();
  const oldest = order([...files].sort((a, b) => (a.modified - b.modified) || byName(a, b)));
  check(JSON.stringify(await names()) === JSON.stringify(oldest), `again: oldest first (${(await names()).join(', ')})`);

  await page.getByRole('button', { name: 'Sort by Size' }).click();
  const largest = order([...files].sort((a, b) => (b.size - a.size) || byName(a, b)));
  check(JSON.stringify(await names()) === JSON.stringify(largest), `Size: largest first (${(await names()).join(', ')})`);

  await page.getByRole('button', { name: 'Sort by Name' }).click();
  check(JSON.stringify(await names()) === JSON.stringify(order([...files].sort(byName))), 'Name: A to Z again');
  await page.getByRole('button', { name: /^Name: sorted ascending/ }).click();
  check(JSON.stringify(await names()) === JSON.stringify([...folders, ...[...files].sort(byName).reverse().map((i) => i.name)]), 'and Z to A, folders still first');

  // Headings over their columns: the date heading starts where the dates do.
  const heading = await page.locator('.file-list-header .file-col-date').boundingBox();
  const date = await page.locator('.file-item .file-date').first().boundingBox();
  check(Math.abs(heading.x - date.x) <= 6, `the Modified heading sits over the dates (${Math.round(heading.x)} / ${Math.round(date.x)})`);

  // On a phone.
  const phone = await context(390);
  await phone.request.post(`${BASE}/api/auth/login`, { form: { username: NAME, password: PASSWORD } });
  const ppage = await phone.newPage();
  ppage.on('pageerror', (e) => errors.push(String(e)));
  await ppage.goto(`${BASE}/filemanager`, { waitUntil: 'networkidle' });
  const pcrumb = ppage.getByRole('button', { name: 'public_html', exact: true });
  if (await pcrumb.count()) await pcrumb.click();
  const prow = ppage.locator('.file-item', { hasText: 'b-large.txt' });
  await prow.waitFor({ timeout: 15000 });
  const overflow = await ppage.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check(await prow.locator('.file-date').isVisible() && overflow <= 0, `on a phone the date is on the row, and nothing runs off the screen (${overflow}px)`);
  await ppage.screenshot({ path: `${OUT}/phone-light-en.png`, fullPage: true });

  check(errors.length === 0, `no page errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} catch (err) {
  ok = false;
  console.log(`FAIL  ${err.message.split('\n')[0]}`);
} finally {
  await removeAll();
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
