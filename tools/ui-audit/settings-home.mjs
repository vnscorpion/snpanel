// Settings as one page of tiles, in a browser.
//
//     node settings-home.mjs [out-dir]        (LOGIN_FILE: the administrator's)
//
// As the administrator: the sidebar has Settings as one entry and no
// submenu, with AI assistants and Notifications above it while their addons
// are installed, and without them while they are not; Settings opens
// /settings, a tile for each settings page - six a row on a wide screen,
// five, four, three and two as it narrows; a tile opens its page,
// Settings stays the highlighted entry there, and the line over the title
// leads back; Panel settings is at /panel-settings and /api-tokens. As a
// throwaway customer: only the tiles of what a customer may open, and AI
// assistants but never Notifications in its sidebar. In Vietnamese on a
// phone, nothing runs off the screen. The customer is deleted and the addons
// left as they were found.
import { chromium } from 'playwright';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/settings-home';
const NAME = 'settingshome';
const PASSWORD = `S-${randomBytes(15).toString('base64url')}`;
mkdirSync(OUT, { recursive: true });
let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };

const browser = await chromium.launch();
const errors = [];
async function context(locale = 'en', width = 1440, theme = 'light') {
  const c = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width, height: 900 }, locale: 'en-US' });
  await c.addInitScript(([l, th]) => { try { localStorage.setItem('snpanel-theme', th); localStorage.setItem('snpanel-locale', l); } catch {} }, [locale, theme]);
  return c;
}
const csrfOf = async (c) => (await c.cookies()).find((k) => k.name === 'snpanel_csrf')?.value;
const api = async (c, method, path, data) => c.request.fetch(`${BASE}/api${path}`, { method, data, headers: { 'X-CSRF-Token': (await csrfOf(c)) || '' } });
const tiles = (page) => page.locator('.settings-grid .settings-tile-label').allTextContents();
// How many tiles share the first row.
const perRow = (page) => page.$$eval('.settings-grid > li', (items) => {
  const top = items[0]?.getBoundingClientRect().top;
  return items.filter((li) => Math.abs(li.getBoundingClientRect().top - top) < 2).length;
});
const current = (page) => page.locator('.sidebar [aria-current="page"]').textContent();
const title = (page) => page.locator('.page-title h1').textContent();

const admin = await context();
await logIn(admin);
const sidebarOf = (page) => page.$$eval('.sidebar-nav button', (bs) => bs.map((b) => b.textContent.trim()));
const addonsInstalled = async () => Object.fromEntries(((await (await api(admin, 'GET', '/addons')).json()).items || []).map((a) => [a.slug, !!a.installed]));
const found = await addonsInstalled();
const setAddon = async (slug, on) => {
  const now = (await addonsInstalled())[slug];
  if (now !== on) await api(admin, 'POST', `/addons/${slug}/${on ? 'install' : 'uninstall'}`);
};
const removeCustomer = async () => {
  const users = await (await api(admin, 'GET', '/users?usage=0')).json();
  const old = (users.items || users).find((u) => u.username === NAME);
  if (old) await api(admin, 'DELETE', `/users/${old.id}`);
};

try {
  // ------------------------------------------------ the sidebar
  const page = await admin.newPage();
  page.on('pageerror', (e) => errors.push(String(e)));
  await setAddon('mcp', true);
  await setAddon('notifications', true);
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  let sidebar = await sidebarOf(page);
  check(sidebar.at(-1) === 'Settings' && !sidebar.includes('PHP config') && await page.locator('.sidebar-subnav, #settings-submenu').count() === 0,
    `the sidebar has Settings as one entry, no submenu (${sidebar.join(', ')})`);
  check(sidebar.slice(-3).join() === 'AI assistants (MCP),Notifications,Settings',
    'with their addons installed, AI assistants and Notifications are just above Settings');
  await page.locator('.sidebar').screenshot({ path: `${OUT}/sidebar-light-en.png` });
  await setAddon('mcp', false);
  await setAddon('notifications', false);
  await page.reload({ waitUntil: 'networkidle' });
  sidebar = await sidebarOf(page);
  check(!sidebar.includes('AI assistants (MCP)') && !sidebar.includes('Notifications') && sidebar.at(-1) === 'Settings',
    `with the addons uninstalled, neither is in the sidebar (${sidebar.slice(-3).join(', ')})`);
  await setAddon('mcp', true);
  await setAddon('notifications', true);
  await page.reload({ waitUntil: 'networkidle' });
  await page.locator('.sidebar-nav').getByRole('button', { name: 'Notifications', exact: true }).click();
  await page.waitForURL(/\/notifications$/);
  check(await current(page) === 'Notifications' && await page.locator('.page-title-back').count() === 0,
    'Notifications opens from the sidebar, as a page of its own, not of Settings');
  await page.locator('.sidebar-nav').getByRole('button', { name: 'Settings', exact: true }).click();
  await page.waitForURL(/\/settings$/);
  await page.locator('.settings-grid').waitFor();
  const adminTiles = await tiles(page);
  const wanted = ['Panel settings', 'Account security', 'PHP config', 'Firewall', 'WAF', 'Malware Scanner', 'Access Logs', 'Updates', 'Addons', 'Services Status'];
  check(wanted.every((w) => adminTiles.includes(w)) && !adminTiles.includes('Notifications') && !adminTiles.includes('AI assistants (MCP)')
    && await title(page) === 'Settings' && await current(page) === 'Settings',
    `it opens Settings: a tile for each settings page, the two addons not among them (${adminTiles.length}: ${adminTiles.join(', ')})`);
  const layout = await page.$$eval('.settings-tile', (all) => all.map((tile) => {
    const icon = tile.querySelector('.settings-tile-icon').getBoundingClientRect();
    const label = tile.querySelector('.settings-tile-label').getBoundingClientRect();
    const about = tile.querySelector('.settings-tile-about');
    return icon.right <= label.left && !!about && about.textContent.trim() !== '' && about.getBoundingClientRect().top >= label.bottom - 1;
  }));
  check(layout.length > 0 && layout.every(Boolean), 'each tile: its icon on the left, its name, and a line about it under the name');

  // ------------------------------------------------ five a row, fewer as it narrows
  for (const [width, columns] of [[1440, 6], [1200, 5], [1000, 4], [760, 3], [390, 2]]) {
    await page.setViewportSize({ width, height: 900 });
    await page.waitForTimeout(200);
    const n = await perRow(page);
    check(n === columns, `${width}px: ${columns} a row (${n})`);
    if (width === 1440) await page.locator('.content-body').screenshot({ path: `${OUT}/settings-light-en-1440.png` });
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  const sideways = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  check(sideways <= 0, `no sideways scroll (${sideways}px)`);

  // ------------------------------------------------ a tile, and back
  await page.locator('.settings-grid').getByRole('link', { name: 'PHP config', exact: true }).click();
  await page.waitForURL(/\/php$/);
  await page.locator('.page-title-back').waitFor();
  check(await title(page) === 'PHP config' && await current(page) === 'Settings', `a tile opens its page; Settings stays highlighted (${await title(page)} / ${await current(page)})`);
  await page.locator('.page-title').screenshot({ path: `${OUT}/back-link-light-en.png` });
  await page.locator('.page-title-back').click();
  await page.waitForURL(/\/settings$/);
  check(await page.locator('.settings-grid').isVisible(), 'the line over the title leads back to Settings');
  await page.goto(`${BASE}/panel-settings`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.settings-tabs');
  check(await title(page) === 'Panel settings' && await current(page) === 'Settings', '/panel-settings is Panel settings');
  await page.goto(`${BASE}/api-tokens`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.settings-tabs');
  check(await title(page) === 'Panel settings' && await page.locator('.settings-tabs [role="tab"][aria-selected="true"]').textContent() === 'API tokens',
    '/api-tokens is still its tokens tab');
  await page.goto(`${BASE}/websites`, { waitUntil: 'networkidle' });
  check(await page.locator('.page-title-back').count() === 0, 'a page outside Settings has no link back to it');

  // ------------------------------------------------ a customer
  await removeCustomer();
  const made = await api(admin, 'POST', '/users', { username: NAME, email: `${NAME}@example.invalid`, password: PASSWORD, role: 'end_user', website_limit: 1, storage_limit_mb: 100 });
  check(made.ok(), `a customer ${NAME} (${made.status()})`);
  const customer = await context();
  await customer.request.post(`${BASE}/api/auth/login`, { form: { username: NAME, password: PASSWORD } });
  const cpage = await customer.newPage();
  cpage.on('pageerror', (e) => errors.push(String(e)));
  await cpage.goto(`${BASE}/settings`, { waitUntil: 'networkidle' });
  await cpage.locator('.settings-grid').waitFor({ timeout: 15000 });
  const customerTiles = await tiles(cpage);
  check(customerTiles.join() === 'Account security,WAF,Services Status', `a customer gets only its own tiles (${customerTiles.join(', ')})`);
  const customerSidebar = await sidebarOf(cpage);
  check(customerSidebar.slice(-2).join() === 'AI assistants (MCP),Settings' && !customerSidebar.includes('Notifications'),
    `and AI assistants above Settings, never Notifications (${customerSidebar.slice(-3).join(', ')})`);
  await cpage.locator('.content-body').screenshot({ path: `${OUT}/settings-customer-light-en.png` });

  // ------------------------------------------------ in Vietnamese: dark, and on a phone
  const dark = await context('vi', 1440, 'dark');
  await logIn(dark);
  const dpage = await dark.newPage();
  dpage.on('pageerror', (e) => errors.push(String(e)));
  await dpage.goto(`${BASE}/settings`, { waitUntil: 'networkidle' });
  await dpage.locator('.settings-grid').waitFor();
  check(await title(dpage) === 'Cài đặt' && (await tiles(dpage)).includes('Cấu hình PHP'), `in Vietnamese: ${await title(dpage)}, ${(await tiles(dpage)).slice(0, 3).join(', ')}...`);
  await dpage.locator('.content-body').screenshot({ path: `${OUT}/settings-dark-vi-1440.png` });
  const phone = await context('vi', 390);
  await logIn(phone);
  const ppage = await phone.newPage();
  ppage.on('pageerror', (e) => errors.push(String(e)));
  await ppage.goto(`${BASE}/settings`, { waitUntil: 'networkidle' });
  await ppage.locator('.settings-grid').waitFor();
  const phoneSideways = await ppage.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  check(phoneSideways <= 0 && await perRow(ppage) === 2, `in Vietnamese on a phone: two a row, nothing off the screen (${phoneSideways}px)`);
  await ppage.screenshot({ path: `${OUT}/settings-light-vi-390.png`, fullPage: true });
  await ppage.locator('.mobile-nav-toggle').click();
  await ppage.waitForTimeout(400);
  await ppage.screenshot({ path: `${OUT}/menu-light-vi-390.png` });

  check(errors.length === 0, `no page errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} catch (err) {
  ok = false;
  console.log(`FAIL  ${err.message.split('\n')[0]}`);
} finally {
  for (const [slug, on] of Object.entries(found).filter(([slug]) => ['mcp', 'notifications'].includes(slug))) await setAddon(slug, on);
  await removeCustomer();
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
