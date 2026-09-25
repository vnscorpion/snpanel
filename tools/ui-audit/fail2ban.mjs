// The Fail2ban addon, from nothing installed to banning, and back.
//
//     node fail2ban.mjs [out-dir]
//
// Runs on the box, as root: it purges fail2ban first, reads fail2ban's files
// and nftables, and writes test lines into a site's access log.
//
// The browser comes from 127.0.0.1, which the panel trusts to forward the
// real address, and says it is 198.51.100.60 - so "your address" is an
// address fail2ban could ban, not loopback, which it never does.
//
//   - Addons: install; the addon is marked installed only with fail2ban
//     running, and the installing address is never banned.
//   - The Dashboard has a tile, the settings menu an entry.
//   - The page: running, the jails, your address; a ban and an unban; your
//     own address refused; settings saved into fail2ban's own file; your
//     address taken off the never-ban list and put back with one click.
//   - Detection: five failed panel sign-ins from one address ban it on the
//     panel's port; five failed WordPress sign-ins in a site's log ban
//     theirs, and the same from a Cloudflare address bans nobody.
//   - A site created after the install has its log watched; deleted, not.
//   - Uninstall stops fail2ban and lifts every ban; installing again brings
//     the settings back.
// Ends with the addon installed.
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { BASE, logIn, adminPassword } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/fail2ban';
mkdirSync(OUT, { recursive: true });
const ME = '198.51.100.60';
const BANNED_BY_HAND = '198.51.100.61';
const PANEL_ATTACKER = '198.51.100.62';
const WP_ATTACKER = '198.51.100.63';
const CLOUDFLARE_EDGE = '104.16.0.10';
const JAIL_FILE = '/etc/fail2ban/jail.d/snpanel.local';
const SITE_LOG = '/var/log/nginx/static.snpanel.deb13.access.log';

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, ...args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim(); } catch (e) { return String(e.stdout || '').trim(); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (test, ms, step = 1000) => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) { if (await test()) return true; await sleep(step); }
  return !!(await test());
};
const jailStatus = (jail) => run('fail2ban-client', 'status', jail);
const bannedIn = (jail, address) => jailStatus(jail).split('\n').some((l) => l.includes('Banned IP list') && l.split(/\s+/).includes(address));
const jailFile = () => (existsSync(JAIL_FILE) ? readFileSync(JAIL_FILE, 'utf8') : '');
const section = (text, name) => (text.split(/\n(?=\[)/).find((s) => s.startsWith(`[${name}]`)) || '');

// nginx's $time_local, in this machine's zone.
function nginxTime(date = new Date()) {
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const pad = (n) => String(n).padStart(2, '0');
  const offset = -date.getTimezoneOffset();
  const sign = offset >= 0 ? '+' : '-';
  const zone = `${sign}${pad(Math.floor(Math.abs(offset) / 60))}${pad(Math.abs(offset) % 60)}`;
  return `${pad(date.getDate())}/${months[date.getMonth()]}/${date.getFullYear()}:${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())} ${zone}`;
}

const browser = await chromium.launch();
const newContext = (extra = {}) => browser.newContext({
  ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: 'en-US',
  extraHTTPHeaders: { 'X-Forwarded-For': ME }, ...extra,
});
const context = await newContext();
await context.addInitScript(() => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', 'en'); } catch {} });
await logIn(context);
const csrf = async () => (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
const api = async (method, path, options = {}) => context.request.fetch(`${BASE}/api${path}`, {
  method, ...options, headers: { 'X-CSRF-Token': await csrf(), ...(options.headers || {}) }, timeout: 900000,
});
const page = await context.newPage();
page.on('dialog', (d) => d.accept());
const consoleErrors = [];
page.on('console', (m) => { if (m.type() === 'error' && !/jobs\/latest/.test(m.location()?.url || '')) consoleErrors.push(m.text()); });
const go = async (path) => { await page.goto(`${BASE}${path}`, { waitUntil: 'networkidle' }); await page.waitForTimeout(300); };
const addonCard = () => page.locator('.addon-card').filter({ has: page.locator('strong', { hasText: /^Fail2ban$/ }) });
// The settings menu's entries are buttons, drawn while the menu is open.
const menuEntry = async () => {
  if (await page.locator('#settings-submenu').count() === 0) await page.getByRole('button', { name: 'Settings', exact: true }).click();
  return page.locator('#settings-submenu').getByRole('button', { name: 'Fail2ban', exact: true });
};

try {
  // ---------------------------------------------------------------- from nothing
  await api('POST', '/addons/fail2ban/uninstall');
  run('apt-get', 'purge', '-y', '-q', 'fail2ban');
  rmSync('/etc/fail2ban', { recursive: true, force: true });
  rmSync('/var/lib/snpanel/fail2ban.json', { force: true });
  check(!existsSync('/usr/bin/fail2ban-client'), 'start: fail2ban is not installed');

  // ---------------------------------------------------------------- install
  await go('/addons');
  check(await addonCard().getByText('Not installed', { exact: true }).isVisible(), 'the Addons page lists Fail2ban, not installed');
  await page.screenshot({ path: `${OUT}/addons-before-light-en.png`, fullPage: true });
  const installAnswer = page.waitForResponse((r) => r.url().endsWith('/api/addons/fail2ban/install'), { timeout: 900000 });
  await addonCard().getByRole('button', { name: 'Install' }).click();
  const installed = await installAnswer;
  check(installed.status() === 200, `Install answers 200 (${installed.status()})`);
  await page.waitForTimeout(800);
  check(await addonCard().getByText('Installed', { exact: true }).isVisible()
    && await addonCard().getByRole('button', { name: 'Open Fail2ban' }).isVisible(), 'the card says installed, with a way to the page');
  check(run('systemctl', 'is-active', 'fail2ban') === 'active' && run('systemctl', 'is-enabled', 'fail2ban') === 'enabled',
    'fail2ban runs, and starts at boot');
  const saved = JSON.parse(readFileSync('/var/lib/snpanel/fail2ban.json', 'utf8'));
  check(saved.ignoreip.includes(ME), `the installing address is never banned (${saved.ignoreip.join(' ')})`);

  // ---------------------------------------------------------------- dashboard, menu
  await go('/');
  check(await page.locator('a[href="/fail2ban"]').first().isVisible(), 'the Dashboard has a Fail2ban tile');
  check(await (await menuEntry()).isVisible(), 'and the settings menu an entry');

  // ---------------------------------------------------------------- the page
  await go('/fail2ban');
  check(await page.getByRole('heading', { name: 'Fail2ban is running' }).isVisible(), 'the page: running');
  check(await page.getByText(`Your address, ${ME}, is never banned.`).isVisible(), 'your address, never banned');
  const jailNames = await page.locator('.f2b-jail strong').allTextContents();
  check(JSON.stringify(jailNames) === JSON.stringify(['SSH', 'Panel sign-in', 'WordPress sign-in', 'Password-protected folders', 'Repeat offenders']),
    `the panel's jails, in order (${jailNames.join(', ')})`);

  const own = await api('POST', '/fail2ban/ban', { data: { jail: 'recidive', address: ME } });
  check(own.status() === 400 && /your own address/.test(await own.text()), 'banning your own address is refused');

  await page.getByLabel('Address', { exact: true }).fill(BANNED_BY_HAND);
  await page.getByLabel('Jail', { exact: true }).selectOption('recidive');
  await page.getByRole('button', { name: 'Ban', exact: true }).click();
  await page.locator('.data-table code', { hasText: BANNED_BY_HAND }).waitFor({ timeout: 30000 });
  check(bannedIn('recidive', BANNED_BY_HAND) && run('nft', 'list', 'table', 'inet', 'f2b-table').includes(BANNED_BY_HAND),
    'a ban from the page lands in fail2ban and nftables');
  await page.getByRole('button', { name: `Unban ${BANNED_BY_HAND}` }).click();
  await page.locator('.data-table code', { hasText: BANNED_BY_HAND }).waitFor({ state: 'detached', timeout: 30000 });
  check(!bannedIn('recidive', BANNED_BY_HAND) && !run('nft', 'list', 'table', 'inet', 'f2b-table').includes(BANNED_BY_HAND),
    'and Unban takes it out of both');

  // ---------------------------------------------------------------- settings
  await page.getByLabel('Banned for').selectOption('3600');
  await page.locator('.f2b-jail', { hasText: 'Password-protected folders' }).locator('input[type="checkbox"]').check();
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await page.getByText('Fail2ban settings saved.').waitFor({ timeout: 60000 });
  let file = jailFile();
  check(/\nbantime = 3600\n/.test(section(file, 'DEFAULT')) && /enabled = true/.test(section(file, 'nginx-http-auth')),
    'Save writes the ban time and the jail into fail2ban\'s file');
  check(await until(() => jailStatus('nginx-http-auth').includes('Currently banned'), 15000), 'and the new jail runs');

  await page.getByLabel('Never ban', { exact: true }).fill('');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await page.getByText(/is not on the never-ban list/).waitFor({ timeout: 60000 });
  check(!jailFile().includes(`${ME}/32`), 'your address off the list: the page warns you, and the file no longer has it');
  await page.screenshot({ path: `${OUT}/page-warn-light-en.png`, fullPage: true });
  await page.getByRole('button', { name: 'Never ban it' }).click();
  await page.getByText(`Your address, ${ME}, is never banned.`).waitFor({ timeout: 60000 });
  check(jailFile().includes(`${ME}/32`), 'and one click puts it back');

  // ---------------------------------------------------------------- detection: the panel
  const stranger = await browser.newContext({ ignoreHTTPSErrors: true, extraHTTPHeaders: { 'X-Forwarded-For': PANEL_ATTACKER } });
  for (let i = 0; i < 5; i++) {
    await stranger.request.post(`${BASE}/api/auth/login`, { form: { username: 'admin', password: `wrong-${i}-${adminPassword().length}` } });
  }
  await stranger.close();
  check(await until(() => bannedIn('snpanel-login', PANEL_ATTACKER), 20000),
    `five failed panel sign-ins from ${PANEL_ATTACKER} ban it`);
  const panelRule = run('nft', 'list', 'table', 'inet', 'f2b-table');
  check(/2222/.test(panelRule) && panelRule.includes(PANEL_ATTACKER), 'on the panel\'s port');
  await go('/fail2ban');
  const row = page.locator('.data-table tr', { hasText: PANEL_ATTACKER });
  check(await row.getByText('Panel sign-in').isVisible(), 'the page lists it under Panel sign-in');

  // ---------------------------------------------------------------- detection: WordPress
  const wpLine = (address) => `${address} - - [${nginxTime()}] "POST /wp-login.php HTTP/1.1" 200 4520 "-" "Mozilla/5.0"\n`;
  for (let i = 0; i < 6; i++) appendFileSync(SITE_LOG, wpLine(WP_ATTACKER) + wpLine(CLOUDFLARE_EDGE));
  check(await until(() => bannedIn('snpanel-wordpress', WP_ATTACKER), 30000), `failed WordPress sign-ins from ${WP_ATTACKER} ban it`);
  check(!bannedIn('snpanel-wordpress', CLOUDFLARE_EDGE), `the same from Cloudflare's ${CLOUDFLARE_EDGE} bans nobody`);

  // The page, with bans in it: both themes, both languages, and a phone.
  // A context each: an init script sets theme and language before the page
  // runs, and a context's init script runs again on every navigation.
  for (const [theme, locale, width] of [['light', 'en', 1440], ['dark', 'en', 1440], ['light', 'vi', 1440], ['dark', 'vi', 1440], ['light', 'en', 390], ['dark', 'vi', 390]]) {
    const shot = await newContext({ viewport: { width, height: width > 500 ? 900 : 844 } });
    await shot.addInitScript(([th, lo]) => { try { localStorage.setItem('snpanel-theme', th); localStorage.setItem('snpanel-locale', lo); } catch {} }, [theme, locale]);
    await logIn(shot);
    const view = await shot.newPage();
    await view.goto(`${BASE}/fail2ban`, { waitUntil: 'networkidle' });
    await view.waitForTimeout(400);
    const applied = await view.evaluate(() => [document.documentElement.dataset.theme || '', document.documentElement.lang || '']);
    if (width < 500) {
      const overflow = await view.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      check(overflow <= 0, `no sideways scroll on a phone, ${theme} ${locale} (${overflow}px)`);
    }
    await view.screenshot({ path: `${OUT}/page-${width < 500 ? 'phone-' : ''}${theme}-${locale}.png`, fullPage: true });
    console.log(`  screenshot ${theme} ${locale} ${width}px (page says theme=${applied[0]} lang=${applied[1]})`);
    await shot.close();
  }

  for (const address of [PANEL_ATTACKER, WP_ATTACKER]) await api('POST', '/fail2ban/unban', { data: { address } });
  check(!bannedIn('snpanel-login', PANEL_ATTACKER) && !bannedIn('snpanel-wordpress', WP_ATTACKER), 'Unban lets both back in');

  // ---------------------------------------------------------------- a new site
  const domain = `f2b${Date.now() % 1000000}.example.com`;
  const created = await api('POST', '/websites', { data: { domain, app_type: 'static' } });
  const site = await created.json().catch(() => ({}));
  check(created.status() === 200, `a site created after the install (${created.status()})`);
  const watched = () => run('fail2ban-client', 'get', 'snpanel-wordpress', 'logpath').includes(`/var/log/nginx/${domain}.access.log`);
  check(await until(watched, 30000), 'has its access log watched');
  const deleted = site.id ? await api('DELETE', `/websites/${site.id}?delete_files=true`) : null;
  // Its log files stay behind - deleting a site keeps them - and a file that
  // is there stays watched, with nothing writing to it. What this checks is
  // that fail2ban came back from re-reading its settings after the delete.
  check(deleted?.status() === 200 && await until(() => run('fail2ban-client', 'ping').includes('pong'), 15000),
    'deleted: the site goes, and fail2ban still answers after re-reading its settings');
  for (const kind of ['access', 'error']) rmSync(`/var/log/nginx/${domain}.${kind}.log`, { force: true });

  // ---------------------------------------------------------------- uninstall, reinstall
  await api('POST', '/fail2ban/ban', { data: { jail: 'recidive', address: BANNED_BY_HAND } });
  await go('/addons');
  const uninstallAnswer = page.waitForResponse((r) => r.url().endsWith('/api/addons/fail2ban/uninstall'), { timeout: 120000 });
  await addonCard().getByRole('button', { name: 'Uninstall' }).click();
  check((await uninstallAnswer).status() === 200, 'Uninstall answers 200');
  check(run('systemctl', 'is-active', 'fail2ban') !== 'active' && run('systemctl', 'is-enabled', 'fail2ban') === 'disabled',
    'fail2ban is stopped and disabled');
  check(!run('nft', 'list', 'tables').includes('f2b-table'), 'and every ban is lifted with it');
  await go('/');
  check(await page.locator('a[href="/fail2ban"]').count() === 0 && await (await menuEntry()).count() === 0,
    'the tile and the menu entry are gone');
  await go('/fail2ban');
  check(await page.getByText('The Fail2ban addon is not installed on this server.').isVisible(), 'the page says the addon is not installed');

  await go('/addons');
  const again = page.waitForResponse((r) => r.url().endsWith('/api/addons/fail2ban/install'), { timeout: 900000 });
  await addonCard().getByRole('button', { name: 'Install' }).click();
  check((await again).status() === 200, 'installing again answers 200');
  file = jailFile();
  check(/\nbantime = 3600\n/.test(section(file, 'DEFAULT')) && /enabled = true/.test(section(file, 'nginx-http-auth')),
    'with the settings from before');
  check(consoleErrors.length === 0, `no console errors (${consoleErrors.slice(0, 3).join(' | ')})`);
} finally {
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
