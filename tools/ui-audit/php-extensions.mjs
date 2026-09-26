// PHP extensions on the PHP configuration page, end to end.
//
//     node php-extensions.mjs [out-dir] [version]   (LOGIN_FILE: the administrator's)
//
// For one installed PHP version (8.3 by default): the catalogue with what
// PHP loads; the base set not removable; igbinary refused because redis is
// built on it; nothing outside the catalogue; a version that is not
// installed; a customer kept out. Then memcached installed from the page -
// the package, FPM restarted, PHP loading it - and removed again. The
// machine is left with the extensions it had.
import { chromium } from 'playwright';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/php-extensions';
const VERSION = process.argv[3] || '8.3';
const NAME = 'phpextcheck';
const PASSWORD = `E-${randomBytes(15).toString('base64url')}`;
mkdirSync(OUT, { recursive: true });
let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };

const browser = await chromium.launch();
const errors = [];
const admin = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: 'en-US' });
await admin.addInitScript(() => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', 'en'); } catch {} });
await logIn(admin);
const csrfOf = async (c) => (await c.cookies()).find((k) => k.name === 'snpanel_csrf')?.value;
const api = async (c, method, path, data) => c.request.fetch(`${BASE}/api${path}`, { method, data, headers: { 'X-CSRF-Token': (await csrfOf(c)) || '' }, timeout: 600000 });
const extensions = async () => (await api(admin, 'GET', `/maintenance/php-versions/${VERSION}/extensions`)).json();
const entry = (view, key) => view.extensions.find((e) => e.key === key);
let hadMemcached = null;

try {
  // ------------------------------------------------ the catalogue
  let view = await extensions();
  hadMemcached = entry(view, 'memcached')?.installed;
  const loadedBefore = [...view.loaded];
  check(view.read && view.extensions.length === 29 && view.loaded.length > 20,
    `PHP ${VERSION}: 29 extensions offered, ${view.loaded.length} modules loaded`);
  check(entry(view, 'redis').installed && entry(view, 'redis').base && entry(view, 'mysql').installed,
    'redis and mysql are loaded, and come with PHP');

  // ------------------------------------------------ what is refused
  let answer = await api(admin, 'POST', `/maintenance/php-versions/${VERSION}/extensions/redis/remove`);
  check(answer.status() === 400 && /does not remove it/.test(await answer.text()), `the base set is not removed (${answer.status()})`);
  if (entry(view, 'igbinary').installed) {
    answer = await api(admin, 'POST', `/maintenance/php-versions/${VERSION}/extensions/igbinary/remove`);
    const text = await answer.text();
    check(answer.status() === 400 && new RegExp(`would also remove php${VERSION.replace('.', '\\.')}-redis`).test(text),
      `igbinary is refused: redis is built on it (${text.slice(0, 120)})`);
    check(entry(await extensions(), 'igbinary').installed && entry(await extensions(), 'redis').installed, 'and both are still loaded');
  }
  answer = await api(admin, 'POST', `/maintenance/php-versions/${VERSION}/extensions/nosuch/install`);
  check(answer.status() === 404, `nothing outside the catalogue (${answer.status()})`);
  answer = await api(admin, 'GET', '/maintenance/php-versions/7.4/extensions');
  check(answer.status() === 404, `a version that is not installed (${answer.status()})`);
  const users = await (await api(admin, 'GET', '/users?usage=0')).json();
  const old = (users.items || users).find((u) => u.username === NAME);
  if (old) await api(admin, 'DELETE', `/users/${old.id}`);
  await api(admin, 'POST', '/users', { username: NAME, email: `${NAME}@example.invalid`, password: PASSWORD, role: 'end_user', website_limit: 1, storage_limit_mb: 100 });
  const customer = await browser.newContext({ ignoreHTTPSErrors: true });
  await customer.request.post(`${BASE}/api/auth/login`, { form: { username: NAME, password: PASSWORD } });
  answer = await customer.request.get(`${BASE}/api/maintenance/php-versions/${VERSION}/extensions`);
  check(answer.status() === 403, `a customer is kept out (${answer.status()})`);

  // ------------------------------------------------ installed and removed from the page
  if (hadMemcached) await api(admin, 'POST', `/maintenance/php-versions/${VERSION}/extensions/memcached/remove`);
  const page = await admin.newPage();
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('dialog', (d) => d.accept());
  await page.goto(`${BASE}/php`, { waitUntil: 'networkidle' });
  await page.getByLabel('PHP version').selectOption(VERSION);
  // The default version's list shows first; this version's replaces it.
  await page.getByRole('heading', { name: `Extensions of PHP ${VERSION}` }).waitFor({ timeout: 20000 });
  const card = page.locator('#php-ext-memcached');
  await card.getByText('Not installed').waitFor({ timeout: 20000 });
  check(await page.getByRole('heading', { name: `Extensions of PHP ${VERSION}` }).isVisible()
    && await card.getByText('Not installed').isVisible(), `the page lists memcached for PHP ${VERSION}, not installed`);
  check(await page.locator('#php-ext-redis').getByText('Comes with PHP').isVisible()
    && await page.locator('#php-ext-redis').getByRole('button').count() === 0, 'redis comes with PHP: no button to remove it');
  await page.screenshot({ path: `${OUT}/before-light-en.png`, fullPage: true });
  const started = Date.now();
  await card.getByRole('button', { name: 'Install memcached' }).click();
  await card.getByText('Installed', { exact: true }).waitFor({ timeout: 300000 });
  view = await extensions();
  check(entry(view, 'memcached').installed && view.loaded.includes('memcached'),
    `installed from the page: PHP ${VERSION} loads memcached (${Math.round((Date.now() - started) / 1000)} s)`);
  await page.screenshot({ path: `${OUT}/installed-light-en.png`, fullPage: true });
  await card.getByRole('button', { name: 'Remove memcached' }).click();
  await card.getByText('Not installed').waitFor({ timeout: 300000 });
  view = await extensions();
  check(!entry(view, 'memcached').installed && entry(view, 'redis').installed, 'removed from the page: gone, and redis still loaded');
  // What came in with it went with it: memcached brings msgpack.
  if (!loadedBefore.includes('msgpack')) {
    check(!view.loaded.includes('msgpack') && view.loaded.length === loadedBefore.length,
      `msgpack, installed with memcached, went with it: PHP ${VERSION} loads what it did before (${view.loaded.length} modules)`);
  }

  check(errors.length === 0, `no page errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} catch (err) {
  ok = false;
  console.log(`FAIL  ${err.message.split('\n')[0]}`);
} finally {
  const view = await extensions().catch(() => null);
  if (view && entry(view, 'memcached')?.installed && !hadMemcached) await api(admin, 'POST', `/maintenance/php-versions/${VERSION}/extensions/memcached/remove`);
  const users = await (await api(admin, 'GET', '/users?usage=0')).json().catch(() => []);
  const probe = (users.items || users).find((u) => u.username === NAME);
  if (probe) await api(admin, 'DELETE', `/users/${probe.id}`);
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
