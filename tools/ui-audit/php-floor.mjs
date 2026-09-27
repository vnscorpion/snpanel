// The PHP Configuration floor, through the API, as the administrator:
//   - each limit one below its floor is a 422 naming that field;
//   - the floor itself saves, and a lowercase size is saved capitalised;
//   - the page marks a value below the floor and will not save it.
//
//     node php-floor.mjs [php-version]
//
// It leaves the version's config at the floor values, which are the defaults.
import { chromium } from 'playwright';
import { BASE, logIn } from './capture.mjs';

const VERSION = process.argv[2] || '8.4';
let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };

const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
await context.addInitScript(() => { try { localStorage.setItem('snpanel-locale', 'en'); } catch {} });
await logIn(context);
const csrf = (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
const headers = { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) };

const FLOOR = {
  php_version: VERSION, display_errors: 'Off',
  max_execution_time: 300, max_input_time: 600, max_input_vars: 10000,
  memory_limit: '1024M', post_max_size: '1024M', upload_max_filesize: '1024M',
};
const save = async (body) => {
  const res = await context.request.post(`${BASE}/api/maintenance/php-config`, { headers, data: JSON.stringify(body) });
  return { status: res.status(), body: await res.json().catch(() => ({})) };
};

for (const [field, low] of [
  ['max_execution_time', 299], ['max_input_time', 599], ['max_input_vars', 9999],
  ['memory_limit', '512M'], ['post_max_size', '1023M'], ['upload_max_filesize', '1048575K'],
]) {
  const { status, body } = await save({ ...FLOOR, [field]: low });
  const item = Array.isArray(body.detail) ? body.detail[0] : null;
  check(status === 422 && item?.loc?.[1] === field && /greater than or equal to/.test(item?.msg || ''),
    `${field} = ${low} is refused (${status} ${item?.msg || JSON.stringify(body).slice(0, 80)})`);
}

const atFloor = await save(FLOOR);
check(atFloor.status === 200, `the floor itself saves (${atFloor.status})`);
const lower = await save({ ...FLOOR, memory_limit: '2g' });
check(lower.status === 200, `a lowercase size saves (${lower.status} ${JSON.stringify(lower.body).slice(0, 80)})`);
const read = await (await context.request.get(`${BASE}/api/maintenance/php-config?php_version=${VERSION}`)).json();
check(read.memory_limit === '2G', `... and is written as 2G (${read.memory_limit})`);
await save(FLOOR);

// The page: a value below the floor is marked, and Save will not send it.
const page = await context.newPage();
await page.goto(`${BASE}/php`, { waitUntil: 'networkidle' });
await page.waitForTimeout(600);
const memory = page.locator('label.php-limit', { hasText: 'memory_limit' }).locator('input');
await memory.fill('256M');
check(await memory.getAttribute('aria-invalid') === 'true', 'memory_limit 256M is marked invalid');
check(await page.getByRole('button', { name: 'Save', exact: true }).isDisabled(), 'Save is disabled while it is');
const note = await page.locator('#php-limit-memory_limit').textContent();
check(/1024M/.test(note || ''), `its note names the floor (${note})`);
await memory.fill('1024M');
check(!(await page.getByRole('button', { name: 'Save', exact: true }).isDisabled()), 'Save is enabled again at 1024M');

await browser.close();
console.log(ok ? 'ALL PASS' : 'SOME CHECKS FAILED');
process.exit(ok ? 0 : 1);
