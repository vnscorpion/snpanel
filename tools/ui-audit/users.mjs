// Panel users: the list first, each storage figure after it.
//
//     node users.mjs [out-dir]
//
// As the administrator, checks that
//   - the page asks for the list without figures (`/users?usage=0`), and the
//     list is on screen while every figure is still held back, each row
//     saying it is measuring;
//   - once the figures are let through, every row shows its own, fetched
//     from `/users/{id}/usage`;
//   - `?usage=0` leaves the figures null and keeps the limits, and
//     `/users/{id}/usage` gives the figure the full list gives - timing both
//     with the cache emptied by a restart, for the record;
//   - no console errors, no sideways scroll;
// and saves screenshots in both themes and both languages.
//
// Restarts snpanel-rust.service once, to empty the API's usage cache.
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/users';
mkdirSync(OUT, { recursive: true });

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const browser = await chromium.launch();

async function newContext({ theme = 'light', locale = 'en', viewport = { width: 1440, height: 900 } } = {}) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport, locale: 'en-US' });
  await context.addInitScript(([t, l]) => {
    try { localStorage.setItem('snpanel-theme', t); localStorage.setItem('snpanel-locale', l); } catch {}
  }, [theme, locale]);
  await logIn(context);
  return context;
}

// ---------------------------------------------------------------- cold timing
execFileSync('systemctl', ['restart', 'snpanel-rust.service']);
for (let i = 0; i < 40; i += 1) {
  try { execFileSync('curl', ['-sfk', '-o', '/dev/null', `${BASE}/api/panel-settings/public`]); break; } catch { await new Promise((r) => setTimeout(r, 500)); }
}
{
  const context = await newContext();
  const time = async (path) => {
    const started = performance.now();
    const res = await context.request.get(`${BASE}/api${path}`);
    const body = await res.json();
    return { ms: performance.now() - started, body };
  };
  const quick = await time('/users?usage=0');
  const full = await time('/users');
  const warm = await time('/users');
  console.log(`      cold: ?usage=0 ${quick.ms.toFixed(0)} ms, with figures ${full.ms.toFixed(0)} ms; warm with figures ${warm.ms.toFixed(0)} ms`);
  check(quick.body.every((u) => u.storage_used_bytes === null && u.storage_percent === null && 'storage_limit_bytes' in u),
    `?usage=0 leaves the figures null and keeps the limits (${quick.body.length} users)`);
  check(full.body.every((u) => typeof u.storage_used_bytes === 'number'), 'without it, the list is the old one, figures and all');
  // Reported, not asserted: on a box whose accounts hold a few kilobytes the
  // walk is instant and the two times are noise. What is asserted is that
  // the page does not wait for it - below, with every figure held back.
  const one = await (await context.request.get(`${BASE}/api/users/${quick.body[0].id}/usage`)).json();
  const same = full.body.find((u) => u.id === one.id);
  check(one.storage_used_bytes === same.storage_used_bytes && one.storage_limit_bytes === same.storage_limit_bytes,
    `/users/{id}/usage gives the list's figure (${one.storage_used_bytes} bytes)`);
  await context.close();
}

// ---------------------------------------------------------------- list first
{
  const context = await newContext();
  const page = await context.newPage();
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(String(e)));
  const listUrls = [];
  page.on('request', (r) => { if (/\/api\/users(\?|$)/.test(r.url())) listUrls.push(new URL(r.url()).search); });

  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let held = 0;
  await page.route(/\/api\/users\/\d+\/usage$/, async (route) => { held += 1; await gate; await route.continue(); });

  await page.goto(`${BASE}/users`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('.user-row', { timeout: 15000 });
  await page.waitForTimeout(500);
  const rows = await page.locator('.user-row').count();
  const measuring = await page.locator('.user-row .usage-pending').count();
  check(listUrls.length > 0 && listUrls.every((q) => q === '?usage=0'), `the page asks for the list without figures (${listUrls.join(', ')})`);
  check(rows > 0 && measuring === rows, `the list is on screen while every figure is held back (${rows} users, ${measuring} measuring, ${held} figure requests waiting)`);
  await page.screenshot({ path: `${OUT}/measuring-light-en-1440.png`, fullPage: true });

  release();
  await page.waitForFunction(() => document.querySelectorAll('.usage-pending').length === 0, null, { timeout: 30000 });
  const figures = await page.locator('.user-row .user-metric').allTextContents();
  check(figures.length === rows && figures.every((f) => /\d/.test(f)), `then every row shows its figure (${figures.join(' | ')})`);
  check(errors.length === 0, `no console errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
  await context.close();
}

// ---------------------------------------------------------------- looks
for (const theme of ['light', 'dark']) {
  for (const locale of ['en', 'vi']) {
    for (const [width, height] of [[1440, 900], [390, 844]]) {
      const context = await newContext({ theme, locale, viewport: { width, height } });
      const page = await context.newPage();
      const errors = [];
      page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
      await page.goto(`${BASE}/users`, { waitUntil: 'networkidle' });
      await page.waitForFunction(() => document.querySelectorAll('.user-row').length > 0 && document.querySelectorAll('.usage-pending').length === 0, null, { timeout: 30000 });
      const sideways = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      check(sideways <= 0 && errors.length === 0, `${theme} ${locale} ${width}px: no sideways scroll (${sideways}px), no console errors`);
      await page.screenshot({ path: `${OUT}/${theme}-${locale}-${width}.png`, fullPage: true });
      await context.close();
    }
  }
}

await browser.close();
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
