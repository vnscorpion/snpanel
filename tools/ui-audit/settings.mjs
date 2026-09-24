// Panel settings: four tabs, with the API tokens as the fourth.
//
//     node settings.mjs [out-dir]
//
// As the administrator, checks that
//   - the sidebar has no API Tokens entry and the dashboard no tile for it;
//   - /settings opens on General; the tokens tab moves the address to
//     /api-tokens, and /api-tokens and /api-token open on the tokens tab -
//     with Panel settings still the highlighted entry and the page title;
//   - a token can be created (shown once, then hidden), is listed with its
//     allowed address, and can be revoked from its row;
//   - no console errors, no sideways scroll;
// and saves screenshots of the General and API tokens tabs in both themes and
// both languages. No screenshot is taken while a new token is on screen.
//
// It creates one token, "uiprobe-token", and revokes it again.
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/settings';
mkdirSync(OUT, { recursive: true });
const TOKEN = 'uiprobe-token';
const TOKEN_IP = '203.0.113.9';

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const browser = await chromium.launch();

async function open(path, { theme = 'light', locale = 'en', viewport = { width: 1440, height: 900 } } = {}) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport, locale: 'en-US' });
  await context.addInitScript(([t, l]) => {
    try { localStorage.setItem('snpanel-theme', t); localStorage.setItem('snpanel-locale', l); } catch {}
  }, [theme, locale]);
  await logIn(context);
  const page = await context.newPage();
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(`${BASE}${path}`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.settings-tabs');
  await page.waitForTimeout(300);
  return { context, page, errors };
}
const selectedTab = (page) => page.locator('.settings-tabs [role="tab"][aria-selected="true"]').textContent();
const title = (page) => page.locator('.page-title h1').textContent();
const current = (page) => page.locator('.sidebar [aria-current="page"]').textContent();

const { context, page, errors } = await open('/settings');
try {
  // ---------------------------------------------------------------- where it is
  const toggle = page.locator('.sidebar-group-toggle');
  if ((await toggle.getAttribute('aria-expanded')) === 'false') await toggle.click();
  const sidebar = await page.$$eval('.sidebar-nav button', (bs) => bs.map((b) => b.textContent.trim()));
  check(!sidebar.includes('API Tokens'), 'the sidebar has no API Tokens entry');
  check(await page.getByRole('tab').count() === 4, `four tabs (${(await page.getByRole('tab').allTextContents()).join(', ')})`);
  check(await selectedTab(page) === 'General' && new URL(page.url()).pathname === '/settings', '/settings opens on General');
  // The selected tab under the pointer keeps a readable label.
  const selected = page.locator('.settings-tabs [role="tab"][aria-selected="true"]');
  await selected.hover();
  await page.waitForTimeout(300);
  const [fg, bg] = await selected.evaluate((el) => { const s = getComputedStyle(el); return [s.color, s.backgroundColor]; });
  check(fg !== bg, `the selected tab stays readable under the pointer (${fg} on ${bg})`);

  await page.getByRole('tab', { name: 'API tokens' }).click();
  await page.waitForURL(/\/api-tokens$/);
  check(await page.getByRole('tabpanel', { name: 'API tokens' }).isVisible(), 'the tokens tab shows the tokens, at /api-tokens');
  check(await title(page) === 'Panel settings' && await current(page) === 'Panel settings',
    `Panel settings stays the title and the highlighted entry (${await title(page)} / ${await current(page)})`);
  await page.getByRole('tab', { name: 'General' }).click();
  await page.waitForURL(/\/settings$/);
  check(await selectedTab(page) === 'General', 'General goes back to /settings');

  for (const path of ['/api-tokens', '/api-token']) {
    await page.goto(`${BASE}${path}`, { waitUntil: 'networkidle' });
    await page.waitForSelector('.settings-tabs');
    check(await selectedTab(page) === 'API tokens', `${path} opens on the tokens tab`);
  }

  // ---------------------------------------------------------------- a token
  const dialogs = [];
  page.on('dialog', (d) => { dialogs.push(d.message()); d.accept(); });
  const form = page.locator('.token-form');
  await form.getByLabel('Name').fill(TOKEN);
  await form.getByLabel('Allowed IPs').fill(TOKEN_IP);
  await form.getByRole('button', { name: 'Create token' }).click();
  const reveal = page.locator('.token-reveal');
  await reveal.waitFor({ timeout: 15000 });
  const secret = await reveal.locator('input').inputValue();
  check(secret.length >= 20, `the new token is shown once (${secret.length} characters)`);
  await reveal.getByRole('button', { name: 'Done' }).click();
  check(await reveal.count() === 0, 'and hidden again with Done');

  const row = page.locator('.data-table tbody tr', { hasText: TOKEN }).filter({ has: page.locator('.badge', { hasText: 'Active' }) }).first();
  await row.waitFor({ timeout: 15000 });
  const text = (await row.textContent()).replace(/\s+/g, ' ').trim();
  check(text.includes(TOKEN_IP) && text.includes('Never'), `it is listed with its allowed IP, never used (${text})`);
  await page.screenshot({ path: `${OUT}/tokens-with-one-light-en-1440.png`, fullPage: true });

  await row.getByRole('button', { name: `Revoke ${TOKEN}` }).click();
  await page.locator('.data-table tbody tr', { hasText: TOKEN }).filter({ has: page.locator('.badge', { hasText: 'Active' }) }).waitFor({ state: 'detached', timeout: 15000 });
  check(dialogs.some((m) => m.includes(`Revoke the API token ${TOKEN}?`)), 'revoking asks first, then the token is no longer active');

  // ---------------------------------------------------------------- the dashboard
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.dash-group');
  const admin = await page.locator('.dash-group', { hasText: 'Administration' }).locator('.dash-tile').allTextContents();
  check(!admin.includes('API Tokens') && admin.includes('Panel settings'), `no API Tokens tile on the dashboard (${admin.join(', ')})`);

  check(errors.length === 0, `no console errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} finally {
  // Whatever happened above: nothing named uiprobe-token stays active.
  const csrf = (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
  const tokens = await (await context.request.get(`${BASE}/api/provisioning/v1/tokens`)).json();
  for (const token of tokens.filter?.((x) => x.name === TOKEN && x.is_active) || []) {
    await context.request.delete(`${BASE}/api/provisioning/v1/tokens/${token.id}`, { headers: csrf ? { 'X-CSRF-Token': csrf } : {} });
  }
  await context.close();
}

// ---------------------------------------------------------------- looks
for (const theme of ['light', 'dark']) {
  for (const locale of ['en', 'vi']) {
    for (const [width, height] of [[1440, 900], [390, 844]]) {
      for (const path of ['/settings', '/api-tokens']) {
        const view = await open(path, { theme, locale, viewport: { width, height } });
        const sideways = await view.page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        check(sideways <= 0 && view.errors.length === 0, `${theme} ${locale} ${width}px ${path}: no sideways scroll (${sideways}px), no console errors`);
        // Every tab whole: no two overlapping, no label cut off.
        const tabs = await view.page.$$eval('.settings-tabs [role="tab"]', (els) => els.map((el) => {
          const r = el.getBoundingClientRect();
          return { x: r.left, y: r.top, w: r.width, h: r.height, cut: el.scrollWidth > el.clientWidth + 1 };
        }));
        const overlap = tabs.some((a, i) => tabs.some((b, j) => i < j
          && a.x < b.x + b.w - 1 && b.x < a.x + a.w - 1 && a.y < b.y + b.h - 1 && b.y < a.y + a.h - 1));
        check(!overlap && !tabs.some((tab) => tab.cut), `${theme} ${locale} ${width}px ${path}: four whole tabs`);
        await view.page.screenshot({ path: `${OUT}/${path.slice(1)}-${theme}-${locale}-${width}.png`, fullPage: true });
        await view.context.close();
      }
    }
  }
}

await browser.close();
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
