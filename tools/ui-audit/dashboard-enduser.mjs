// The dashboard as a customer sees it.
//
//     node dashboard-enduser.mjs [out-dir]
//
// Creates a throwaway end user (random password, 100 MB, no websites),
// signs in as it and checks that
//   - its tiles are exactly its sidebar's pages - no administration pages;
//   - it gets its storage quota as a card, and no server figures;
//   - with no website yet, the first-run prompt is there and leads to Websites;
// saves screenshots, then deletes the user again - also when a check fails.
import { chromium } from 'playwright';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/dashboard';
const USERNAME = 'uiprobe';
mkdirSync(OUT, { recursive: true });

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };

const browser = await chromium.launch();
const admin = await browser.newContext({ ignoreHTTPSErrors: true });
await logIn(admin);
const csrf = (await admin.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
const adminApi = (method, path, data) => admin.request.fetch(`${BASE}/api${path}`, {
  method, data, headers: csrf ? { 'X-CSRF-Token': csrf } : {},
});

async function removeProbe() {
  const users = await (await adminApi('GET', '/users')).json();
  const probe = (users.items || users).find((u) => u.username === USERNAME);
  if (!probe) return true;
  const res = await adminApi('DELETE', `/users/${probe.id}`);
  return res.ok();
}

check(await removeProbe(), `no ${USERNAME} left over from an earlier run`);
const password = randomBytes(18).toString('base64url');
const created = await adminApi('POST', '/users', {
  username: USERNAME, email: `${USERNAME}@example.invalid`, password,
  role: 'end_user', package_id: null, website_limit: 1, storage_limit_mb: 100,
});
check(created.ok(), `created ${USERNAME} (HTTP ${created.status()})`);

try {
  for (const [theme, locale, width, height] of [['light', 'en', 1440, 900], ['dark', 'vi', 1440, 900], ['light', 'en', 390, 844]]) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width, height }, locale: 'en-US' });
    await context.addInitScript(([t, l]) => {
      try { localStorage.setItem('snpanel-theme', t); localStorage.setItem('snpanel-locale', l); } catch {}
    }, [theme, locale]);
    const login = await context.request.post(`${BASE}/api/auth/login`, { form: { username: USERNAME, password } });
    check(login.status() === 200, `${USERNAME} signs in (HTTP ${login.status()})`);
    const page = await context.newPage();
    const errors = [];
    page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    page.on('pageerror', (e) => errors.push(String(e)));
    await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
    await page.waitForSelector('.dash-group');
    await page.waitForTimeout(500);

    if (theme === 'light' && width === 1440) {
      const groups = await page.$$eval('.dash-group', (gs) => gs.map((g) => ({
        title: g.querySelector('.dash-group-title').textContent,
        tiles: [...g.querySelectorAll('.dash-tile')].map((a) => a.textContent),
      })));
      for (const g of groups) console.log(`      ${g.title}: ${g.tiles.join(', ')}`);
      const toggle = page.locator('.sidebar-group-toggle');
      if ((await toggle.getAttribute('aria-expanded')) === 'false') await toggle.click();
      const sidebar = (await page.$$eval('.sidebar-nav > button, .sidebar-subnav > button', (bs) => bs.map((b) => b.textContent)))
        .filter((l) => l !== 'Dashboard');
      const tiles = groups.flatMap((g) => g.tiles);
      check(sidebar.length > 0 && sidebar.every((l) => tiles.includes(l)) && tiles.every((l) => sidebar.includes(l)),
        `the tiles are exactly the sidebar's ${sidebar.length} pages (${sidebar.join(', ')})`);
      check(!groups.some((g) => g.title === 'Administration'), 'no Administration group');
      for (const adminOnly of ['Firewall', 'PHP config', 'Panel users', 'Updates', 'Malware Scanner']) {
        check(!tiles.includes(adminOnly), `no ${adminOnly} tile`);
      }

      const cards = await page.$$eval('.resource-card', (cs) => cs.map((c) => ({
        label: c.querySelector('.resource-head span:last-child').textContent,
        value: c.querySelector('strong').textContent,
        detail: c.querySelector('small').textContent,
        bar: !!c.querySelector('.resource-track'),
      })));
      console.log(`      cards: ${JSON.stringify(cards)}`);
      check(cards.length === 1 && cards[0].label === 'Storage', 'one card, the storage quota; no server figures');
      check(cards[0]?.bar && /%$/.test(cards[0].value) && /\/ 100 MB$/.test(cards[0].detail),
        `the quota card shows a share of 100 MB (${cards[0]?.value}, ${cards[0]?.detail})`);

      const prompt = page.locator('.dash-first-run');
      check(await prompt.isVisible(), 'a new account gets the first-run prompt');
      await prompt.getByRole('button', { name: 'Add domain' }).click();
      await page.waitForURL(/\/website$/);
      check(true, 'Add domain opens Websites');
    }
    check(errors.length === 0, `${theme} ${locale} ${width}px: no console errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
    if (!(theme === 'light' && width === 1440)) {
      await page.screenshot({ path: `${OUT}/enduser-${theme}-${locale}-${width}.png`, fullPage: true });
    } else {
      await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
      await page.waitForSelector('.dash-group');
      await page.waitForTimeout(400);
      await page.screenshot({ path: `${OUT}/enduser-${theme}-${locale}-${width}.png`, fullPage: true });
    }
    await context.close();
  }
} finally {
  check(await removeProbe(), `${USERNAME} deleted again`);
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
