// The dashboard as a customer sees it.
//
//     node dashboard-enduser.mjs [out-dir]
//
// Creates a throwaway end user (random password, one website, 100 MB, no
// two-step verification), signs in as it and checks that
//   - it gets its package's usage - websites, databases, storage - and no
//     server figures;
//   - its three cards are SSL, WAF and two-step verification, the last one
//     amber while the authenticator app is off;
//   - "Needs attention" says two-step verification is off, with the way to
//     Account security;
//   - its quick actions include New website and SFTP accounts (the SFTP
//     page) and no
//     administrator's action;
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
    await page.waitForSelector('.dash-cards:not(.skeleton) .dash-card');
    await page.waitForTimeout(500);

    if (theme === 'light' && width === 1440) {
      const usage = await page.$$eval('.dash-usage .resource-card', (cs) => cs.map((c) => c.querySelector('.resource-head span:last-child').textContent));
      check(JSON.stringify(usage) === JSON.stringify(['Websites', 'Databases', 'Storage']), `the package's usage: ${usage.join(', ')}`);
      check(await page.locator('.resource-card', { hasText: 'CPU' }).count() === 0, 'no server figures');
      const cards = await page.$$eval('.dash-card', (cs) => cs.map((c) => ({ label: c.querySelector('.dash-card-label').textContent, tone: c.dataset.tone })));
      check(JSON.stringify(cards.map((c) => c.label)) === JSON.stringify(['SSL', 'WAF', 'Two-step verification']), `three cards: ${cards.map((c) => `${c.label} [${c.tone}]`).join(', ')}`);
      check(cards.find((c) => c.label === 'Two-step verification')?.tone === 'warn', 'two-step verification off is amber');
      const attention = page.locator('.dash-attention-list li', { hasText: 'Two-step verification is off' });
      check(await attention.count() === 1 && (await attention.locator('a').getAttribute('href')) === '/security', 'needs attention: two-step verification is off, with the way to Account security');
      const actions = await page.$$eval('.dash-action', (as) => as.map((a) => a.textContent));
      check(actions.includes('New website') && actions.includes('SFTP accounts'), `quick actions: ${actions.join(', ')}`);
      for (const adminOnly of ['Panel users', 'New SFTP account']) check(!actions.includes(adminOnly), `no ${adminOnly}`);
    }
    const sideways = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    check(sideways <= 0, `${theme} ${locale} ${width}px: no sideways scroll (${sideways}px over)`);
    check(errors.length === 0, `${theme} ${locale} ${width}px: no console errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
    await page.screenshot({ path: `${OUT}/enduser-${theme}-${locale}-${width}.png`, fullPage: true });
    await context.close();
  }
} finally {
  check(await removeProbe(), `${USERNAME} deleted again`);
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
