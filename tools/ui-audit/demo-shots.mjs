// The README's screenshots: the main pages of a panel with demo data, in
// English and in Vietnamese, light theme, 1440 x 900 - and the dashboard on
// a phone.
//
//     node demo-shots.mjs [out-dir] [page ...]     (LOGIN_FILE: the administrator's)
//
// The browser opens the panel as https://panel.example.com:<port> - the name
// mapped to the test machine's address inside Chromium alone - so no
// picture shows the machine's own address. Writes <out-dir>/<locale>/<name>.png.
// Toasts and the loading bar are hidden before each picture; nothing is
// changed on the panel.
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/demo-shots';
const ONLY = process.argv.slice(3);
const HOST = 'panel.example.com';
const real = new URL(BASE);
const SHOWN = `https://${HOST}:${real.port || 443}`;

// The site a page opens on, picked from the first list that offers it.
const pickSite = (domain) => async (page) => {
  const list = page.locator('select').filter({ has: page.locator('option', { hasText: domain }) }).first();
  await list.selectOption({ label: domain });
  await page.waitForTimeout(1500);
};
const PAGES = [
  // The dashboard's figures settle once the browser has stopped loading.
  ['dashboard', '/', async (page) => { await page.waitForTimeout(12000); }],
  ['websites', '/website'],
  ['files', '/filemanager', pickSite('blog.example.com')],
  ['databases', '/database'],
  ['backups', '/backups', pickSite('shop.example.com')],
  ['settings', '/settings'],
  ['php', '/php'],
  ['firewall', '/firewall'],
  ['waf', '/waf'],
  ['malware', '/malware'],
  ['notifications', '/notifications'],
  ['ai-assistants', '/ai-assistants'],
];

const browser = await chromium.launch({ args: [`--host-resolver-rules=MAP ${HOST} ${real.hostname}`] });
async function shoot(locale, width, height, pages) {
  mkdirSync(`${OUT}/${locale}`, { recursive: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width, height }, locale: 'en-US' });
  await context.addInitScript((l) => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', l); } catch {} }, locale);
  await logIn(context);
  // The session signed in at the machine's address, carried over to the name.
  const cookies = await context.cookies(BASE);
  await context.addCookies(cookies.map(({ name, value, path, expires, httpOnly, secure, sameSite }) => ({
    name, value, domain: HOST, path, expires, httpOnly, secure, sameSite,
  })));
  const page = await context.newPage();
  for (const [name, path, prepare] of pages) {
    await page.goto(`${SHOWN}${path}`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(1500);
    if (prepare) await prepare(page);
    await page.evaluate(() => {
      document.querySelectorAll('.app-toast-stack, .loading').forEach((el) => { el.style.display = 'none'; });
      window.scrollTo(0, 0);
    });
    const file = `${OUT}/${locale}/${name}${width < 800 ? '-phone' : ''}.png`;
    await page.screenshot({ path: file });
    console.log(`saved ${file}`);
  }
  await context.close();
}

const wanted = ONLY.length ? PAGES.filter(([name]) => ONLY.includes(name)) : PAGES;
for (const locale of ['en', 'vi']) {
  await shoot(locale, 1440, 900, wanted);
  if (!ONLY.length || ONLY.includes('dashboard')) await shoot(locale, 390, 844, [PAGES[0]]);
}
await browser.close();
