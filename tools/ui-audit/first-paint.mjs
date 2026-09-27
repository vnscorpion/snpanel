// The theme and the language are right before the app has loaded.
//
//     node first-paint.mjs
//
// The app bundle is held back, so what the page shows is only what arrived
// before it. A user who chose dark mode must already be in dark mode then -
// otherwise the page paints light and flips once the app mounts. And no page
// may log the Content-Security-Policy refusing a script.
import { chromium } from 'playwright';
import { BASE } from './capture.mjs';

const browser = await chromium.launch();
let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= cond; };

for (const [theme, locale] of [['dark', 'vi'], ['light', 'en']]) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.addInitScript(([t, l]) => {
    try { localStorage.setItem('snpanel-theme', t); localStorage.setItem('snpanel-locale', l); } catch {}
  }, [theme, locale]);
  const page = await context.newPage();
  const csp = [];
  page.on('console', (m) => { if (m.type() === 'error' && /Content Security Policy/.test(m.text())) csp.push(m.text()); });

  let held = false;
  await page.route(/\/assets\/index-[^/]+\.js$/, async (route) => {
    held = true;
    await new Promise((r) => setTimeout(r, 2000));
    await route.continue();
  });
  await page.goto(`${BASE}/`, { waitUntil: 'commit' });
  await page.waitForTimeout(500); // the app is still being held back
  const early = await page.evaluate(() => ({
    theme: document.documentElement.getAttribute('data-theme'),
    lang: document.documentElement.lang,
    mounted: document.getElementById('root')?.childElementCount > 0,
  }));
  check(held && !early.mounted, `${theme}/${locale}: the app has not mounted yet (${held ? 'bundle held back' : 'bundle never requested'})`);
  check(early.theme === theme, `${theme}/${locale}: data-theme is "${theme}" before the app loads (got ${early.theme})`);
  check(early.lang === locale, `${theme}/${locale}: lang is "${locale}" before the app loads (got ${early.lang})`);

  await page.waitForLoadState('networkidle');
  check(csp.length === 0, `${theme}/${locale}: no Content-Security-Policy error`);
  await context.close();
}

await browser.close();
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
