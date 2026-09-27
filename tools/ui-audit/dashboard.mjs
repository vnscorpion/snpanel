// The dashboard as the administrator sees it: how things are, not where.
//
//     node dashboard.mjs [out-dir]
//
// Checks that
//   - there are eight status cards - Websites, SSL, Databases, Backups,
//     Firewall, WAF, Malware, Services - each a link to its page, each
//     coloured ok, warn or bad, and that the colours agree with what
//     /api/dashboard/summary says;
//   - "Needs attention" lists the worst first, each with a link, or says
//     everything is fine;
//   - "New website" lands on the Websites page with the create form open and
//     its domain field focused, and the ?new=1 it came with is gone;
//   - a card is reached by Tab, shows it is focused, and Enter opens its page
//     without a reload; a Ctrl-click opens a new tab instead;
//   - at 1440, 1024, 768 and 390px, in both themes and both languages, the
//     page never scrolls sideways and logs no console errors;
// and saves a screenshot per width, theme and language to out-dir.
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/dashboard';
const WIDTHS = [[1440, 900], [1024, 768], [768, 1024], [390, 844]];
const CARDS = ['Websites', 'SSL', 'Databases', 'Backups', 'Firewall', 'WAF', 'Malware', 'Services'];
const RANK = { bad: 0, warn: 1, info: 2 };
mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch();
let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };

async function openDashboard({ theme = 'light', locale = 'en', viewport = { width: 1440, height: 900 } } = {}) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport, locale: 'en-US' });
  await context.addInitScript(([t, l]) => {
    try { localStorage.setItem('snpanel-theme', t); localStorage.setItem('snpanel-locale', l); } catch {}
  }, [theme, locale]);
  await logIn(context);
  const page = await context.newPage();
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.dash-cards:not(.skeleton) .dash-card');
  await page.waitForTimeout(500);
  return { context, page, errors };
}

// ------------------------------------------------------------ in English, 1440
{
  const { context, page, errors } = await openDashboard();
  const summary = await (await context.request.get(`${BASE}/api/dashboard/summary`)).json();
  const cards = await page.$$eval('.dash-card', (cs) => cs.map((c) => ({
    label: c.querySelector('.dash-card-label').textContent,
    tone: c.dataset.tone,
    href: c.getAttribute('href'),
    value: c.querySelector('.dash-card-value').textContent,
  })));
  for (const c of cards) console.log(`      ${c.label}: ${c.value} [${c.tone}] -> ${c.href}`);
  check(JSON.stringify(cards.map((c) => c.label)) === JSON.stringify(CARDS), `the eight cards, in order (${cards.map((c) => c.label).join(', ')})`);
  check(cards.every((c) => ['ok', 'warn', 'bad'].includes(c.tone) && c.href?.startsWith('/')), 'each is a link, coloured ok, warn or bad');
  const tone = (label) => cards.find((c) => c.label === label)?.tone;
  const stopped = summary.services?.stopped || [];
  check(tone('Services') === (stopped.length ? 'bad' : 'ok'), `Services is ${tone('Services')} with ${stopped.length} stopped`);
  const fw = summary.firewall || {};
  const fwWant = fw.state === 'enabled' ? (fw.chain_active === false ? 'warn' : 'ok') : fw.state === 'disabled' ? 'bad' : 'warn';
  check(tone('Firewall') === fwWant, `Firewall is ${tone('Firewall')} for state ${fw.state}`);
  const withSsl = summary.websites?.with_ssl || 0;
  check(tone('SSL') === (withSsl < (summary.websites?.total || 0) ? 'warn' : 'ok'), `SSL is ${tone('SSL')} with ${withSsl}/${summary.websites?.total}`);
  check(tone('Malware') === ({ threats: 'bad', clean: 'ok' }[summary.malware?.state] || 'warn'), `Malware is ${tone('Malware')} for ${summary.malware?.state}`);

  const items = await page.$$eval('.dash-attention-list li', (lis) => lis.map((li) => ({
    tone: li.dataset.tone, text: li.querySelector('.dash-attention-text').textContent, href: li.querySelector('a')?.getAttribute('href'),
  })));
  const allGood = await page.locator('.dash-all-good').count();
  for (const i of items) console.log(`      [${i.tone}] ${i.text} -> ${i.href}`);
  check(items.length > 0 || allGood === 1, `needs attention: ${items.length} item(s)${allGood ? ', or everything is fine' : ''}`);
  check(items.every((i, n) => n === 0 || RANK[items[n - 1].tone] <= RANK[i.tone]), 'the worst first');
  check(items.every((i) => i.href?.startsWith('/')), 'each with the way to the page that fixes it');

  // Keyboard: Tab reaches a card, shows it, and Enter opens the page in place.
  const first = page.locator('.dash-card').first();
  await first.focus();
  await page.keyboard.press('Tab');
  // After the card's .15s transition: at once the shadow is still nothing.
  await page.waitForTimeout(300);
  const focus = await page.evaluate(() => {
    const el = document.activeElement;
    return { card: el?.classList.contains('dash-card'), ring: getComputedStyle(el).boxShadow };
  });
  check(focus.card && /\b3px\b/.test(focus.ring), `Tab reaches the next card and it shows a 3px ring (${focus.ring})`);
  await page.evaluate(() => { window.__sameDocument = true; });
  await page.keyboard.press('Enter');
  await page.waitForURL(/\/ssl$/);
  check(await page.evaluate(() => window.__sameDocument === true), 'Enter on a card opens its page, no reload');

  // New website: the form, open, with the domain field focused.
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.dash-action');
  await page.locator('.dash-action', { hasText: /^New website$/ }).click();
  await page.waitForURL(/\/website(\?new=1)?$/);
  await page.waitForTimeout(400);
  const landed = await page.evaluate(() => ({
    search: window.location.search,
    focused: document.activeElement?.getAttribute('placeholder'),
  }));
  check(landed.focused === 'domain.com' && landed.search === '', `New website opens the create form, domain focused (${landed.focused}), ?new=1 gone (${landed.search || 'none'})`);

  // Ctrl-click: a new tab, and the dashboard stays.
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.dash-card');
  const [tab] = await Promise.all([
    context.waitForEvent('page'),
    page.locator('.dash-card', { hasText: 'Databases' }).click({ modifiers: ['Control'] }),
  ]);
  await tab.waitForLoadState('domcontentloaded');
  check(tab.url().endsWith('/database') && new URL(page.url()).pathname === '/', `Ctrl-click opens a new tab (${new URL(tab.url()).pathname}) and leaves the dashboard`);
  check(errors.length === 0, `no console errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
  await context.close();
}

// ----------------------------------------------------- widths, themes, languages
for (const theme of ['light', 'dark']) {
  for (const locale of ['en', 'vi']) {
    for (const [width, height] of WIDTHS) {
      const { context, page, errors } = await openDashboard({ theme, locale, viewport: { width, height } });
      const sideways = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      const columns = await page.$eval('.dash-cards', (el) => getComputedStyle(el).gridTemplateColumns.split(' ').length);
      check(sideways <= 0, `${theme} ${locale} ${width}px: no sideways scroll (${sideways}px over); cards in ${columns} column(s)`);
      if (errors.length) check(false, `${theme} ${locale} ${width}px: console errors: ${errors.join(' | ')}`);
      await page.screenshot({ path: `${OUT}/admin-${theme}-${locale}-${width}.png`, fullPage: true });
      await context.close();
    }
  }
}

await browser.close();
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
