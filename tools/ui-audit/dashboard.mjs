// The dashboard: a map of the panel, grouped, six tiles to a row.
//
//     node dashboard.mjs [out-dir]
//
// As the administrator, checks that
//   - the tiles are exactly the sidebar's pages (less the dashboard itself),
//     plus one per installed addon, and each group is where it should be;
//   - a row holds six tiles at 1440px, fewer as the page narrows, and the
//     page never scrolls sideways;
//   - a click on a tile moves inside the panel without a reload, Enter on a
//     focused tile does the same, and a Ctrl-click opens a new tab instead;
//   - a focused tile shows that it is focused;
//   - the page logs no console errors;
// and saves a screenshot per width, theme and language to out-dir.
import { chromium } from 'playwright';
import { mkdirSync, writeFileSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/dashboard';
const WIDTHS = [[1440, 900], [1024, 768], [768, 1024], [390, 844]];
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
  await page.waitForSelector('.dash-group');
  await page.waitForTimeout(500);
  return { context, page, errors };
}

const readGroups = (page) => page.$$eval('.dash-group', (groups) => groups.map((g) => ({
  title: g.querySelector('.dash-group-title').textContent,
  tiles: [...g.querySelectorAll('.dash-tile')].map((a) => ({ label: a.textContent, href: a.getAttribute('href') })),
  columns: getComputedStyle(g.querySelector('.dash-grid')).gridTemplateColumns.split(' ').length,
})));

// ---------------------------------------------------------------- structure
{
  const { context, page, errors } = await openDashboard();
  const groups = await readGroups(page);
  for (const g of groups) console.log(`      ${g.title}: ${g.tiles.map((t) => t.label).join(', ')}`);

  // The sidebar, with its settings group opened so every entry is rendered.
  const toggle = page.locator('.sidebar-group-toggle');
  if ((await toggle.getAttribute('aria-expanded')) === 'false') await toggle.click();
  const sidebar = (await page.$$eval('.sidebar-nav > button, .sidebar-subnav > button', (bs) => bs.map((b) => b.textContent)))
    .filter((label) => label !== 'Dashboard');

  const addonsRoute = '/addons';
  const addonGroup = groups.find((g) => g.title === 'Addons');
  // An addon without a page of its own opens the Addons page; it has no
  // sidebar entry to match.
  const tiles = groups.flatMap((g) => g.tiles.filter((t) => !(g === addonGroup && t.href === addonsRoute)).map((t) => t.label));
  const missing = sidebar.filter((l) => !tiles.includes(l));
  const extra = tiles.filter((l) => !sidebar.includes(l));
  check(sidebar.length > 0 && missing.length === 0, `every sidebar page has a tile (${sidebar.length} pages; missing: ${missing.join(', ') || 'none'})`);
  check(extra.length === 0 || (addonGroup && extra.every((l) => addonGroup.tiles.some((t) => t.label === l))),
    `no tile outside the sidebar's pages (extra: ${extra.join(', ') || 'none'})`);
  check(new Set(tiles).size === tiles.length, 'no page has two tiles');

  const res = await context.request.get(`${BASE}/api/addons`);
  const installed = (await res.json()).items.filter((a) => a.installed);
  check((addonGroup?.tiles.length || 0) === installed.length,
    `one Addons tile per installed addon (${installed.map((a) => a.slug).join(', ') || 'none installed'}; tiles: ${addonGroup?.tiles.length || 0})`);

  const expectFirst = { Hosting: 'Websites', Security: 'Two-step verification', Server: 'PHP config', Administration: 'Panel users' };
  for (const [title, first] of Object.entries(expectFirst)) {
    const g = groups.find((x) => x.title === title);
    check(g && g.tiles[0].label === first, `the ${title} group starts with ${first}`);
  }
  check(groups.every((g) => g.columns === 6), `six tiles to a row at 1440px (${groups.map((g) => g.columns).join('/')})`);
  check(await page.locator('.stats-grid, .site-grid').count() === 0, 'the counters row and the quick overview are gone');

  // Keyboard: focus shows, and Enter follows the tile. Tab from the tile
  // before, so the focus arrives the way a keyboard user's does.
  const ssl = page.locator('.dash-tile', { hasText: /^SSL$/ });
  await page.locator('.dash-tile', { hasText: /^Websites$/ }).focus();
  await page.keyboard.press('Tab');
  const focus = await ssl.evaluate((el) => ({
    focused: document.activeElement === el,
    visible: el.matches(':focus-visible'),
    ring: getComputedStyle(el).boxShadow,
  }));
  check(focus.focused && focus.visible && focus.ring !== 'none', `Tab reaches the next tile and it shows a ring (${focus.ring})`);
  await page.evaluate(() => { window.__sameDocument = true; });
  await ssl.press('Enter');
  await page.waitForURL(/\/ssl$/);
  check(await page.evaluate(() => window.__sameDocument === true), 'Enter on a tile moves inside the panel, no reload');

  // Mouse: a plain click stays in the panel; Ctrl-click opens a new tab.
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.dash-group');
  await page.evaluate(() => { window.__sameDocument = true; });
  await page.locator('.dash-tile', { hasText: /^Websites$/ }).click();
  await page.waitForURL(/\/website$/);
  const h1 = await page.locator('.page-title h1').textContent();
  check(await page.evaluate(() => window.__sameDocument === true) && h1 === 'Websites', `a click opens the page in place (title: ${h1})`);

  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.dash-group');
  const [tab] = await Promise.all([
    context.waitForEvent('page'),
    page.locator('.dash-tile', { hasText: /^Database$/ }).click({ modifiers: ['Control'] }),
  ]);
  await tab.waitForLoadState('domcontentloaded');
  check(tab.url().endsWith('/database') && new URL(page.url()).pathname === '/', `Ctrl-click opens a new tab (${new URL(tab.url()).pathname}) and leaves the dashboard`);

  check(errors.length === 0, `no console errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
  writeFileSync(`${OUT}/aria-en.yml`, await page.locator('.dashboard').ariaSnapshot());
  await context.close();
}

// ----------------------------------------------------- widths, themes, languages
const columnsAt = {};
for (const theme of ['light', 'dark']) {
  for (const locale of ['en', 'vi']) {
    for (const [width, height] of WIDTHS) {
      const { context, page, errors } = await openDashboard({ theme, locale, viewport: { width, height } });
      const groups = await readGroups(page);
      const room = await page.$eval('.dash-groups', (el) => el.clientWidth);
      columnsAt[room] = groups[0].columns;
      const sideways = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      const tall = await page.evaluate(() => document.documentElement.scrollHeight);
      check(sideways <= 0, `${theme} ${locale} ${width}px: no sideways scroll (${sideways}px over); ${groups[0].columns} columns in ${room}px; page ${tall}px tall`);
      if (width === 1440) check(tall <= height, `${theme} ${locale} 1440x${height}: the whole dashboard fits without scrolling`);
      if (errors.length) check(false, `${theme} ${locale} ${width}px: console errors: ${errors.join(' | ')}`);
      if (locale === 'vi' && theme === 'light' && width === 1440) {
        writeFileSync(`${OUT}/aria-vi.yml`, await page.locator('.dashboard').ariaSnapshot());
      }
      await page.screenshot({ path: `${OUT}/${theme}-${locale}-${width}.png`, fullPage: true });
      await context.close();
    }
  }
}
// The columns follow the room the dashboard has, which is not the window's
// width: the sidebar is hidden on a tablet, so 768px can have more room than
// 1024px.
const rooms = Object.keys(columnsAt).map(Number).sort((a, b) => b - a);
check(rooms.every((r, i) => i === 0 || columnsAt[r] <= columnsAt[rooms[i - 1]]),
  `rows never widen as the room narrows (${rooms.map((r) => `${r}px:${columnsAt[r]}`).join(' ')})`);

await browser.close();
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
