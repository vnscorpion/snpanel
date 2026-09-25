// Screenshot every page of a live panel, in both themes, and record each
// page's accessibility snapshot.
//
// Run on the box the panel is on, as root, after:
//
//     npm install && npx playwright install --with-deps chromium
//
// then:
//
//     node capture.mjs <out-dir> [light|dark|both]
//
// It logs in through the panel's own API with the password from
// /root/login.txt (LOGIN_FILE to override) - the way the acceptance check
// does - so the browser context carries the session and CSRF cookies. The
// theme goes into localStorage before any page script runs, because the
// panel applies it on first paint.
//
// The aria snapshots are the regression oracle for frontend refactors: roles,
// names, labels and text for the whole page, which a change that means to
// alter nothing must leave identical. Digit runs are normalised because the
// dashboard carries live CPU and network figures. Two captures of the same
// build must match before a comparison against one means anything; check
// that first on a new box.
import { chromium } from 'playwright';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';

export const BASE = process.env.PANEL_BASE || 'https://127.0.0.1:2222';
// en or vi. Unset means whatever the panel picks for a browser that says
// en-US, which is English.
const LOCALE = process.env.LOCALE || '';
const LOGIN_FILE = process.env.LOGIN_FILE || '/root/login.txt';

export const ROUTES = {
  dashboard: '/',
  websites: '/website',
  databases: '/database',
  files: '/filemanager',
  backups: '/backups',
  users: '/users',
  settings: '/settings',
  'api-tokens': '/api-tokens',
  security: '/security',
  php: '/php',
  firewall: '/firewall',
  fail2ban: '/fail2ban',
  waf: '/waf',
  malware: '/malware',
  'access-logs': '/access-logs',
  updates: '/updates',
  services: '/services',
  addons: '/addons',
  ssl: '/ssl',
  cron: '/cron',
  applications: '/applications',
};

export function adminPassword() {
  const password = readFileSync(LOGIN_FILE, 'utf8')
    .split('\n')
    .find((l) => l.startsWith('Password: '))
    ?.slice('Password: '.length);
  if (!password) throw new Error(`no password in ${LOGIN_FILE}`);
  return password;
}

export async function logIn(context) {
  const res = await context.request.post(`${BASE}/api/auth/login`, {
    form: { username: 'admin', password: adminPassword() },
  });
  if (res.status() !== 200) throw new Error(`login failed: HTTP ${res.status()} ${await res.text()}`);
}

const normalise = (text) => text.replace(/\d+/g, '#');

export async function capture(out, themes) {
  const browser = await chromium.launch();
  const report = {};

  for (const theme of themes) {
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      viewport: { width: 1440, height: 900 },
    });
    await context.addInitScript(([t, l]) => {
      try {
        localStorage.setItem('snpanel-theme', t);
        if (l) localStorage.setItem('snpanel-locale', l);
      } catch {}
    }, [theme, LOCALE]);

    mkdirSync(`${out}/${theme}`, { recursive: true });
    mkdirSync(`${out}/aria`, { recursive: true });
    {
      const page = await context.newPage();
      await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(600);
      await page.screenshot({ path: `${out}/${theme}/00-login.png`, fullPage: true });
      if (theme === themes[0]) {
        writeFileSync(`${out}/aria/00-login.yml`, normalise(await page.locator('body').ariaSnapshot()));
      }
      await page.close();
    }

    await logIn(context);

    for (const [name, route] of Object.entries(ROUTES)) {
      const page = await context.newPage();
      const errors = [];
      page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
      page.on('pageerror', (e) => errors.push(String(e)));

      const started = Date.now();
      await page.goto(`${BASE}${route}`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(800);
      const settled = Date.now() - started;

      await page.screenshot({ path: `${out}/${theme}/${name}.png`, fullPage: true });
      // One theme is enough for structure; the snapshot carries no colour.
      if (theme === themes[0]) {
        writeFileSync(`${out}/aria/${name}.yml`, normalise(await page.locator('body').ariaSnapshot()));
      }
      report[`${theme}/${name}`] = { ms: settled, errors };
      await page.close();
    }
    await context.close();
  }

  await browser.close();
  writeFileSync(`${out}/report.json`, JSON.stringify(report, null, 2));
  return report;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const out = process.argv[2] || 'shots';
  const which = process.argv[3] || 'both';
  const report = await capture(out, which === 'both' ? ['light', 'dark'] : [which]);
  for (const [k, v] of Object.entries(report)) {
    console.log(`${k.padEnd(24)} ${String(v.ms).padStart(6)}ms  ${v.errors.length} errors`);
  }
}
