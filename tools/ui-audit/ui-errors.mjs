// Every page of a panel, as an administrator: console errors and requests that
// answer 4xx or 5xx. The frontend is the same on every distribution; what each
// page asks the API is not, so this is the UI half of a per-OS check.
//
//     PANEL_BASE=https://<ip>:2222 LOGIN_FILE=login-<name>.txt node ui-errors.mjs
import { chromium } from 'playwright';
import { BASE, logIn, ROUTES } from './capture.mjs';

const pages = { ...ROUTES, mcp: '/ai-assistants', 'waf-site': '/waf-site' };
const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: 'en-US' });
await logIn(context);
let bad = 0;
for (const [name, path] of Object.entries(pages)) {
  const page = await context.newPage();
  const problems = [];
  page.on('console', (m) => { if (m.type() === 'error') problems.push(`console: ${m.text().slice(0, 160)}`); });
  page.on('response', (r) => { if (r.status() >= 400) problems.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}`); });
  page.on('pageerror', (e) => problems.push(`pageerror: ${String(e).slice(0, 160)}`));
  await page.goto(`${BASE}${path}`, { waitUntil: 'networkidle', timeout: 60000 }).catch((e) => problems.push(`goto: ${e.message.slice(0, 120)}`));
  await page.waitForTimeout(1500);
  const unique = [...new Set(problems)];
  if (unique.length) bad += 1;
  console.log(`${unique.length ? 'FAIL' : 'PASS'}  ${name.padEnd(14)} ${unique.join(' | ') || 'no console errors, no 4xx/5xx'}`);
  await page.close();
}
await browser.close();
console.log(`${Object.keys(pages).length - bad} of ${Object.keys(pages).length} pages clean`);
