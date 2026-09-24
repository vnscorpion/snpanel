// The Panel settings form must not be overwritten by a late public response.
//
//     node settings-race.mjs
//
// Opening /settings with a live session fires two requests for the same
// state: the public one from mount, before the session is known, and the
// authenticated one once it is. The public answer carries an empty hostname
// and `ssl_enabled: false`. If it lands second and is allowed to write, the
// form shows the panel's IP and SSL off - and "Save settings" makes both true.
//
// This holds the public response back so it always lands second, then checks
// the form against what the authenticated endpoint itself says.
import { chromium } from 'playwright';
import { BASE, logIn } from './capture.mjs';

const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true });
await logIn(context);

const expected = await (await context.request.get(`${BASE}/api/panel-settings`)).json();
if (!expected.panel_hostname) {
  console.log('SKIP: this panel has no hostname set, so the race has nothing to overwrite');
  await browser.close();
  process.exit(0);
}

const page = await context.newPage();
let held = 0;
await page.route('**/api/panel-settings/public', async (route) => {
  held++;
  await new Promise((r) => setTimeout(r, 2500));
  await route.continue();
});

await page.goto(`${BASE}/settings`, { waitUntil: 'networkidle' });
await page.waitForTimeout(3500); // past the held-back response

const hostname = await page.getByRole('textbox', { name: 'Panel hostname' }).inputValue();
const ssl = await page.getByRole('checkbox', { name: 'Panel SSL' }).isChecked();
await browser.close();

console.log(`public requests held back: ${held}`);
console.log(`expected: hostname=${JSON.stringify(expected.panel_hostname)} ssl=${!!expected.ssl_enabled}`);
console.log(`form:     hostname=${JSON.stringify(hostname)} ssl=${ssl}`);
const ok = held > 0 && hostname === expected.panel_hostname && ssl === !!expected.ssl_enabled;
console.log(ok ? 'PASS' : held === 0 ? 'FAIL: no public request was made, so nothing was tested' : 'FAIL: the late public response overwrote the form');
process.exit(ok ? 0 : 1);
