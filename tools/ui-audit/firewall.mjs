// The Firewall page: state at a glance, open ports on their own, addresses
// in a real table.
//
//     node firewall.mjs [out-dir]
//
// Checks, as the administrator, on a box whose firewall is on:
//   - the state is said in words, and the helper's raw text is folded away
//     until asked for;
//   - "Open ports" lists the always-open ports and takes one port number -
//     nothing else - and a port opened there is a chip with its own close
//     button, not a row of the address table;
//   - the address form always needs an address, allow and block alike, with
//     protocol only when a port is given;
//   - rules added through either form appear, and their close/delete removes
//     them;
//   - no console errors, no sideways scroll;
// and saves screenshots in both themes and both languages.
//
// It adds and deletes three rules: open 65002/tcp, allow 203.0.113.78 on
// 65003, and block 203.0.113.77 - addresses reserved for documentation.
// Whatever the checks do, all are removed again before it exits.
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/firewall';
mkdirSync(OUT, { recursive: true });
const PORT = '65002';
const ALLOW_ADDRESS = '203.0.113.78';
const ALLOW_PORT = '65003';
const ADDRESS = '203.0.113.77';

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };

const browser = await chromium.launch();

async function open({ theme = 'light', locale = 'en', viewport = { width: 1440, height: 900 } } = {}) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport, locale: 'en-US' });
  await context.addInitScript(([t, l]) => {
    try { localStorage.setItem('snpanel-theme', t); localStorage.setItem('snpanel-locale', l); } catch {}
  }, [theme, locale]);
  await logIn(context);
  const page = await context.newPage();
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(`${BASE}/firewall`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.fw-status:not([data-state="loading"])');
  await page.waitForTimeout(300);
  return { context, page, errors };
}

async function cleanUp(context) {
  const csrf = (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
  const headers = csrf ? { 'X-CSRF-Token': csrf } : {};
  // Deleting renumbers the rest, so one at a time, highest first.
  for (let round = 0; round < 5; round += 1) {
    const status = await (await context.request.get(`${BASE}/api/firewall/status`)).json();
    const ours = (status.rules || []).filter((rule) => rule.to === `${PORT}/tcp` || rule.to === `${ALLOW_PORT}/tcp`
      || String(rule.from).startsWith(`${ADDRESS}`) || String(rule.from).startsWith(`${ALLOW_ADDRESS}`));
    if (!ours.length) return;
    const last = ours.sort((a, b) => Number(b.id) - Number(a.id))[0];
    await context.request.delete(`${BASE}/api/firewall/rules/${last.id}`, { headers });
  }
}

const { context, page, errors } = await open();
try {
  await cleanUp(context);
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForSelector('.fw-status:not([data-state="loading"])');

  // ---------------------------------------------------------------- state
  const state = await page.getAttribute('.fw-status', 'data-state');
  const heading = await page.locator('.fw-status h2').textContent();
  check(state === 'on' && heading === 'The firewall is on', `the state is said in words (${state}: "${heading}")`);
  check(await page.getByRole('button', { name: 'Turn off' }).isVisible()
    && await page.getByRole('button', { name: 'Turn on' }).count() === 0, 'one on/off button, the one that changes something');
  check(!(await page.locator('.fw-details').evaluate((d) => d.open)) && !(await page.locator('.fw-details pre').first().isVisible()),
    'the raw status is folded away');

  // ---------------------------------------------------------------- open ports
  const always = await page.$$eval('.fw-port-chip.always code', (cs) => cs.map((c) => c.textContent));
  check(always.join(',') === '22,80,443,465,587,2222', `the always-open ports are listed under Open ports (${always.join(', ')})`);
  const portForm = page.locator('.fw-port-form');
  const portInput = portForm.getByLabel('Port');
  const openButton = portForm.getByRole('button', { name: 'Open port' });
  check(await openButton.isDisabled(), 'Open port waits for a number');
  for (const bad of ['abc', '0', '70000', '8000:8100', '80 81']) {
    await portInput.fill(bad);
    check(await openButton.isDisabled(), `"${bad}" is not a port it will send`);
  }
  await portInput.fill(PORT);
  check(await openButton.isEnabled(), `${PORT} is`);

  const dialogs = [];
  page.on('dialog', (d) => { dialogs.push(d.message()); d.accept(); });

  await openButton.click();
  const chip = page.locator('.fw-port-chip:not(.always)', { hasText: `${PORT}/tcp` });
  await chip.waitFor({ timeout: 15000 });
  check(await chip.isVisible(), `an opened port is a chip (${(await chip.textContent()).trim()})`);
  check(await portInput.inputValue() === '', 'the port form clears after opening');
  check(await page.locator('.fw-table tbody tr', { hasText: `${PORT}/tcp` }).count() === 0, 'and it is not a row of the address table');

  // ---------------------------------------------------------------- addresses
  check(await page.locator('.fw-rules form').count() === 1, 'one form for addresses');
  const form = page.locator('.fw-rule-form');
  const action = form.locator('select').first();
  const address = form.getByLabel('From address');
  const port = form.getByLabel('Port');
  const protocol = form.getByLabel('Protocol');
  const submit = form.locator('button[type="submit"]');
  check(await protocol.isDisabled(), 'protocol is off without a port');
  await port.fill(ALLOW_PORT);
  check(await protocol.isEnabled(), 'protocol is on with one');
  check(await submit.isDisabled(), 'allowing a port needs an address here - a port for everyone is Open ports');
  await address.fill(ALLOW_ADDRESS);
  check(await submit.isEnabled(), 'with an address it can be sent');
  await submit.click();
  const allowRow = page.locator('.fw-table tbody tr', { hasText: ALLOW_ADDRESS });
  await allowRow.waitFor({ timeout: 15000 });
  check(await allowRow.locator('.badge').textContent() === 'Allow' && (await allowRow.textContent()).includes(`${ALLOW_PORT}/tcp`),
    `an allowed address on one port appears in the table (${(await allowRow.textContent()).replace(/\s+/g, ' ').trim()})`);
  check(await page.locator('.fw-port-chip', { hasText: `${ALLOW_PORT}/tcp` }).count() === 0, 'and not among the open ports');

  await action.selectOption('block');
  check(await submit.isDisabled(), 'blocking needs an address');
  await address.fill(ADDRESS);
  await submit.click();
  const blockRow = page.locator('.fw-table tbody tr', { hasText: `${ADDRESS}/32` });
  await blockRow.waitFor({ timeout: 15000 });
  check(dialogs.some((m) => m.includes(`Block ${ADDRESS}?`)), `blocking asks first (${dialogs.at(-1)})`);
  check(await blockRow.locator('.badge').textContent() === 'Block' && (await blockRow.textContent()).includes('All ports'),
    `a blocked address appears in the table (${(await blockRow.textContent()).replace(/\s+/g, ' ').trim()})`);

  await page.screenshot({ path: `${OUT}/with-rules-light-en-1440.png`, fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(300);
  const sidewaysWithRules = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  check(sidewaysWithRules <= 0, `with rules, no sideways scroll at 390px (${sidewaysWithRules}px)`);
  await page.screenshot({ path: `${OUT}/with-rules-light-en-390.png`, fullPage: true });
  await page.setViewportSize({ width: 1440, height: 900 });

  // Highest rule number first: deleting one renumbers the rules after it.
  for (const [row, what] of [[blockRow, 'the blocked address'], [allowRow, 'the allowed address']]) {
    const id = (await row.locator('.fw-id').textContent()).trim();
    await row.getByRole('button', { name: `Delete rule #${id}` }).click();
    await row.waitFor({ state: 'detached', timeout: 15000 });
    check(dialogs.some((m) => m.includes(`Delete firewall rule #${id}?`)), `deleting ${what} asks first, then removes the row`);
  }
  await chip.getByRole('button', { name: `Close port ${PORT}/tcp` }).click();
  await chip.waitFor({ state: 'detached', timeout: 15000 });
  check(true, 'closing the opened port removes its chip');
  check(await page.locator('.fw-table tbody tr', { hasText: ADDRESS }).count() === 0
    && await page.locator('.fw-table tbody tr', { hasText: ALLOW_ADDRESS }).count() === 0,
    'the address table no longer lists either address');

  // ---------------------------------------------------------------- blocklists, details
  const facts = await page.locator('.fw-blocklist-facts').textContent();
  check(/\d[\d,.]* networks blocked/.test(facts), `the blocklists say how much they block (${facts})`);
  await page.locator('.fw-details summary').click();
  const raw = await page.locator('.fw-details pre').first().textContent();
  check(raw.includes('Status: enabled') && raw.includes('Engine: nftables'), 'the raw status is there when asked for');

  check(errors.length === 0, `no console errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} finally {
  await cleanUp(context);
  await context.close();
}

// ---------------------------------------------------------------- looks
for (const theme of ['light', 'dark']) {
  for (const locale of ['en', 'vi']) {
    for (const [width, height] of [[1440, 900], [390, 844]]) {
      const view = await open({ theme, locale, viewport: { width, height } });
      const sideways = await view.page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      check(sideways <= 0 && view.errors.length === 0, `${theme} ${locale} ${width}px: no sideways scroll (${sideways}px), no console errors`);
      await view.page.screenshot({ path: `${OUT}/${theme}-${locale}-${width}.png`, fullPage: true });
      await view.context.close();
    }
  }
}

await browser.close();
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
