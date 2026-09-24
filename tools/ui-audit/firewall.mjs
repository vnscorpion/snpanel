// The Firewall page: state at a glance, one form for rules, a real table.
//
//     node firewall.mjs [out-dir]
//
// Checks, as the administrator, on a box whose firewall is on:
//   - the state is said in words, with the always-open ports beside it, and
//     the helper's raw text is folded away until asked for;
//   - the add form is one form: protocol only with a port, block only with
//     an address;
//   - a rule added through the form appears in the table, and the table's
//     delete removes it - allow by port, and block by address;
//   - no console errors, no sideways scroll;
// and saves screenshots in both themes and both languages.
//
// It adds and deletes two rules: allow 65002/tcp, and block 203.0.113.77, an
// address reserved for documentation. Whatever the checks do, both are
// removed again before it exits.
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/firewall';
mkdirSync(OUT, { recursive: true });
const PORT = '65002';
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
  const status = await (await context.request.get(`${BASE}/api/firewall/status`)).json();
  for (const rule of status.rules || []) {
    if (rule.to === `${PORT}/tcp` || rule.from === `${ADDRESS}/32`) {
      await context.request.delete(`${BASE}/api/firewall/rules/${rule.id}`, { headers });
    }
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
  const ports = await page.$$eval('.fw-ports code', (cs) => cs.map((c) => c.textContent));
  check(ports.join(',') === '22,80,443,465,587,2222', `the always-open ports are listed (${ports.join(', ')})`);
  check(await page.getByRole('button', { name: 'Turn off' }).isVisible()
    && await page.getByRole('button', { name: 'Turn on' }).count() === 0, 'one on/off button, the one that changes something');
  check(!(await page.locator('.fw-details').evaluate((d) => d.open)) && !(await page.locator('.fw-details pre').first().isVisible()),
    'the raw status is folded away');
  check(await page.getByText('Delete rule #', { exact: true }).count() === 0, 'no rule-number field');
  check(await page.locator('.fw-rules form').count() === 1, 'one form adds every kind of rule');

  // ---------------------------------------------------------------- the form
  const form = page.locator('.fw-rule-form');
  const action = form.locator('select').first();
  const address = form.getByLabel('From address');
  const port = form.getByLabel('Port');
  const protocol = form.getByLabel('Protocol');
  const submit = form.locator('button[type="submit"]');
  check(await protocol.isDisabled(), 'protocol is off without a port');
  await port.fill(PORT);
  check(await protocol.isEnabled(), 'protocol is on with one');
  await port.fill('');
  await action.selectOption('block');
  check(await submit.isDisabled(), 'blocking needs an address');
  await address.fill(ADDRESS);
  check(await submit.isEnabled() && (await submit.textContent()).includes('Add block'), 'with one it can be sent');
  await address.fill('');
  await action.selectOption('allow');

  // ---------------------------------------------------------------- add, see, delete
  const dialogs = [];
  page.on('dialog', (d) => { dialogs.push(d.message()); d.accept(); });

  await port.fill(PORT);
  await submit.click();
  const allowRow = page.locator('.fw-table tbody tr', { hasText: `${PORT}/tcp` });
  await allowRow.waitFor({ timeout: 15000 });
  check(await allowRow.locator('.badge').textContent() === 'Allow' && (await allowRow.textContent()).includes('Anyone'),
    `an allowed port appears in the table (${(await allowRow.textContent()).replace(/\s+/g, ' ').trim()})`);
  check(await port.inputValue() === '', 'the form clears after adding');

  await action.selectOption('block');
  await address.fill(ADDRESS);
  await submit.click();
  const blockRow = page.locator('.fw-table tbody tr', { hasText: `${ADDRESS}/32` });
  await blockRow.waitFor({ timeout: 15000 });
  check(dialogs.some((m) => m.includes(`Block ${ADDRESS}?`)), `blocking asks first (${dialogs.at(-1)})`);
  check(await blockRow.locator('.badge').textContent() === 'Block' && (await blockRow.textContent()).includes('All ports'),
    `a blocked address appears in the table (${(await blockRow.textContent()).replace(/\s+/g, ' ').trim()})`);

  await page.screenshot({ path: `${OUT}/with-rules-light-en-1440.png`, fullPage: true });
  // The table on a phone: it scrolls inside its frame, the page does not.
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(300);
  const sidewaysWithRules = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  check(sidewaysWithRules <= 0, `with rules in the table, no sideways scroll at 390px (${sidewaysWithRules}px)`);
  await page.screenshot({ path: `${OUT}/with-rules-light-en-390.png`, fullPage: true });
  await page.setViewportSize({ width: 1440, height: 900 });

  for (const [row, what] of [[allowRow, 'the allowed port'], [blockRow, 'the blocked address']]) {
    const id = (await row.locator('.fw-id').textContent()).trim();
    await row.getByRole('button', { name: `Delete rule #${id}` }).click();
    await row.waitFor({ state: 'detached', timeout: 15000 });
    check(dialogs.some((m) => m.includes(`Delete firewall rule #${id}?`)), `deleting ${what} asks first, then removes the row`);
  }
  check(await page.locator('.fw-empty').isVisible(), 'the table is back to its empty state');

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
