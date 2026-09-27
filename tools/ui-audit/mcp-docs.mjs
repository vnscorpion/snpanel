// The AI assistants page documents what an assistant can do, for each role.
//
//     node mcp-docs.mjs [out-dir]        (LOGIN_FILE: the administrator's)
//
// As the administrator: how to connect is shown with no token made - five
// clients, the endpoint and a <token> placeholder - and every tool is listed,
// the administrators' own marked, with its arguments; a new token fills the
// snippets in, and Done takes it back out. As a throwaway customer: only the
// tools an end user's token is offered, none marked for administrators. The
// page in Vietnamese reads the tools' own words in Vietnamese. The MCP addon
// is left installed or not, as it was found; the customer and the token are
// removed at the end.
import { chromium } from 'playwright';
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/mcp-docs';
const NAME = 'mcpdocs';
const PASSWORD = `D-${randomBytes(15).toString('base64url')}`;
mkdirSync(OUT, { recursive: true });
let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };

const browser = await chromium.launch();
const errors = [];
async function context(locale = 'en', width = 1440) {
  const c = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width, height: 900 }, locale: 'en-US' });
  await c.addInitScript((l) => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', l); } catch {} }, locale);
  return c;
}
const csrfOf = async (c) => (await c.cookies()).find((k) => k.name === 'snpanel_csrf')?.value;
const api = async (c, method, path, data) => c.request.fetch(`${BASE}/api${path}`, { method, data, headers: { 'X-CSRF-Token': (await csrfOf(c)) || '' } });

const admin = await context();
await logIn(admin);
const addons = await (await api(admin, 'GET', '/addons')).json();
const wasInstalled = !!addons.items?.find((a) => a.slug === 'mcp')?.installed;
const removeCustomer = async () => {
  const users = await (await api(admin, 'GET', '/users?usage=0')).json();
  const old = (users.items || users).find((u) => u.username === NAME);
  if (old) await api(admin, 'DELETE', `/users/${old.id}`);
};

try {
  if (!wasInstalled) await api(admin, 'POST', '/addons/mcp/install');
  await removeCustomer();
  const made = await api(admin, 'POST', '/users', { username: NAME, email: `${NAME}@example.invalid`, password: PASSWORD, role: 'end_user', website_limit: 1, storage_limit_mb: 100 });
  check(made.ok(), `a customer ${NAME} (${made.status()})`);

  // ------------------------------------------------ the administrator's page
  const catalogue = await (await api(admin, 'GET', '/mcp/tools')).json();
  const adminOnly = catalogue.tools.filter((t) => t.admin_only).length;
  check(catalogue.admin === true && catalogue.tools.length === 32 && adminOnly === 12,
    `GET /api/mcp/tools gives an administrator every tool (${catalogue.tools.length}, ${adminOnly} theirs alone)`);
  const page = await admin.newPage();
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(`${BASE}/ai-assistants`, { waitUntil: 'networkidle' });
  const connect = page.locator('.mcp-connect');
  await connect.waitFor({ timeout: 15000 });
  const snippets = await connect.locator('pre').allTextContents();
  check(snippets.length === 5 && snippets.every((s) => s.includes('/api/mcp') && s.includes('<token>')),
    `how to connect is shown with no token made: ${snippets.length} clients, each with the endpoint and <token>`);
  check(/mcp-remote/.test(snippets.join('\n')), 'Claude Desktop is among them, through mcp-remote');
  const cards = page.locator('.mcp-tool');
  check(await cards.count() === 32, `every tool is documented, none folded away (${await cards.count()} cards)`);
  check(await page.locator('.mcp-tool .badge.mcp-admin').count() === 12, 'the administrators\' own tools are marked');
  const block = page.locator('#mcp-tool-block_ip');
  check(await block.isVisible() && /203\.0\.113\.7/.test(await block.textContent()) && (await block.locator('.mcp-required').count()) >= 1,
    'a tool shows its arguments, their kinds, which are required and what they mean');
  check(await page.locator('.mcp-groups a').count() === 8, `the tools are in groups, with a link to each (${await page.locator('.mcp-groups a').count()})`);
  await page.screenshot({ path: `${OUT}/admin-light-en.png`, fullPage: true });
  await page.getByLabel('Find a tool').fill('firewall');
  const found = await cards.count();
  check(found > 0 && found < 32 && await page.locator('#mcp-tool-list_firewall_rules').isVisible(), `"Find a tool" narrows the list (${found} for "firewall")`);
  await page.getByLabel('Find a tool').fill('');

  // A token fills the snippets in; Done takes it back out.
  await page.getByLabel('Name', { exact: true }).fill('docs check');
  await page.getByRole('button', { name: 'Create token' }).click();
  const tokenText = (await page.locator('#mcp-token + pre, .mcp-made pre').first().textContent({ timeout: 15000 })).trim();
  const filled = await connect.locator('pre').allTextContents();
  check(tokenText.startsWith('snmcp_') && filled.every((s) => s.includes(tokenText) && !s.includes('<token>')),
    'a new token is carried by every snippet while it is shown');
  await page.getByRole('button', { name: 'Done' }).click();
  const cleared = await connect.locator('pre').allTextContents();
  check(cleared.every((s) => s.includes('<token>') && !s.includes(tokenText)), 'Done puts the placeholder back');
  const tokens = await (await api(admin, 'GET', '/mcp/tokens')).json();
  for (const item of tokens.items.filter((t) => t.name === 'docs check')) await api(admin, 'DELETE', `/mcp/tokens/${item.id}`);

  // ------------------------------------------------ a customer's page
  const customer = await context();
  const login = await customer.request.post(`${BASE}/api/auth/login`, { form: { username: NAME, password: PASSWORD } });
  check(login.status() === 200, `the customer signs in (${login.status()})`);
  const theirs = await (await api(customer, 'GET', '/mcp/tools')).json();
  check(theirs.admin === false && theirs.tools.length === 20 && theirs.tools.every((t) => !t.admin_only),
    `a customer is shown only what their token is offered (${theirs.tools.length}, none of the administrators')`);
  const cpage = await customer.newPage();
  cpage.on('pageerror', (e) => errors.push(String(e)));
  await cpage.goto(`${BASE}/ai-assistants`, { waitUntil: 'networkidle' });
  await cpage.locator('.mcp-docs').waitFor({ timeout: 15000 });
  check(await cpage.locator('.mcp-tool').count() === 20 && await cpage.locator('.badge.mcp-admin').count() === 0
    && await cpage.locator('#mcp-tool-block_ip').count() === 0,
  'the customer\'s page lists their 20 tools, and not block_ip');
  await cpage.screenshot({ path: `${OUT}/customer-light-en.png`, fullPage: true });

  // ------------------------------------------------ in Vietnamese
  const vi = await context('vi', 390);
  await logIn(vi);
  const vpage = await vi.newPage();
  vpage.on('pageerror', (e) => errors.push(String(e)));
  await vpage.goto(`${BASE}/ai-assistants`, { waitUntil: 'networkidle' });
  await vpage.locator('#mcp-tool-list_websites').waitFor({ timeout: 15000 });
  await vpage.getByText('Danh sách website', { exact: true }).waitFor({ timeout: 10000 });
  check(/Tên miền của website/.test(await vpage.locator('#mcp-tool-get_website').textContent()),
    'in Vietnamese the tools\' titles and arguments are Vietnamese too');
  const overflow = await vpage.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check(overflow <= 0, `nothing runs off a phone's screen (${overflow}px)`);
  await vpage.screenshot({ path: `${OUT}/admin-phone-light-vi.png`, fullPage: true });

  check(errors.length === 0, `no page errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} catch (err) {
  ok = false;
  console.log(`FAIL  ${err.message.split('\n')[0]}`);
} finally {
  await removeCustomer();
  if (!wasInstalled) await api(admin, 'POST', '/addons/mcp/uninstall');
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
